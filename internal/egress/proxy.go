package egress

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// DefaultHoldTimeout is how long a connection to an unknown host is held
	// while the owner decides (contract: <= 60 s, then deny).
	DefaultHoldTimeout = 60 * time.Second
	// DefaultFlushInterval batches egress.log frames.
	DefaultFlushInterval = 5 * time.Second

	// denyTTL keeps an explicit "deny" for a while, so a client that retries
	// in a loop (package managers do) doesn't raise a new prompt per retry.
	denyTTL = 30 * time.Second
	// maxLogEntries bounds the per-workspace log kept while no tunnel
	// session is connected; the oldest entries are dropped first.
	maxLogEntries = 1000

	headerTimeout   = 30 * time.Second
	upstreamTimeout = 15 * time.Second
)

// Decisions in egress.decision frames.
const (
	DecisionAllowOnce    = "allow_once"
	DecisionAllowProject = "allow_project"
	DecisionDeny         = "deny"
)

// Sender is the slice of tunnel.Session the proxy needs.
type Sender interface {
	TrySend(frame any) bool
}

// LogEntry is one egress.log entry.
type LogEntry struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Decision string `json:"decision"` // allowed | denied | prompted
	TS       string `json:"ts"`
	BytesOut int64  `json:"bytes_out"`
	BytesIn  int64  `json:"bytes_in"`
}

// Proxy is the egress proxy. Safe for concurrent use.
type Proxy struct {
	HoldTimeout   time.Duration
	FlushInterval time.Duration
	// Logf, if set, receives one line per prompt and per denial.
	Logf func(format string, args ...any)

	key      []byte
	stateDir string

	// Test seams.
	dial   func(ctx context.Context, network, addr string) (net.Conn, error)
	lookup func(ctx context.Context, host string) ([]net.IP, error)
	now    func() time.Time

	mu      sync.Mutex
	sender  Sender
	ws      map[string]*workspace
	pending map[string]*pending // by request_id
}

type workspace struct {
	policy Policy
	denied map[string]time.Time // host -> until
	asking map[string]*pending  // host -> in-flight request
	log    []LogEntry
}

type pending struct {
	id, wsID, host string
	port           int
	done           chan struct{}
	decision       string
}

// New returns a proxy whose per-workspace passwords are derived from key.
// stateDir (optional) persists policies so allow_project survives a restart.
func New(key []byte, stateDir string) *Proxy {
	d := &net.Dialer{Timeout: upstreamTimeout, KeepAlive: 30 * time.Second}
	p := &Proxy{
		HoldTimeout:   DefaultHoldTimeout,
		FlushInterval: DefaultFlushInterval,
		key:           key,
		stateDir:      stateDir,
		dial:          d.DialContext,
		lookup: func(ctx context.Context, host string) ([]net.IP, error) {
			addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			ips := make([]net.IP, 0, len(addrs))
			for _, a := range addrs {
				ips = append(ips, a.IP)
			}
			return ips, err
		},
		now:     time.Now,
		ws:      map[string]*workspace{},
		pending: map[string]*pending{},
	}
	p.loadState()
	return p
}

// LoadOrCreateKey reads the proxy secret from path, creating a random one
// (0600) on first use.
func LoadOrCreateKey(path string) ([]byte, error) {
	if b, err := os.ReadFile(path); err == nil && len(b) >= 32 {
		return b, nil
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, key, 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

// ValidWorkspaceID limits ids to what the backend issues (integers today),
// since they end up in file names, proxy user names and pf-free paths.
func ValidWorkspaceID(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	for _, c := range id {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func (p *Proxy) password(id string) string {
	m := hmac.New(sha256.New, p.key)
	m.Write([]byte("clux-egress.v1\n" + id))
	return hex.EncodeToString(m.Sum(nil))[:32]
}

// URL is the HTTP(S)_PROXY value for workspace id on proxy port port.
func (p *Proxy) URL(id string, port int) string {
	return fmt.Sprintf("http://ws-%s:%s@127.0.0.1:%d", id, p.password(id), port)
}

// SetSender points prompts and logs at the current tunnel session (nil
// while disconnected: unknown hosts are then denied at once).
func (p *Proxy) SetSender(s Sender) {
	p.mu.Lock()
	p.sender = s
	p.mu.Unlock()
}

// SetPolicy installs or replaces a workspace's policy.
func (p *Proxy) SetPolicy(id string, pol Policy) error {
	if !ValidWorkspaceID(id) {
		return fmt.Errorf("invalid workspace id %q", id)
	}
	p.mu.Lock()
	w := p.ws[id]
	if w == nil {
		w = newWorkspace()
		p.ws[id] = w
	}
	w.policy = pol
	p.mu.Unlock()
	return p.saveState(id, pol)
}

// Policy returns a workspace's current policy.
func (p *Proxy) Policy(id string) (Policy, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	w := p.ws[id]
	if w == nil {
		return Policy{}, false
	}
	return w.policy, true
}

// Forget removes a deleted workspace; held requests are denied.
func (p *Proxy) Forget(id string) {
	p.mu.Lock()
	var held []*pending
	for _, pr := range p.pending {
		if pr.wsID == id {
			held = append(held, pr)
		}
	}
	for _, pr := range held {
		p.resolveLocked(pr, DecisionDeny)
	}
	delete(p.ws, id)
	p.mu.Unlock()
	if p.stateDir != "" {
		_ = os.Remove(filepath.Join(p.stateDir, id+".json"))
	}
}

// Decide applies an egress.decision frame. A decision for a request that
// already timed out still applies allow_project to the policy, so the
// owner's late "allow for project" helps the client's next attempt.
func (p *Proxy) Decide(id, requestID, decision, host string) {
	p.mu.Lock()
	pr := p.pending[requestID]
	if pr != nil && pr.wsID != id {
		pr = nil
	}
	w := p.ws[id]
	if pr != nil {
		host = pr.host
	} else {
		host = NormalizeHost(host)
	}
	var save *Policy
	if w != nil && host != "" {
		switch decision {
		case DecisionAllowProject:
			w.policy = w.policy.with(host)
			pol := w.policy
			save = &pol
		case DecisionDeny:
			w.denied[host] = p.now().Add(denyTTL)
		}
	}
	if pr != nil {
		p.resolveLocked(pr, decision)
	}
	p.mu.Unlock()
	if save != nil {
		if err := p.saveState(id, *save); err != nil {
			p.logf("egress: saving policy for workspace %s: %v", id, err)
		}
	}
}

func (p *Proxy) resolveLocked(pr *pending, decision string) {
	if _, ok := p.pending[pr.id]; !ok {
		return
	}
	delete(p.pending, pr.id)
	if w := p.ws[pr.wsID]; w != nil && w.asking[pr.host] == pr {
		delete(w.asking, pr.host)
	}
	pr.decision = decision
	close(pr.done)
}

func newWorkspace() *workspace {
	return &workspace{denied: map[string]time.Time{}, asking: map[string]*pending{}}
}

// --- serving -----------------------------------------------------------------

// ListenAndServe serves on 127.0.0.1:port and [::1]:port until ctx ends.
// IPv6 is best-effort (a machine with IPv6 disabled on lo0 still works).
func (p *Proxy) ListenAndServe(ctx context.Context, port int) error {
	l4, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return fmt.Errorf("egress proxy: %w", err)
	}
	go p.Serve(ctx, l4)
	if l6, err := net.Listen("tcp6", fmt.Sprintf("[::1]:%d", port)); err == nil {
		go p.Serve(ctx, l6)
	} else {
		p.logf("egress proxy: not listening on [::1]:%d: %v", port, err)
	}
	return nil
}

// Serve accepts proxy connections on l until ctx ends.
func (p *Proxy) Serve(ctx context.Context, l net.Listener) {
	go func() {
		<-ctx.Done()
		l.Close()
	}()
	for {
		c, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			p.logf("egress proxy: accept: %v", err)
			return
		}
		go p.handle(ctx, c)
	}
}

// Run flushes batched egress.log frames until ctx ends.
func (p *Proxy) Run(ctx context.Context) {
	iv := p.FlushInterval
	if iv <= 0 {
		iv = DefaultFlushInterval
	}
	t := time.NewTicker(iv)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.Flush()
		}
	}
}

// Flush sends every workspace's buffered log entries now. Entries that can't
// be sent stay buffered (bounded) for the next session.
func (p *Proxy) Flush() {
	type batch struct {
		id      string
		entries []LogEntry
	}
	p.mu.Lock()
	s := p.sender
	if s == nil {
		p.mu.Unlock()
		return
	}
	var out []batch
	for id, w := range p.ws {
		if len(w.log) > 0 {
			out = append(out, batch{id, w.log})
			w.log = nil
		}
	}
	p.mu.Unlock()
	for _, b := range out {
		frame := map[string]any{"type": "egress.log", "workspace_id": wireID(b.id), "entries": b.entries}
		if !s.TrySend(frame) {
			p.mu.Lock()
			if w := p.ws[b.id]; w != nil {
				w.log = capLog(append(b.entries, w.log...))
			}
			p.mu.Unlock()
		}
	}
}

func (p *Proxy) handle(ctx context.Context, c net.Conn) {
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(headerTimeout))
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	_ = c.SetReadDeadline(time.Time{})
	id, ok := p.authenticate(req)
	if !ok {
		io.WriteString(c, "HTTP/1.1 407 Proxy Authentication Required\r\n"+
			"Proxy-Authenticate: Basic realm=\"clux\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		return
	}
	if req.Method == http.MethodConnect {
		p.serveConnect(ctx, c, br, req, id)
		return
	}
	p.serveHTTP(ctx, c, req, id)
}

func (p *Proxy) authenticate(req *http.Request) (string, bool) {
	h := req.Header.Get("Proxy-Authorization")
	req.Header.Del("Proxy-Authorization")
	scheme, b64, ok := strings.Cut(h, " ")
	if !ok || !strings.EqualFold(scheme, "Basic") {
		return "", false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return "", false
	}
	user, pass, ok := strings.Cut(string(raw), ":")
	id, isWS := strings.CutPrefix(user, "ws-")
	if !ok || !isWS || !ValidWorkspaceID(id) {
		return "", false
	}
	if !hmac.Equal([]byte(pass), []byte(p.password(id))) {
		return "", false
	}
	p.mu.Lock()
	_, known := p.ws[id]
	p.mu.Unlock()
	return id, known
}

func (p *Proxy) serveConnect(ctx context.Context, c net.Conn, br *bufio.Reader, req *http.Request, id string) {
	host, port := splitTarget(req.Host, 443)
	started := p.now()
	addr, err := p.admit(ctx, id, host, port)
	if err != nil {
		p.record(id, host, port, "denied", started, 0, 0)
		p.logf("egress: workspace %s: denied %s:%d (%v)", id, host, port, err)
		fmt.Fprintf(c, "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n"+
			"clux egress: %s:%d is not allowed for this workspace (%v)\n", host, port, err)
		return
	}
	up, err := p.dial(ctx, "tcp", addr)
	if err != nil {
		p.record(id, host, port, "allowed", started, 0, 0)
		io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
		return
	}
	defer up.Close()
	if _, err := io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	var out, in atomic.Int64
	done := make(chan struct{}, 2)
	go func() { // client -> upstream (incl. bytes already buffered by the request reader)
		n, _ := io.Copy(up, br)
		out.Add(n)
		closeWrite(up)
		done <- struct{}{}
	}()
	go func() {
		n, _ := io.Copy(c, up)
		in.Add(n)
		closeWrite(c)
		done <- struct{}{}
	}()
	<-done
	// One side finished; don't let a peer that never closes its half pin
	// the other goroutine (and this connection) forever.
	deadline := time.Now().Add(30 * time.Second)
	_ = c.SetDeadline(deadline)
	_ = up.SetDeadline(deadline)
	<-done
	p.record(id, host, port, "allowed", started, out.Load(), in.Load())
}

// serveHTTP forwards one plain-HTTP request (absolute-form URI) and closes
// the client connection afterwards; plain HTTP through the proxy is rare
// (package indexes and APIs are HTTPS = CONNECT), so no keep-alive.
func (p *Proxy) serveHTTP(ctx context.Context, c net.Conn, req *http.Request, id string) {
	started := p.now()
	if req.URL == nil || req.URL.Scheme != "http" || req.URL.Host == "" {
		io.WriteString(c, "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
		return
	}
	host, port := splitTarget(req.URL.Host, 80)
	addr, err := p.admit(ctx, id, host, port)
	if err != nil {
		p.record(id, host, port, "denied", started, 0, 0)
		p.logf("egress: workspace %s: denied %s:%d (%v)", id, host, port, err)
		fmt.Fprintf(c, "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n"+
			"clux egress: %s:%d is not allowed for this workspace (%v)\n", host, port, err)
		return
	}
	up, err := p.dial(ctx, "tcp", addr)
	if err != nil {
		p.record(id, host, port, "allowed", started, 0, 0)
		io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
		return
	}
	defer up.Close()
	for _, h := range []string{"Proxy-Connection", "Connection", "Keep-Alive", "Te", "Trailer", "Upgrade"} {
		req.Header.Del(h)
	}
	req.RequestURI = ""
	req.Close = true
	upW := &countingWriter{w: up}
	if err := req.Write(upW); err != nil {
		p.record(id, host, port, "allowed", started, upW.n, 0)
		return
	}
	resp, err := http.ReadResponse(bufio.NewReader(up), req)
	if err != nil {
		p.record(id, host, port, "allowed", started, upW.n, 0)
		io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
		return
	}
	defer resp.Body.Close()
	resp.Close = true
	cW := &countingWriter{w: c}
	_ = resp.Write(cW)
	p.record(id, host, port, "allowed", started, upW.n, cW.n)
}

// admit decides whether workspace id may reach host:port, asking the owner
// if needed, and returns the vetted address to dial (never re-resolved, so
// DNS can't swap in a loopback/LAN address after the check).
func (p *Proxy) admit(ctx context.Context, id, rawHost string, port int) (string, error) {
	host := NormalizeHost(rawHost)
	if host == "" || port < 1 || port > 65535 {
		return "", errors.New("invalid destination")
	}
	pol, known := p.Policy(id)
	if !known {
		return "", errors.New("unknown workspace")
	}
	if !pol.Allows(host, port) {
		decision := p.ask(ctx, id, host, port)
		if decision != DecisionAllowOnce && decision != DecisionAllowProject {
			return "", errors.New("not on the allow list")
		}
		pol, _ = p.Policy(id)
		if decision == DecisionAllowOnce {
			// allow_once covers exactly this destination; it may still only be
			// a LAN address if the owner named it explicitly.
			pol = Policy{Mode: pol.Mode, Allow: append(append([]string(nil), pol.Allow...), host)}
		}
	}
	var ips []net.IP
	if ip := net.ParseIP(host); ip != nil {
		ips = []net.IP{ip}
	} else {
		lctx, cancel := context.WithTimeout(ctx, upstreamTimeout)
		var err error
		ips, err = p.lookup(lctx, host)
		cancel()
		if err != nil {
			return "", fmt.Errorf("resolving: %w", err)
		}
	}
	for _, ip := range ips {
		if ip.IsLoopback() || ip.IsUnspecified() {
			continue // never: that is the owner's own machine
		}
		if !isPublic(ip) && !pol.listsExactly(host, port) {
			continue
		}
		return net.JoinHostPort(ip.String(), strconv.Itoa(port)), nil
	}
	return "", errors.New("resolves only to local or private addresses")
}

// ask sends one egress.request (shared by concurrent connections to the
// same host) and waits for the owner's decision.
func (p *Proxy) ask(ctx context.Context, id, host string, port int) string {
	p.mu.Lock()
	w := p.ws[id]
	if w == nil {
		p.mu.Unlock()
		return DecisionDeny
	}
	if until, ok := w.denied[host]; ok {
		if p.now().Before(until) {
			p.mu.Unlock()
			return DecisionDeny
		}
		delete(w.denied, host)
	}
	pr := w.asking[host]
	created := false
	if pr == nil {
		pr = &pending{id: newRequestID(), wsID: id, host: host, port: port, done: make(chan struct{})}
		w.asking[host] = pr
		p.pending[pr.id] = pr
		created = true
	}
	sender := p.sender
	p.mu.Unlock()

	if created {
		frame := map[string]any{
			"type":         "egress.request",
			"workspace_id": wireID(id),
			"request_id":   pr.id,
			"host":         host,
			"port":         port,
		}
		if sender == nil || !sender.TrySend(frame) {
			p.mu.Lock()
			p.resolveLocked(pr, DecisionDeny)
			p.mu.Unlock()
			return DecisionDeny
		}
		p.record(id, host, port, "prompted", p.now(), 0, 0)
		p.logf("egress: workspace %s: asking the owner about %s:%d", id, host, port)
	}

	hold := p.HoldTimeout
	if hold <= 0 {
		hold = DefaultHoldTimeout
	}
	t := time.NewTimer(hold)
	defer t.Stop()
	select {
	case <-pr.done:
	case <-t.C:
		p.mu.Lock()
		p.resolveLocked(pr, DecisionDeny)
		p.mu.Unlock()
	case <-ctx.Done():
		return DecisionDeny
	}
	<-pr.done
	return pr.decision
}

func (p *Proxy) record(id, host string, port int, decision string, at time.Time, out, in int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	w := p.ws[id]
	if w == nil {
		return
	}
	w.log = capLog(append(w.log, LogEntry{
		Host: host, Port: port, Decision: decision,
		TS: at.UTC().Format(time.RFC3339), BytesOut: out, BytesIn: in,
	}))
}

func (p *Proxy) logf(format string, args ...any) {
	if p.Logf != nil {
		p.Logf(format, args...)
	}
}

// --- persistence -------------------------------------------------------------

func (p *Proxy) saveState(id string, pol Policy) error {
	if p.stateDir == "" {
		return nil
	}
	if err := os.MkdirAll(p.stateDir, 0o700); err != nil {
		return err
	}
	b, err := json.Marshal(pol)
	if err != nil {
		return err
	}
	tmp := filepath.Join(p.stateDir, "."+id+".json.tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(p.stateDir, id+".json"))
}

func (p *Proxy) loadState() {
	if p.stateDir == "" {
		return
	}
	entries, err := os.ReadDir(p.stateDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		id, ok := strings.CutSuffix(e.Name(), ".json")
		if !ok || !ValidWorkspaceID(id) {
			continue
		}
		b, err := os.ReadFile(filepath.Join(p.stateDir, e.Name()))
		if err != nil {
			continue
		}
		var pol Policy
		if json.Unmarshal(b, &pol) != nil {
			continue
		}
		if pol.Mode != ModeOpen {
			pol.Mode = ModeAllowlist
		}
		w := newWorkspace()
		w.policy = pol
		p.ws[id] = w
	}
}

// --- helpers -----------------------------------------------------------------

// wireID echoes the backend's integer workspace ids as JSON numbers.
func wireID(id string) any {
	if n, err := strconv.ParseInt(id, 10, 64); err == nil {
		return n
	}
	return id
}

func capLog(l []LogEntry) []LogEntry {
	if len(l) > maxLogEntries {
		return l[len(l)-maxLogEntries:]
	}
	return l
}

func splitTarget(hostport string, defPort int) (string, int) {
	h, ps, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport, defPort
	}
	n, err := strconv.Atoi(ps)
	if err != nil {
		return h, 0
	}
	return h, n
}

var (
	cgnat     = mustCIDR("100.64.0.0/10")
	benchmark = mustCIDR("198.18.0.0/15")
	reserved  = mustCIDR("240.0.0.0/4")
	thisNet   = mustCIDR("0.0.0.0/8")
	ietf      = mustCIDR("192.0.0.0/24")
)

func mustCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return n
}

// isPublic reports whether ip is a globally routable unicast address.
func isPublic(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() || ip.IsMulticast() {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		for _, n := range []*net.IPNet{cgnat, benchmark, reserved, thisNet, ietf} {
			if n.Contains(v4) {
				return false
			}
		}
	}
	return true
}

func newRequestID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(b []byte) (int, error) {
	n, err := c.w.Write(b)
	c.n += int64(n)
	return n, err
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = c.Close()
}
