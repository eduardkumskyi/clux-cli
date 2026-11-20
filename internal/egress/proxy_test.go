package egress

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeSender records frames; alive=false makes TrySend fail.
type fakeSender struct {
	mu     sync.Mutex
	alive  bool
	frames []map[string]any
	onSend func(map[string]any)
}

func (f *fakeSender) TrySend(frame any) bool {
	f.mu.Lock()
	if !f.alive {
		f.mu.Unlock()
		return false
	}
	m := frame.(map[string]any)
	f.frames = append(f.frames, m)
	cb := f.onSend
	f.mu.Unlock()
	if cb != nil {
		go cb(m)
	}
	return true
}

func (f *fakeSender) ofType(t string) []map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []map[string]any
	for _, m := range f.frames {
		if m["type"] == t {
			out = append(out, m)
		}
	}
	return out
}

// testProxy starts a proxy whose "internet" is a local echo server: every
// name resolves to resolveTo and every dial lands on the echo server.
func testProxy(t *testing.T, resolveTo string) (*Proxy, string) {
	t.Helper()
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { echo.Close() })
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				br := bufio.NewReader(c)
				// Plain HTTP request -> canned response; otherwise echo a line.
				peek, _ := br.Peek(4)
				if string(peek) == "GET " {
					req, err := http.ReadRequest(br)
					if err != nil {
						return
					}
					body := "hello " + req.URL.Path
					fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
					return
				}
				line, _ := br.ReadString('\n')
				io.WriteString(c, "echo:"+line)
			}()
		}
	}()

	p := New([]byte("0123456789abcdef0123456789abcdef"), t.TempDir())
	p.HoldTimeout = 2 * time.Second
	p.lookup = func(ctx context.Context, host string) ([]net.IP, error) {
		return []net.IP{net.ParseIP(resolveTo)}, nil
	}
	p.dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return net.Dial("tcp", echo.Addr().String())
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go p.Serve(ctx, l)
	return p, l.Addr().String()
}

func auth(p *Proxy, id string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte("ws-"+id+":"+p.password(id)))
}

// connect issues CONNECT target through the proxy; on 200 it writes a line
// and returns the echoed reply.
func connect(t *testing.T, proxyAddr, target, authz string) (int, string) {
	t.Helper()
	c, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n", target, target)
	if authz != "" {
		fmt.Fprintf(c, "Proxy-Authorization: %s\r\n", authz)
	}
	io.WriteString(c, "\r\n")
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("reading CONNECT response: %v", err)
	}
	if resp.StatusCode != 200 {
		return resp.StatusCode, ""
	}
	io.WriteString(c, "ping\n")
	line, _ := br.ReadString('\n')
	return 200, strings.TrimSpace(line)
}

func TestConnectAllowedAndLogged(t *testing.T) {
	p, addr := testProxy(t, "93.184.216.34")
	p.SetPolicy("7", Policy{Mode: ModeAllowlist, Allow: []string{"*.example.com"}})
	code, reply := connect(t, addr, "api.example.com:443", auth(p, "7"))
	if code != 200 || reply != "echo:ping" {
		t.Fatalf("code=%d reply=%q", code, reply)
	}
	s := &fakeSender{alive: true}
	p.SetSender(s)
	waitFor(t, func() bool { p.Flush(); return len(s.ofType("egress.log")) == 1 })
	f := s.ofType("egress.log")[0]
	if f["workspace_id"] != int64(7) {
		t.Fatalf("workspace_id = %#v, want number 7", f["workspace_id"])
	}
	e := f["entries"].([]LogEntry)[0]
	if e.Host != "api.example.com" || e.Port != 443 || e.Decision != "allowed" || e.BytesOut == 0 || e.BytesIn == 0 {
		t.Fatalf("entry %+v", e)
	}
}

func TestProxyRequiresWorkspaceCredentials(t *testing.T) {
	p, addr := testProxy(t, "93.184.216.34")
	p.SetPolicy("7", Policy{Mode: ModeOpen})
	if code, _ := connect(t, addr, "example.com:443", ""); code != 407 {
		t.Fatalf("no credentials: %d", code)
	}
	bad := "Basic " + base64.StdEncoding.EncodeToString([]byte("ws-7:wrong"))
	if code, _ := connect(t, addr, "example.com:443", bad); code != 407 {
		t.Fatalf("wrong password: %d", code)
	}
	// Valid password for a workspace this proxy was never told about.
	if code, _ := connect(t, addr, "example.com:443", auth(p, "8")); code != 407 {
		t.Fatalf("unknown workspace: %d", code)
	}
}

func TestUnknownHostAllowProjectSticks(t *testing.T) {
	p, addr := testProxy(t, "93.184.216.34")
	p.SetPolicy("7", Policy{Mode: ModeAllowlist})
	s := &fakeSender{alive: true}
	s.onSend = func(m map[string]any) {
		if m["type"] == "egress.request" {
			p.Decide("7", m["request_id"].(string), DecisionAllowProject, "ignored.example")
		}
	}
	p.SetSender(s)
	if code, _ := connect(t, addr, "new.example.org:443", auth(p, "7")); code != 200 {
		t.Fatalf("allow_project: %d", code)
	}
	reqs := s.ofType("egress.request")
	if len(reqs) != 1 || reqs[0]["host"] != "new.example.org" || reqs[0]["port"] != 443 {
		t.Fatalf("requests %v", reqs)
	}
	if code, _ := connect(t, addr, "new.example.org:443", auth(p, "7")); code != 200 {
		t.Fatalf("second connection: %d", code)
	}
	if n := len(s.ofType("egress.request")); n != 1 {
		t.Fatalf("allow_project must not prompt again, got %d prompts", n)
	}
	// Persisted: a fresh proxy over the same state dir knows it.
	q := New(p.key, p.stateDir)
	if pol, _ := q.Policy("7"); !pol.Allows("new.example.org", 443) {
		t.Fatalf("allow_project not persisted: %+v", pol)
	}
}

func TestAllowOnceDoesNotStick(t *testing.T) {
	p, addr := testProxy(t, "93.184.216.34")
	p.SetPolicy("7", Policy{Mode: ModeAllowlist})
	s := &fakeSender{alive: true}
	s.onSend = func(m map[string]any) {
		if m["type"] == "egress.request" {
			p.Decide("7", m["request_id"].(string), DecisionAllowOnce, "")
		}
	}
	p.SetSender(s)
	connect(t, addr, "once.example.org:443", auth(p, "7"))
	connect(t, addr, "once.example.org:443", auth(p, "7"))
	if n := len(s.ofType("egress.request")); n != 2 {
		t.Fatalf("allow_once must prompt each time, got %d", n)
	}
}

func TestHoldTimesOutToDeny(t *testing.T) {
	p, addr := testProxy(t, "93.184.216.34")
	p.HoldTimeout = 150 * time.Millisecond
	p.SetPolicy("7", Policy{Mode: ModeAllowlist})
	p.SetSender(&fakeSender{alive: true})
	start := time.Now()
	if code, _ := connect(t, addr, "slow.example.org:443", auth(p, "7")); code != 403 {
		t.Fatalf("timeout: %d", code)
	}
	if d := time.Since(start); d < 150*time.Millisecond {
		t.Fatalf("denied before the hold elapsed (%s)", d)
	}
}

func TestNoSessionDeniesUnknownHostImmediately(t *testing.T) {
	p, addr := testProxy(t, "93.184.216.34")
	p.SetPolicy("7", Policy{Mode: ModeAllowlist})
	if code, _ := connect(t, addr, "x.example.org:443", auth(p, "7")); code != 403 {
		t.Fatalf("got %d", code)
	}
	p.SetSender(&fakeSender{alive: false}) // session gone mid-way
	if code, _ := connect(t, addr, "x.example.org:443", auth(p, "7")); code != 403 {
		t.Fatalf("got %d", code)
	}
}

func TestDenyIsCachedBriefly(t *testing.T) {
	p, addr := testProxy(t, "93.184.216.34")
	p.SetPolicy("7", Policy{Mode: ModeAllowlist})
	s := &fakeSender{alive: true}
	s.onSend = func(m map[string]any) {
		if m["type"] == "egress.request" {
			p.Decide("7", m["request_id"].(string), DecisionDeny, "")
		}
	}
	p.SetSender(s)
	for i := 0; i < 3; i++ {
		if code, _ := connect(t, addr, "nope.example.org:443", auth(p, "7")); code != 403 {
			t.Fatalf("attempt %d: %d", i, code)
		}
	}
	if n := len(s.ofType("egress.request")); n != 1 {
		t.Fatalf("deny must be cached, got %d prompts", n)
	}
}

func TestConcurrentConnectionsShareOnePrompt(t *testing.T) {
	p, addr := testProxy(t, "93.184.216.34")
	p.SetPolicy("7", Policy{Mode: ModeAllowlist})
	s := &fakeSender{alive: true}
	p.SetSender(s)
	var wg sync.WaitGroup
	codes := make([]int, 3)
	for i := range codes {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			codes[i], _ = connect(t, addr, "shared.example.org:443", auth(p, "7"))
		}(i)
	}
	waitFor(t, func() bool { return len(s.ofType("egress.request")) == 1 })
	time.Sleep(50 * time.Millisecond) // let the other two join the wait
	req := s.ofType("egress.request")[0]
	p.Decide("7", req["request_id"].(string), DecisionAllowOnce, "")
	wg.Wait()
	for i, c := range codes {
		if c != 200 {
			t.Fatalf("connection %d: %d", i, c)
		}
	}
	if n := len(s.ofType("egress.request")); n != 1 {
		t.Fatalf("got %d prompts", n)
	}
}

func TestLocalDestinationsNeverReachable(t *testing.T) {
	p, addr := testProxy(t, "127.0.0.1")
	p.SetPolicy("7", Policy{Mode: ModeOpen, Allow: []string{"localhost", "db.local"}})
	// Loopback is the owner's own machine: refused even when listed.
	for _, target := range []string{"localhost:5433", "127.0.0.1:5433", "[::1]:5433", "db.local:5432"} {
		if code, _ := connect(t, addr, target, auth(p, "7")); code != 403 {
			t.Fatalf("%s: %d", target, code)
		}
	}
}

func TestPrivateDestinationsNeedExplicitEntry(t *testing.T) {
	p, addr := testProxy(t, "192.168.1.20")
	p.SetPolicy("7", Policy{Mode: ModeOpen, Allow: []string{"*.lan"}})
	if code, _ := connect(t, addr, "nas.lan:443", auth(p, "7")); code != 403 {
		t.Fatalf("open mode + wildcard reached a LAN address: %d", code)
	}
	p.SetPolicy("7", Policy{Mode: ModeAllowlist, Allow: []string{"nas.lan:443"}})
	if code, _ := connect(t, addr, "nas.lan:443", auth(p, "7")); code != 200 {
		t.Fatalf("explicit entry: %d", code)
	}
	if code, _ := connect(t, addr, "169.254.169.254:80", auth(p, "7")); code != 403 {
		t.Fatalf("link-local metadata address: %d", code)
	}
}

func TestPlainHTTPForward(t *testing.T) {
	p, addr := testProxy(t, "93.184.216.34")
	p.SetPolicy("7", Policy{Mode: ModeAllowlist, Allow: []string{"plain.example.com"}})
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fmt.Fprintf(c, "GET http://plain.example.com/simple/ HTTP/1.1\r\nHost: plain.example.com\r\nProxy-Authorization: %s\r\n\r\n", auth(p, "7"))
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || string(body) != "hello /simple/" {
		t.Fatalf("status=%d body=%q", resp.StatusCode, body)
	}
}

func TestFlushRequeuesWhenSendFails(t *testing.T) {
	p := New([]byte("k"), "")
	p.SetPolicy("3", Policy{})
	p.record("3", "a.com", 443, "denied", time.Now(), 0, 0)
	dead := &fakeSender{alive: false}
	p.SetSender(dead)
	p.Flush()
	live := &fakeSender{alive: true}
	p.SetSender(live)
	p.Flush()
	logs := live.ofType("egress.log")
	if len(logs) != 1 || len(logs[0]["entries"].([]LogEntry)) != 1 {
		t.Fatalf("entry lost across a failed send: %v", logs)
	}
}

func TestForgetDeniesHeldRequests(t *testing.T) {
	p, addr := testProxy(t, "93.184.216.34")
	p.SetPolicy("7", Policy{Mode: ModeAllowlist})
	s := &fakeSender{alive: true}
	s.onSend = func(m map[string]any) {
		if m["type"] == "egress.request" {
			p.Forget("7")
		}
	}
	p.SetSender(s)
	if code, _ := connect(t, addr, "held.example.org:443", auth(p, "7")); code != 403 {
		t.Fatalf("got %d", code)
	}
	if _, ok := p.Policy("7"); ok {
		t.Fatal("workspace still known")
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met in time")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
