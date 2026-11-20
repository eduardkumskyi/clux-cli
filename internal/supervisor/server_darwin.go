//go:build darwin

package supervisor

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/rand/v2"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/eduardkumskyi/clux-cli/internal/egress"
	"github.com/eduardkumskyi/clux-cli/internal/native"
)

const (
	readyTimeout = 120 * time.Second
	stopGrace    = 10 * time.Second
	maxLogBytes  = 20 << 20
)

// Options configures a supervisor. Zero paths take the native.* defaults;
// tests point them at temp dirs.
type Options struct {
	Config      *native.Config
	Version     string
	Socket      string
	AgentHome   string
	RuntimeRoot string
	// SkipUIDCheck lets tests run the server as the invoking user.
	SkipUIDCheck bool
	Logf         func(format string, args ...any)
}

// Server is a running supervisor.
type Server struct {
	opts    Options
	cfg     *native.Config
	sandbox string
	base    native.ProfileParams // per-user parts of every workspace profile

	mu    sync.Mutex
	procs map[string]*proc
	locks map[string]chan struct{}
}

type proc struct {
	ID             string `json:"id"`
	PID            int    `json:"pid"`
	Port           int    `json:"port"`
	RuntimeVersion string `json:"runtime_version"`
	WorkspaceDir   string `json:"workspace_dir"`
	exited         chan struct{}
}

// NewServer prepares directories, runs the sandbox self-check and adopts
// sidecars that survived a supervisor restart.
func NewServer(opts Options) (*Server, error) {
	if opts.Config == nil {
		return nil, errors.New("supervisor: no config")
	}
	if opts.Socket == "" {
		opts.Socket = native.SupervisorSocket
	}
	if opts.AgentHome == "" {
		opts.AgentHome = native.AgentHome
	}
	if opts.RuntimeRoot == "" {
		opts.RuntimeRoot = native.RuntimeRoot
	}
	if opts.Logf == nil {
		opts.Logf = func(string, ...any) {}
	}
	if !opts.SkipUIDCheck && os.Getuid() != opts.Config.AgentUID {
		return nil, fmt.Errorf("supervisor must run as %s (uid %d), not uid %d", native.AgentUser, opts.Config.AgentUID, os.Getuid())
	}
	s := &Server{opts: opts, cfg: opts.Config, procs: map[string]*proc{}, locks: map[string]chan struct{}{}}
	for _, d := range []string{s.workspacesDir(), s.runDir(), s.logDir(), s.gitTemplateDir()} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, err
		}
	}
	home, err := filepath.EvalSymlinks(opts.AgentHome)
	if err != nil {
		return nil, err
	}
	s.base = native.ProfileParams{AgentHome: home, DeveloperDir: developerDir()}
	s.base.UserCache, s.base.UserTemp = userDirs()
	s.sandbox = s.selfCheck()
	s.adopt()
	return s, nil
}

// Sandbox is the self-check result.
func (s *Server) Sandbox() string { return s.sandbox }

func (s *Server) workspacesDir() string { return filepath.Join(s.opts.AgentHome, "workspaces") }
func (s *Server) runDir() string        { return filepath.Join(s.opts.AgentHome, "run") }
func (s *Server) logDir() string        { return filepath.Join(s.opts.AgentHome, "logs") }

// gitTemplateDir is empty on purpose and lives in Library/, which the
// workspace profile can read (run/ it can't).
func (s *Server) gitTemplateDir() string {
	return filepath.Join(s.opts.AgentHome, "Library", "clux", "git-template")
}

// Serve listens on the socket until ctx ends. The socket's directory is
// created by the root pf daemon at boot; wait for it rather than failing
// (launchd starts both daemons in no particular order).
func (s *Server) Serve(ctx context.Context) error {
	dir := filepath.Dir(s.opts.Socket)
	for i := 0; ; i++ {
		if st, err := os.Stat(dir); err == nil && st.IsDir() {
			break
		}
		if i == 0 {
			s.opts.Logf("waiting for %s (created by the pf daemon)", dir)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(time.Second):
		}
	}
	_ = os.Remove(s.opts.Socket)
	l, err := net.Listen("unix", s.opts.Socket)
	if err != nil {
		return err
	}
	// Group comes from the directory (_cluxctl, BSD semantics).
	if err := os.Chmod(s.opts.Socket, 0o660); err != nil {
		l.Close()
		return err
	}
	s.opts.Logf("listening on %s (sandbox: %s)", s.opts.Socket, s.sandbox)
	go func() {
		<-ctx.Done()
		l.Close()
	}()
	for {
		c, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go s.handle(ctx, c.(*net.UnixConn))
	}
}

func (s *Server) handle(ctx context.Context, c *net.UnixConn) {
	defer c.Close()
	reply := func(r Response) {
		b, _ := json.Marshal(r)
		_ = c.SetWriteDeadline(time.Now().Add(10 * time.Second))
		_, _ = c.Write(append(b, '\n'))
	}
	uid, err := peerUID(c)
	if err != nil || uid != s.cfg.OwnerUID {
		s.opts.Logf("rejected connection from uid %d (owner is %d) %v", uid, s.cfg.OwnerUID, err)
		reply(Response{Error: "permission denied: only the machine owner configured at install may use the native supervisor"})
		return
	}
	_ = c.SetReadDeadline(time.Now().Add(30 * time.Second))
	line, err := readLine(bufio.NewReader(c))
	if err != nil {
		return
	}
	_ = c.SetReadDeadline(time.Time{})
	var req Request
	if err := json.Unmarshal(line, &req); err != nil {
		reply(Response{Error: "bad request: " + err.Error()})
		return
	}
	reply(s.Dispatch(ctx, req))
}

// Dispatch executes one request.
func (s *Server) Dispatch(ctx context.Context, req Request) Response {
	if req.Op != OpStatus && !egress.ValidWorkspaceID(req.WorkspaceID) {
		return Response{Error: fmt.Sprintf("invalid workspace id %q", req.WorkspaceID)}
	}
	var resp Response
	var err error
	switch req.Op {
	case OpStart:
		resp.SidecarPort, err = s.start(ctx, req)
	case OpStop:
		err = s.withLock(ctx, req.WorkspaceID, func() error { s.stopLocked(req.WorkspaceID); return nil })
	case OpDelete:
		resp.FreedBytes, err = s.delete(ctx, req.WorkspaceID)
	case OpStatus:
		resp = s.status()
	default:
		err = fmt.Errorf("unknown op %q", req.Op)
	}
	if err != nil {
		s.opts.Logf("%s %s failed: %v", req.Op, req.WorkspaceID, err)
		return Response{Error: err.Error()}
	}
	if req.Op != OpStatus {
		s.opts.Logf("%s %s ok", req.Op, req.WorkspaceID)
	}
	resp.OK = true
	return resp
}

func (s *Server) withLock(ctx context.Context, id string, fn func() error) error {
	s.mu.Lock()
	ch := s.locks[id]
	if ch == nil {
		ch = make(chan struct{}, 1)
		s.locks[id] = ch
	}
	s.mu.Unlock()
	select {
	case ch <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-ch }()
	return fn()
}

func (s *Server) start(ctx context.Context, req Request) (int, error) {
	if req.HMACSecret == "" {
		return 0, errors.New("hmac_secret is required")
	}
	if !validProxyURL(req.ProxyURL, req.WorkspaceID, s.cfg.ProxyPort) {
		return 0, errors.New("proxy_url must be this workspace's credentials on the configured egress proxy port")
	}
	rt, err := s.checkRuntime(req.Runtime)
	if err != nil {
		return 0, err
	}
	var port int
	err = s.withLock(ctx, req.WorkspaceID, func() error {
		// Same semantics as the docker runtime: a start replaces whatever
		// is running for this workspace (its files are kept).
		s.stopLocked(req.WorkspaceID)
		p, err := s.spawn(req, rt)
		if err != nil {
			return err
		}
		port = p.Port
		return nil
	})
	return port, err
}

// checkRuntime confines the runtime the owner points at to RuntimeRoot
// (after resolving symlinks: the venv's python links into RuntimeRoot/python).
func (s *Server) checkRuntime(rt *RuntimeSpec) (RuntimeSpec, error) {
	if rt == nil {
		return RuntimeSpec{}, errors.New("runtime is required")
	}
	root, err := filepath.EvalSymlinks(s.opts.RuntimeRoot)
	if err != nil {
		return RuntimeSpec{}, err
	}
	out := *rt
	for _, p := range []*string{&out.Dir, &out.Python, &out.Sidecar, &out.Claude} {
		r, err := filepath.EvalSymlinks(*p)
		if err != nil {
			return RuntimeSpec{}, fmt.Errorf("runtime: %w", err)
		}
		if !within(root, r) {
			return RuntimeSpec{}, fmt.Errorf("runtime path %s is outside %s", *p, root)
		}
		if p != &out.Python { // keep the venv path: python finds its venv via argv[0]
			*p = r
		}
	}
	out.Dir = filepath.Clean(out.Dir)
	return out, nil
}

func within(root, p string) bool {
	rel, err := filepath.Rel(root, p)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, "../") && !filepath.IsAbs(rel)
}

func (s *Server) spawn(req Request, rt RuntimeSpec) (*proc, error) {
	id := req.WorkspaceID
	wsDir := filepath.Join(s.workspacesDir(), id)
	for _, d := range []string{wsDir, filepath.Join(wsDir, ".home"), filepath.Join(wsDir, ".tmp")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, err
		}
	}
	wsDir, err := filepath.EvalSymlinks(wsDir)
	if err != nil {
		return nil, err
	}
	port, err := freePortPair(s.cfg.ProxyPort)
	if err != nil {
		return nil, err
	}
	argv := []string{rt.Python, rt.Sidecar}
	if s.sandbox == SandboxActive {
		params := s.base
		params.WorkspaceDir = wsDir
		// The whole runtime root (venvs reference the shared uv Python in
		// RuntimeRoot/python); it is read-only for the agent anyway.
		if params.RuntimeDir, err = filepath.EvalSymlinks(s.opts.RuntimeRoot); err != nil {
			return nil, err
		}
		prof, err := native.SandboxProfile(params)
		if err != nil {
			return nil, err
		}
		profPath := filepath.Join(s.runDir(), id+".sb")
		if err := os.WriteFile(profPath, []byte(prof), 0o600); err != nil {
			return nil, err
		}
		argv = append([]string{"/usr/bin/sandbox-exec", "-f", profPath}, argv...)
	}
	logPath := filepath.Join(s.logDir(), id+".log")
	if st, err := os.Stat(logPath); err == nil && st.Size() > maxLogBytes {
		_ = os.Rename(logPath, logPath+".1")
	}
	logf, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	defer logf.Close()
	fmt.Fprintf(logf, "--- %s clux native: starting workspace %s (runtime %s, port %d, sandbox %s)\n",
		time.Now().UTC().Format(time.RFC3339), id, rt.Version, port, s.sandbox)

	mem, _ := unix.SysctlUint64("hw.memsize")
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Dir = wsDir
	cmd.Env = SidecarEnv(SidecarEnvParams{
		WorkspaceID: id, WorkspaceDir: wsDir, Port: port, HMACSecret: req.HMACSecret,
		GithubCloneURL: req.GithubCloneURL, ProxyURL: req.ProxyURL, Runtime: rt,
		DeveloperDir: s.base.DeveloperDir, CPUCount: runtime.NumCPU(), MemoryMB: int64(mem >> 20),
		AgentUser: native.AgentUser, GitTemplateDir: s.gitTemplateDir(),
	})
	cmd.Stdin = nil
	cmd.Stdout = logf
	cmd.Stderr = logf
	// Own process group: stop signals the whole tree, and a supervisor
	// restart (launchd only reaps the job's own group) leaves it running.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting sidecar: %w", err)
	}
	p := &proc{ID: id, PID: cmd.Process.Pid, Port: port, RuntimeVersion: rt.Version, WorkspaceDir: wsDir, exited: make(chan struct{})}
	go func() {
		_ = cmd.Wait()
		close(p.exited)
	}()
	s.mu.Lock()
	s.procs[id] = p
	s.mu.Unlock()
	s.saveState(p)

	if err := waitListening(p, port, readyTimeout); err != nil {
		s.stopLocked(id)
		return nil, fmt.Errorf("%w; sidecar log tail:\n%s", err, tail(logPath, 2048))
	}
	return p, nil
}

// waitListening waits until the sidecar listens on port (read from the
// kernel's socket table, so it doesn't depend on pf letting a loopback
// probe through) or exits.
func waitListening(p *proc, port int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	uid := os.Getuid()
	for {
		select {
		case <-p.exited:
			return errors.New("sidecar exited during startup")
		default:
		}
		if ls, err := native.TCPListeners(); err == nil {
			for _, l := range ls {
				if l.Port == port && l.UID == uid {
					return nil
				}
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("sidecar did not listen on port %d within %s", port, timeout)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// stopLocked ends a workspace's processes: SIGTERM to its process group,
// SIGKILL after a grace period, then a sweep for anything of this
// workspace that left the group (setsid, double fork). Caller holds the
// workspace lock.
func (s *Server) stopLocked(id string) {
	s.mu.Lock()
	p := s.procs[id]
	delete(s.procs, id)
	s.mu.Unlock()
	wsDir := filepath.Join(s.workspacesDir(), id)
	if r, err := filepath.EvalSymlinks(wsDir); err == nil {
		wsDir = r
	}
	if p != nil {
		_ = syscall.Kill(-p.PID, syscall.SIGTERM)
		select {
		case <-p.exited:
		case <-time.After(stopGrace):
		}
		_ = syscall.Kill(-p.PID, syscall.SIGKILL)
		select {
		case <-p.exited:
		case <-time.After(2 * time.Second):
		}
	}
	for i := 0; i < 3; i++ {
		if sweep(id, wsDir) == 0 {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	_ = os.Remove(filepath.Join(s.runDir(), id+".json"))
}

// sweep SIGKILLs every process of this uid whose environment says it
// belongs to workspace id. Returns how many were signalled.
func sweep(id, wsDir string) int {
	procs, err := unix.SysctlKinfoProcSlice("kern.proc.uid", os.Getuid())
	if err != nil {
		return 0
	}
	self := os.Getpid()
	n := 0
	for _, kp := range procs {
		pid := int(kp.Proc.P_pid)
		if pid == self || pid <= 1 {
			continue
		}
		if belongsTo(pid, id, wsDir) {
			if syscall.Kill(pid, syscall.SIGKILL) == nil {
				n++
			}
		}
	}
	return n
}

func belongsTo(pid int, id, wsDir string) bool {
	buf, err := unix.SysctlRaw("kern.procargs2", pid)
	if err != nil {
		return false
	}
	_, env, err := parseProcArgs(buf)
	if err != nil {
		return false
	}
	v, ok := envValue(env, "WORKSPACE_ID")
	d, _ := envValue(env, "WORKSPACE_DIR")
	return ok && v == id && d == wsDir
}

func (s *Server) delete(ctx context.Context, id string) (int64, error) {
	var freed int64
	err := s.withLock(ctx, id, func() error {
		s.stopLocked(id)
		wsDir := filepath.Join(s.workspacesDir(), id)
		freed = dirSize(wsDir)
		if err := removeAll(wsDir); err != nil {
			return err
		}
		for _, f := range []string{id + ".sb", id + ".json"} {
			_ = os.Remove(filepath.Join(s.runDir(), f))
		}
		_ = os.Remove(filepath.Join(s.logDir(), id+".log"))
		_ = os.Remove(filepath.Join(s.logDir(), id+".log.1"))
		return nil
	})
	return freed, err
}

func (s *Server) status() Response {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := Response{Version: s.opts.Version, Sandbox: s.sandbox}
	for _, p := range s.procs {
		running := true
		select {
		case <-p.exited:
			running = false
		default:
		}
		r.Workspaces = append(r.Workspaces, WorkspaceStatus{ID: p.ID, PID: p.PID, Port: p.Port, Running: running, RuntimeVersion: p.RuntimeVersion})
	}
	return r
}

// --- restart survival ----------------------------------------------------------

func (s *Server) saveState(p *proc) {
	b, _ := json.Marshal(p)
	_ = os.WriteFile(filepath.Join(s.runDir(), p.ID+".json"), b, 0o600)
}

// adopt re-attaches sidecars started by a previous supervisor process.
// A state file whose pid is gone or now belongs to something else is
// dropped, and any stray processes of that workspace are swept.
func (s *Server) adopt() {
	entries, _ := os.ReadDir(s.runDir())
	for _, e := range entries {
		id, ok := strings.CutSuffix(e.Name(), ".json")
		if !ok || !egress.ValidWorkspaceID(id) {
			continue
		}
		path := filepath.Join(s.runDir(), e.Name())
		var p proc
		b, err := os.ReadFile(path)
		if err != nil || json.Unmarshal(b, &p) != nil || p.ID != id {
			_ = os.Remove(path)
			continue
		}
		if p.PID > 1 && belongsTo(p.PID, id, p.WorkspaceDir) {
			p.exited = make(chan struct{})
			pp := p
			go watchPID(&pp)
			s.procs[id] = &pp
			s.opts.Logf("adopted workspace %s (pid %d, port %d)", id, p.PID, p.Port)
			continue
		}
		sweep(id, p.WorkspaceDir)
		_ = os.Remove(path)
	}
}

func watchPID(p *proc) {
	for {
		if syscall.Kill(p.PID, 0) != nil || !belongsTo(p.PID, p.ID, p.WorkspaceDir) {
			close(p.exited)
			return
		}
		time.Sleep(time.Second)
	}
}

// --- sandbox self-check ----------------------------------------------------------

// selfCheck runs a tiny probe under a real workspace profile: it must be
// able to read inside its workspace and must NOT read a file next to it.
// Anything else (no sandbox-exec, profile rejected, nothing enforced) is
// "unavailable"; workspaces then run without Seatbelt (user + pf remain).
func (s *Server) selfCheck() string {
	if _, err := os.Stat("/usr/bin/sandbox-exec"); err != nil {
		s.opts.Logf("sandbox self-check: sandbox-exec missing")
		return SandboxUnavailable
	}
	dir := filepath.Join(s.runDir(), "selfcheck")
	_ = removeAll(dir)
	ws := filepath.Join(dir, "ws")
	if err := os.MkdirAll(ws, 0o700); err != nil {
		return SandboxUnavailable
	}
	dir, _ = filepath.EvalSymlinks(dir)
	ws = filepath.Join(dir, "ws")
	_ = os.WriteFile(filepath.Join(ws, "ok"), []byte("ok"), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "denied"), []byte("denied"), 0o600)
	params := s.base
	params.WorkspaceDir = ws
	params.RuntimeDir = filepath.Clean(s.opts.RuntimeRoot)
	prof, err := native.SandboxProfile(params)
	if err != nil {
		s.opts.Logf("sandbox self-check: %v", err)
		return SandboxUnavailable
	}
	pf := filepath.Join(dir, "profile.sb")
	_ = os.WriteFile(pf, []byte(prof), 0o600)
	run := func(target string) error {
		cmd := exec.Command("/usr/bin/sandbox-exec", "-f", pf, "/bin/cat", target)
		cmd.Dir = ws
		cmd.Stdout = io.Discard
		return cmd.Run()
	}
	if err := run(filepath.Join(ws, "ok")); err != nil {
		s.opts.Logf("sandbox self-check: sandboxed probe failed to run: %v", err)
		return SandboxUnavailable
	}
	if run(filepath.Join(dir, "denied")) == nil {
		s.opts.Logf("sandbox self-check: profile is not enforced (probe read a denied file)")
		return SandboxUnavailable
	}
	return SandboxActive
}

// --- helpers -----------------------------------------------------------------

func peerUID(c *net.UnixConn) (int, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return -1, err
	}
	var cred *unix.Xucred
	var cerr error
	if err := raw.Control(func(fd uintptr) {
		cred, cerr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	}); err != nil {
		return -1, err
	}
	if cerr != nil {
		return -1, cerr
	}
	return int(cred.Uid), nil
}

// freePortPair picks p such that p (WebSocket) and p+1 (the sidecar's
// health/HTTP server) are free on IPv4 and IPv6 wildcard addresses.
func freePortPair(avoid int) (int, error) {
	for i := 0; i < 200; i++ {
		p := 20000 + rand.IntN(40000)
		if p == avoid || p+1 == avoid {
			continue
		}
		if portFree(p) && portFree(p+1) {
			return p, nil
		}
	}
	return 0, errors.New("no free port pair for the sidecar")
}

func portFree(p int) bool {
	for _, nw := range []struct{ net, addr string }{{"tcp4", "0.0.0.0"}, {"tcp6", "[::]"}} {
		l, err := net.Listen(nw.net, fmt.Sprintf("%s:%d", nw.addr, p))
		if err != nil {
			return false
		}
		l.Close()
	}
	return true
}

func developerDir() string {
	out, err := exec.Command("/usr/bin/xcode-select", "-p").Output()
	if err != nil {
		return ""
	}
	d := strings.TrimSpace(string(out))
	if r, err := filepath.EvalSymlinks(d); err == nil {
		return r
	}
	return d
}

// userDirs returns this user's confstr() cache/temp dirs, resolved.
func userDirs() (cache, temp string) {
	get := func(name string) string {
		out, err := exec.Command("/usr/bin/getconf", name).Output()
		if err != nil {
			return ""
		}
		d := strings.TrimSuffix(strings.TrimSpace(string(out)), "/")
		if r, err := filepath.EvalSymlinks(d); err == nil {
			return r
		}
		return d
	}
	cache, temp = get("DARWIN_USER_CACHE_DIR"), get("DARWIN_USER_TEMP_DIR")
	if cache == "" {
		cache = "/private/var/empty/cache"
	}
	if temp == "" {
		temp = "/private/var/empty/temp"
	}
	return cache, temp
}

func dirSize(root string) int64 {
	var n int64
	_ = filepath.WalkDir(root, func(_ string, d fs.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() {
			if info, err := d.Info(); err == nil {
				n += info.Size()
			}
		}
		return nil
	})
	return n
}

// removeAll is os.RemoveAll that also copes with read-only directories
// (Go module caches, some build outputs) by making them writable first.
func removeAll(root string) error {
	if err := os.RemoveAll(root); err == nil {
		return nil
	}
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.IsDir() {
			_ = os.Chmod(p, 0o700)
		}
		return nil
	})
	return os.RemoveAll(root)
}

func tail(path string, n int64) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	if st, err := f.Stat(); err == nil && st.Size() > n {
		_, _ = f.Seek(-n, io.SeekEnd)
	}
	b, _ := io.ReadAll(f)
	return string(b)
}
