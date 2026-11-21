//go:build darwin

package supervisor

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/eduardkumskyi/clux-cli/internal/native"
)

// The test binary doubles as the fake sidecar: copied into the runtime dir
// as "python" it records its environment, starts a child that escapes the
// process group (new session), then listens on SIDECAR_PORT like the real
// sidecar. (A copy of /bin/sh can't be used: AMFI kills relocated platform
// binaries, and the kernel hides their environment from procargs2.)
func TestMain(m *testing.M) {
	switch filepath.Base(os.Args[0]) {
	case "python":
		fakeSidecar()
		return
	case "escapee":
		_, _ = unix.Setsid()
		time.Sleep(10 * time.Minute)
		return
	}
	os.Exit(m.Run())
}

func fakeSidecar() {
	ws := os.Getenv("WORKSPACE_DIR")
	_ = os.WriteFile(filepath.Join(ws, "env.txt"), []byte(strings.Join(os.Environ(), "\n")+"\n"), 0o600)
	self, _ := os.Executable()
	c := exec.Command(self)
	c.Args = []string{"escapee"}
	_ = c.Start()
	l, err := net.Listen("tcp", ":"+os.Getenv("SIDECAR_PORT"))
	if err != nil {
		os.Exit(3)
	}
	for {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		conn.Close()
	}
}

func fakeRuntime(t *testing.T, root string) *RuntimeSpec {
	t.Helper()
	dir := filepath.Join(root, "sidecar", "v1")
	for _, d := range []string{filepath.Join(dir, "venv", "bin"), filepath.Join(dir, "claude")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	bin, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	py := filepath.Join(dir, "venv", "bin", "python")
	if err := os.WriteFile(py, bin, 0o755); err != nil {
		t.Fatal(err)
	}
	sc := filepath.Join(dir, "sidecar.py")
	if err := os.WriteFile(sc, []byte("# fake\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cl := filepath.Join(dir, "claude", "claude")
	os.WriteFile(cl, []byte("#!/bin/sh\n"), 0o755)
	return &RuntimeSpec{Version: "v1", Dir: dir, Python: py, Sidecar: sc, Claude: cl}
}

func testServer(t *testing.T, ownerUID int) (*Server, string) {
	t.Helper()
	return testServerWith(t, ownerUID, nil)
}

func testServerWith(t *testing.T, ownerUID int, mut func(*Options)) (*Server, string) {
	t.Helper()
	// Short socket path: sun_path is limited to 104 bytes.
	tmp, err := os.MkdirTemp("/tmp", "cluxsv")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { removeAll(tmp) })
	tmp, _ = filepath.EvalSymlinks(tmp)
	home := filepath.Join(tmp, "home")
	rt := filepath.Join(tmp, "rt")
	os.MkdirAll(filepath.Join(home, "Library"), 0o700)
	os.MkdirAll(rt, 0o755)
	cfg := &native.Config{Version: 2, OwnerUID: ownerUID, Slots: []native.Slot{{N: 1, User: "_clux1", UID: 431, GID: 431}},
		SlotsGID: 433, CtlGID: 432, ProxyPort: 47821, BinaryPath: "/x"}
	mapping := filepath.Join(tmp, "mapping.plist")
	os.WriteFile(mapping, []byte("<?xml version=\"1.0\"?><plist/>"), 0o644)
	opts := Options{
		Config: cfg, Slot: 1, Version: "test", Socket: filepath.Join(tmp, "s.sock"),
		AgentHome: home, RuntimeRoot: rt, SimMapping: mapping, SkipUIDCheck: true, Logf: t.Logf,
		// Never touch the developer's real simulators or processes from tests.
		ShutdownSimulators: func(context.Context) error { return nil },
		KillSlot:           func() int { return 0 },
		PFCheck:            func() error { return nil },
	}
	if mut != nil {
		mut(&opts)
	}
	s, err := NewServer(opts)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go s.Serve(ctx)
	for i := 0; i < 100; i++ {
		if _, err := os.Stat(s.opts.Socket); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	return s, rt
}

func TestPeerUIDCheck(t *testing.T) {
	s, _ := testServer(t, os.Getuid())
	c := &Client{Socket: s.opts.Socket}
	resp, err := c.Call(context.Background(), Request{Op: OpStatus})
	if err != nil || resp.Version != "test" {
		t.Fatalf("owner rejected: %+v %v", resp, err)
	}

	other, _ := testServer(t, os.Getuid()+1)
	_, err = (&Client{Socket: other.opts.Socket}).Call(context.Background(), Request{Op: OpStatus})
	if err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("non-owner uid accepted: %v", err)
	}
}

func TestStartStopLifecycle(t *testing.T) {
	s, rt := testServer(t, os.Getuid())
	t.Logf("sandbox: %s", s.Sandbox())
	c := &Client{Socket: s.opts.Socket}
	ctx := context.Background()
	req := Request{
		Op: OpStart, WorkspaceID: "12", HMACSecret: "sekret",
		ProxyURL: "http://ws-12:pw@127.0.0.1:47821", Runtime: fakeRuntime(t, rt),
	}
	resp, err := c.Call(ctx, req)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	if resp.SidecarPort < 20000 {
		t.Fatalf("port %d", resp.SidecarPort)
	}
	ws := filepath.Join(s.workspacesDir(), "12")
	env, _ := os.ReadFile(filepath.Join(ws, "env.txt"))
	for _, want := range []string{"SIDECAR_HMAC_SECRET=sekret", "WORKSPACE_ID=12", "HTTPS_PROXY=http://ws-12:pw@127.0.0.1:47821"} {
		if !strings.Contains(string(env), want+"\n") {
			t.Errorf("sidecar env lacks %s", want)
		}
	}
	st, _ := c.Call(ctx, Request{Op: OpStatus})
	if len(st.Workspaces) != 1 || !st.Workspaces[0].Running || st.Workspaces[0].Port != resp.SidecarPort {
		t.Fatalf("status %+v", st)
	}
	pid := st.Workspaces[0].PID
	wsResolved, _ := filepath.EvalSymlinks(ws)

	// A second start replaces the first (docker semantics).
	resp2, err := c.Call(ctx, req)
	if err != nil {
		t.Fatalf("restart: %v", err)
	}
	if syscall.Kill(pid, 0) == nil {
		t.Fatal("first sidecar still running after restart")
	}

	if _, err := c.Call(ctx, Request{Op: OpStop, WorkspaceID: "12"}); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if n := sweep("12", wsResolved); n != 0 {
		t.Fatalf("stop left %d process(es) behind (escaped process group not swept)", n)
	}
	if _, err := os.Stat(ws); err != nil {
		t.Fatal("stop must keep the workspace files")
	}
	_ = resp2

	d, err := c.Call(ctx, Request{Op: OpDelete, WorkspaceID: "12"})
	if err != nil || d.FreedBytes == 0 {
		t.Fatalf("delete: %+v %v", d, err)
	}
	if _, err := os.Stat(ws); !os.IsNotExist(err) {
		t.Fatal("delete kept the workspace dir")
	}
}

func TestStartRejectsForeignRuntimeAndBadInput(t *testing.T) {
	s, rt := testServer(t, os.Getuid())
	good := fakeRuntime(t, rt)
	cases := []Request{
		{Op: OpStart, WorkspaceID: "../x", HMACSecret: "s", ProxyURL: "http://ws-../x:p@127.0.0.1:47821", Runtime: good},
		{Op: OpStart, WorkspaceID: "12", ProxyURL: "http://ws-12:p@127.0.0.1:47821", Runtime: good},
		{Op: OpStart, WorkspaceID: "12", HMACSecret: "s", ProxyURL: "http://ws-12:p@127.0.0.1:9999", Runtime: good},
		{Op: OpStart, WorkspaceID: "12", HMACSecret: "s", ProxyURL: "http://ws-12:p@127.0.0.1:47821",
			Runtime: &RuntimeSpec{Dir: "/bin", Python: "/bin/sh", Sidecar: "/bin/sh", Claude: "/bin/sh"}},
		{Op: "rm-rf", WorkspaceID: "12"},
	}
	for i, req := range cases {
		if r := s.Dispatch(context.Background(), req); r.OK {
			t.Errorf("case %d accepted: %+v", i, req)
		}
	}
}

func TestProcArgsLive(t *testing.T) {
	// Not /bin/sleep: the kernel hides platform binaries' environment.
	self, _ := os.Executable()
	cmd := exec.Command(self)
	cmd.Args = []string{"escapee"}
	cmd.Env = []string{"WORKSPACE_ID=99", "WORKSPACE_DIR=/nowhere"}
	cmd.Stdout = io.Discard
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	time.Sleep(100 * time.Millisecond)
	if !belongsTo(cmd.Process.Pid, "99", "/nowhere") {
		t.Fatal("procargs2 env not read")
	}
	if belongsTo(cmd.Process.Pid, "9", "/nowhere") {
		t.Fatal("wrong workspace matched")
	}
}

// Stop and delete end everything the slot uid runs: simulators first
// (gracefully), then every remaining process (apps the agent built, which
// run outside the sandbox and may have hidden their environment).
func TestStopAndDeleteClearTheWholeSlot(t *testing.T) {
	var order []string
	var kills atomic.Int32
	s, rt := testServerWith(t, os.Getuid(), func(o *Options) {
		o.ShutdownSimulators = func(context.Context) error { order = append(order, "simctl"); return nil }
		o.KillSlot = func() int { kills.Add(1); order = append(order, "kill"); return 0 }
	})
	c := &Client{Socket: s.opts.Socket}
	ctx := context.Background()
	start := Request{Op: OpStart, WorkspaceID: "21", HMACSecret: "s", ProxyURL: "http://ws-21:pw@127.0.0.1:47821", Runtime: fakeRuntime(t, rt)}
	if _, err := c.Call(ctx, start); err != nil {
		t.Fatalf("start: %v", err)
	}
	if kills.Load() != 1 {
		t.Fatal("start must clear leftovers of the slot before spawning")
	}
	order = nil
	if _, err := c.Call(ctx, Request{Op: OpStop, WorkspaceID: "21"}); err != nil {
		t.Fatal(err)
	}
	if strings.Join(order, ",") != "simctl,kill" {
		t.Fatalf("stop: %v, want simctl then kill", order)
	}
	// Leave state behind that a later workspace in this slot must not see.
	lib := filepath.Join(s.opts.AgentHome, "Library")
	os.MkdirAll(filepath.Join(lib, "Developer", "CoreSimulator", "Devices", "X"), 0o700)
	os.WriteFile(filepath.Join(lib, "Keychains-login"), []byte("secret"), 0o600)
	order = nil
	if _, err := c.Call(ctx, Request{Op: OpDelete, WorkspaceID: "21"}); err != nil {
		t.Fatal(err)
	}
	if strings.Join(order, ",") != "simctl,kill" {
		t.Fatalf("delete: %v", order)
	}
	for _, gone := range []string{"Developer/CoreSimulator", "Keychains-login"} {
		if _, err := os.Stat(filepath.Join(lib, gone)); !os.IsNotExist(err) {
			t.Errorf("delete kept Library/%s", gone)
		}
	}
	mapping := filepath.Join(lib, "Developer", "Xcode", "SDKToSimulatorIndexMapping.plist")
	if _, err := os.Stat(mapping); err != nil {
		t.Errorf("home skeleton not restored after the wipe: %v", err)
	}
	if st, _ := c.Call(ctx, Request{Op: OpStatus}); len(st.Resident) != 0 || st.Slot != 1 {
		t.Fatalf("status after delete: %+v", st)
	}
}

func TestSlotServesOneWorkspace(t *testing.T) {
	s, rt := testServer(t, os.Getuid())
	ctx := context.Background()
	r := fakeRuntime(t, rt)
	req := func(id string) Request {
		return Request{Op: OpStart, WorkspaceID: id, HMACSecret: "s", ProxyURL: "http://ws-" + id + ":pw@127.0.0.1:47821", Runtime: r}
	}
	if resp := s.Dispatch(ctx, req("31")); !resp.OK {
		t.Fatalf("start 31: %s", resp.Error)
	}
	defer s.Dispatch(ctx, Request{Op: OpDelete, WorkspaceID: "31"})
	resp := s.Dispatch(ctx, req("32"))
	if resp.OK || !strings.Contains(resp.Error, "already holds workspace 31") {
		t.Fatalf("second workspace in one slot: %+v", resp)
	}
	if st := s.Dispatch(ctx, Request{Op: OpStatus}); len(st.Resident) != 1 || st.Resident[0] != "31" {
		t.Fatalf("resident %v", st.Resident)
	}
}

func TestStartRefusedWithoutPF(t *testing.T) {
	s, rt := testServerWith(t, os.Getuid(), func(o *Options) {
		o.PFCheck = func() error { return errors.New("pf firewall not active") }
	})
	resp := s.Dispatch(context.Background(), Request{
		Op: OpStart, WorkspaceID: "41", HMACSecret: "s", ProxyURL: "http://ws-41:pw@127.0.0.1:47821", Runtime: fakeRuntime(t, rt),
	})
	if resp.OK || !strings.Contains(resp.Error, "pf firewall not active") {
		t.Fatalf("started without pf: %+v", resp)
	}
	if _, err := os.Stat(filepath.Join(s.workspacesDir(), "41")); !os.IsNotExist(err) {
		t.Fatal("workspace dir created although the start was refused")
	}
}

// Finding: the agent shares its supervisor's uid, so it could stop the
// supervisor and bind a socket of its own; a client checking for "the slot
// uid" would accept it. The owner's client insists on a socket root
// created, which a non-root process -- here the test user, standing in for
// the agent -- can't provide: nothing is sent to it.
func TestClientRefusesSocketNotCreatedByRoot(t *testing.T) {
	s, rt := testServer(t, os.Getuid())
	if _, err := (&Client{Socket: s.opts.Socket}).Call(context.Background(), Request{Op: OpStatus}); err != nil {
		t.Fatalf("plain client: %v", err)
	}
	_, err := (&Client{Socket: s.opts.Socket, RootListener: true}).Call(context.Background(),
		startReq(t, "41", rt))
	if err == nil || !strings.Contains(err.Error(), "refusing to use it") {
		t.Fatalf("a socket the test user bound was accepted: %v", err)
	}
	if _, err := os.Stat(filepath.Join(s.workspacesDir(), "41")); !os.IsNotExist(err) {
		t.Fatal("the start request reached the server")
	}
}

func startReq(t *testing.T, id, rt string) Request {
	return Request{Op: OpStart, WorkspaceID: id, HMACSecret: "s", ProxyURL: "http://ws-" + id + ":pw@127.0.0.1:47821", Runtime: fakeRuntime(t, rt)}
}

// The supervisor refuses a workspace root's keeper has not given the slot.
func TestStartRefusedWithoutRootClaim(t *testing.T) {
	s, rt := testServerWith(t, os.Getuid(), func(o *Options) {
		o.SlotClaim = func(id string) error {
			return errors.New("root's slot keeper has not assigned slot 1 to workspace " + id)
		}
	})
	resp := s.Dispatch(context.Background(), startReq(t, "41", rt))
	if resp.OK || !strings.Contains(resp.Error, "has not assigned slot 1") {
		t.Fatalf("started without a claim: %+v", resp)
	}
	if _, err := os.Stat(filepath.Join(s.workspacesDir(), "41")); !os.IsNotExist(err) {
		t.Fatal("workspace dir created although the start was refused")
	}
}
