package hostsession

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eduardkumskyi/clux-cli/internal/egress"
	"github.com/eduardkumskyi/clux-cli/internal/sidecarrt"
	"github.com/eduardkumskyi/clux-cli/internal/supervisor"
)

type fakeRuntime struct {
	name  string
	calls *[]string
}

func (f fakeRuntime) Start(_ context.Context, frame map[string]any) (map[string]any, error) {
	*f.calls = append(*f.calls, f.name+".start")
	return map[string]any{"sidecar_port": 1234}, nil
}
func (f fakeRuntime) Stop(context.Context, map[string]any) error {
	*f.calls = append(*f.calls, f.name+".stop")
	return nil
}
func (f fakeRuntime) Delete(context.Context, map[string]any) (map[string]any, error) {
	*f.calls = append(*f.calls, f.name+".delete")
	return map[string]any{"freed_storage_gb": 0}, nil
}
func (f fakeRuntime) Status(context.Context, map[string]any) (map[string]any, error) {
	return nil, nil
}

// decode turns a JSON literal into a frame exactly as the tunnel reader does.
func decode(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestDispatchByRuntimeField(t *testing.T) {
	var calls []string
	h := New(context.Background(), nil, nil, Options{Runtimes: map[string]Runtime{
		RuntimeDocker:      fakeRuntime{"docker", &calls},
		RuntimeNativeMacOS: fakeRuntime{"native", &calls},
	}})
	ctx := context.Background()
	// No runtime field = docker (every backend that predates runtimes).
	if _, err := h.dispatch(ctx, "workspace.start", decode(t, `{"container_name":"clux-ws-1"}`)); err != nil {
		t.Fatal(err)
	}
	h.dispatch(ctx, "workspace.stop", decode(t, `{"runtime":"native_macos","workspace_id":1}`))
	h.dispatch(ctx, "workspace.delete", decode(t, `{"runtime":"docker"}`))
	if strings.Join(calls, ",") != "docker.start,native.stop,docker.delete" {
		t.Fatalf("calls %v", calls)
	}
	if _, err := h.dispatch(ctx, "workspace.start", decode(t, `{"runtime":"vm"}`)); err == nil {
		t.Fatal("unknown runtime accepted")
	}
}

func TestNativeUnavailableIsAClearError(t *testing.T) {
	h := New(context.Background(), nil, nil, Options{})
	_, err := h.dispatch(context.Background(), "workspace.start", decode(t, `{"runtime":"native_macos","workspace_id":3}`))
	if err == nil || !strings.Contains(err.Error(), "clux native install") {
		t.Fatalf("got %v", err)
	}
	if _, ok := h.opts.Runtimes[RuntimeDocker].(DockerRuntime); !ok {
		t.Fatal("docker runtime must always be present")
	}
}

func TestEgressCommands(t *testing.T) {
	p := egress.New([]byte("k"), "")
	h := New(context.Background(), nil, nil, Options{Egress: p})
	ctx := context.Background()
	if _, err := h.dispatch(ctx, "egress.policy", decode(t, `{"workspace_id":7,"mode":"allowlist","allow":["*.github.com"]}`)); err != nil {
		t.Fatal(err)
	}
	pol, ok := p.Policy("7")
	if !ok || !pol.Allows("api.github.com", 443) || pol.Allows("example.com", 443) {
		t.Fatalf("policy %+v", pol)
	}
	if _, err := h.dispatch(ctx, "egress.decision", decode(t, `{"workspace_id":7,"request_id":"gone","decision":"allow_project","host":"pypi.org"}`)); err != nil {
		t.Fatal(err)
	}
	if pol, _ := p.Policy("7"); !pol.Allows("pypi.org", 443) {
		t.Fatal("late allow_project not applied")
	}
	if _, err := h.dispatch(ctx, "egress.decision", decode(t, `{"workspace_id":7,"request_id":"x","decision":"allow_forever"}`)); err == nil {
		t.Fatal("unknown decision accepted")
	}
	if _, err := New(ctx, nil, nil, Options{}).dispatch(ctx, "egress.policy", decode(t, `{"workspace_id":7}`)); err == nil {
		t.Fatal("egress.policy without a proxy must fail")
	}
}

func TestEgressWithoutCorrelationIDSendsNoResult(t *testing.T) {
	r := NewResults()
	h := New(context.Background(), nil, r, Options{Egress: egress.New([]byte("k"), "")})
	h.HandleCommand(context.Background(), "egress.policy", decode(t, `{"workspace_id":7,"mode":"open"}`))
	if r.Pending() != 0 {
		t.Fatal("fire-and-forget egress frame produced a result")
	}
	h.HandleCommand(context.Background(), "egress.policy", decode(t, `{"workspace_id":7,"mode":"open","correlation_id":"c1"}`))
	if r.Pending() != 1 {
		t.Fatal("egress frame with correlation_id must be answered")
	}
}

type fakeSupervisor struct {
	reqs     []supervisor.Request
	err      error
	resident []string
}

func (f *fakeSupervisor) Call(_ context.Context, req supervisor.Request) (supervisor.Response, error) {
	f.reqs = append(f.reqs, req)
	if f.err != nil {
		return supervisor.Response{}, f.err
	}
	switch req.Op {
	case supervisor.OpStart:
		return supervisor.Response{OK: true, SidecarPort: 40001}, nil
	case supervisor.OpDelete:
		return supervisor.Response{OK: true, FreedBytes: 3 << 30}, nil
	case supervisor.OpStatus:
		return supervisor.Response{OK: true, Resident: f.resident, Workspaces: []supervisor.WorkspaceStatus{{ID: "5", Running: true, RuntimeVersion: "old"}}}, nil
	}
	return supervisor.Response{OK: true}, nil
}

type fakeInstaller struct {
	bundle sidecarrt.Bundle
	inUse  []string
}

func (f *fakeInstaller) Ensure(_ context.Context, b sidecarrt.Bundle, inUse []string) (sidecarrt.Runtime, error) {
	f.bundle, f.inUse = b, inUse
	return sidecarrt.Runtime{Version: b.Version, Dir: "/rt/" + b.Version, Python: "/rt/py", Sidecar: "/rt/s.py", Claude: "/rt/claude"}, nil
}

const nativeStart = `{"type":"workspace.start","runtime":"native_macos","workspace_id":12,
 "container_name":"clux-ws-12","volume_name":"clux-ws-12-data","image":"ignored","cpu_limit":2,"memory_limit_mb":4096,
 "hmac_secret":"sek","github_clone_url":"https://github.com/o/r.git",
 "sidecar_bundle":{"version":"abc123","sha256":"` + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" + `","url":"https://api.clux.space/b/abc123.tar.gz"},
 "egress":{"mode":"allowlist","allow":["api.anthropic.com"]}}`

func TestNativeRuntimeStart(t *testing.T) {
	sup := &fakeSupervisor{}
	inst := &fakeInstaller{}
	p := egress.New([]byte("k"), "")
	n := &NativeRuntime{Supervisor: one(sup), Slots: testSlots(t, 1), Installer: inst, Egress: p, ProxyPort: 47821}
	res, err := n.Start(context.Background(), decode(t, nativeStart))
	if err != nil {
		t.Fatal(err)
	}
	if res["sidecar_port"] != 40001 {
		t.Fatalf("result %v", res)
	}
	if inst.bundle.Version != "abc123" || len(inst.inUse) != 1 || inst.inUse[0] != "old" {
		t.Fatalf("installer got %+v in use %v", inst.bundle, inst.inUse)
	}
	start := sup.reqs[len(sup.reqs)-1]
	if start.Op != supervisor.OpStart || start.WorkspaceID != "12" || start.HMACSecret != "sek" ||
		start.GithubCloneURL != "https://github.com/o/r.git" || start.Runtime.Claude != "/rt/claude" {
		t.Fatalf("supervisor request %+v", start)
	}
	if start.ProxyURL != p.URL("12", 47821) {
		t.Fatalf("proxy url %q", start.ProxyURL)
	}
	if pol, ok := p.Policy("12"); !ok || !pol.Allows("api.anthropic.com", 443) || pol.Allows("evil.io", 443) {
		t.Fatalf("policy not installed before start: %+v", pol)
	}
}

func TestNativeRuntimeValidatesInput(t *testing.T) {
	n := &NativeRuntime{Supervisor: one(&fakeSupervisor{}), Slots: testSlots(t, 2), Installer: &fakeInstaller{}, Egress: egress.New([]byte("k"), ""), ProxyPort: 47821}
	for _, mut := range []func(map[string]any){
		func(f map[string]any) { delete(f, "sidecar_bundle") },
		func(f map[string]any) { delete(f, "hmac_secret") },
		func(f map[string]any) { f["workspace_id"] = "../../etc" },
		func(f map[string]any) { delete(f, "workspace_id") },
	} {
		f := decode(t, nativeStart)
		mut(f)
		if _, err := n.Start(context.Background(), f); err == nil {
			t.Errorf("accepted %v", f)
		}
	}
}

func TestNativeRuntimeDeleteAndErrors(t *testing.T) {
	sup := &fakeSupervisor{}
	p := egress.New([]byte("k"), "")
	p.SetPolicy("12", egress.Policy{})
	n := &NativeRuntime{Supervisor: one(sup), Slots: testSlots(t, 2), Installer: &fakeInstaller{}, Egress: p, ProxyPort: 47821}
	if _, err := n.Slots.Assign("12", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := n.Slots.Assign("13", nil); err != nil {
		t.Fatal(err)
	}
	res, err := n.Delete(context.Background(), decode(t, `{"runtime":"native_macos","workspace_id":12}`))
	if err != nil || res["freed_storage_gb"] != 3 {
		t.Fatalf("%v %v", res, err)
	}
	if _, ok := p.Policy("12"); ok {
		t.Fatal("delete must drop the egress policy")
	}
	if _, ok := n.Slots.Lookup("12"); ok || n.Slots.Free() != 1 {
		t.Fatal("delete must free the slot")
	}
	// Never started: nothing to stop or delete, no supervisor call.
	calls := len(sup.reqs)
	if err := n.Stop(context.Background(), decode(t, `{"workspace_id":99}`)); err != nil {
		t.Fatal(err)
	}
	if res, err := n.Delete(context.Background(), decode(t, `{"workspace_id":99}`)); err != nil || res["freed_storage_gb"] != 0 {
		t.Fatalf("%v %v", res, err)
	}
	if len(sup.reqs) != calls {
		t.Fatal("supervisor called for a workspace without a slot")
	}
	sup.err = errors.New("native supervisor not reachable")
	if err := n.Stop(context.Background(), decode(t, `{"workspace_id":13}`)); err == nil {
		t.Fatal("supervisor error swallowed")
	}
	if _, err := n.Delete(context.Background(), decode(t, `{"workspace_id":13}`)); err == nil {
		t.Fatal("supervisor error swallowed")
	}
	if _, ok := n.Slots.Lookup("13"); !ok {
		t.Fatal("a failed delete must keep the slot (its files are still there)")
	}
}

func one(s SupervisorCaller) func(int) SupervisorCaller {
	return func(int) SupervisorCaller { return s }
}

func testSlots(t *testing.T, n int) *SlotMap {
	t.Helper()
	m, err := LoadSlotMap(filepath.Join(t.TempDir(), "native-slots.json"), n)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// Each workspace gets a slot of its own for its whole life; with all slots
// held, a start fails with a clear message.
func TestNativeRuntimeAssignsSlots(t *testing.T) {
	sups := map[int]*fakeSupervisor{1: {}, 2: {resident: []string{"77"}}, 3: {}}
	path := filepath.Join(t.TempDir(), "native-slots.json")
	slots, _ := LoadSlotMap(path, 3)
	n := &NativeRuntime{
		Supervisor: func(i int) SupervisorCaller { return sups[i] },
		Slots:      slots, Installer: &fakeInstaller{}, Egress: egress.New([]byte("k"), ""), ProxyPort: 47821,
	}
	start := func(id string) error {
		f := decode(t, nativeStart)
		f["workspace_id"] = id
		_, err := n.Start(context.Background(), f)
		return err
	}
	if err := start("12"); err != nil {
		t.Fatal(err)
	}
	if err := start("13"); err != nil { // slot 2 holds another workspace's files: skipped
		t.Fatal(err)
	}
	if s, _ := slots.Lookup("12"); s != 1 {
		t.Fatalf("12 -> slot %d", s)
	}
	if s, _ := slots.Lookup("13"); s != 3 {
		t.Fatalf("13 -> slot %d, want 3", s)
	}
	if err := start("12"); err != nil { // restart keeps the slot
		t.Fatal(err)
	}
	if s, _ := slots.Lookup("12"); s != 1 {
		t.Fatal("restart moved the workspace")
	}
	err := start("14")
	if err == nil || !strings.Contains(err.Error(), "all 3 native slots in use; run `sudo clux native install --slots 4`") {
		t.Fatalf("full pool: %v", err)
	}
	for i, sup := range sups {
		for _, r := range sup.reqs {
			if r.Op == supervisor.OpStart && (i == 1) != (r.WorkspaceID == "12") {
				t.Fatalf("slot %d got start of workspace %s", i, r.WorkspaceID)
			}
			if r.Op == supervisor.OpStart && i == 2 {
				t.Fatal("slot holding another workspace's files got a start")
			}
		}
	}
	// Persisted: a restarted host agent keeps the assignments.
	again, err := LoadSlotMap(path, 3)
	if err != nil {
		t.Fatal(err)
	}
	if s, _ := again.Lookup("13"); s != 3 || again.Free() != 1 {
		t.Fatalf("reloaded: 13 -> %d, free %d", s, again.Free())
	}
}

func TestWorkspaceIDField(t *testing.T) {
	if id, err := workspaceIDField(decode(t, `{"workspace_id":42}`)); err != nil || id != "42" {
		t.Fatalf("%q %v", id, err)
	}
	if id, _ := workspaceIDField(decode(t, `{"workspace_id":"ab-1"}`)); id != "ab-1" {
		t.Fatalf("%q", id)
	}
	for _, bad := range []string{`{}`, `{"workspace_id":1.5}`, `{"workspace_id":-1}`, `{"workspace_id":""}`} {
		if _, err := workspaceIDField(decode(t, bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}
