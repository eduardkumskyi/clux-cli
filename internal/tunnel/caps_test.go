package tunnel

import (
	"context"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/eduardkumskyi/clux-cli/internal/sysinfo"
)

type recordingHandler struct {
	nopHandler
	got chan string
}

func (h recordingHandler) HandleCommand(_ context.Context, frameType string, _ map[string]any) {
	h.got <- frameType
}

func TestRegisterCarriesCapabilities(t *testing.T) {
	fb := newFakeBackend(t, "alive")
	caps := map[string]any{"runtimes": []string{"docker", "native_macos"}}
	sess, err := Dial(context.Background(), fb.srv.URL, "tok", "0.3.0", sysinfo.Info{}, caps)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	fb.mu.Lock()
	reg := fb.reg
	fb.mu.Unlock()
	c, _ := reg["capabilities"].(map[string]any)
	rts, _ := c["runtimes"].([]any)
	if len(rts) != 2 || rts[1] != "native_macos" {
		t.Fatalf("register frame %v", reg)
	}

	fb2 := newFakeBackend(t, "alive")
	sess2, err := Dial(context.Background(), fb2.srv.URL, "tok", "0.3.0", sysinfo.Info{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer sess2.Close()
	fb2.mu.Lock()
	defer fb2.mu.Unlock()
	if _, ok := fb2.reg["capabilities"]; ok {
		t.Fatal("nil capabilities must be omitted")
	}
}

func TestRegisterCarriesMachineIDAndPlatform(t *testing.T) {
	id := strings.Repeat("ab", 32)
	for _, tc := range []struct {
		machineID string
		wantID    bool
	}{{id, true}, {"", false}} {
		fb := newFakeBackend(t, "alive")
		sess, err := Dial(context.Background(), fb.srv.URL, "tok", "0.5.0", sysinfo.Info{MachineID: tc.machineID}, nil)
		if err != nil {
			t.Fatal(err)
		}
		sess.Close()
		fb.mu.Lock()
		reg := fb.reg
		fb.mu.Unlock()
		if got, ok := reg["machine_id"]; ok != tc.wantID || (ok && got != id) {
			t.Fatalf("machine_id %q: register frame %v", tc.machineID, reg)
		}
		if reg["os"] != runtime.GOOS || reg["arch"] != runtime.GOARCH {
			t.Fatalf("os/arch missing: %v", reg)
		}
	}
	if _, ok := heartbeatFrame(sysinfo.Info{MachineID: id}, "1", nil)["machine_id"]; ok {
		t.Fatal("machine_id belongs to register only")
	}
}

func TestHeartbeatCapabilitiesOnlyWhenGiven(t *testing.T) {
	if _, ok := heartbeatFrame(sysinfo.Info{}, "1", nil)["capabilities"]; ok {
		t.Fatal("unchanged capabilities must be omitted")
	}
	if _, ok := heartbeatFrame(sysinfo.Info{}, "1", map[string]any{"runtimes": []string{"docker"}})["capabilities"]; !ok {
		t.Fatal("capabilities missing")
	}
}

func TestEgressFramesReachHandleCommand(t *testing.T) {
	fb := newFakeBackend(t, "egress")
	sess := dialFake(t, fb)
	h := recordingHandler{got: make(chan string, 4)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go sess.Run(ctx, h)
	want := map[string]bool{"egress.decision": true, "egress.policy": true}
	for i := 0; i < 2; i++ {
		select {
		case ft := <-h.got:
			delete(want, ft)
		case <-time.After(3 * time.Second):
			t.Fatalf("egress frames not dispatched, still missing %v", want)
		}
	}
	if len(want) != 0 {
		t.Fatalf("missing %v", want)
	}
}
