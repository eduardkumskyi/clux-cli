package hostsession

import (
	"context"
	"strings"
	"testing"

	"github.com/eduardkumskyi/clux-cli/internal/hostexec"
)

func TestHostExecRunWithoutExecutorIsRefused(t *testing.T) {
	r := NewResults()
	h := New(context.Background(), nil, r, Options{})
	h.HandleCommand(context.Background(), "host_exec.run", decode(t, `{"correlation_id":"c1","workspace_id":7}`))
	res := r.pending[0].frame
	if res["ok"] != false || !strings.Contains(res["error"].(string), "not available") {
		t.Fatalf("result %v", res)
	}
}

func TestHostExecRunRefusalIsTheResult(t *testing.T) {
	r := NewResults()
	h := New(context.Background(), nil, r, Options{HostExec: hostexec.New(func(map[string]any) {})})
	h.HandleCommand(context.Background(), "host_exec.run", decode(t,
		`{"correlation_id":"c1","workspace_id":7,"request_id":"0123456789abcdef0123456789abcdef","command":"sudo ls"}`))
	res := r.pending[0].frame
	if res["ok"] != false || !strings.HasPrefix(res["error"].(string), "needs_password:") {
		t.Fatalf("result %v", res)
	}
}

func TestBackendURLField(t *testing.T) {
	if got := backendURLField(decode(t, `{"backend_url":"https://api.clux.space"}`)); got != "https://api.clux.space" {
		t.Fatalf("got %q", got)
	}
	for _, f := range []string{`{}`, `{"backend_url":"https://u:p@x"}`, `{"backend_url":"x"}`, `{"backend_url":5}`} {
		if got := backendURLField(decode(t, f)); got != "" {
			t.Fatalf("%s: got %q", f, got)
		}
	}
}
