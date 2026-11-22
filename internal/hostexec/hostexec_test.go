//go:build !windows

package hostexec

import (
	"strings"
	"sync"
	"testing"
	"time"
)

const reqID = "0123456789abcdef0123456789abcdef"

type collector struct {
	mu     sync.Mutex
	frames []map[string]any
	got    chan map[string]any
}

func newCollector() *collector { return &collector{got: make(chan map[string]any, 16)} }

func (c *collector) deliver(f map[string]any) {
	c.mu.Lock()
	c.frames = append(c.frames, f)
	c.mu.Unlock()
	c.got <- f
}

func (c *collector) wait(t *testing.T) map[string]any {
	t.Helper()
	select {
	case f := <-c.got:
		return f
	case <-time.After(20 * time.Second):
		t.Fatal("no host_exec.result")
		return nil
	}
}

func testExecutor(t *testing.T, c *collector) (*Executor, string) {
	t.Helper()
	home := t.TempDir()
	e := New(c.deliver)
	e.Logf = func(string, ...any) {}
	e.home = func() (string, error) { return home, nil }
	e.shell = func() string { return "/bin/sh" }
	e.geteuid = func() int { return 501 }
	e.grace = 200 * time.Millisecond
	return e, home
}

func frame(command string, extra map[string]any) map[string]any {
	f := map[string]any{"workspace_id": float64(7), "request_id": reqID, "command": command}
	for k, v := range extra {
		f[k] = v
	}
	return f
}

func TestRunReportsOutputAndExitCode(t *testing.T) {
	c := newCollector()
	e, home := testExecutor(t, c)
	if err := e.Start(frame("pwd; echo out; echo err >&2; exit 3", nil)); err != nil {
		t.Fatal(err)
	}
	f := c.wait(t)
	if f["type"] != "host_exec.result" || f["request_id"] != reqID || f["workspace_id"] != int64(7) {
		t.Fatalf("frame %v", f)
	}
	if f["exit_code"] != 3 || f["timed_out"] != false || f["error"] != "" || f["truncated"] != false {
		t.Fatalf("frame %v", f)
	}
	out := f["output"].(string)
	for _, want := range []string{"out", "err"} {
		if !strings.Contains(out, want) {
			t.Errorf("output %q lacks %q", out, want)
		}
	}
	// Runs in the owner's home by default (macOS reports /private/var/...).
	if !strings.Contains(out, strings.TrimPrefix(home, "/private")) {
		t.Errorf("output %q: not run in home %q", out, home)
	}
	if e.Running() != 0 {
		t.Fatal("still running")
	}
}

func TestEnvAndStdin(t *testing.T) {
	c := newCollector()
	e, _ := testExecutor(t, c)
	// read gets EOF at once from /dev/null instead of waiting.
	if err := e.Start(frame(`read x; echo "[$x] $NONINTERACTIVE $CLUX_HOST_EXEC"`, nil)); err != nil {
		t.Fatal(err)
	}
	f := c.wait(t)
	if got := strings.TrimSpace(f["output"].(string)); got != "[] 1 1" {
		t.Fatalf("output %q", got)
	}
}

func TestOutputTailIsCapped(t *testing.T) {
	c := newCollector()
	e, _ := testExecutor(t, c)
	cmd := `i=0; while [ $i -lt 400 ]; do printf '%080d\n' $i; i=$((i+1)); done; echo LAST`
	if err := e.Start(frame(cmd, map[string]any{"output_limit_bytes": float64(1024)})); err != nil {
		t.Fatal(err)
	}
	f := c.wait(t)
	out := f["output"].(string)
	if len(out) > 1024 || f["truncated"] != true || !strings.HasSuffix(out, "LAST\n") {
		t.Fatalf("len %d truncated %v tail %q", len(out), f["truncated"], out[len(out)-10:])
	}
}

func TestTimeoutKillsProcessGroup(t *testing.T) {
	c := newCollector()
	e, _ := testExecutor(t, c)
	start := time.Now()
	if err := e.Start(frame("sleep 30 & sleep 30; echo never", map[string]any{"timeout_seconds": float64(1)})); err != nil {
		t.Fatal(err)
	}
	f := c.wait(t)
	if f["timed_out"] != true || f["exit_code"] != nil || !strings.Contains(f["error"].(string), "timed out") {
		t.Fatalf("frame %v", f)
	}
	if time.Since(start) > 10*time.Second {
		t.Fatalf("took %s", time.Since(start))
	}
}

func TestRefusals(t *testing.T) {
	c := newCollector()
	e, home := testExecutor(t, c)
	cases := []struct {
		name  string
		frame map[string]any
		want  string
	}{
		{"sudo", frame("sudo ls", nil), "needs_password:"},
		{"bad id", map[string]any{"workspace_id": float64(7), "request_id": "x", "command": "ls"}, "request_id"},
		{"no workspace", map[string]any{"request_id": reqID, "command": "ls"}, "workspace_id"},
		{"empty", frame("  ", nil), "command is required"},
		{"nul", frame("ls\x00", nil), "NUL"},
		{"long", frame(strings.Repeat("a", MaxCommandBytes+1), nil), "at most"},
		{"relative cwd", frame("ls", map[string]any{"cwd": "src"}), "absolute"},
		{"missing cwd", frame("ls", map[string]any{"cwd": home + "/nope"}), "not an existing"},
	}
	for _, tc := range cases {
		err := e.Start(tc.frame)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err %v, want %q", tc.name, err, tc.want)
		}
	}
	e.geteuid = func() int { return 0 }
	if err := e.Start(frame("ls", nil)); err == nil || !strings.Contains(err.Error(), "root") {
		t.Errorf("root: %v", err)
	}
	if len(c.frames) != 0 {
		t.Fatalf("refused requests must not run: %v", c.frames)
	}
}

func TestDuplicateAndConcurrencyLimit(t *testing.T) {
	c := newCollector()
	e, _ := testExecutor(t, c)
	if err := e.Start(frame("sleep 0.3", nil)); err != nil {
		t.Fatal(err)
	}
	if err := e.Start(frame("sleep 0.3", nil)); err == nil {
		t.Fatal("a running request id must be refused")
	}
	c.wait(t)
	if err := e.Start(frame("echo again", nil)); err == nil || !strings.Contains(err.Error(), "already ran") {
		t.Fatalf("a finished request id must be refused: %v", err)
	}

	ids := []string{
		"10000000000000000000000000000000", "20000000000000000000000000000000",
		"30000000000000000000000000000000", "40000000000000000000000000000000",
	}
	for _, id := range ids {
		f := frame("sleep 1", nil)
		f["request_id"] = id
		if err := e.Start(f); err != nil {
			t.Fatal(err)
		}
	}
	f := frame("sleep 1", nil)
	f["request_id"] = "50000000000000000000000000000000"
	if err := e.Start(f); err == nil || !strings.Contains(err.Error(), "already running") {
		t.Fatalf("5th concurrent command: %v", err)
	}
	for range ids {
		c.wait(t)
	}
}

func TestParseRequestDefaultsAndClamps(t *testing.T) {
	home := t.TempDir()
	req, err := ParseRequest(frame("ls", map[string]any{"cwd": "~"}), home)
	if err != nil {
		t.Fatal(err)
	}
	if req.Dir != home || req.Timeout != DefaultTimeout || req.OutputLimit != DefaultOutputLimit {
		t.Fatalf("%+v", req)
	}
	req, err = ParseRequest(frame("ls", map[string]any{
		"cwd": "~/", "timeout_seconds": float64(999999), "output_limit_bytes": float64(10),
	}), home)
	if err != nil {
		t.Fatal(err)
	}
	if req.Timeout != MaxTimeout || req.OutputLimit != MinOutputLimit || req.Dir != home {
		t.Fatalf("%+v", req)
	}
}

func TestTailValidUTF8(t *testing.T) {
	tl := &tail{limit: 3}
	_, _ = tl.Write([]byte("ab\xe2\x82\xacc"))
	got, truncated := tl.text()
	if !truncated || strings.ContainsRune(got, 0xFFFD) == false {
		t.Fatalf("%q %v: the cut euro sign must be replaced", got, truncated)
	}
}
