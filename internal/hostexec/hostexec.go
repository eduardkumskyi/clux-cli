// Package hostexec runs owner-approved host commands for `clux host start`.
//
// The coding agent in a BYOC workspace can ask for a command its sandbox or
// container can't run (e.g. `brew install ...`). The owner approves it in
// the clux UI (or a per-computer policy does), and only then does the
// backend send a host_exec.run frame over this host's own tunnel:
//
//	backend -> host  host_exec.run {workspace_id, request_id, command, cwd,
//	                 timeout_seconds, output_limit_bytes}
//	host -> backend  result {ok, error}            (accepted or refused, at once)
//	host -> backend  host_exec.result {workspace_id, request_id, exit_code,
//	                 output, truncated, timed_out, duration_ms, error}
//
// The command runs as the user running `clux host start` (never root), in
// that user's login shell, with stdin on /dev/null: nothing can prompt, so
// commands that ask for a password (sudo, su, ...) are refused up front.
// Output is a tail of output_limit_bytes; the command is killed (its whole
// process group) after timeout_seconds.
package hostexec

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/eduardkumskyi/clux-cli/internal/redact"
)

// Limits of one request.
const (
	DefaultTimeout     = 15 * time.Minute
	MaxTimeout         = time.Hour
	DefaultOutputLimit = 64 << 10
	MinOutputLimit     = 1 << 10
	MaxOutputLimit     = 256 << 10
	MaxCommandBytes    = 4096
	// MaxRunning commands at once per host.
	MaxRunning = 4
	// rememberFinished: a request id seen this recently is a duplicate.
	rememberFinished = 30 * time.Minute
	// killGrace between SIGTERM and SIGKILL on timeout.
	killGrace = 5 * time.Second
	// waitDelay: after the shell exits, how long a background child that
	// still holds the output pipe may delay the result.
	waitDelay = 2 * time.Second
)

// NeedsPasswordError prefixes the refusal of a command that needs a password.
const NeedsPasswordError = "needs_password: this command needs an administrator password, " +
	"which clux can't type for you. Use \"I'll do it myself\" and run it in your own terminal."

var requestIDRe = regexp.MustCompile(`^[0-9a-f]{32}$`)

// Request is one validated host_exec.run frame.
type Request struct {
	WorkspaceID int64
	RequestID   string
	Command     string
	Dir         string // absolute, existing
	Timeout     time.Duration
	OutputLimit int
}

// Result is what host_exec.result reports.
type Result struct {
	ExitCode  *int
	Output    string
	Truncated bool
	TimedOut  bool
	Duration  time.Duration
	Error     string
}

// Frame is the host_exec.result frame for req.
func (r Result) Frame(req Request) map[string]any {
	var exit any
	if r.ExitCode != nil {
		exit = *r.ExitCode
	}
	return map[string]any{
		"type":         "host_exec.result",
		"workspace_id": req.WorkspaceID,
		"request_id":   req.RequestID,
		"exit_code":    exit,
		"output":       r.Output,
		"truncated":    r.Truncated,
		"timed_out":    r.TimedOut,
		"duration_ms":  r.Duration.Milliseconds(),
		"error":        r.Error,
	}
}

// Executor runs requests. Safe for concurrent use; one per process.
type Executor struct {
	// Deliver receives each host_exec.result frame (a courier that survives
	// tunnel reconnects). Required.
	Deliver func(frame map[string]any)
	// Logf receives one line per start and end (default log.Printf).
	Logf func(format string, args ...any)

	mu       sync.Mutex
	running  map[string]bool
	finished map[string]time.Time

	// Test seams.
	shell   func() string
	home    func() (string, error)
	geteuid func() int
	now     func() time.Time
	grace   time.Duration
}

// New returns an executor that hands results to deliver.
func New(deliver func(frame map[string]any)) *Executor {
	return &Executor{Deliver: deliver}
}

func (e *Executor) logf(format string, args ...any) {
	if e.Logf != nil {
		e.Logf(format, args...)
		return
	}
	log.Printf(format, args...)
}

func (e *Executor) clock() time.Time {
	if e.now != nil {
		return e.now()
	}
	return time.Now()
}

// ParseRequest validates a host_exec.run frame. home resolves "" and "~".
func ParseRequest(frame map[string]any, home string) (Request, error) {
	var req Request
	switch v := frame["workspace_id"].(type) {
	case float64:
		if v != float64(int64(v)) || v <= 0 {
			return req, fmt.Errorf("invalid workspace_id %v", v)
		}
		req.WorkspaceID = int64(v)
	case string:
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n <= 0 {
			return req, fmt.Errorf("invalid workspace_id %q", v)
		}
		req.WorkspaceID = n
	default:
		return req, errors.New("workspace_id is required")
	}
	req.RequestID, _ = frame["request_id"].(string)
	if !requestIDRe.MatchString(req.RequestID) {
		return req, errors.New("invalid request_id")
	}
	req.Command, _ = frame["command"].(string)
	if strings.TrimSpace(req.Command) == "" {
		return req, errors.New("command is required")
	}
	if len(req.Command) > MaxCommandBytes || strings.ContainsRune(req.Command, 0) {
		return req, fmt.Errorf("command must be at most %d bytes without NUL", MaxCommandBytes)
	}
	dir, err := resolveDir(stringOf(frame["cwd"]), home)
	if err != nil {
		return req, err
	}
	req.Dir = dir
	req.Timeout = clampDuration(frame["timeout_seconds"], DefaultTimeout, time.Second, MaxTimeout)
	req.OutputLimit = clampInt(frame["output_limit_bytes"], DefaultOutputLimit, MinOutputLimit, MaxOutputLimit)
	return req, nil
}

func stringOf(v any) string {
	s, _ := v.(string)
	return s
}

func resolveDir(cwd, home string) (string, error) {
	if home == "" {
		return "", errors.New("no home directory for the owner")
	}
	switch {
	case cwd == "" || cwd == "~":
		cwd = home
	case strings.HasPrefix(cwd, "~/"):
		cwd = filepath.Join(home, cwd[2:])
	case !filepath.IsAbs(cwd):
		return "", fmt.Errorf("cwd must be absolute or start with ~/: %q", cwd)
	}
	cwd = filepath.Clean(cwd)
	info, err := os.Stat(cwd)
	if err != nil || !info.IsDir() {
		return "", fmt.Errorf("cwd %q is not an existing directory", cwd)
	}
	return cwd, nil
}

func clampDuration(v any, def, min, max time.Duration) time.Duration {
	n, ok := v.(float64)
	if !ok || n <= 0 {
		return def
	}
	d := time.Duration(n) * time.Second
	if d < min {
		return min
	}
	if d > max {
		return max
	}
	return d
}

func clampInt(v any, def, min, max int) int {
	n, ok := v.(float64)
	if !ok || n <= 0 {
		return def
	}
	switch {
	case n < float64(min):
		return min
	case n > float64(max):
		return max
	}
	return int(n)
}

// Start validates frame and runs it in the background; the error is the
// refusal reported in the command's result frame.
func (e *Executor) Start(frame map[string]any) error {
	if runtime.GOOS == "windows" {
		return errors.New("host commands are not supported on Windows")
	}
	geteuid := os.Geteuid
	if e.geteuid != nil {
		geteuid = e.geteuid
	}
	if geteuid() == 0 {
		return errors.New("clux host start runs as root; host commands only run as a normal user")
	}
	homeFn := os.UserHomeDir
	if e.home != nil {
		homeFn = e.home
	}
	home, _ := homeFn()
	req, err := ParseRequest(frame, home)
	if err != nil {
		return err
	}
	if NeedsPassword(req.Command) {
		return errors.New(NeedsPasswordError)
	}
	if err := e.claim(req.RequestID); err != nil {
		return err
	}
	e.logf("host command %s (workspace %d) started in %s: %s",
		req.RequestID, req.WorkspaceID, req.Dir, redact.String(req.Command))
	go func() {
		res := e.run(req)
		e.release(req.RequestID)
		exit := "none"
		if res.ExitCode != nil {
			exit = strconv.Itoa(*res.ExitCode)
		}
		e.logf("host command %s (workspace %d) finished: exit %s, %s%s",
			req.RequestID, req.WorkspaceID, exit, res.Duration.Round(time.Millisecond), errSuffix(res.Error))
		if e.Deliver != nil {
			e.Deliver(res.Frame(req))
		}
	}()
	return nil
}

func errSuffix(s string) string {
	if s == "" {
		return ""
	}
	return " (" + s + ")"
}

func (e *Executor) claim(id string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.running == nil {
		e.running = map[string]bool{}
		e.finished = map[string]time.Time{}
	}
	now := e.clock()
	for k, at := range e.finished {
		if now.Sub(at) > rememberFinished {
			delete(e.finished, k)
		}
	}
	if e.running[id] {
		return fmt.Errorf("request %s is already running", id)
	}
	if _, ok := e.finished[id]; ok {
		return fmt.Errorf("request %s already ran", id)
	}
	if len(e.running) >= MaxRunning {
		return fmt.Errorf("%d host commands are already running; try again when one finishes", MaxRunning)
	}
	e.running[id] = true
	return nil
}

func (e *Executor) release(id string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.running, id)
	e.finished[id] = e.clock()
}

// Running is the number of commands running now.
func (e *Executor) Running() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.running)
}

// loginShell is $SHELL when it is an absolute executable, else the platform
// default.
func loginShell() string {
	if s := os.Getenv("SHELL"); filepath.IsAbs(s) {
		if info, err := os.Stat(s); err == nil && !info.IsDir() && info.Mode()&0o111 != 0 {
			return s
		}
	}
	if runtime.GOOS == "darwin" {
		return "/bin/zsh"
	}
	return "/bin/sh"
}

// tail keeps the last limit bytes written to it.
type tail struct {
	mu    sync.Mutex
	limit int
	buf   []byte
	total int64
}

func (t *tail) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.total += int64(len(p))
	t.buf = append(t.buf, p...)
	// Trim only once it is well past the limit (amortized copying).
	if len(t.buf) > 2*t.limit {
		t.buf = append(t.buf[:0], t.buf[len(t.buf)-t.limit:]...)
	}
	return len(p), nil
}

// text is the kept tail as valid UTF-8, and whether bytes were dropped.
func (t *tail) text() (string, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	b := t.buf
	if len(b) > t.limit {
		b = b[len(b)-t.limit:]
	}
	return strings.ToValidUTF8(string(b), "�"), t.total > int64(len(b))
}
