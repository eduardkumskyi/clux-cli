package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/eduardkumskyi/clux-cli/internal/config"
	"github.com/eduardkumskyi/clux-cli/internal/devicelogin"
	"github.com/eduardkumskyi/clux-cli/internal/service"
)

type bgFake struct {
	installs int
	saved    []string
	installE error
	out      bytes.Buffer
}

// newFakeBackground: interactive, supported, never asked.
func newFakeBackground(f *bgFake, answer string) *backgroundOffer {
	return &backgroundOffer{
		interactive: true,
		supported:   true,
		install:     func() error { f.installs++; return f.installE },
		save:        func(a string) error { f.saved = append(f.saved, a); return nil },
		in:          strings.NewReader(answer),
		out:         &f.out,
	}
}

func TestBackgroundDecide(t *testing.T) {
	cases := []struct {
		name string
		mod  func(o *backgroundOffer)
		want backgroundAction
	}{
		{"first interactive run", func(o *backgroundOffer) {}, bgPrompt},
		{"non-interactive (scripts, the service)", func(o *backgroundOffer) { o.interactive = false }, bgForeground},
		{"--foreground", func(o *backgroundOffer) { o.foreground = true }, bgForeground},
		{"--foreground beats a yes", func(o *backgroundOffer) { o.foreground = true; o.answer = config.ServiceYes }, bgForeground},
		{"remembered yes", func(o *backgroundOffer) { o.answer = config.ServiceYes }, bgInstall},
		{"remembered no", func(o *backgroundOffer) { o.answer = config.ServiceNo }, bgForeground},
		{"--background after a no", func(o *backgroundOffer) { o.answer = config.ServiceNo; o.background = true }, bgInstall},
		{"windows", func(o *backgroundOffer) { o.supported = false }, bgUnsupported},
		{"windows, non-interactive", func(o *backgroundOffer) { o.supported = false; o.interactive = false }, bgForeground},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o := newFakeBackground(&bgFake{}, "")
			c.mod(o)
			if got := o.decide(); got != c.want {
				t.Fatalf("decide = %v, want %v", got, c.want)
			}
		})
	}
}

func TestBackgroundPromptAnswers(t *testing.T) {
	cases := []struct {
		answer             string
		installs           int
		saved              string
		handedOver         bool
		outContains        string
		installErr         error
		notOutContainsText string
	}{
		{answer: "\n", installs: 1, saved: config.ServiceYes, handedOver: true},
		{answer: "y\n", installs: 1, saved: config.ServiceYes, handedOver: true},
		{answer: "n\n", saved: config.ServiceNo, outContains: "clux host start --background"},
		{answer: "maybe\nno\n", saved: config.ServiceNo, outContains: "Please answer y or n"},
		{answer: "", outContains: backgroundPromptText}, // EOF: ask next time, nothing saved
		{answer: "y\n", installs: 1, saved: config.ServiceYes, installErr: errors.New("boom"), outContains: "Staying in the foreground"},
	}
	for _, c := range cases {
		f := &bgFake{installE: c.installErr}
		o := newFakeBackground(f, c.answer)
		got := o.run()
		if got != c.handedOver || f.installs != c.installs {
			t.Fatalf("%q: handedOver=%v installs=%d", c.answer, got, f.installs)
		}
		if strings.Join(f.saved, ",") != c.saved {
			t.Fatalf("%q: saved %v, want %q", c.answer, f.saved, c.saved)
		}
		if c.outContains != "" && !strings.Contains(f.out.String(), c.outContains) {
			t.Fatalf("%q: output %q lacks %q", c.answer, f.out.String(), c.outContains)
		}
	}
}

func TestBackgroundRememberedYesDoesNotAsk(t *testing.T) {
	f := &bgFake{}
	o := newFakeBackground(f, "")
	o.answer = config.ServiceYes
	if !o.run() || f.installs != 1 || len(f.saved) != 0 || strings.Contains(f.out.String(), "[Y/n]") {
		t.Fatalf("installs=%d saved=%v out=%q", f.installs, f.saved, f.out.String())
	}
}

func TestBackgroundNonInteractiveIsSilent(t *testing.T) {
	f := &bgFake{}
	o := newFakeBackground(f, "y\n")
	o.interactive = false
	if o.run() || f.installs != 0 || f.out.Len() != 0 || len(f.saved) != 0 {
		t.Fatalf("non-TTY must behave like before: installs=%d out=%q", f.installs, f.out.String())
	}
}

func TestInstallServiceRefusesTempBinaryAndReports(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no background service on Windows")
	}
	home := t.TempDir()
	var calls []string
	m := &service.Manager{
		GOOS: "darwin", Home: home, UID: 501, StateDir: filepath.Join(home, ".clux"),
		Exe: filepath.Join(os.TempDir(), "go-build1/b001/exe/clux"),
		Run: func(name string, args ...string) ([]byte, error) {
			calls = append(calls, name)
			return nil, nil
		},
	}
	var out bytes.Buffer
	err := installService(m, &config.Config{HostName: "My Mac"}, &out)
	if err == nil || !strings.Contains(err.Error(), "temporary location") || len(calls) != 0 {
		t.Fatalf("temp binary: err=%v calls=%v", err, calls)
	}

	calls = nil
	m = &service.Manager{
		GOOS: "darwin", Home: home, UID: 501, StateDir: filepath.Join(home, ".clux"),
		Exe: "/opt/homebrew/bin/clux",
		Run: func(name string, args ...string) ([]byte, error) {
			line := name + " " + strings.Join(args, " ")
			calls = append(calls, line)
			if strings.HasPrefix(line, "launchctl print") {
				if len(calls) == 1 {
					return nil, errors.New("not loaded")
				}
				return []byte("state = running\npid = 9\n"), nil
			}
			return nil, nil
		},
		Sleep: func(time.Duration) {},
	}
	out.Reset()
	if err := installService(m, &config.Config{HostName: "My Mac"}, &out); err != nil {
		t.Fatal(err)
	}
	s := out.String()
	if !strings.Contains(s, `Running "My Mac" in the background`) {
		t.Fatalf("output: %s", s)
	}
}

// fakeDeviceBackend approves on the second poll.
func fakeDeviceBackend(t *testing.T, final map[string]any) *httptest.Server {
	polls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/compute-hosts/device-codes/":
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"device_code": "dc", "user_code": "ABCD-EFGH",
				"verification_url": "https://app.clux.space/connect?code=ABCD-EFGH",
				"expires_in":       600, "interval": 3,
			})
		case "/api/compute-hosts/device-codes/poll/":
			polls++
			if polls < 2 {
				_ = json.NewEncoder(w).Encode(map[string]any{"status": "pending"})
				return
			}
			_ = json.NewEncoder(w).Encode(final)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func instant(ctx context.Context, _ time.Duration) error { return ctx.Err() }

func TestLoginFlowPrintsCodeOpensBrowserAndConnects(t *testing.T) {
	srv := fakeDeviceBackend(t, map[string]any{
		"status": "approved", "token": "pat", "host": map[string]any{"id": 312, "name": "My Mac"}, "reused": true,
	})
	var out bytes.Buffer
	var opened []string
	f := &loginFlow{
		client: &devicelogin.Client{BaseURL: srv.URL, Sleep: instant},
		out:    &out,
		open:   func(u string) error { opened = append(opened, u); return errors.New("no browser") },
	}
	res, err := f.run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := "To connect this computer, open:\n  https://app.clux.space/connect?code=ABCD-EFGH\nand confirm the code ABCD-EFGH. Waiting...\n"
	if out.String() != want {
		t.Fatalf("output:\n%s\nwant:\n%s", out.String(), want)
	}
	if len(opened) != 1 || opened[0] != "https://app.clux.space/connect?code=ABCD-EFGH" {
		t.Fatalf("opened %v", opened)
	}
	if got := connectedLine(res); got != `Connected as "My Mac" (id 312) (the same computer as before - its projects are kept)` {
		t.Fatal(got)
	}
	res.Reused = false
	if got := connectedLine(res); got != `Connected as "My Mac" (id 312)` {
		t.Fatal(got)
	}
}

func TestLoginFlowCancelAndDeny(t *testing.T) {
	srv := fakeDeviceBackend(t, map[string]any{"status": "denied"})
	f := &loginFlow{client: &devicelogin.Client{BaseURL: srv.URL, Sleep: instant}, out: &bytes.Buffer{}}
	if _, err := f.run(context.Background()); !errors.Is(err, devicelogin.ErrDenied) {
		t.Fatalf("err = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	f.client.Sleep = func(context.Context, time.Duration) error { cancel(); return context.Canceled }
	if _, err := f.run(ctx); !errors.Is(err, errLoginCancelled) {
		t.Fatalf("Ctrl+C: err = %v", err)
	}
}

func TestPrintTail(t *testing.T) {
	p := filepath.Join(t.TempDir(), "host.log")
	var b strings.Builder
	for i := 0; i < 5000; i++ {
		b.WriteString("line ")
		b.WriteString(strings.Repeat("x", i%40))
		b.WriteString("\n")
	}
	b.WriteString("last\n")
	if err := os.WriteFile(p, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	f, _ := os.Open(p)
	defer f.Close()
	var out bytes.Buffer
	end, err := printTail(f, 3, &out)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
	if len(lines) != 3 || lines[2] != "last" || end != int64(b.Len()) {
		t.Fatalf("tail = %q (end %d)", lines, end)
	}
}

func TestPrintLogFollowsAppendsAndRotation(t *testing.T) {
	p := filepath.Join(t.TempDir(), "host.log")
	_ = os.WriteFile(p, []byte("a\n"), 0o600)
	ctx, cancel := context.WithCancel(context.Background())
	var out syncBuffer
	done := make(chan error, 1)
	go func() { done <- printLog(ctx, p, 10, true, &out, 5*time.Millisecond) }()
	waitFor(t, &out, "a\n")
	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0)
	_, _ = f.WriteString("b\n")
	f.Close()
	waitFor(t, &out, "a\nb\n")
	_ = os.Rename(p, p+".1")
	_ = os.WriteFile(p, []byte("c\n"), 0o600)
	waitFor(t, &out, "a\nb\nc\n")
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestDescribeLiveAgent(t *testing.T) {
	none := func() (int, bool) { return 0, false }
	pid := func(n int) func() (int, bool) { return func() (int, bool) { return n, true } }
	if s, ok := describeLiveAgent(pid(7), pid(7)); !ok || !strings.Contains(s, "background service (pid 7)") {
		t.Fatal(s)
	}
	if s, ok := describeLiveAgent(none, pid(9)); !ok || !strings.Contains(s, "`clux host start` (pid 9)") {
		t.Fatal(s)
	}
	if _, ok := describeLiveAgent(none, none); ok {
		t.Fatal("nothing running: whoami/doctor may register")
	}
}

func TestBackendReachableDoesNotRegister(t *testing.T) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		w.WriteHeader(http.StatusNotFound) // any HTTP answer means reachable
	}))
	defer srv.Close()
	if err := backendReachable(srv.URL); err != nil {
		t.Fatal(err)
	}
	if len(paths) != 1 || paths[0] != "/" {
		t.Fatalf("paths = %v (must not touch /ws/host/)", paths)
	}
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func waitFor(t *testing.T, s *syncBuffer, want string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for s.String() != want {
		if time.Now().After(deadline) {
			t.Fatalf("output %q, want %q", s.String(), want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestLastConnectionEvent(t *testing.T) {
	p := filepath.Join(t.TempDir(), "host.log")
	_ = os.WriteFile(p, []byte("x registered as host \"m\" (id=1)\nx something else\nx tunnel down: EOF\nx heartbeat\n"), 0o600)
	if got := lastConnectionEvent(p); got != "x tunnel down: EOF" {
		t.Fatal(got)
	}
	if lastConnectionEvent(filepath.Join(t.TempDir(), "none")) != "" {
		t.Fatal("no file, no event")
	}
}
