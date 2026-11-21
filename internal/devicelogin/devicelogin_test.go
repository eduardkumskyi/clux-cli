package devicelogin

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeBackend serves device-codes/ and answers polls from a script.
type fakeBackend struct {
	t        *testing.T
	mu       sync.Mutex
	started  map[string]any
	polls    []map[string]string
	answers  []func(w http.ResponseWriter) // one per poll, last one repeats
	startRes func(w http.ResponseWriter)
	srv      *httptest.Server
}

func newFakeBackend(t *testing.T) *fakeBackend {
	fb := &fakeBackend{t: t}
	fb.startRes = func(w http.ResponseWriter) {
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"device_code": "secret-dc", "user_code": "ABCD-EFGH",
			"verification_url": "https://app.example/connect?code=ABCD-EFGH",
			"expires_in":       600, "interval": 3,
		})
	}
	fb.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("unexpected %s %s (%s)", r.Method, r.URL.Path, r.Header.Get("Content-Type"))
		}
		fb.mu.Lock()
		defer fb.mu.Unlock()
		switch r.URL.Path {
		case codesPath:
			_ = json.NewDecoder(r.Body).Decode(&fb.started)
			fb.startRes(w)
		case pollPath:
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			fb.polls = append(fb.polls, body)
			i := len(fb.polls) - 1
			if i >= len(fb.answers) {
				i = len(fb.answers) - 1
			}
			fb.answers[i](w)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(fb.srv.Close)
	return fb
}

func status(s string, extra map[string]any) func(w http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		m := map[string]any{"status": s}
		for k, v := range extra {
			m[k] = v
		}
		_ = json.NewEncoder(w).Encode(m)
	}
}

func httpStatus(code int) func(w http.ResponseWriter) {
	return func(w http.ResponseWriter) { w.WriteHeader(code) }
}

// fakeClock: sleep advances now instead of waiting, and records intervals.
type fakeClock struct {
	now    time.Time
	sleeps []time.Duration
}

func (c *fakeClock) client(base string) *Client {
	return &Client{
		BaseURL: base,
		now:     func() time.Time { return c.now },
		Sleep: func(ctx context.Context, d time.Duration) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			c.sleeps = append(c.sleeps, d)
			c.now = c.now.Add(d)
			return nil
		},
	}
}

func startAndWait(t *testing.T, fb *fakeBackend, clk *fakeClock) (*Result, error) {
	t.Helper()
	c := clk.client(fb.srv.URL + "/")
	code, err := c.Start(context.Background(), Request{MachineID: strings.Repeat("a", 64), MachineSecret: strings.Repeat("s", 43), Name: "My Mac", OS: "darwin", Arch: "arm64", CLIVersion: "0.5.0"})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	return c.Wait(context.Background(), code)
}

func TestApprovedAfterPending(t *testing.T) {
	fb := newFakeBackend(t)
	fb.answers = []func(http.ResponseWriter){
		status("pending", nil),
		status("approved", map[string]any{"token": "pat", "host": map[string]any{"id": 312, "name": "My Mac"}, "reused": true}),
	}
	clk := &fakeClock{now: time.Unix(0, 0)}
	res, err := startAndWait(t, fb, clk)
	if err != nil {
		t.Fatal(err)
	}
	if res.Token != "pat" || res.Host.ID != 312 || res.Host.Name != "My Mac" || !res.Reused {
		t.Fatalf("result = %+v", res)
	}
	if fb.started["machine_id"] != strings.Repeat("a", 64) || fb.started["machine_secret"] != strings.Repeat("s", 43) || fb.started["name"] != "My Mac" ||
		fb.started["os"] != "darwin" || fb.started["arch"] != "arm64" || fb.started["cli_version"] != "0.5.0" {
		t.Fatalf("start body = %v", fb.started)
	}
	if len(fb.polls) != 2 || fb.polls[0]["device_code"] != "secret-dc" {
		t.Fatalf("polls = %v", fb.polls)
	}
	for _, d := range clk.sleeps {
		if d != 3*time.Second {
			t.Fatalf("poll interval = %v, want the backend's 3s", d)
		}
	}
}

func TestSlowDownAnd429StretchInterval(t *testing.T) {
	fb := newFakeBackend(t)
	fb.answers = []func(http.ResponseWriter){
		status("pending", map[string]any{"slow_down": true}),
		httpStatus(http.StatusTooManyRequests),
		status("approved", map[string]any{"token": "pat", "host": map[string]any{"id": 1, "name": "x"}}),
	}
	clk := &fakeClock{now: time.Unix(0, 0)}
	if _, err := startAndWait(t, fb, clk); err != nil {
		t.Fatal(err)
	}
	want := []time.Duration{3 * time.Second, 8 * time.Second, 13 * time.Second}
	if len(clk.sleeps) != len(want) {
		t.Fatalf("sleeps = %v", clk.sleeps)
	}
	for i := range want {
		if clk.sleeps[i] != want[i] {
			t.Fatalf("sleeps = %v, want %v", clk.sleeps, want)
		}
	}
}

func TestDeniedAndExpired(t *testing.T) {
	for st, want := range map[string]error{"denied": ErrDenied, "expired": ErrExpired} {
		fb := newFakeBackend(t)
		fb.answers = []func(http.ResponseWriter){status(st, nil)}
		_, err := startAndWait(t, fb, &fakeClock{now: time.Unix(0, 0)})
		if !errors.Is(err, want) {
			t.Fatalf("%s: err = %v", st, err)
		}
	}
}

func TestGivesUpAtExpiryThroughBackendErrors(t *testing.T) {
	fb := newFakeBackend(t)
	fb.answers = []func(http.ResponseWriter){httpStatus(http.StatusBadGateway)}
	clk := &fakeClock{now: time.Unix(0, 0)}
	_, err := startAndWait(t, fb, clk)
	if !errors.Is(err, ErrExpired) || !strings.Contains(err.Error(), "502") {
		t.Fatalf("err = %v", err)
	}
	// 600s at 3s each: ~200 polls, then stop -- not forever.
	if n := len(fb.polls); n < 190 || n > 200 {
		t.Fatalf("%d polls before giving up", n)
	}
}

func TestCancelStopsWaiting(t *testing.T) {
	fb := newFakeBackend(t)
	fb.answers = []func(http.ResponseWriter){status("pending", nil)}
	c := (&fakeClock{now: time.Unix(0, 0)}).client(fb.srv.URL)
	code, err := c.Start(context.Background(), Request{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Wait(ctx, code); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
}

func TestStartErrors(t *testing.T) {
	cases := map[string]struct {
		res  func(w http.ResponseWriter)
		want string
	}{
		"old backend": {httpStatus(http.StatusNotFound), "does not support browser login"},
		"throttled":   {httpStatus(http.StatusTooManyRequests), "too many login attempts"},
		"bad url": {func(w http.ResponseWriter) {
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"device_code": "d", "user_code": "u", "verification_url": "file:///etc/passwd"})
		}, "non-web verification URL"},
		"validation": {func(w http.ResponseWriter) {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"detail": "bad machine_id"})
		}, "bad machine_id"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			fb := newFakeBackend(t)
			fb.startRes = c.res
			_, err := (&Client{BaseURL: fb.srv.URL}).Start(context.Background(), Request{})
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
		})
	}
}

func TestBrowserCommand(t *testing.T) {
	u := "https://app.clux.space/connect?code=ABCD-EFGH"
	if got := BrowserCommand("darwin", u); strings.Join(got, " ") != "open "+u {
		t.Fatal(got)
	}
	if got := BrowserCommand("linux", u); strings.Join(got, " ") != "xdg-open "+u {
		t.Fatal(got)
	}
	if got := BrowserCommand("windows", u); strings.Join(got, " ") != "rundll32 url.dll,FileProtocolHandler "+u {
		t.Fatal(got)
	}
	if OpenBrowser("javascript:alert(1)") == nil {
		t.Fatal("non-web URLs must never reach the opener")
	}
}
