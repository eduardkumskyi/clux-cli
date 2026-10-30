package tunnel

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/eduardkumskyi/clux-cli/internal/sysinfo"
)

type nopHandler struct{}

func (nopHandler) HandleCommand(context.Context, string, map[string]any) {}
func (nopHandler) HandleDialOpen(context.Context, string, int, string)   {}
func (nopHandler) HandleDialData(string, string)                         {}
func (nopHandler) HandleDialClose(string)                                {}

// fakeBackend registers the CLI, then behaves per mode.
type fakeBackend struct {
	mode      string // "silent" (half-open: stop reading, never pong), "alive", "restart", "reject_outdated"
	srv       *httptest.Server
	mu        sync.Mutex
	conn      *websocket.Conn
	closeCode int
}

func newFakeBackend(t *testing.T, mode string) *fakeBackend {
	t.Helper()
	fb := &fakeBackend{mode: mode}
	up := websocket.Upgrader{}
	fb.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		fb.mu.Lock()
		fb.conn = c
		fb.mu.Unlock()
		var reg map[string]any
		if err := c.ReadJSON(&reg); err != nil {
			return
		}
		if fb.mode == "reject_unknown" {
			_ = c.WriteJSON(map[string]any{"type": "register_rejected", "reason": "maintenance"})
			return
		}
		if fb.mode == "reject_outdated" {
			_ = c.WriteJSON(map[string]any{"type": "register_rejected", "reason": "cli_outdated", "min_version": "9.9.9"})
			_ = c.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(CloseCLIOutdated, ""))
			return
		}
		_ = c.WriteJSON(map[string]any{"type": "register_ack", "host_id": 6, "name": "test"})
		switch fb.mode {
		case "silent":
			// Never read again: gorilla only answers pings while reading, so
			// the client's pings go unanswered -- a half-open connection.
			<-r.Context().Done()
		case "supersede":
			time.Sleep(50 * time.Millisecond)
			_ = c.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(CloseSuperseded, ""))
			<-r.Context().Done()
		case "record_close":
			for {
				if _, _, err := c.ReadMessage(); err != nil {
					var ce *websocket.CloseError
					if errors.As(err, &ce) {
						fb.mu.Lock()
						fb.closeCode = ce.Code
						fb.mu.Unlock()
					}
					return
				}
			}
		case "restart":
			time.Sleep(50 * time.Millisecond)
			_ = c.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseServiceRestart, ""))
			<-r.Context().Done()
		default: // alive: keep reading so pings are answered
			for {
				if _, _, err := c.ReadMessage(); err != nil {
					return
				}
			}
		}
	}))
	t.Cleanup(fb.srv.Close)
	return fb
}

func dialFake(t *testing.T, fb *fakeBackend) *Session {
	t.Helper()
	sess, err := Dial(context.Background(), fb.srv.URL, "tok", "0.3.0", sysinfo.Info{})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	sess.PingInterval = 50 * time.Millisecond
	sess.ReadTimeout = 300 * time.Millisecond
	sess.WriteTimeout = 200 * time.Millisecond
	return sess
}

func TestRunDetectsHalfOpenConnection(t *testing.T) {
	fb := newFakeBackend(t, "silent")
	sess := dialFake(t, fb)
	start := time.Now()
	err := sess.Run(context.Background(), nopHandler{})
	if err == nil || !strings.Contains(err.Error(), "silent") {
		t.Fatalf("want silence error, got %v", err)
	}
	if el := time.Since(start); el > 2*time.Second {
		t.Fatalf("detection took %s, want ~ReadTimeout", el)
	}
}

func TestRunStaysUpWhileBackendAnswersPings(t *testing.T) {
	fb := newFakeBackend(t, "alive")
	sess := dialFake(t, fb)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second) // > 3x ReadTimeout
	defer cancel()
	if err := sess.Run(ctx, nopHandler{}); err != nil {
		t.Fatalf("Run on healthy connection: %v", err)
	}
}

func TestRunReportsBackendRestart(t *testing.T) {
	fb := newFakeBackend(t, "restart")
	sess := dialFake(t, fb)
	err := sess.Run(context.Background(), nopHandler{})
	if err == nil || !strings.Contains(err.Error(), "restarting") {
		t.Fatalf("want restart error, got %v", err)
	}
	if IsFatal(err) {
		t.Fatal("restart must not be fatal")
	}
}

func TestKickReturnsReconnectRequested(t *testing.T) {
	fb := newFakeBackend(t, "alive")
	sess := dialFake(t, fb)
	go func() {
		time.Sleep(50 * time.Millisecond)
		sess.Kick(errors.New("woke up"))
	}()
	err := sess.Run(context.Background(), nopHandler{})
	if !errors.Is(err, ErrReconnectRequested) {
		t.Fatalf("want ErrReconnectRequested, got %v", err)
	}
}

func TestSendNeverBlocksAfterRunReturns(t *testing.T) {
	fb := newFakeBackend(t, "silent")
	sess := dialFake(t, fb)
	_ = sess.Run(context.Background(), nopHandler{})
	done := make(chan struct{})
	go func() {
		for i := 0; i < outboxBuffer*2; i++ {
			sess.Send(map[string]any{"type": "dial.data"})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Send blocked after the session ended (goroutine leak)")
	}
	if sess.TrySend(map[string]any{}) {
		t.Fatal("TrySend must report false after Run returned")
	}
}

func TestRegisterRejectedOutdatedIsFatal(t *testing.T) {
	fb := newFakeBackend(t, "reject_outdated")
	_, err := Dial(context.Background(), fb.srv.URL, "tok", "0.1.0", sysinfo.Info{})
	if !IsFatal(err) {
		t.Fatalf("want fatal error, got %v", err)
	}
}

func TestSupersededIsTypedAndNotFatal(t *testing.T) {
	fb := newFakeBackend(t, "supersede")
	sess := dialFake(t, fb)
	err := sess.Run(context.Background(), nopHandler{})
	if !errors.Is(err, ErrSuperseded) || IsFatal(err) {
		t.Fatalf("want non-fatal ErrSuperseded, got %v", err)
	}
}

func TestUnknownRegisterRejectionRetries(t *testing.T) {
	fb := newFakeBackend(t, "reject_unknown")
	_, err := Dial(context.Background(), fb.srv.URL, "tok", "0.3.0", sysinfo.Info{})
	if err == nil || IsFatal(err) {
		t.Fatalf("unknown rejection must be retryable, got %v", err)
	}
}

func TestRunSendsGracefulCloseOnExit(t *testing.T) {
	fb := newFakeBackend(t, "record_close")
	sess := dialFake(t, fb)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(50 * time.Millisecond); cancel() }()
	_ = sess.Run(ctx, nopHandler{})
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		fb.mu.Lock()
		code := fb.closeCode
		fb.mu.Unlock()
		if code == websocket.CloseNormalClosure {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("backend never received a normal close frame")
}

func TestProbeTimeoutReportsProbeWindow(t *testing.T) {
	fb := newFakeBackend(t, "silent")
	sess := dialFake(t, fb)
	sess.ReadTimeout = 10 * time.Second // only the probe can end this run quickly
	sess.PingInterval = time.Hour
	go func() {
		time.Sleep(30 * time.Millisecond)
		sess.Probe(100 * time.Millisecond)
	}()
	err := sess.Run(context.Background(), nopHandler{})
	if err == nil || !strings.Contains(err.Error(), "probe within 100ms") {
		t.Fatalf("want probe timeout error, got %v", err)
	}
}
