package dialproxy

import (
	"context"
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// sidecarStub accepts one WS and reports when the client side closed it.
func sidecarStub(t *testing.T) (port int, closed <-chan struct{}) {
	t.Helper()
	ch := make(chan struct{})
	up := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		for {
			if _, _, err := c.ReadMessage(); err != nil {
				close(ch)
				return
			}
		}
	}))
	t.Cleanup(srv.Close)
	_, p, _ := net.SplitHostPort(srv.Listener.Addr().String())
	port, _ = strconv.Atoi(p)
	return port, ch
}

type frames struct {
	mu  sync.Mutex
	got []map[string]any
}

func (f *frames) send(frame any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.got = append(f.got, frame.(map[string]any))
}

func TestSessionEndClosesLocalSidecarConnection(t *testing.T) {
	port, closed := sidecarStub(t)
	r := NewRegistry()
	ctx, cancel := context.WithCancel(context.Background())
	var f frames
	r.Open(ctx, "s1", port, "secret", f.send)
	if r.Len() != 1 {
		t.Fatalf("stream not registered: %+v", f.got)
	}
	cancel() // tunnel session ended
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("local sidecar connection left open after the session ended")
	}
}

func TestCloseAll(t *testing.T) {
	p1, c1 := sidecarStub(t)
	p2, c2 := sidecarStub(t)
	r := NewRegistry()
	var f frames
	r.Open(context.Background(), "a", p1, "", f.send)
	r.Open(context.Background(), "b", p2, "", f.send)
	r.CloseAll()
	for _, c := range []<-chan struct{}{c1, c2} {
		select {
		case <-c:
		case <-time.After(2 * time.Second):
			t.Fatal("stream not closed")
		}
	}
	if r.Len() != 0 {
		t.Fatalf("registry not empty: %d", r.Len())
	}
}

// stuckSidecar accepts a WS but never reads, so writes back up.
func stuckSidecar(t *testing.T) int {
	t.Helper()
	up := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		<-r.Context().Done()
		c.Close()
	}))
	t.Cleanup(srv.Close)
	_, p, _ := net.SplitHostPort(srv.Listener.Addr().String())
	port, _ := strconv.Atoi(p)
	return port
}

func TestDataNeverBlocksTunnelReaderWhenStreamIsStuck(t *testing.T) {
	port := stuckSidecar(t)
	r := NewRegistry()
	var f frames
	r.Open(context.Background(), "slow", port, "", f.send)
	big := base64Payload(1 << 20) // 1 MiB messages fill socket buffers fast
	done := make(chan struct{})
	go func() {
		for i := 0; i < 500; i++ {
			r.Data("slow", big)
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Data blocked the caller (the tunnel reader)")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	sawClose := false
	for _, fr := range f.got {
		if fr["type"] == "dial.close" && fr["stream_id"] == "slow" {
			sawClose = true
		}
	}
	if !sawClose {
		t.Fatal("overflowing stream was not closed with dial.close")
	}
}

func base64Payload(n int) string {
	return base64.StdEncoding.EncodeToString(make([]byte, n))
}
