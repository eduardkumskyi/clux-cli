package dialproxy

import (
	"context"
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
