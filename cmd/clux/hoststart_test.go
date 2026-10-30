package main

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/eduardkumskyi/clux-cli/internal/logx"
	"github.com/eduardkumskyi/clux-cli/internal/netwatch"
	"github.com/eduardkumskyi/clux-cli/internal/tunnel"
)

func TestIsLoopback(t *testing.T) {
	if !isLoopback(&net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 5000}) {
		t.Fatal("127.0.0.1 is loopback")
	}
	if !isLoopback(&net.TCPAddr{IP: net.ParseIP("::1"), Port: 5000}) {
		t.Fatal("::1 is loopback")
	}
	if isLoopback(&net.TCPAddr{IP: net.ParseIP("192.168.1.34"), Port: 5000}) {
		t.Fatal("LAN address is not loopback")
	}
}

func TestDispatchWakesPendingWaitWhenDisconnected(t *testing.T) {
	h := newHostLoop(nil, time.Second, logx.New(&bytes.Buffer{}))
	ev := make(chan netwatch.Event, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go h.dispatch(ctx, ev)
	done := make(chan bool, 1)
	go func() { done <- h.wait(ctx, time.Minute) }()
	time.Sleep(10 * time.Millisecond)
	ev <- netwatch.Event{Kind: netwatch.NetworkChanged}
	select {
	case ok := <-done:
		if !ok {
			t.Fatal("wait reported cancel")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("network change did not end the reconnect wait")
	}
}

func TestStaleWakeDrainedOnNewSession(t *testing.T) {
	h := newHostLoop(nil, time.Second, logx.New(&bytes.Buffer{}))
	h.wake <- struct{}{} // event that arrived while dialing
	h.setCurrent(nil)    // still dialing: kept
	if len(h.wake) != 1 {
		t.Fatal("wake dropped while no session")
	}
	h.setCurrent(&tunnel.Session{})
	if len(h.wake) != 0 {
		t.Fatal("stale wake survived a fresh session")
	}
}

func TestSummarizeDropsEphemeralPort(t *testing.T) {
	a := summarize(errString("read tcp 192.168.1.34:57584->172.67.204.116:443: i/o timeout"))
	b := summarize(errString("read tcp 192.168.1.34:57586->172.67.204.116:443: i/o timeout"))
	if a != b {
		t.Fatalf("%q != %q", a, b)
	}
}

type errString string

func (e errString) Error() string { return string(e) }
