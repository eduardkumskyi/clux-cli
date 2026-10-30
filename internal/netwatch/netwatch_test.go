package netwatch

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"
)

func TestClockJump(t *testing.T) {
	cases := []struct {
		name             string
		mono, wall, want time.Duration
	}{
		{"normal tick", 5 * time.Second, 5 * time.Second, 0},
		{"slept 10 minutes", 5 * time.Second, 10*time.Minute + 5*time.Second, 10 * time.Minute},
		{"process stalled 40s", 45 * time.Second, 45 * time.Second, 40 * time.Second},
		{"NTP step backwards", 5 * time.Second, -time.Minute, 0},
	}
	for _, c := range cases {
		if got := clockJump(c.mono, c.wall, 5*time.Second); got != c.want {
			t.Errorf("%s: got %s want %s", c.name, got, c.want)
		}
	}
	now := time.Now()
	if got := ClockJump(now, now.Add(5*time.Second), 5*time.Second); got != 0 {
		t.Errorf("real clock steady tick: got %s", got)
	}
}

func TestWatchEmitsWakeAndNetworkChange(t *testing.T) {
	var mu sync.Mutex
	base := time.Now().Round(0) // wall-only: Sub uses wall time
	cur := base
	addrs := []string{"192.168.1.34"}
	opts := Options{
		Interval:  10 * time.Millisecond,
		Threshold: time.Minute,
		Now: func() time.Time {
			mu.Lock()
			defer mu.Unlock()
			cur = cur.Add(10 * time.Millisecond)
			return cur
		},
		Addrs: func() ([]string, error) {
			mu.Lock()
			defer mu.Unlock()
			return append([]string(nil), addrs...), nil
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ev := Watch(ctx, opts)
	time.Sleep(50 * time.Millisecond) // let Watch take its baseline first

	mu.Lock()
	cur = cur.Add(5 * time.Minute) // lid closed for 5 minutes
	mu.Unlock()
	got := waitKind(t, ev, Woke)
	if got.Gap < 4*time.Minute {
		t.Fatalf("gap %s", got.Gap)
	}

	mu.Lock()
	addrs = []string{"172.30.4.3"} // switched to another network
	mu.Unlock()
	got = waitKind(t, ev, NetworkChanged)
	if len(got.Addrs) != 1 || got.Addrs[0] != "172.30.4.3" {
		t.Fatalf("addrs %v", got.Addrs)
	}
}

func waitKind(t *testing.T, ev <-chan Event, k EventKind) Event {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		select {
		case e := <-ev:
			if e.Kind == k {
				return e
			}
		case <-deadline:
			t.Fatalf("no event of kind %d", k)
		}
	}
}

func TestHasIP(t *testing.T) {
	addr := &net.TCPAddr{IP: net.ParseIP("192.168.1.34"), Port: 57584}
	if !HasIP([]string{"10.0.0.1", "192.168.1.34"}, addr) {
		t.Fatal("should find IP")
	}
	if HasIP([]string{"172.30.4.3"}, addr) {
		t.Fatal("IP gone")
	}
}
