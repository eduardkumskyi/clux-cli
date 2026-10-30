// Package netwatch notices the two events that silently kill a laptop's
// tunnel long before TCP reports anything: the machine sleeping (lid
// closed) and the network changing under it (Wi-Fi <-> hotspot, VPN up or
// down, DHCP lease change).
//
// Sleep is detected by comparing wall-clock time with Go's monotonic clock:
// on macOS the monotonic clock stops while the machine sleeps, the wall
// clock does not, so after a wake the wall clock has jumped ahead of the
// monotonic one. A process that was merely starved (heavy load) shows a
// long monotonic gap too; both mean "the connection probably died while we
// weren't looking".
//
// Network changes are detected by polling the set of local unicast
// addresses. The caller decides what to do: if the tunnel's own local IP is
// gone the connection is certainly dead; otherwise it may have survived and
// only needs a quick probe.
package netwatch

import (
	"context"
	"net"
	"sort"
	"strings"
	"time"
)

// Event is one detected disruption.
type Event struct {
	Kind EventKind
	// Gap is how much time passed unnoticed (sleep/stall events).
	Gap time.Duration
	// Addrs is the new local address set (network events).
	Addrs []string
}

type EventKind int

const (
	// Woke: wall clock jumped ahead of the monotonic clock (machine slept)
	// or the ticker fired far too late (process stalled).
	Woke EventKind = iota + 1
	// NetworkChanged: the set of local unicast addresses changed.
	NetworkChanged
)

// Options tune the watcher; zero values pick defaults.
type Options struct {
	Interval  time.Duration // poll period (default 5s)
	Threshold time.Duration // unexplained gap that counts as a wake (default 10s)
	// Hooks for tests.
	Now   func() time.Time
	Addrs func() ([]string, error)
}

func (o *Options) defaults() {
	if o.Interval <= 0 {
		o.Interval = 5 * time.Second
	}
	if o.Threshold <= 0 {
		o.Threshold = 10 * time.Second
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Addrs == nil {
		o.Addrs = LocalAddrs
	}
}

// ClockJump reports how much longer than expected the interval between prev
// and now really was, combining both signals: wall time running ahead of
// monotonic time (sleep) and monotonic time running past the expected tick
// (stall). Zero means nothing unusual.
func ClockJump(prev, now time.Time, expected time.Duration) time.Duration {
	mono := now.Sub(prev)                   // uses monotonic readings when both have them
	wall := now.Round(0).Sub(prev.Round(0)) // Round(0) strips the monotonic reading
	return clockJump(mono, wall, expected)
}

func clockJump(mono, wall, expected time.Duration) time.Duration {
	gap := time.Duration(0)
	if d := wall - mono; d > gap {
		gap = d
	}
	if d := mono - expected; d > gap {
		gap = d
	}
	return gap
}

// Watch polls until ctx is done, sending events on the returned channel
// (buffered; events are dropped if the consumer is behind -- the next one
// will carry the current state anyway).
func Watch(ctx context.Context, opts Options) <-chan Event {
	opts.defaults()
	out := make(chan Event, 4)
	go func() {
		defer close(out)
		t := time.NewTicker(opts.Interval)
		defer t.Stop()
		prev := opts.Now()
		prevAddrs, _ := opts.Addrs()
		emit := func(e Event) {
			select {
			case out <- e:
			default:
			}
		}
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			now := opts.Now()
			if gap := ClockJump(prev, now, opts.Interval); gap >= opts.Threshold {
				emit(Event{Kind: Woke, Gap: gap})
			}
			prev = now
			if addrs, err := opts.Addrs(); err == nil {
				if !sameSet(addrs, prevAddrs) {
					emit(Event{Kind: NetworkChanged, Addrs: addrs})
				}
				prevAddrs = addrs
			}
		}
	}()
	return out
}

// LocalAddrs lists this machine's non-loopback, non-link-local unicast IPs.
func LocalAddrs() ([]string, error) {
	ifaceAddrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	var out []string
	for _, a := range ifaceAddrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipnet.IP
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			continue
		}
		out = append(out, ip.String())
	}
	sort.Strings(out)
	return out, nil
}

// HasIP reports whether addr's IP is one of addrs.
func HasIP(addrs []string, addr net.Addr) bool {
	host := addr.String()
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, a := range addrs {
		if other := net.ParseIP(a); other != nil && other.Equal(ip) {
			return true
		}
	}
	return false
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	as := append([]string(nil), a...)
	bs := append([]string(nil), b...)
	sort.Strings(as)
	sort.Strings(bs)
	for i := range as {
		if as[i] != bs[i] {
			return false
		}
	}
	return true
}
