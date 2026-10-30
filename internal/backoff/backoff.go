// Package backoff computes reconnect delays: the first retry after a
// healthy session is immediate (a blip should cost nothing), then delays
// grow exponentially with jitter up to a cap, so a long outage (DNS down,
// laptop offline) neither hammers the network nor waits needlessly long
// once it's back.
package backoff

import (
	"math/rand"
	"sync"
	"time"
)

// Policy is a reconnect backoff state machine. Not safe for concurrent use.
type Policy struct {
	Base    time.Duration // first non-zero delay (default 1s)
	Max     time.Duration // cap (default 30s)
	Jitter  float64       // +/- fraction of the delay (default 0.2)
	Healthy time.Duration // a session this long resets the policy (default 60s)

	attempt int
	rnd     *rand.Rand
	once    sync.Once
}

func (p *Policy) init() {
	p.once.Do(func() {
		if p.Base <= 0 {
			p.Base = time.Second
		}
		if p.Max <= 0 {
			p.Max = 30 * time.Second
		}
		if p.Jitter <= 0 {
			p.Jitter = 0.2
		}
		if p.Healthy <= 0 {
			p.Healthy = 60 * time.Second
		}
		if p.rnd == nil {
			p.rnd = rand.New(rand.NewSource(time.Now().UnixNano()))
		}
	})
}

// SessionEnded records that a connection attempt or session ended after
// lasting `lived` and returns how long to wait before the next attempt.
// immediate=true (e.g. after sleep/wake) skips the wait once without
// resetting the growth.
func (p *Policy) SessionEnded(lived time.Duration, immediate bool) time.Duration {
	p.init()
	if lived >= p.Healthy {
		p.attempt = 0
	}
	if immediate {
		return 0
	}
	n := p.attempt
	p.attempt++
	if n == 0 {
		return 0
	}
	d := p.Base << (n - 1)
	if d <= 0 || d > p.Max {
		d = p.Max
	}
	j := (p.rnd.Float64()*2 - 1) * p.Jitter * float64(d)
	d += time.Duration(j)
	if d > p.Max {
		d = p.Max
	}
	if d < 0 {
		d = 0
	}
	return d
}

// Attempt is the number of consecutive failed attempts recorded so far.
func (p *Policy) Attempt() int { return p.attempt }

// Reset forgets past failures.
func (p *Policy) Reset() { p.attempt = 0 }
