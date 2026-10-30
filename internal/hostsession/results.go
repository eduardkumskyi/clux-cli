package hostsession

import (
	"sync"
	"time"
)

// Sender is the slice of tunnel.Session the result courier needs.
type Sender interface {
	TrySend(frame any) bool
}

// Results delivers lifecycle command results across tunnel sessions.
//
// A docker command can outlive the tunnel session it arrived on (it runs
// under the process context, see Handler.cmdCtx). Its result must still
// reach the backend, so Results is process-wide: a result goes to the
// session that is current when it is ready; if there is none, or the
// session it was queued on died shortly after (the frame may never have
// left the socket), it is kept and re-sent after the next register. The
// backend treats results idempotently by correlation_id, so a duplicate is
// harmless; one it no longer waits for is ignored.
type Results struct {
	mu      sync.Mutex
	cur     Sender
	pending []pendingResult
	sent    []sentResult

	// Window: results queued this long before a session ended are re-sent.
	Window time.Duration
	// TTL: a result older than this is dropped (the backend gave up long ago).
	TTL time.Duration
	// Max bounds memory.
	Max int
	now func() time.Time
}

type pendingResult struct {
	frame map[string]any
	at    time.Time
}

type sentResult struct {
	frame map[string]any
	via   Sender
	at    time.Time
}

// NewResults returns a courier with sane defaults.
func NewResults() *Results {
	return &Results{Window: 15 * time.Second, TTL: 10 * time.Minute, Max: 64, now: time.Now}
}

// Deliver sends a result now if possible, else keeps it for the next session.
func (r *Results) Deliver(frame map[string]any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	if r.cur != nil && r.cur.TrySend(frame) {
		r.sent = append(r.sent, sentResult{frame: frame, via: r.cur, at: now})
		r.trimLocked(now)
		return
	}
	r.pending = append(r.pending, pendingResult{frame: frame, at: now})
	r.trimLocked(now)
}

// Attach makes s the current session and flushes kept results to it.
// Returns how many were re-sent.
func (r *Results) Attach(s Sender) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cur = s
	now := r.now()
	r.trimLocked(now)
	keep := r.pending[:0]
	n := 0
	for _, p := range r.pending {
		if s.TrySend(p.frame) {
			r.sent = append(r.sent, sentResult{frame: p.frame, via: s, at: now})
			n++
		} else {
			keep = append(keep, p)
		}
	}
	r.pending = keep
	return n
}

// Detach marks s as gone. Results queued on it within Window before now are
// moved back to pending (they may not have reached the backend).
func (r *Results) Detach(s Sender) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cur == s {
		r.cur = nil
	}
	now := r.now()
	keep := r.sent[:0]
	for _, x := range r.sent {
		if x.via == s {
			if now.Sub(x.at) <= r.Window {
				r.pending = append(r.pending, pendingResult{frame: x.frame, at: x.at})
			}
			continue
		}
		keep = append(keep, x)
	}
	r.sent = keep
	r.trimLocked(now)
}

// Pending is the number of results waiting for a session.
func (r *Results) Pending() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.pending)
}

func (r *Results) trimLocked(now time.Time) {
	keep := r.pending[:0]
	for _, p := range r.pending {
		if now.Sub(p.at) <= r.TTL {
			keep = append(keep, p)
		}
	}
	r.pending = keep
	if len(r.pending) > r.Max {
		r.pending = r.pending[len(r.pending)-r.Max:]
	}
	sk := r.sent[:0]
	for _, x := range r.sent {
		if now.Sub(x.at) <= r.Window {
			sk = append(sk, x)
		}
	}
	r.sent = sk
}
