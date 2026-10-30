package hostsession

import (
	"testing"
	"time"
)

type fakeSender struct {
	alive bool
	got   []map[string]any
}

func (f *fakeSender) TrySend(frame any) bool {
	if !f.alive {
		return false
	}
	f.got = append(f.got, frame.(map[string]any))
	return true
}

func TestResultWithoutSessionIsSentOnNextRegister(t *testing.T) {
	r := NewResults()
	r.Deliver(map[string]any{"correlation_id": "c1", "ok": true})
	if r.Pending() != 1 {
		t.Fatal("result should be kept")
	}
	s := &fakeSender{alive: true}
	if n := r.Attach(s); n != 1 || len(s.got) != 1 {
		t.Fatalf("re-sent %d", n)
	}
	if r.Pending() != 0 {
		t.Fatal("pending not cleared")
	}
}

func TestResultQueuedJustBeforeDropIsResent(t *testing.T) {
	now := time.Now()
	r := NewResults()
	r.now = func() time.Time { return now }
	old := &fakeSender{alive: true}
	r.Attach(old)
	r.Deliver(map[string]any{"correlation_id": "c2"})
	old.alive = false
	now = now.Add(3 * time.Second) // session died 3s later: frame may not have left
	r.Detach(old)
	next := &fakeSender{alive: true}
	if n := r.Attach(next); n != 1 {
		t.Fatalf("want 1 re-sent, got %d", n)
	}
}

func TestOldDeliveredResultsAreNotResent(t *testing.T) {
	now := time.Now()
	r := NewResults()
	r.now = func() time.Time { return now }
	old := &fakeSender{alive: true}
	r.Attach(old)
	r.Deliver(map[string]any{"correlation_id": "c3"})
	now = now.Add(time.Minute) // long since written
	r.Detach(old)
	if n := r.Attach(&fakeSender{alive: true}); n != 0 {
		t.Fatalf("re-sent %d stale results", n)
	}
}

func TestExpiredResultsDropped(t *testing.T) {
	now := time.Now()
	r := NewResults()
	r.now = func() time.Time { return now }
	r.Deliver(map[string]any{"correlation_id": "c4"})
	now = now.Add(11 * time.Minute)
	if n := r.Attach(&fakeSender{alive: true}); n != 0 {
		t.Fatalf("re-sent expired result")
	}
}
