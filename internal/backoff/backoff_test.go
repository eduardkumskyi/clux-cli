package backoff

import (
	"math/rand"
	"testing"
	"time"
)

func TestSequenceAndCap(t *testing.T) {
	p := &Policy{rnd: rand.New(rand.NewSource(1))}
	if d := p.SessionEnded(0, false); d != 0 {
		t.Fatalf("first retry must be immediate, got %s", d)
	}
	wants := []time.Duration{1, 2, 4, 8, 16, 30, 30, 30}
	for i, w := range wants {
		w *= time.Second
		d := p.SessionEnded(0, false)
		lo, hi := time.Duration(float64(w)*0.8), time.Duration(float64(w)*1.2)
		if hi > 30*time.Second {
			hi = 30 * time.Second
		}
		if d < lo || d > hi {
			t.Fatalf("attempt %d: %s not within [%s,%s]", i+2, d, lo, hi)
		}
	}
}

func TestHealthySessionResets(t *testing.T) {
	p := &Policy{rnd: rand.New(rand.NewSource(2))}
	for i := 0; i < 6; i++ {
		p.SessionEnded(0, false)
	}
	if d := p.SessionEnded(2*time.Minute, false); d != 0 {
		t.Fatalf("after a healthy session the retry must be immediate, got %s", d)
	}
	if d := p.SessionEnded(0, false); d > 1200*time.Millisecond {
		t.Fatalf("growth must restart from Base, got %s", d)
	}
}

func TestImmediateSkipsWaitWithoutGrowth(t *testing.T) {
	p := &Policy{rnd: rand.New(rand.NewSource(3))}
	p.SessionEnded(0, false)
	p.SessionEnded(0, false)
	before := p.Attempt()
	if d := p.SessionEnded(0, true); d != 0 {
		t.Fatalf("immediate: %s", d)
	}
	if p.Attempt() != before {
		t.Fatal("immediate must not grow the backoff")
	}
}

func TestJitterSpreads(t *testing.T) {
	seen := map[time.Duration]bool{}
	for seed := int64(0); seed < 20; seed++ {
		p := &Policy{rnd: rand.New(rand.NewSource(seed))}
		p.SessionEnded(0, false)
		p.SessionEnded(0, false)
		p.SessionEnded(0, false)
		seen[p.SessionEnded(0, false)] = true
	}
	if len(seen) < 5 {
		t.Fatalf("jitter too uniform: %d distinct delays", len(seen))
	}
}
