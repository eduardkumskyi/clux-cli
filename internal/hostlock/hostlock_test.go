package hostlock

import (
	"os"
	"testing"
)

func TestSecondAcquireFailsWithPID(t *testing.T) {
	dir := t.TempDir()
	l, err := Acquire(dir)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Acquire(dir)
	if !IsHeld(err) {
		t.Fatalf("want ErrHeld, got %v", err)
	}
	if h := err.(*ErrHeld); h.PID != os.Getpid() {
		t.Fatalf("pid %d", h.PID)
	}
	l.Release()
	l2, err := Acquire(dir)
	if err != nil {
		t.Fatalf("re-acquire after release: %v", err)
	}
	l2.Release()
}
