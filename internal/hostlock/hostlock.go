// Package hostlock guarantees a single `clux host start` per state
// directory. Two agents running with the same token keep replacing each
// other's tunnel on the backend (each register supersedes the other), which
// looks like an endlessly flapping connection; refusing to start the second
// one turns that into a clear message instead.
package hostlock

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ErrHeld is returned when another live process holds the lock.
type ErrHeld struct{ PID int }

func (e *ErrHeld) Error() string {
	if e.PID > 0 {
		return fmt.Sprintf("another `clux host start` is already running (pid %d); stop it first", e.PID)
	}
	return "another `clux host start` is already running; stop it first"
}

// IsHeld reports whether err means the lock is held by someone else.
func IsHeld(err error) bool {
	var h *ErrHeld
	return errors.As(err, &h)
}

// Lock is a held lock; Release it on exit (the OS also drops it when the
// process dies, so a crash never leaves a stale lock behind).
type Lock struct {
	f    *os.File
	path string
}

// Acquire takes the lock file dir/host.lock.
func Acquire(dir string) (*Lock, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("creating %s: %w", dir, err)
	}
	p := filepath.Join(dir, "host.lock")
	f, err := os.OpenFile(p, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("opening lock file: %w", err)
	}
	if err := tryLock(f); err != nil {
		pid := readPID(f)
		f.Close()
		if errors.Is(err, errWouldBlock) {
			return nil, &ErrHeld{PID: pid}
		}
		return nil, fmt.Errorf("locking %s: %w", p, err)
	}
	_ = f.Truncate(0)
	_, _ = f.WriteAt([]byte(strconv.Itoa(os.Getpid())+"\n"), 0)
	return &Lock{f: f, path: p}, nil
}

// Release drops the lock.
func (l *Lock) Release() {
	if l == nil || l.f == nil {
		return
	}
	_ = l.f.Truncate(0)
	unlock(l.f)
	_ = l.f.Close()
	l.f = nil
}

func readPID(f *os.File) int {
	buf := make([]byte, 32)
	n, _ := f.ReadAt(buf, 0)
	pid, _ := strconv.Atoi(strings.TrimSpace(string(buf[:n])))
	return pid
}

var errWouldBlock = errors.New("lock held")
