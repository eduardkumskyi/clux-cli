// Package logx is a tiny line logger for `clux host start`: every line is
// timestamped, and a run of identical messages (the same reconnect error
// every few seconds during an outage) collapses into one line plus a
// "(repeated N×)" summary when something different happens.
package logx

import (
	"fmt"
	"io"
	"sync"
	"time"
)

// Logger is safe for concurrent use.
type Logger struct {
	mu   sync.Mutex
	w    io.Writer
	now  func() time.Time
	last string
	reps int
}

func New(w io.Writer) *Logger { return &Logger{w: w, now: time.Now} }

// WithClock replaces the time source (tests).
func (l *Logger) WithClock(now func() time.Time) *Logger { l.now = now; return l }

func (l *Logger) stamp() string { return l.now().Format("2006-01-02 15:04:05") }

func (l *Logger) flushLocked() {
	if l.reps > 0 {
		fmt.Fprintf(l.w, "%s   (previous message repeated %d×)\n", l.stamp(), l.reps)
	}
	l.reps = 0
}

// Printf always prints (after flushing a pending repeat count).
func (l *Logger) Printf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	l.mu.Lock()
	defer l.mu.Unlock()
	l.flushLocked()
	l.last = ""
	fmt.Fprintf(l.w, "%s %s\n", l.stamp(), msg)
}

// Repeatable prints msg unless it equals the previous Repeatable message, in
// which case it is only counted.
func (l *Logger) Repeatable(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	l.mu.Lock()
	defer l.mu.Unlock()
	if msg == l.last {
		l.reps++
		return
	}
	l.flushLocked()
	l.last = msg
	fmt.Fprintf(l.w, "%s %s\n", l.stamp(), msg)
}

// Flush prints any pending repeat count.
func (l *Logger) Flush() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.flushLocked()
}
