package logx

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixed() time.Time { return time.Date(2026, 10, 30, 15, 43, 52, 0, time.UTC) }

func TestRepeatsCollapse(t *testing.T) {
	var b bytes.Buffer
	l := New(&b).WithClock(fixed)
	for i := 0; i < 25; i++ {
		l.Repeatable("tunnel down: dial tcp: lookup api.clux.space: no such host")
	}
	l.Printf("reconnected after 2m")
	out := b.String()
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 3 {
		t.Fatalf("want 3 lines, got %d:\n%s", len(lines), out)
	}
	if !strings.Contains(lines[1], "repeated 24×") {
		t.Fatalf("missing repeat summary: %q", lines[1])
	}
	if !strings.HasPrefix(lines[0], "2026-10-30 15:43:52 ") {
		t.Fatalf("missing timestamp: %q", lines[0])
	}
}

func TestDifferentMessagesAllPrint(t *testing.T) {
	var b bytes.Buffer
	l := New(&b).WithClock(fixed)
	l.Repeatable("a")
	l.Repeatable("b")
	l.Repeatable("a")
	if n := strings.Count(b.String(), "\n"); n != 3 {
		t.Fatalf("want 3 lines, got %d", n)
	}
}

func TestRotatingFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "logs", "host.log")
	f, err := OpenRotating(p, 100, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	line := []byte(strings.Repeat("x", 39) + "\n") // 40 bytes
	for i := 0; i < 10; i++ {
		if _, err := f.Write(line); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"host.log", "host.log.1", "host.log.2"} {
		st, err := os.Stat(filepath.Join(dir, "logs", name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if st.Size() > 100 {
			t.Fatalf("%s too big: %d", name, st.Size())
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "logs", "host.log.3")); err == nil {
		t.Fatal("kept more files than Keep")
	}
}
