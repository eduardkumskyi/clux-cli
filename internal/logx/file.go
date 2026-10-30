package logx

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// RotatingFile is an append-only log file that rolls over at MaxBytes,
// keeping Keep old files (host.log.1 ... host.log.N), so a long-running
// agent leaves a bounded, after-the-fact diagnosable trail.
type RotatingFile struct {
	Path     string
	MaxBytes int64
	Keep     int

	mu   sync.Mutex
	f    *os.File
	size int64
}

// OpenRotating opens (creating dirs) path for appending.
func OpenRotating(path string, maxBytes int64, keep int) (*RotatingFile, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	r := &RotatingFile{Path: path, MaxBytes: maxBytes, Keep: keep}
	if err := r.open(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *RotatingFile) open() error {
	f, err := os.OpenFile(r.Path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	r.f, r.size = f, st.Size()
	return nil
}

func (r *RotatingFile) rotate() error {
	if r.f != nil {
		r.f.Close()
		r.f = nil
	}
	for i := r.Keep - 1; i >= 1; i-- {
		_ = os.Rename(fmt.Sprintf("%s.%d", r.Path, i), fmt.Sprintf("%s.%d", r.Path, i+1))
	}
	if r.Keep > 0 {
		_ = os.Rename(r.Path, r.Path+".1")
	} else {
		_ = os.Remove(r.Path)
	}
	return r.open()
}

// Write implements io.Writer. Errors are returned but never fatal for the
// caller's logging (stderr keeps working through io.MultiWriter callers
// that ignore them).
func (r *RotatingFile) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		if err := r.open(); err != nil {
			return 0, err
		}
	}
	if r.MaxBytes > 0 && r.size+int64(len(p)) > r.MaxBytes && r.size > 0 {
		if err := r.rotate(); err != nil {
			return 0, err
		}
	}
	n, err := r.f.Write(p)
	r.size += int64(n)
	return n, err
}

// Close closes the current file.
func (r *RotatingFile) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		return nil
	}
	err := r.f.Close()
	r.f = nil
	return err
}

// Tee writes to every writer, ignoring errors from all but the first (a
// broken log file must never break stderr logging).
type Tee struct {
	Primary   interface{ Write([]byte) (int, error) }
	Secondary []interface{ Write([]byte) (int, error) }
}

func (t Tee) Write(p []byte) (int, error) {
	for _, w := range t.Secondary {
		_, _ = w.Write(p)
	}
	return t.Primary.Write(p)
}
