//go:build darwin

package native

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// readRootFile reads a regular file that root owns and only root can write,
// from a directory (RunDir) with the same property.
func readRootFile(path string) ([]byte, error) {
	if err := checkRootDir(filepath.Dir(path)); err != nil {
		return nil, fmt.Errorf("untrusted status directory: %w", err)
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok || !st.Mode().IsRegular() || !containsInt(trustedUIDs, int(sys.Uid)) || st.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("untrusted status file %s", path)
	}
	return io.ReadAll(io.LimitReader(f, 1<<20))
}
