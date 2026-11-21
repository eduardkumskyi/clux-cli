//go:build darwin

package native

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// Root-side filesystem primitives. The rule they enforce: root only creates,
// replaces or re-owns *entries of directories nobody but root can modify*,
// and it opens those entries without following symlinks, so a slot user (or
// the owner) can't redirect a root write, chown or chmod to some other file
// by planting a symlink or hard link. Anything inside a directory another
// user can write is left to that user (the slot supervisors populate their
// own homes) or is done with that user's privileges (runAs).

// ForeignOwnerError is returned when an existing entry is owned by someone
// root would not hand it to.
type ForeignOwnerError struct {
	Path string
	UID  int
	Want []int
}

func (e *ForeignOwnerError) Error() string {
	return fmt.Sprintf("refusing to use %s: owned by uid %d (expected one of %v)", e.Path, e.UID, e.Want)
}

// trustedDir resolves dir and checks that it and every ancestor is a real
// directory owned by root that only root can modify (group write is
// tolerated only for wheel and daemon, /private/var/run is root:daemon
// 0775). It returns the resolved path: callers must use it, not dir.
func trustedDir(dir string) (string, error) {
	r, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return "", err
	}
	for d := r; ; d = filepath.Dir(d) {
		if err := checkRootDir(d); err != nil {
			return "", err
		}
		if d == "/" {
			return r, nil
		}
	}
}

// trustedUIDs own trusted directories: root. Unit tests, which can't run as
// root, add their own uid.
var trustedUIDs = []int{0}

// lockUID:lockGID own quarantined and locked directories (root:wheel;
// tests, which can't run as root, use their own ids).
var lockUID, lockGID = 0, 0

func checkRootDir(d string) error {
	st, err := os.Lstat(d)
	if err != nil {
		return err
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	switch {
	case !ok:
		return fmt.Errorf("%s: no ownership info", d)
	case st.Mode()&os.ModeSymlink != 0 || !st.IsDir():
		return fmt.Errorf("%s is not a directory", d)
	case !containsInt(trustedUIDs, int(sys.Uid)):
		return fmt.Errorf("%s is owned by uid %d, not root", d, sys.Uid)
	case st.Mode().Perm()&0o002 != 0:
		return fmt.Errorf("%s is world-writable", d)
	case st.Mode().Perm()&0o020 != 0 && sys.Gid != 0 && sys.Gid != 1:
		return fmt.Errorf("%s is writable by group %d", d, sys.Gid)
	}
	return nil
}

// inTrustedDir splits path into its trusted (resolved) parent and the final
// entry name.
func inTrustedDir(path string) (string, error) {
	name := filepath.Base(path)
	if name == "." || name == ".." || name == "/" || strings.ContainsRune(name, 0) {
		return "", fmt.Errorf("invalid path %q", path)
	}
	dir, err := trustedDir(filepath.Dir(path))
	if err != nil {
		return "", fmt.Errorf("%s: %w", path, err)
	}
	return filepath.Join(dir, name), nil
}

// writeFileSafe atomically replaces path (whose directory must be trusted)
// with data: a fresh temp file (random name, O_EXCL|O_NOFOLLOW) owned and
// moded through its descriptor, then renamed over the final name (rename
// replaces a symlink there instead of following it).
func writeFileSafe(path string, data []byte, mode os.FileMode, uid, gid int) error {
	final, err := inTrustedDir(path)
	if err != nil {
		return err
	}
	tmp := filepath.Join(filepath.Dir(final), "."+filepath.Base(final)+"."+randHex(8)+".tmp")
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		if !ok {
			f.Close()
			os.Remove(tmp)
		}
	}()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Chown(uid, gid); err != nil {
		return err
	}
	if err := f.Chmod(mode); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, final); err != nil {
		return err
	}
	ok = true
	return nil
}

// ensureDirIn makes path (an entry of a trusted directory) a real directory
// owned by uid:gid with mode. An existing entry is accepted only if it is a
// directory (not a symlink) owned by root or uid; anything else is refused
// with a *ForeignOwnerError or a "not a directory" error.
func ensureDirIn(path string, mode os.FileMode, uid, gid int) error {
	p, err := inTrustedDir(path)
	if err != nil {
		return err
	}
	if err := os.Mkdir(p, 0o700); err != nil && !os.IsExist(err) {
		return err
	}
	fd, err := unix.Open(p, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("%s: not a directory (%w)", p, err)
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	if int(st.Uid) != 0 && int(st.Uid) != uid {
		return &ForeignOwnerError{Path: p, UID: int(st.Uid), Want: []int{0, uid}}
	}
	if err := unix.Fchown(fd, uid, gid); err != nil {
		return err
	}
	return unix.Fchmod(fd, uint32(mode.Perm()))
}

// ensureFileIn creates (or keeps) path, an entry of a trusted directory, as
// a regular single-link file owned by uid:gid with mode (log files the
// daemons append to).
func ensureFileIn(path string, mode os.FileMode, uid, gid int) error {
	p, err := inTrustedDir(path)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_APPEND|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); !st.Mode().IsRegular() || !ok || sys.Nlink != 1 {
		return fmt.Errorf("%s is not a regular single-link file", p)
	}
	if err := f.Chown(uid, gid); err != nil {
		return err
	}
	return f.Chmod(mode)
}

// quarantine moves path (an entry of a trusted directory) out of the way
// under a random name in the same directory and, for a directory, makes it
// root:wheel 0700, so whoever owned it can no longer reach anything inside.
// It returns the new path ("" if nothing was there).
func quarantine(path string) (string, error) {
	return quarantineAs(path, "."+filepath.Base(path)+".clux-old-"+randHex(6))
}

// quarantineAs is quarantine with a chosen new name (in the same directory;
// it must not exist).
func quarantineAs(path, newName string) (string, error) {
	p, err := inTrustedDir(path)
	if err != nil {
		return "", err
	}
	if newName == "" || strings.ContainsRune(newName, '/') || newName == "." || newName == ".." {
		return "", fmt.Errorf("invalid quarantine name %q", newName)
	}
	st, err := os.Lstat(p)
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	q := filepath.Join(filepath.Dir(p), newName)
	if _, err := os.Lstat(q); err == nil {
		return "", fmt.Errorf("%s already exists", q)
	}
	if err := os.Rename(p, q); err != nil {
		return "", err
	}
	if !st.IsDir() {
		return q, nil
	}
	fd, err := unix.Open(q, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return q, err
	}
	defer unix.Close(fd)
	if err := unix.Fchown(fd, lockUID, lockGID); err != nil {
		return q, err
	}
	return q, unix.Fchmod(fd, 0o700)
}

// removeQuarantined deletes path after quarantining it. os.RemoveAll walks
// with openat/unlinkat and O_NOFOLLOW, so links inside are removed, never
// followed.
func removeQuarantined(path string) error {
	q, err := quarantine(path)
	if err != nil || q == "" {
		return err
	}
	return os.RemoveAll(q)
}

// lockDir makes an existing directory entry of a trusted directory
// root:wheel 0700 (through an O_NOFOLLOW descriptor), so the user who owned
// it keeps no access to what's inside.
func lockDir(path string) error {
	p, err := inTrustedDir(path)
	if err != nil {
		return err
	}
	fd, err := unix.Open(p, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err := unix.Fchown(fd, lockUID, lockGID); err != nil {
		return err
	}
	return unix.Fchmod(fd, 0o700)
}

// ownerOf returns the uid owning path (not following a final symlink).
func ownerOf(path string) (uid, gid int, err error) {
	st, err := os.Lstat(path)
	if err != nil {
		return -1, -1, err
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return -1, -1, errors.New("no ownership info")
	}
	if st.Mode()&os.ModeSymlink != 0 {
		return int(sys.Uid), int(sys.Gid), fmt.Errorf("%s is a symlink", path)
	}
	return int(sys.Uid), int(sys.Gid), nil
}

// runAs runs a tool with uid/gid's privileges only (no supplementary
// groups), for work on files that user controls: root never touches them
// by name itself.
func runAs(uid, gid int, stdout io.Writer, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: []uint32{}}}
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin"}
	cmd.Dir = "/"
	var errb strings.Builder
	cmd.Stdout = stdout
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %s (as uid %d): %v: %s", filepath.Base(name), strings.Join(args, " "), uid, err, strings.TrimSpace(errb.String()))
	}
	return nil
}

// readFileAs reads at most max bytes of path with uid/gid's privileges.
func readFileAs(uid, gid int, path string, max int64) ([]byte, error) {
	var b limitedBuffer
	b.max = max
	if err := runAs(uid, gid, &b, "/bin/cat", "--", path); err != nil {
		return nil, err
	}
	if b.over {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, max)
	}
	return b.data, nil
}

type limitedBuffer struct {
	data []byte
	max  int64
	over bool
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	if int64(len(l.data)+len(p)) > l.max {
		l.over = true
		return len(p), nil
	}
	l.data = append(l.data, p...)
	return len(p), nil
}

func containsInt(s []int, v int) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
