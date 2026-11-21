//go:build darwin

package native

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

// Root-created control sockets (the slot keeper's and every supervisor's).
//
// The socket is bound and listened on by root in a root-owned directory the
// slots can't enter or write. Two consequences, both enforced by the kernel:
// nobody but root can unlink, replace or bind anything at that path, and
// LOCAL_PEERCRED on a client's connection reports the credentials the
// listening socket was created with (XNU caches them at listen()), i.e.
// uid 0 -- also after the supervisor drops to its slot uid. A same-uid agent
// can stop or kill its supervisor, but it can't make a socket at that path,
// and a socket it binds anywhere else reports its own uid, so a client that
// insists on a root listener never sends a workspace's secrets to it.
// (The supervisor's own process changed credentials, so the kernel also
// refuses a same-uid task_for_pid/ptrace on it: P_SUGID.)

// PeerUID is the uid LOCAL_PEERCRED reports for a unix socket connection.
func PeerUID(c *net.UnixConn) (int, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return -1, err
	}
	var cred *unix.Xucred
	var cerr error
	if err := raw.Control(func(fd uintptr) {
		cred, cerr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	}); err != nil {
		return -1, err
	}
	if cerr != nil {
		return -1, cerr
	}
	return int(cred.Uid), nil
}

// VerifyRootListener checks that conn, dialed to path, reached a socket
// root created: every directory from path's up to / is root-owned and not
// writable by anyone else, the socket file is root's, and the listening
// socket's credentials are root's.
func VerifyRootListener(conn net.Conn, path string) error {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return errors.New("not a unix socket")
	}
	if _, err := trustedDir(filepath.Dir(path)); err != nil {
		return fmt.Errorf("socket %s is not in a root-only directory (%v); refusing to use it", path, err)
	}
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok || st.Mode()&os.ModeSocket == 0 || !containsInt(trustedUIDs, int(sys.Uid)) {
		return fmt.Errorf("socket %s is not a socket created by root; refusing to use it", path)
	}
	uid, err := PeerUID(uc)
	if err != nil {
		return fmt.Errorf("checking the identity of %s: %w", path, err)
	}
	if !containsInt(trustedUIDs, uid) {
		return fmt.Errorf("socket %s was not created by root (listener uid %d); refusing to use it", path, uid)
	}
	return nil
}

// listenRootSocket (root) binds path, an entry of a trusted directory, as a
// unix socket root:gid 0660 (a stale one is removed first).
func listenRootSocket(path string, gid int) (*net.UnixListener, error) {
	p, err := inTrustedDir(path)
	if err != nil {
		return nil, err
	}
	if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	// Created 0600 (umask) and opened up only once owned right.
	old := syscall.Umask(0o077)
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: p, Net: "unix"})
	syscall.Umask(old)
	if err != nil {
		return nil, err
	}
	if err := os.Lchown(p, 0, gid); err != nil {
		l.Close()
		return nil, err
	}
	if err := os.Chmod(p, 0o660); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

// ListenSlotSocket is the root half of `clux native supervise`: it makes
// slot s's socket directory (root:_cluxctl 0750, replacing an older
// layout's slot-owned one) and binds the supervisor socket in it.
func ListenSlotSocket(cfg *Config, s Slot, logf func(string, ...any)) (*net.UnixListener, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("the supervisor's socket must be created by root")
	}
	for _, d := range []string{RunDir, SlotRunDir} {
		if err := ensureDirReplacing(d, 0o755, 0, 0, logf); err != nil {
			return nil, err
		}
	}
	if err := ensureDirReplacing(SlotSocketDir(s.N), 0o750, 0, cfg.CtlGID, logf); err != nil {
		return nil, err
	}
	return listenRootSocket(SlotSocket(s.N), cfg.CtlGID)
}

// DropToSlot permanently switches this (root) process to slot s's user:
// groups {slot group, _cluxslots}, gid, uid -- in that order -- and checks
// root can't be regained. macOS credentials are per process, so this covers
// every thread of the Go runtime.
func DropToSlot(cfg *Config, s Slot) error {
	if err := syscall.Setgroups([]int{s.GID, cfg.SlotsGID}); err != nil {
		return fmt.Errorf("setgroups: %w", err)
	}
	if err := syscall.Setgid(s.GID); err != nil {
		return fmt.Errorf("setgid %d: %w", s.GID, err)
	}
	if err := syscall.Setuid(s.UID); err != nil {
		return fmt.Errorf("setuid %d: %w", s.UID, err)
	}
	if os.Getuid() != s.UID || os.Geteuid() != s.UID || os.Getgid() != s.GID || os.Getegid() != s.GID {
		return fmt.Errorf("still uid %d/%d gid %d/%d after dropping to %s", os.Getuid(), os.Geteuid(), os.Getgid(), os.Getegid(), s.User)
	}
	if syscall.Setuid(0) == nil || syscall.Seteuid(0) == nil {
		return errors.New("root could be regained after dropping privileges")
	}
	return nil
}
