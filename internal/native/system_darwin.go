//go:build darwin

package native

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// run executes a system tool and returns its combined output.
func run(name string, args ...string) (string, error) {
	return runIn(nil, name, args...)
}

func runIn(stdin io.Reader, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.Stdin = stdin
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	s := strings.TrimSpace(out.String())
	if err != nil {
		return s, fmt.Errorf("%s %s: %v: %s", filepath.Base(name), strings.Join(args, " "), err, s)
	}
	return s, nil
}

// dsAttr reads one attribute of a local directory record ("" if absent).
func dsAttr(record, key string) (string, bool) {
	out, err := run("/usr/bin/dscl", ".", "-read", record, key)
	if err != nil {
		return "", false
	}
	return parseDSAttr(out)
}

func dsID(record, key string) (int, bool) {
	v, ok := dsAttr(record, key)
	if !ok {
		return 0, false
	}
	n, err := strconv.Atoi(v)
	return n, err == nil
}

// usedIDs lists the uids and gids in the local directory.
func usedIDs() (uids, gids map[int]bool, err error) {
	uids, gids = map[int]bool{}, map[int]bool{}
	for _, q := range []struct {
		path, key string
		into      map[int]bool
	}{{"/Users", "UniqueID", uids}, {"/Groups", "PrimaryGroupID", gids}} {
		out, err := run("/usr/bin/dscl", ".", "-list", q.path, q.key)
		if err != nil {
			return nil, nil, err
		}
		for _, line := range strings.Split(out, "\n") {
			f := strings.Fields(line)
			if len(f) == 2 {
				if n, err := strconv.Atoi(f[1]); err == nil {
					q.into[n] = true
				}
			}
		}
	}
	return uids, gids, nil
}

// freeID returns the lowest id in range unused in every given set, and
// marks it used.
func freeID(sets ...map[int]bool) (int, error) {
next:
	for n := idRangeLo; n <= idRangeHi; n++ {
		for _, s := range sets {
			if s[n] {
				continue next
			}
		}
		for _, s := range sets {
			s[n] = true
		}
		return n, nil
	}
	return 0, fmt.Errorf("no free uid/gid in %d-%d", idRangeLo, idRangeHi)
}

// safeChain reports whether every existing directory from dir up to / is
// root-owned and not group/world writable: a root daemon must not run a
// binary that someone else could swap.
func safeChain(dir string) bool {
	for d := dir; ; d = filepath.Dir(d) {
		st, err := os.Lstat(d)
		if err == nil {
			sys, ok := st.Sys().(*syscall.Stat_t)
			if !ok || sys.Uid != 0 || st.Mode()&0o022 != 0 || st.Mode()&os.ModeSymlink != 0 {
				return false
			}
		} else if !os.IsNotExist(err) {
			return false
		}
		if d == "/" {
			return true
		}
	}
}

func libexecDir() (string, error) {
	for _, d := range []string{primaryLibexec, fallbackLibexec} {
		if safeChain(d) {
			return d, nil
		}
	}
	return "", fmt.Errorf("neither %s nor %s has a root-owned, non-writable parent chain", primaryLibexec, fallbackLibexec)
}

func portFree(p int) bool {
	l4, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", p))
	if err != nil {
		return false
	}
	l4.Close()
	if l6, err := net.Listen("tcp6", fmt.Sprintf("[::1]:%d", p)); err == nil {
		l6.Close()
	}
	return true
}

func pickProxyPort() (int, error) {
	for p := DefaultProxyPort; p < DefaultProxyPort+80; p++ {
		if portFree(p) {
			return p, nil
		}
	}
	return 0, fmt.Errorf("no free port for the egress proxy near %d", DefaultProxyPort)
}

// killUser kills every process holding uid (as root: uninstall, slot removal).
func killUser(uid int) { KillIDs(uid, -1, -1) }

// KillUID kills every process holding uid (see KillIDs), except pid except.
func KillUID(uid, except int) int { return KillIDs(uid, -1, except) }

// holdsIDs reports whether a process holds uid as its real, effective or
// saved uid, or gid as its real, effective, saved or a supplementary gid.
// The saved ids matter: a process of another user that ran a setuid file of
// uid keeps uid as its saved uid after seteuid() back to its own, can
// switch to it again at any time, and is invisible to kern.proc.uid/ruid.
// gid < 0 (or outside the slot id range) matches no gid.
func holdsIDs(p *unix.KinfoProc, uid, gid int) bool {
	pc, uc := &p.Eproc.Pcred, &p.Eproc.Ucred
	if uid >= 0 && (int(pc.P_ruid) == uid || int(pc.P_svuid) == uid || int(uc.Uid) == uid) {
		return true
	}
	if gid < 0 || !inIDRange(gid) {
		return false
	}
	if int(pc.P_rgid) == gid || int(pc.P_svgid) == gid {
		return true
	}
	n := int(uc.Ngroups) // cr_groups[0] is the effective gid
	if n > len(uc.Groups) {
		n = len(uc.Groups)
	}
	for _, g := range uc.Groups[:n] {
		if int(g) == gid {
			return true
		}
	}
	return false
}

const szomb = 5 // SZOMB in <sys/proc.h>

// pidsHolding scans every process (kern.proc.all) for those holding uid or
// gid (holdsIDs).
func pidsHolding(uid, gid int) []int {
	procs, err := unix.SysctlKinfoProcSlice("kern.proc.all")
	if err != nil {
		return nil
	}
	var pids []int
	for i := range procs {
		// A zombie can't run any more (and only its parent can reap it).
		if procs[i].Proc.P_stat != szomb && holdsIDs(&procs[i], uid, gid) {
			pids = append(pids, int(procs[i].Proc.P_pid))
		}
	}
	return pids
}

// pidHolds re-reads one process: does pid (still) hold uid or gid?
func pidHolds(pid, uid, gid int) bool {
	p, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil || int(p.Proc.P_pid) != pid {
		return false
	}
	return holdsIDs(p, uid, gid)
}

// KillIDs kills every process that holds uid or gid as a real, effective,
// saved (or supplementary) id, except pid except (a supervisor clearing its
// own slot passes its pid). Each round first stops everything it sees, then
// kills what still holds the ids (a pid may have been reused between the
// listing and the signal), so a process can't escape by forking faster than
// the sweep; rounds repeat until nothing is left. Returns how many
// processes were signalled.
func KillIDs(uid, gid, except int) int {
	return killAll(func() []int { return pidsHolding(uid, gid) },
		func(pid int) bool { return pidHolds(pid, uid, gid) },
		syscall.Kill, except, 10, 100*time.Millisecond)
}

func killAll(list func() []int, still func(int) bool, kill func(int, syscall.Signal) error, except, rounds int, pause time.Duration) int {
	total := 0
	for i := 0; i < rounds; i++ {
		var pids []int
		for _, pid := range list() {
			if pid > 1 && pid != except {
				pids = append(pids, pid)
			}
		}
		if len(pids) == 0 {
			return total
		}
		for _, pid := range pids {
			_ = kill(pid, syscall.SIGSTOP)
		}
		for _, pid := range pids {
			if !still(pid) {
				// Reused by another process after the listing: we stopped
				// an innocent one; let it go on.
				_ = kill(pid, syscall.SIGCONT)
				continue
			}
			if kill(pid, syscall.SIGKILL) == nil {
				total++
			}
		}
		time.Sleep(pause)
	}
	return total
}

func launchdLoaded(label string) (bool, string) {
	out, err := run("/bin/launchctl", "print", "system/"+label)
	if err != nil {
		return false, ""
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if v, ok := strings.CutPrefix(line, "state = "); ok {
			return true, v
		}
	}
	return true, ""
}
