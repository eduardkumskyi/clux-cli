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

// killUser kills every process of uid (as root: uninstall, slot removal).
func killUser(uid int) { KillUID(uid, -1) }

// KillUID kills every process whose real or effective uid is uid, except
// pid except (a supervisor clearing its own slot passes its pid). Each round
// first stops everything it sees, then kills it, so a process can't escape
// by forking faster than the sweep; rounds repeat until nothing is left.
// Returns how many processes were signalled.
func KillUID(uid, except int) int {
	list := func() []int {
		seen := map[int]bool{}
		var pids []int
		for _, name := range []string{"kern.proc.uid", "kern.proc.ruid"} {
			procs, err := unix.SysctlKinfoProcSlice(name, uid)
			if err != nil {
				continue
			}
			for _, p := range procs {
				if pid := int(p.Proc.P_pid); !seen[pid] {
					seen[pid] = true
					pids = append(pids, pid)
				}
			}
		}
		return pids
	}
	return killAll(list, syscall.Kill, except, 10, 100*time.Millisecond)
}

func killAll(list func() []int, kill func(int, syscall.Signal) error, except, rounds int, pause time.Duration) int {
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
