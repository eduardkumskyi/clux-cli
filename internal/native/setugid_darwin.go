//go:build darwin

package native

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// A slot user can chmod u+s/g+s its own files (Seatbelt denies it inside
// the sandbox, but simulator apps run outside it), and any other slot's
// unsandboxed code could execute such a file and so hold the first slot's
// uid (as its saved uid, after seteuid() back to its own). The wipe kills
// every process holding the uid in any form, and this sweep makes sure no
// file that would hand the uid (or gid) out again survives into the next
// workspace of the slot: hard links of it in other slots' homes, copies in
// /private/tmp, in some third-party world-writable directory, anywhere.
//
// It walks every local, writable file system that honours setuid bits
// (the sealed system volume is read-only, nosuid and ownership-ignoring
// volumes can't hand out a uid), on one device at a time, without
// following links (every step is an openat with O_NOFOLLOW from the
// parent's descriptor, so nothing a slot renames under the walk can point
// it elsewhere). It only descends into directories a slot user could
// search -- a file a slot can't reach it can't execute -- which skips the
// owner's home and most of the system, and only looks at the files of
// directories a slot user could have written (create, link or rename an
// entry). A matching file is opened O_NOFOLLOW, re-checked through the
// descriptor and chmod'ed through it.
//
// Other slots keep running while one is wiped; one of them could move a
// hard link from a directory the walk has not reached into one it has
// already passed. So a second walk covers just the trees a slot can write,
// with their processes stopped (SIGSTOP, re-checked every few ms for new
// ones that launchd or cron starts), and resumes them after it.

// slotIDs are the uids and gids of the slot pool.
type slotIDs struct {
	uids, gids map[uint32]bool
}

func poolIDs(cfg *Config) *slotIDs {
	ids := &slotIDs{uids: map[uint32]bool{}, gids: map[uint32]bool{}}
	for _, s := range cfg.Slots {
		if inIDRange(s.UID) {
			ids.uids[uint32(s.UID)] = true
		}
		if inIDRange(s.GID) {
			ids.gids[uint32(s.GID)] = true
		}
	}
	if inIDRange(cfg.SlotsGID) {
		ids.gids[uint32(cfg.SlotsGID)] = true
	}
	return ids
}

// canSearch: could a slot user search (traverse) this directory? Its
// owner can always chmod it.
func (ids *slotIDs) canSearch(st *unix.Stat_t) bool {
	return ids.uids[st.Uid] || st.Mode&0o001 != 0 || ids.gids[st.Gid] && st.Mode&0o010 != 0
}

// canWrite: could a slot user add an entry to this directory?
func (ids *slotIDs) canWrite(st *unix.Stat_t) bool {
	return ids.uids[st.Uid] || st.Mode&0o002 != 0 || ids.gids[st.Gid] && st.Mode&0o020 != 0
}

// dangerous: a regular setuid file of a slot uid, or setgid file of a slot
// gid.
func (ids *slotIDs) dangerous(st *unix.Stat_t) bool {
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return false
	}
	return st.Mode&unix.S_ISUID != 0 && ids.uids[st.Uid] || st.Mode&unix.S_ISGID != 0 && ids.gids[st.Gid]
}

type sweepResult struct {
	Dirs, Files int
	Stripped    []string
	Errors      []string
}

const sweepMaxDepth = 512

// sweepRoots returns the mount points the sweep covers.
func sweepRoots() []string {
	n, err := unix.Getfsstat(nil, unix.MNT_NOWAIT)
	if err != nil || n <= 0 {
		return []string{"/System/Volumes/Data"}
	}
	buf := make([]unix.Statfs_t, n+8)
	n, err = unix.Getfsstat(buf, unix.MNT_NOWAIT)
	if err != nil {
		return []string{"/System/Volumes/Data"}
	}
	var roots []string
	for _, fs := range buf[:n] {
		if fs.Flags&unix.MNT_LOCAL == 0 || fs.Flags&(unix.MNT_RDONLY|unix.MNT_NOSUID|unix.MNT_IGNORE_OWNERSHIP) != 0 {
			continue
		}
		switch unix.ByteSliceToString(fs.Fstypename[:]) {
		case "devfs", "autofs", "nullfs":
			continue
		}
		roots = append(roots, unix.ByteSliceToString(fs.Mntonname[:]))
	}
	return roots
}

// stripSlotSetugid clears S_ISUID/S_ISGID on every slot-owned file the
// slots could reach under roots (see the comment above). It also returns
// the outermost directories a slot can write (writable dirs with no
// writable ancestor): every slot-writable directory is in one of their
// trees, and none of them can be renamed by a slot (their parents aren't
// slot-writable), so a second walk of just these trees sees every place a
// file of a slot can be moved to.
func stripSlotSetugid(ids *slotIDs, roots []string) (sweepResult, []string) {
	w := &sweepWalker{ids: ids}
	for _, r := range roots {
		fd, err := unix.Open(r, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			w.res.Errors = append(w.res.Errors, r+": "+err.Error())
			continue
		}
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != nil {
			unix.Close(fd)
			continue
		}
		w.dir(fd, r, st.Dev, &st, false, 0)
	}
	return w.res, w.writableRoots
}

type sweepWalker struct {
	ids           *slotIDs
	res           sweepResult
	writableRoots []string
}

// dir owns fd (closes it). inWritable: an ancestor is slot-writable.
func (w *sweepWalker) dir(fd int, path string, dev int32, st *unix.Stat_t, inWritable bool, depth int) {
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	w.res.Dirs++
	writable := w.ids.canWrite(st)
	if writable && !inWritable {
		w.writableRoots = append(w.writableRoots, path)
	}
	for {
		entries, err := f.ReadDir(4096)
		for _, e := range entries {
			name := e.Name()
			typ := e.Type()
			if typ&os.ModeSymlink != 0 || typ&(os.ModeNamedPipe|os.ModeSocket|os.ModeDevice|os.ModeCharDevice) != 0 {
				continue
			}
			if !typ.IsDir() && !writable {
				continue // nothing of a slot can have been put here
			}
			var est unix.Stat_t
			if err := unix.Fstatat(fd, name, &est, unix.AT_SYMLINK_NOFOLLOW); err != nil {
				continue
			}
			p := filepath.Join(path, name)
			switch est.Mode & unix.S_IFMT {
			case unix.S_IFDIR:
				if est.Dev != dev || !w.ids.canSearch(&est) || depth >= sweepMaxDepth {
					continue
				}
				sub, err := unix.Openat(fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
				if err != nil {
					continue // e.g. TCC-protected: no slot gets in there either
				}
				var sst unix.Stat_t
				if unix.Fstat(sub, &sst) != nil || sst.Dev != dev || sst.Ino != est.Ino || !w.ids.canSearch(&sst) {
					unix.Close(sub)
					continue
				}
				w.dir(sub, p, dev, &sst, inWritable || writable, depth+1)
			case unix.S_IFREG:
				w.res.Files++
				if !writable || !w.ids.dangerous(&est) {
					continue
				}
				if err := stripAt(fd, name, w.ids); err != nil {
					w.res.Errors = append(w.res.Errors, p+": "+err.Error())
				} else {
					w.res.Stripped = append(w.res.Stripped, p)
				}
			}
		}
		if err != nil || len(entries) == 0 {
			return
		}
	}
}

// stripAt clears the setuid/setgid bits of dir/name through a descriptor
// of the file itself (never a path root resolves again).
func stripAt(dirfd int, name string, ids *slotIDs) error {
	fd, err := unix.Openat(dirfd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	if !ids.dangerous(&st) {
		return nil // replaced under us by something harmless
	}
	mode := uint32(st.Mode) & 0o7777 &^ (unix.S_ISUID | unix.S_ISGID)
	err = unix.Fchmod(fd, mode)
	if errors.Is(err, syscall.EPERM) {
		// The owner may have set uchg/uappnd on its file.
		_ = unix.Fchflags(fd, int(st.Flags&^(unix.UF_IMMUTABLE|unix.UF_APPEND)))
		err = unix.Fchmod(fd, mode)
	}
	return err
}

// --- freezing the other slots for the sweep ----------------------------------------

const sstop = 4 // SSTOP in <sys/proc.h>

// freezeSlots stops every process holding a slot id and keeps stopping new
// ones until the returned function is called, which resumes them (only the
// ones it stopped itself).
func freezeSlots(ids *slotIDs) (thaw func()) {
	var mu sync.Mutex
	frozen := map[int]bool{}
	sweep := func() int {
		procs, err := unix.SysctlKinfoProcSlice("kern.proc.all")
		if err != nil {
			return 0
		}
		n := 0
		mu.Lock()
		defer mu.Unlock()
		for i := range procs {
			p := &procs[i]
			pid := int(p.Proc.P_pid)
			if pid <= 1 || pid == os.Getpid() || p.Proc.P_stat == szomb || !ids.holdsAny(p) {
				continue
			}
			if p.Proc.P_stat == sstop {
				if _, seen := frozen[pid]; !seen {
					frozen[pid] = false // stopped by someone else: leave it so
				}
				continue
			}
			// Running: new, resumed by someone, or a reused pid.
			if syscall.Kill(pid, syscall.SIGSTOP) == nil {
				frozen[pid] = true
				n++
			}
		}
		return n
	}
	// Settle: a fork racing the first passes is caught by the next.
	for i := 0; i < 20; i++ {
		if sweep() == 0 && i >= 2 {
			break
		}
	}
	done := make(chan struct{})
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		t := time.NewTicker(5 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				sweep()
			}
		}
	}()
	return func() {
		close(done)
		<-stopped
		mu.Lock()
		defer mu.Unlock()
		for pid, ours := range frozen {
			if ours {
				_ = syscall.Kill(pid, syscall.SIGCONT)
			}
		}
	}
}

func (ids *slotIDs) holdsAny(p *unix.KinfoProc) bool {
	pc, uc := &p.Eproc.Pcred, &p.Eproc.Ucred
	if ids.uids[pc.P_ruid] || ids.uids[pc.P_svuid] || ids.uids[uc.Uid] {
		return true
	}
	if ids.gids[pc.P_rgid] || ids.gids[pc.P_svgid] {
		return true
	}
	n := int(uc.Ngroups)
	if n > len(uc.Groups) {
		n = len(uc.Groups)
	}
	for _, g := range uc.Groups[:n] {
		if ids.gids[g] {
			return true
		}
	}
	return false
}

// sweepSlotSetugid strips every slot setuid/setgid file: one walk of all
// the slots can reach while they run, then, with every slot process
// stopped, a second walk of just the trees they can write (the frozen
// slots can't move a file out of the second walk's way).
func sweepSlotSetugid(cfg *Config, logf func(string, ...any)) {
	ids := poolIDs(cfg)
	started := time.Now()
	res, writable := stripSlotSetugid(ids, sweepRoots())
	full := time.Since(started)
	frozenAt := time.Now()
	thaw := freezeSlots(ids)
	res2, _ := stripSlotSetugid(ids, writable)
	thaw()
	logf("slot keeper: setuid/setgid sweep: %d dirs, %d files in %s; slots stopped for %s (%d writable trees, %d dirs, %d files); stripped %d%s",
		res.Dirs, res.Files, full.Round(time.Millisecond), time.Since(frozenAt).Round(time.Millisecond), len(writable), res2.Dirs, res2.Files,
		len(res.Stripped)+len(res2.Stripped), listSuffix(append(res.Stripped, res2.Stripped...)))
	if errs := append(res.Errors, res2.Errors...); len(errs) > 0 {
		logf("slot keeper: setuid/setgid sweep errors%s", listSuffix(errs))
	}
}

func listSuffix(l []string) string {
	if len(l) == 0 {
		return ""
	}
	if len(l) > 20 {
		l = append(l[:20:20], "...")
	}
	return ": " + strings.Join(l, ", ")
}
