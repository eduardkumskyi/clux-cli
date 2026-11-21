//go:build darwin

package native

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	// wipeTimeout bounds one wipe (simulator shutdown, deleting a home).
	wipeTimeout = 20 * time.Minute
	// simShutdownTimeout bounds `simctl shutdown all` during a wipe.
	keeperSimTimeout = 30 * time.Second
)

// keeper is the root slot keeper (runs inside the pf daemon).
type keeper struct {
	cfg  *Config
	logf func(string, ...any)

	// Test seams.
	stateDir           string
	stateUID, stateGID int
	wipe               func(ctx context.Context, s Slot) (int64, error)
	resident           func(n int) []string
	prepare            func(s Slot) error

	slots map[int]*sync.Mutex // held while a slot's state changes (wipe: minutes)
}

func newKeeper(cfg *Config, logf func(string, ...any)) (*keeper, error) {
	k := &keeper{cfg: cfg, logf: logf, stateDir: StateDir, slots: map[int]*sync.Mutex{}}
	k.wipe = k.wipeSlot
	k.resident = slotResident
	k.prepare = prepareSlot
	for _, s := range cfg.Slots {
		k.slots[s.N] = &sync.Mutex{}
	}
	return k, nil
}

func listenKeeper(cfg *Config) (net.Listener, error) {
	return listenRootSocket(KeeperSocket, cfg.CtlGID)
}

func (k *keeper) serve(ctx context.Context, l net.Listener) {
	go func() {
		<-ctx.Done()
		l.Close()
	}()
	for {
		c, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			k.logf("slot keeper: accept: %v", err)
			time.Sleep(time.Second)
			continue
		}
		go k.handle(ctx, c.(*net.UnixConn))
	}
}

func (k *keeper) handle(ctx context.Context, c *net.UnixConn) {
	defer c.Close()
	reply := func(r KeeperResponse) {
		b, _ := json.Marshal(r)
		_ = c.SetWriteDeadline(time.Now().Add(10 * time.Second))
		_, _ = c.Write(append(b, '\n'))
	}
	uid, err := PeerUID(c)
	if err != nil || (uid != k.cfg.OwnerUID && uid != 0) {
		k.logf("slot keeper: rejected connection from uid %d (owner is %d) %v", uid, k.cfg.OwnerUID, err)
		reply(KeeperResponse{Error: "permission denied: only the machine owner configured at install may use the slot keeper"})
		return
	}
	_ = c.SetReadDeadline(time.Now().Add(30 * time.Second))
	line, err := bufio.NewReaderSize(c, 4096).ReadSlice('\n')
	if err != nil {
		return
	}
	_ = c.SetReadDeadline(time.Time{})
	var req KeeperRequest
	if err := json.Unmarshal(line, &req); err != nil {
		reply(KeeperResponse{Error: "bad request: " + err.Error()})
		return
	}
	// A wipe outlives a client that gives up: it always runs to the end.
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), wipeTimeout)
	defer cancel()
	reply(k.dispatch(wctx, req))
}

func (k *keeper) dispatch(ctx context.Context, req KeeperRequest) KeeperResponse {
	s, ok := k.cfg.Slot(req.Slot)
	mu := k.slots[req.Slot]
	if !ok || mu == nil {
		return KeeperResponse{Error: fmt.Sprintf("no slot %d", req.Slot)}
	}
	if !validKeeperID(req.WorkspaceID) || req.Op == KeeperOpClaim && req.WorkspaceID == "" {
		return KeeperResponse{Error: fmt.Sprintf("invalid workspace id %q", req.WorkspaceID)}
	}
	switch req.Op {
	case KeeperOpState:
		if !mu.TryLock() {
			st, _ := k.load(s.N)
			st.Busy = true
			return KeeperResponse{OK: true, State: &st}
		}
		defer mu.Unlock()
		st, err := k.load(s.N)
		if err != nil {
			return KeeperResponse{Error: err.Error()}
		}
		return KeeperResponse{OK: true, State: &st}
	case KeeperOpClaim:
		if !mu.TryLock() {
			return KeeperResponse{Error: fmt.Sprintf("slot %d is busy (being wiped)", s.N)}
		}
		defer mu.Unlock()
		st, err := k.load(s.N)
		if err != nil {
			return KeeperResponse{Error: err.Error()}
		}
		var resident []string
		if !st.Known {
			resident = k.resident(s.N)
		}
		next, err := claimSlot(st, req.WorkspaceID, resident)
		if err != nil {
			return KeeperResponse{Error: err.Error(), State: &st}
		}
		if next != st {
			// Handing the slot out: its home is the uid's alone, and no
			// other user's process may still hold the uid.
			if err := k.prepare(s); err != nil {
				k.logf("slot keeper: preparing slot %d for workspace %s: %v", s.N, req.WorkspaceID, err)
				return KeeperResponse{Error: fmt.Sprintf("preparing slot %d: %v", s.N, err), State: &st}
			}
			if err := k.save(next); err != nil {
				return KeeperResponse{Error: err.Error()}
			}
			k.logf("slot keeper: slot %d claimed by workspace %s", s.N, req.WorkspaceID)
		}
		return KeeperResponse{OK: true, State: &next}
	case KeeperOpWipe:
		if !mu.TryLock() {
			return KeeperResponse{Error: fmt.Sprintf("slot %d is busy (being wiped)", s.N)}
		}
		defer mu.Unlock()
		st, err := k.load(s.N)
		if err != nil {
			return KeeperResponse{Error: err.Error()}
		}
		if err := wipeAllowed(st, req.WorkspaceID); err != nil {
			return KeeperResponse{Error: err.Error(), State: &st}
		}
		// Recorded dirty first: a wipe that dies half-way leaves a slot
		// nobody may claim until a wipe completes.
		st.Known, st.Clean = true, false
		if err := k.save(st); err != nil {
			return KeeperResponse{Error: err.Error()}
		}
		k.logf("slot keeper: wiping slot %d (%s) for workspace %q", s.N, s.User, req.WorkspaceID)
		started := time.Now()
		freed, err := k.wipe(ctx, s)
		if err != nil {
			st.LastError = err.Error()
			_ = k.save(st)
			k.logf("slot keeper: wiping slot %d failed: %v", s.N, err)
			return KeeperResponse{Error: fmt.Sprintf("wiping slot %d: %v", s.N, err), State: &st}
		}
		st = SlotState{Slot: s.N, Known: true, Clean: true}
		if err := k.save(st); err != nil {
			return KeeperResponse{Error: err.Error()}
		}
		k.logf("slot keeper: slot %d wiped in %s (%d bytes)", s.N, time.Since(started).Round(time.Millisecond), freed)
		return KeeperResponse{OK: true, State: &st, FreedBytes: freed}
	}
	return KeeperResponse{Error: fmt.Sprintf("unknown op %q", req.Op)}
}

func (k *keeper) statePath(n int) string { return filepath.Join(k.stateDir, strconv.Itoa(n)+".json") }

func (k *keeper) load(n int) (SlotState, error) {
	st, err := readSlotStateFile(k.statePath(n), n)
	if os.IsNotExist(err) {
		return SlotState{Slot: n}, nil
	}
	return st, err
}

func (k *keeper) save(st SlotState) error {
	st.Busy = false
	st.Updated = time.Now().UTC().Format(time.RFC3339)
	b, _ := json.Marshal(st)
	return writeFileSafe(k.statePath(st.Slot), append(b, '\n'), 0o644, k.stateUID, k.stateGID)
}

// ReadSlotState reads slot n's keeper record (root-owned file in a
// root-owned directory; a missing file is an unknown slot).
func ReadSlotState(n int) (SlotState, error) {
	st, err := readSlotStateFile(filepath.Join(StateDir, strconv.Itoa(n)+".json"), n)
	if os.IsNotExist(err) {
		return SlotState{Slot: n}, nil
	}
	return st, err
}

func readSlotStateFile(path string, n int) (SlotState, error) {
	var st SlotState
	b, err := readRootFile(path)
	if err != nil {
		return st, err
	}
	if err := json.Unmarshal(b, &st); err != nil {
		return st, fmt.Errorf("%s: %w", path, err)
	}
	if st.Slot != n {
		return SlotState{}, fmt.Errorf("%s: record of slot %d", path, st.Slot)
	}
	return st, nil
}

// slotResident lists the workspace directories in slot n's home, read
// without following links (the home is the slot user's).
func slotResident(n int) []string {
	home, err := unix.Open(SlotHome(n), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil
	}
	defer unix.Close(home)
	fd, err := unix.Openat(home, "workspaces", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil
	}
	f := os.NewFile(uintptr(fd), "workspaces")
	defer f.Close()
	names, _ := f.Readdirnames(-1)
	var out []string
	for _, name := range names {
		if validKeeperID(name) && name != "" {
			out = append(out, name)
		}
	}
	return out
}

// --- the wipe ---------------------------------------------------------------------

// wipeSlot removes everything slot s's uid left behind, in an order that
// leaves it nothing to come back with:
//
//  1. the supervisor's LaunchDaemon is booted out (it runs as the uid);
//  2. scheduled jobs that would start the uid again later: its crontab and
//     at jobs;
//  3. booted simulators are shut down, then the uid's launchd user and gui
//     domains are booted out and every process holding the uid or gid
//     (real, effective or saved: also another slot's process that ran a
//     setuid file of this one) is killed, again and again until none is
//     left (launchd respawns user-domain services);
//  4. the home is renamed aside inside root-owned SlotsDir (nothing of the
//     uid can reach it any more), replaced by a fresh empty one and deleted;
//     the uid's per-user temp/cache dirs are emptied and its files in the
//     shared temp dirs deleted; no setuid/setgid file of any slot is left
//     where a slot can reach it (sweepSlotSetugid);
//  5. nothing of the uid may have reappeared; the supervisor is started
//     again.
func (k *keeper) wipeSlot(ctx context.Context, s Slot) (int64, error) {
	if !inIDRange(s.UID) {
		return 0, fmt.Errorf("uid %d outside the slot range", s.UID)
	}
	userDirs := slotUserDirs(s) // asks the system as the uid, so before the kill
	_, _ = run("/bin/launchctl", "bootout", "system/"+SupervisorLabel(s.N))
	// The supervisor (by then the slot uid) can't unlink its root-owned
	// socket; remove it so the wait below sees the new one.
	if p, err := inTrustedDir(SlotSocket(s.N)); err == nil {
		_ = os.Remove(p)
	}
	purgeScheduled(s, k.logf)
	shutdownSimulatorsAs(ctx, s, k.logf)
	if err := killUIDCompletely(s.UID, s.GID); err != nil {
		return 0, err
	}

	q, err := quarantine(SlotHome(s.N))
	if err != nil {
		return 0, fmt.Errorf("moving the home aside: %w", err)
	}
	if err := ensureDirIn(SlotHome(s.N), 0o700, s.UID, s.GID); err != nil {
		return 0, fmt.Errorf("fresh home: %w", err)
	}
	var freed int64
	if q != "" {
		freed = treeSize(q)
		if err := removeTree(q); err != nil {
			// Root-owned 0700 now: unreachable for the uid. Logged, not fatal.
			k.logf("slot keeper: deleting %s: %v", q, err)
		}
	}
	for _, d := range userDirs {
		emptyDir(d, k.logf)
	}
	removeSharedFiles(s.UID, k.logf)
	// No setuid/setgid file of a slot may hand this uid (or any slot's)
	// out again: hard links in other slots' homes, copies anywhere.
	sweepSlotSetugid(k.cfg, k.logf)

	if err := killUIDCompletely(s.UID, s.GID); err != nil {
		return freed, err
	}
	if err := startSupervisor(s); err != nil {
		return freed, err
	}
	return freed, nil
}

// prepareSlot runs (as root) right before a slot is handed to a workspace:
//   - the home is reset to mode 0700 without ACL entries, so no other slot
//     can search it, whatever the previous holder did to it;
//   - any process holding the slot's uid or gid that is not purely the slot
//     user (another user that ran a setuid/setgid file of the slot and kept
//     the id as its effective or saved id) is killed. After a wipe nothing
//     like it can exist (the wipe kills every holder and strips every slot
//     setuid/setgid file); this is the check that it really doesn't.
func prepareSlot(s Slot) error {
	if !inIDRange(s.UID) {
		return fmt.Errorf("uid %d outside the slot range", s.UID)
	}
	p, err := inTrustedDir(SlotHome(s.N))
	if err != nil {
		return err
	}
	fd, err := unix.Open(p, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("home %s: %w", p, err)
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	if int(st.Uid) != s.UID {
		return fmt.Errorf("home %s is owned by uid %d, not %d", p, st.Uid, s.UID)
	}
	// The entry is in a root-owned directory: the path still names fd.
	if out, err := run("/bin/chmod", "-N", p); err != nil {
		return fmt.Errorf("clearing the ACL of %s: %v %s", p, err, out)
	}
	if err := unix.Fchmod(fd, 0o700); err != nil {
		return fmt.Errorf("chmod 0700 %s: %w", p, err)
	}
	impostors := func() []int { return impostorPIDs(s.UID, s.GID) }
	for i := 0; i < 5 && len(impostors()) > 0; i++ {
		killAll(impostors, func(pid int) bool { return containsInt(impostorPIDs(s.UID, s.GID), pid) },
			syscall.Kill, -1, 10, 50*time.Millisecond)
	}
	if left := impostors(); len(left) > 0 {
		return fmt.Errorf("processes of other users keep holding uid %d: %v", s.UID, left)
	}
	return nil
}

// impostorPIDs lists the processes holding uid/gid whose real, effective
// and saved uids are not all uid.
func impostorPIDs(uid, gid int) []int {
	procs, err := unix.SysctlKinfoProcSlice("kern.proc.all")
	if err != nil {
		return nil
	}
	var pids []int
	for i := range procs {
		p := &procs[i]
		if p.Proc.P_stat == szomb || !holdsIDs(p, uid, gid) || int(p.Proc.P_pid) <= 1 {
			continue
		}
		pc := &p.Eproc.Pcred
		if int(pc.P_ruid) != uid || int(pc.P_svuid) != uid || int(p.Eproc.Ucred.Uid) != uid {
			pids = append(pids, int(p.Proc.P_pid))
		}
	}
	return pids
}

// purgeUID is what removing a slot (shrinking, uninstall) needs: the
// supervisor gone, nothing scheduled, nothing running.
func purgeUID(s Slot, logf func(string, ...any)) {
	_, _ = run("/bin/launchctl", "bootout", "system/"+SupervisorLabel(s.N))
	if !inIDRange(s.UID) {
		return
	}
	purgeScheduled(s, logf)
	if err := killUIDCompletely(s.UID, s.GID); err != nil {
		logf("%v", err)
	}
}

// purgeScheduled removes the uid's crontab and at jobs.
func purgeScheduled(s Slot, logf func(string, ...any)) {
	_, _ = run("/usr/bin/crontab", "-u", s.User, "-r")
	// /private/var/at/tabs is root:wheel 0700: nobody else can plant a link.
	if err := os.Remove("/private/var/at/tabs/" + s.User); err != nil && !os.IsNotExist(err) {
		logf("removing the crontab of %s: %v", s.User, err)
	}
	// at(1) job files are owned by the submitting user (the spool is
	// daemon:wheel 0755, only root and daemon write it).
	const jobs = "/private/var/at/jobs"
	entries, _ := os.ReadDir(jobs)
	for _, e := range entries {
		p := filepath.Join(jobs, e.Name())
		if st, err := os.Lstat(p); err == nil {
			if sys, ok := st.Sys().(*syscall.Stat_t); ok && int(sys.Uid) == s.UID {
				_ = os.Remove(p)
			}
		}
	}
}

// killUIDCompletely boots out the uid's launchd domains and kills every
// process holding the uid or gid (real, effective or saved id; see
// holdsIDs) until none is left for a while; launchd may respawn
// user-domain services right after a kill.
func killUIDCompletely(uid, gid int) error {
	for round := 0; round < 15; round++ {
		_, _ = run("/bin/launchctl", "bootout", "user/"+strconv.Itoa(uid))
		_, _ = run("/bin/launchctl", "bootout", "gui/"+strconv.Itoa(uid))
		KillIDs(uid, gid, -1)
		time.Sleep(300 * time.Millisecond)
		if len(slotPIDs(uid, gid)) == 0 {
			time.Sleep(700 * time.Millisecond)
			if len(slotPIDs(uid, gid)) == 0 {
				return nil
			}
		}
	}
	return fmt.Errorf("processes holding uid %d / gid %d keep coming back: %v", uid, gid, slotPIDs(uid, gid))
}

// slotPIDs lists the processes (other than launchd) holding uid or gid.
func slotPIDs(uid, gid int) []int {
	var pids []int
	for _, pid := range pidsHolding(uid, gid) {
		if pid > 1 {
			pids = append(pids, pid)
		}
	}
	return pids
}

// shutdownSimulatorsAs runs `xcrun simctl shutdown all` as the slot user.
func shutdownSimulatorsAs(ctx context.Context, s Slot, logf func(string, ...any)) {
	if _, err := os.Stat("/usr/bin/xcrun"); err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, keeperSimTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/xcrun", "simctl", "shutdown", "all")
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(s.UID), Gid: uint32(s.GID), Groups: []uint32{}}}
	cmd.Env = []string{"HOME=" + SlotHome(s.N), "PATH=/usr/bin:/bin:/usr/sbin:/sbin"}
	cmd.Dir = "/"
	if out, err := cmd.CombinedOutput(); err != nil {
		logf("slot keeper: simctl shutdown as %s: %v: %s", s.User, err, strings.TrimSpace(string(out)))
	}
}

var userFolderRE = regexp.MustCompile(`^/private/var/folders/[^/]+/[^/]+$`)

// slotUserDirs returns the uid's per-user folder (/private/var/folders/xx/
// <hash>, holding its confstr temp and cache dirs), asked from the system
// as the uid. Only a uid-owned real directory directly in a root-owned
// /private/var/folders/xx is returned.
func slotUserDirs(s Slot) []string {
	var b bytes.Buffer
	if err := runAs(s.UID, s.GID, &b, "/usr/bin/getconf", "DARWIN_USER_TEMP_DIR"); err != nil {
		return nil
	}
	d := strings.TrimSuffix(strings.TrimSpace(b.String()), "/")
	if strings.HasPrefix(d, "/var/") {
		d = "/private" + d
	}
	base := filepath.Dir(d)
	if !userFolderRE.MatchString(base) || filepath.Clean(base) != base {
		return nil
	}
	if checkRootDir(filepath.Dir(base)) != nil {
		return nil
	}
	if uid, _, err := ownerOf(base); err != nil || uid != s.UID {
		return nil
	}
	if st, err := os.Lstat(base); err != nil || !st.IsDir() {
		return nil
	}
	return []string{base}
}

// emptyDir deletes what is inside dir (a directory of a uid that has no
// process left), depth first, without following links. macOS keeps some
// directories there that even root may not remove (the cache dir C, X,
// data vaults like 0/com.apple.LaunchServices.dv: EPERM); those stay, their
// contents go. Anything else that can't be removed is logged.
func emptyDir(dir string, logf func(string, ...any)) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		p := filepath.Join(dir, e.Name())
		st, err := os.Lstat(p)
		if err != nil {
			continue
		}
		if st.IsDir() {
			emptyDir(p, logf)
			if err := os.Remove(p); err != nil && !errors.Is(err, syscall.EPERM) && !errors.Is(err, syscall.ENOTEMPTY) {
				logf("slot keeper: removing %s: %v", p, err)
			}
			continue
		}
		if err := removeTree(p); err != nil {
			logf("slot keeper: removing %s: %v", p, err)
		}
	}
}

// removeTree is os.RemoveAll that also clears the user immutable/append
// flags a slot user may have set on its own files.
func removeTree(p string) error {
	if err := os.RemoveAll(p); err == nil {
		return nil
	}
	_ = filepath.WalkDir(p, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		// O_SYMLINK: a final symlink is opened itself, never followed.
		fd, err := unix.Open(path, unix.O_RDONLY|unix.O_SYMLINK|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if err == nil {
			_ = unix.Fchflags(fd, 0)
			unix.Close(fd)
		}
		return nil
	})
	return os.RemoveAll(p)
}

func treeSize(root string) int64 {
	var n int64
	_ = filepath.WalkDir(root, func(_ string, d fs.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() {
			if info, err := d.Info(); err == nil {
				n += info.Size()
			}
		}
		return nil
	})
	return n
}

// sharedTempDirs are the world-writable places a slot could leave files
// in outside its home (Seatbelt confines the agent, but code it starts
// outside Seatbelt -- simulator apps -- is not).
var sharedTempDirs = []string{"/private/tmp", "/private/var/tmp", "/Users/Shared", "/cores"}

// removeSharedFiles deletes the uid's files and empty directories in the
// shared temp dirs. find(1) walks physically (-P, the default) and on one
// file system, and only removes entries the uid owns.
func removeSharedFiles(uid int, logf func(string, ...any)) {
	for _, d := range sharedTempDirs {
		if _, err := os.Lstat(d); err != nil {
			continue
		}
		cmd := exec.Command("/usr/bin/find", "-x", d, "-user", strconv.Itoa(uid), "-delete")
		cmd.Dir = "/"
		_ = cmd.Run() // non-empty directories of the uid (others' files inside) stay
	}
}

// startSupervisor bootstraps slot s's LaunchDaemon again and waits for its
// socket.
func startSupervisor(s Slot) error {
	plist, err := inTrustedDir(filepath.Join(LaunchDaemonsDir, SupervisorLabel(s.N)+".plist"))
	if err != nil {
		return err
	}
	var lerr error
	for i := 0; i < 5; i++ {
		if _, lerr = run("/bin/launchctl", "bootstrap", "system", plist); lerr == nil {
			break
		}
		if loaded, _ := launchdLoaded(SupervisorLabel(s.N)); loaded {
			lerr = nil
			break
		}
		time.Sleep(time.Second)
	}
	if lerr != nil {
		return fmt.Errorf("restarting the supervisor: %w", lerr)
	}
	if err := waitFor(20*time.Second, func() bool {
		st, err := os.Lstat(SlotSocket(s.N))
		return err == nil && st.Mode()&os.ModeSocket != 0
	}); err != nil {
		return errors.New("the supervisor did not open its socket after the wipe")
	}
	return nil
}
