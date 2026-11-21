//go:build darwin

package hostsession

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/eduardkumskyi/clux-cli/internal/egress"
	"github.com/eduardkumskyi/clux-cli/internal/native"
	"github.com/eduardkumskyi/clux-cli/internal/supervisor"
)

// setuidHelperEnv makes this test binary act as the attacker's helper
// (TestRootSetuidHelper) instead of running tests.
const setuidHelperEnv = "CLUX_RT_SETUID_HELPER"

// TestRootSetuidHelper is not a test: started (as a copy of this binary)
// with CLUX_RT_SETUID_HELPER=<mode>:<target uid>:<status file>, it reports
// its real/effective/saved uids and
//   - hold: drops its effective uid back to its real one (keeping the
//     setuid file's uid as saved uid), reports again and waits forever;
//   - regain: tries seteuid(target) and reports whether it worked.
func TestRootSetuidHelper(t *testing.T) {
	spec := os.Getenv(setuidHelperEnv)
	if spec == "" {
		t.Skip("helper mode only")
	}
	parts := strings.SplitN(spec, ":", 3)
	target, _ := strconv.Atoi(parts[1])
	report := func(what string) {
		r, e, s := selfUIDs()
		f, err := os.OpenFile(parts[2], os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o666)
		if err == nil {
			fmt.Fprintf(f, "%s r=%d e=%d s=%d\n", what, r, e, s)
			f.Close()
		}
	}
	report("start")
	switch parts[0] {
	case "hold":
		_ = syscall.Seteuid(syscall.Getuid())
		report("dropped")
		for {
			time.Sleep(time.Second)
		}
	case "regain":
		if err := syscall.Seteuid(target); err != nil {
			report("regain-failed")
		} else {
			report("regained")
		}
	}
}

func selfUIDs() (r, e, s int) {
	p, err := unix.SysctlKinfoProc("kern.proc.pid", os.Getpid())
	if err != nil {
		return -1, -1, -1
	}
	return int(p.Eproc.Pcred.P_ruid), int(p.Eproc.Ucred.Uid), int(p.Eproc.Pcred.P_svuid)
}

// procsHolding lists processes holding uid as real, effective or saved uid.
func procsHolding(uid int) []string {
	procs, err := unix.SysctlKinfoProcSlice("kern.proc.all")
	if err != nil {
		return []string{"sysctl: " + err.Error()}
	}
	var out []string
	for i := range procs {
		p := &procs[i]
		pc := &p.Eproc.Pcred
		if int(pc.P_ruid) == uid || int(pc.P_svuid) == uid || int(p.Eproc.Ucred.Uid) == uid {
			if p.Proc.P_pid <= 1 || p.Proc.P_stat == 5 { // zombies can't act
				continue
			}
			cmd, _ := exec.Command("/bin/ps", "-ww", "-o", "command=", "-p", strconv.Itoa(int(p.Proc.P_pid))).Output()
			out = append(out, fmt.Sprintf("pid %d r=%d e=%d s=%d %s", p.Proc.P_pid, pc.P_ruid, p.Eproc.Ucred.Uid, pc.P_svuid, strings.TrimSpace(string(cmd))))
		}
	}
	return out
}

// TestRootSetuidCannotCarryASlotUID is a real-system test (root,
// CLUX_NATIVE_ROOT_TEST=1, installed pool of >= 2 slots; uses the last two,
// which must hold no workspace).
//
// Slot A's code (outside Seatbelt) makes setuid copies of a helper in
// /private/tmp, in its home (made searchable) and in a third-party style
// world-writable directory; slot B runs them, so its processes hold A's uid
// as saved uid after seteuid() back to B, and hard-links A's file into its
// own home. Workspace A is then deleted through the normal path. No process
// may hold A's uid in any form, no setuid file of A may be left anywhere B
// can reach, B's other processes must run again (the sweep stops them for
// a moment), and after the slot is handed to a new workspace B can't get
// A's uid back.
func TestRootSetuidCannotCarryASlotUID(t *testing.T) {
	if os.Getenv("CLUX_NATIVE_ROOT_TEST") == "" || os.Geteuid() != 0 {
		t.Skip("real-system test: run as root with CLUX_NATIVE_ROOT_TEST=1")
	}
	cfg, err := native.LoadConfig()
	if err != nil {
		t.Fatalf("native mode must be installed: %v", err)
	}
	if len(cfg.Slots) < 2 {
		t.Skip("needs two slots")
	}
	A, B := cfg.Slots[len(cfg.Slots)-1], cfg.Slots[len(cfg.Slots)-2]
	ctx := context.Background()
	kc := &native.KeeperClient{Socket: native.KeeperSocket}
	for _, s := range []native.Slot{A, B} {
		st, err := kc.State(ctx, s.N)
		if err != nil {
			t.Fatalf("keeper: %v", err)
		}
		if st.ClaimedBy != "" {
			t.Fatalf("slot %d is held by workspace %s; free it first", s.N, st.ClaimedBy)
		}
		if !st.Free() {
			if _, err := kc.Wipe(ctx, s.N, ""); err != nil {
				t.Fatalf("initial wipe of slot %d: %v", s.N, err)
			}
		}
	}
	const idA, idA2, idB = "990011", "990012", "990013"
	tag := fmt.Sprintf("clux-rt-su-%d", A.UID)
	tmpCopy := "/private/tmp/" + tag
	homeCopy := native.SlotHome(A.N) + "/" + tag
	wwDir := "/usr/local/" + tag + "-ww" // like a third-party 0777 dir, not a listed temp dir
	wwCopy := wwDir + "/su"
	linkInB := native.SlotHome(B.N) + "/" + tag + "-link"
	status := "/private/tmp/" + tag + "-status" // root's, 0666: the helpers append
	resetStatus := func() {
		os.Remove(status)
		if err := os.WriteFile(status, nil, 0o666); err != nil {
			t.Fatal(err)
		}
		os.Chmod(status, 0o666)
	}

	var bProcs []*exec.Cmd
	cleanup := func() {
		for _, c := range bProcs {
			if c.Process != nil {
				c.Process.Kill()
			}
		}
		for _, p := range []string{tmpCopy, wwCopy, linkInB, status} {
			os.Remove(p)
		}
		os.Remove(wwDir)
		for _, id := range []string{idA, idA2} {
			if st, err := kc.State(ctx, A.N); err == nil && st.ClaimedBy == id {
				_, _ = kc.Wipe(ctx, A.N, id)
			}
		}
		if st, err := kc.State(ctx, B.N); err == nil && st.ClaimedBy == idB {
			_, _ = kc.Wipe(ctx, B.N, idB)
		}
	}
	cleanup()
	defer cleanup()
	resetStatus()

	cred := func(s native.Slot) *syscall.SysProcAttr {
		return &syscall.SysProcAttr{Setsid: true, Credential: &syscall.Credential{Uid: uint32(s.UID), Gid: uint32(s.GID), Groups: []uint32{uint32(cfg.SlotsGID)}}}
	}
	as := func(s native.Slot, args ...string) ([]byte, error) {
		cmd := exec.Command(args[0], args[1:]...)
		cmd.SysProcAttr = cred(s)
		cmd.Env = []string{"HOME=" + native.SlotHome(s.N), "PATH=/usr/bin:/bin:/usr/sbin:/sbin", "USER=" + s.User}
		cmd.Dir = "/"
		return cmd.CombinedOutput()
	}
	helper := func(s native.Slot, bin, mode string) *exec.Cmd {
		cmd := exec.Command(bin, "-test.run=^TestRootSetuidHelper$")
		cmd.SysProcAttr = cred(s)
		cmd.Env = []string{setuidHelperEnv + "=" + mode + ":" + strconv.Itoa(A.UID) + ":" + status, "HOME=" + native.SlotHome(s.N)}
		cmd.Dir = "/"
		cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
		return cmd
	}
	readStatus := func() string { b, _ := os.ReadFile(status); return string(b) }

	// Both workspaces start.
	if err := kc.Claim(ctx, A.N, idA); err != nil {
		t.Fatalf("claim A: %v", err)
	}
	if err := kc.Claim(ctx, B.N, idB); err != nil {
		t.Fatalf("claim B: %v", err)
	}
	if st, err := os.Lstat(native.SlotHome(A.N)); err != nil || st.Mode().Perm() != 0o700 {
		t.Errorf("A's home at claim: %v %v, want 0700", st.Mode(), err)
	}

	// --- A plants setuid copies --------------------------------------------------
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(wwDir, 0o777); err != nil && !os.IsExist(err) {
		t.Fatal(err)
	}
	os.Chmod(wwDir, 0o777)
	for _, dst := range []string{tmpCopy, homeCopy, wwCopy} {
		if out, err := as(A, "/bin/sh", "-c", fmt.Sprintf("cp '%s' '%s' && chmod 4755 '%s'", self, dst, dst)); err != nil {
			t.Fatalf("A planting %s: %v %s", dst, err, out)
		}
		if st, err := os.Lstat(dst); err != nil || st.Mode()&os.ModeSetuid == 0 {
			t.Fatalf("A could not make %s setuid: %v %v", dst, st, err)
		}
	}
	if out, err := as(A, "/bin/chmod", "755", native.SlotHome(A.N)); err != nil {
		t.Fatalf("A opening its home: %v %s", err, out)
	}

	// --- B runs them and keeps A's uid as saved uid --------------------------------
	for _, bin := range []string{tmpCopy, homeCopy, wwCopy} {
		c := helper(B, bin, "hold")
		if err := c.Start(); err != nil {
			t.Fatalf("B running %s: %v", bin, err)
		}
		go c.Wait()
		bProcs = append(bProcs, c)
	}
	if out, err := as(B, "/bin/ln", tmpCopy, linkInB); err != nil {
		t.Fatalf("B hard-linking A's file: %v %s", err, out)
	}
	want := fmt.Sprintf("dropped r=%d e=%d s=%d", B.UID, B.UID, A.UID)
	if err := waitUntil(15*time.Second, func() bool { return strings.Count(readStatus(), want) == 3 }); err != nil {
		t.Fatalf("B's helpers did not end up holding A's uid as saved uid (%q):\n%s", want, readStatus())
	}
	t.Logf("before the delete:\n%s", readStatus())
	if held := procsHolding(A.UID); len(held) < 3 {
		t.Fatalf("the attack setup did not take: %v", held)
	}
	// An innocent process of B: the sweep may stop it for a moment only.
	sleeper := exec.Command("/bin/sleep", "600")
	sleeper.SysProcAttr = cred(B)
	if err := sleeper.Start(); err != nil {
		t.Fatal(err)
	}
	go sleeper.Wait()
	bProcs = append(bProcs, sleeper)

	// --- delete workspace A through the normal path --------------------------------
	mapPath := filepath.Join(t.TempDir(), "native-slots.json")
	os.WriteFile(mapPath, []byte(fmt.Sprintf(`{"workspaces":{%q:%d}}`, idA, A.N)), 0o600)
	slots, err := LoadSlotMap(mapPath, len(cfg.Slots))
	if err != nil {
		t.Fatal(err)
	}
	n := &NativeRuntime{
		Supervisor: func(i int) SupervisorCaller {
			return &supervisor.Client{Socket: native.SlotSocket(i), RootListener: true}
		},
		Slots: slots, Keeper: kc, Egress: egress.New([]byte("0123456789abcdef"), ""), ProxyPort: cfg.ProxyPort,
	}
	started := time.Now()
	if _, err := n.Delete(ctx, map[string]any{"workspace_id": idA}); err != nil {
		t.Fatalf("delete: %v", err)
	}
	t.Logf("delete took %s", time.Since(started).Round(time.Millisecond))
	time.Sleep(time.Second)

	for _, p := range procsHolding(A.UID) {
		if !strings.Contains(p, "native supervise --slot "+strconv.Itoa(A.N)) {
			t.Errorf("survived the delete holding A's uid: %s", p)
		}
	}
	for _, p := range []string{tmpCopy, homeCopy, wwCopy, linkInB} {
		st, err := os.Lstat(p)
		if err != nil {
			continue // removed: fine
		}
		if st.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 {
			t.Errorf("%s is still %s", p, st.Mode())
		} else {
			t.Logf("%s left without setuid: %s", p, st.Mode())
		}
	}
	out, _ := exec.Command("/usr/bin/find", "-x", "/private/tmp", "/private/var/tmp", "/Users/Shared", native.SlotsDir, wwDir,
		"-type", "f", "-perm", "+6000", "(", "-user", strconv.Itoa(A.UID), "-o", "-group", strconv.Itoa(A.GID), ")").CombinedOutput()
	if s := strings.TrimSpace(string(out)); s != "" {
		t.Errorf("setuid/setgid files of A left:\n%s", s)
	}
	p, err := unix.SysctlKinfoProc("kern.proc.pid", sleeper.Process.Pid)
	if err != nil {
		t.Errorf("B's innocent process is gone: %v", err)
	} else if p.Proc.P_stat == 4 {
		t.Error("B's innocent process was left stopped")
	}

	// --- the slot goes to a new workspace; B tries to get A's uid back --------------
	if err := kc.Claim(ctx, A.N, idA2); err != nil {
		t.Fatalf("claim of the reused slot: %v", err)
	}
	if st, err := os.Lstat(native.SlotHome(A.N)); err != nil || st.Mode().Perm() != 0o700 {
		t.Errorf("A's home handed out as %v %v, want 0700", st.Mode(), err)
	}
	resetStatus()
	for _, bin := range []string{linkInB, wwCopy} {
		if _, err := os.Lstat(bin); err != nil {
			continue
		}
		_ = helper(B, bin, "regain").Run()
	}
	got := readStatus()
	t.Logf("B's attempts after the reuse:\n%s", got)
	if strings.Contains(got, "regained") || strings.Contains(got, fmt.Sprintf("s=%d", A.UID)) || strings.Contains(got, fmt.Sprintf("e=%d", A.UID)) {
		t.Errorf("B got A's uid back after the reuse:\n%s", got)
	}
	if held := procsHolding(A.UID); len(held) > 0 {
		for _, h := range held {
			if !strings.Contains(h, "native supervise --slot "+strconv.Itoa(A.N)) {
				t.Errorf("after the reuse, holding A's uid: %s", h)
			}
		}
	}
}
