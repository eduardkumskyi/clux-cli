//go:build darwin

package hostsession

import (
	"bytes"
	"context"
	"fmt"
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

// TestRootSlotWipeLeavesNothingOfTheAgent is a real-system test: it needs
// root and an installed slot pool (CLUX_NATIVE_ROOT_TEST=1), and uses the
// last slot, which must hold no workspace.
//
// Acting as a hostile agent with code outside Seatbelt (running as the slot
// user), it plants a crontab, `launchctl submit` jobs (from the system
// bootstrap, where the supervisor runs, and from the user's own), a
// detached process and files in the home, the uid's temp dir and the shared
// temp dirs; then it SIGSTOPs its supervisor and tries to take over its
// socket and to pass a socket of its own off as the supervisor. The
// workspace is then deleted through NativeRuntime.Delete (root's keeper),
// and nothing of the uid may survive or come back.
func TestRootSlotWipeLeavesNothingOfTheAgent(t *testing.T) {
	if os.Getenv("CLUX_NATIVE_ROOT_TEST") == "" || os.Geteuid() != 0 {
		t.Skip("real-system test: run as root with CLUX_NATIVE_ROOT_TEST=1")
	}
	cfg, err := native.LoadConfig()
	if err != nil {
		t.Fatalf("native mode must be installed: %v", err)
	}
	s := cfg.Slots[len(cfg.Slots)-1]
	ctx := context.Background()
	kc := &native.KeeperClient{Socket: native.KeeperSocket}
	st, err := kc.State(ctx, s.N)
	if err != nil {
		t.Fatalf("keeper: %v", err)
	}
	if st.ClaimedBy != "" {
		t.Fatalf("slot %d is held by workspace %s; free it first", s.N, st.ClaimedBy)
	}
	if !st.Free() {
		if _, err := kc.Wipe(ctx, s.N, ""); err != nil {
			t.Fatalf("initial wipe: %v", err)
		}
	}
	const id = "990001"
	marker := fmt.Sprintf("clux-rt-%d", s.UID)
	uidS := strconv.Itoa(s.UID)
	const plantLabel = "space.clux.rt.plant"
	labels := []string{"space.clux.rt.persist-agent"}
	markerFile := func(name string) string { return "/private/tmp/" + marker + "-" + name }
	cleanup := func() {
		_, _ = exec.Command("/bin/launchctl", "bootout", "system/"+plantLabel).CombinedOutput()
		_, _ = exec.Command("/usr/bin/crontab", "-u", s.User, "-r").CombinedOutput()
		for _, l := range labels {
			_, _ = exec.Command("/bin/launchctl", "bootout", "user/"+uidS+"/"+l).CombinedOutput()
			_, _ = exec.Command("/bin/launchctl", "bootout", "gui/"+uidS+"/"+l).CombinedOutput()
		}
		matches, _ := filepath.Glob("/private/tmp/" + marker + "*")
		for _, m := range matches {
			os.Remove(m)
		}
		os.Remove("/private/var/tmp/" + marker + "-file")
		if st, err := kc.State(ctx, s.N); err == nil && st.ClaimedBy == id {
			_, _ = kc.Wipe(ctx, s.N, id)
		}
		_, _ = exec.Command("/bin/launchctl", "kickstart", "system/"+native.SupervisorLabel(s.N)).CombinedOutput()
	}
	cleanup()
	defer cleanup()

	// The workspace is "started": root records the claim, the host maps it.
	if err := kc.Claim(ctx, s.N, id); err != nil {
		t.Fatalf("claim: %v", err)
	}
	mapPath := filepath.Join(t.TempDir(), "native-slots.json")
	os.WriteFile(mapPath, []byte(fmt.Sprintf(`{"workspaces":{%q:%d}}`, id, s.N)), 0o600)
	slots, err := LoadSlotMap(mapPath, len(cfg.Slots))
	if err != nil {
		t.Fatal(err)
	}

	as := func(args ...string) ([]byte, error) {
		cmd := exec.Command(args[0], args[1:]...)
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(s.UID), Gid: uint32(s.GID), Groups: []uint32{uint32(cfg.SlotsGID)}}}
		cmd.Env = []string{"HOME=" + native.SlotHome(s.N), "PATH=/usr/bin:/bin:/usr/sbin:/sbin", "USER=" + s.User}
		cmd.Dir = "/"
		return cmd.CombinedOutput()
	}

	// --- plants -------------------------------------------------------------
	loop := func(name string) string {
		return fmt.Sprintf("while :; do /usr/bin/touch %s; /bin/sleep 2; done", markerFile(name))
	}
	// The agent's own context: a process launchd started as the slot user
	// in the system domain (like the supervisor's children), with its own
	// TCC responsibility. It installs a crontab, submits a launchd job and
	// leaves an escaped loop behind (AbandonProcessGroup).
	plantLog := markerFile("plant.log")
	script := strings.Join([]string{
		"exec >> " + plantLog + " 2>&1",
		"/usr/bin/id; /bin/launchctl managername",
		fmt.Sprintf(`printf '* * * * * /usr/bin/touch %s\n' | /usr/bin/crontab -; echo "crontab exit=$?"`, markerFile("cron")),
		"/usr/bin/crontab -l",
		fmt.Sprintf(`/bin/launchctl submit -l %s -- /bin/sh -c '%s'; echo "submit exit=$?"`, labels[0], loop("submit")),
		fmt.Sprintf(`/bin/sh -c '%s' </dev/null >/dev/null 2>&1 &`, loop("escaped")),
		"/usr/bin/touch " + markerFile("plant-done"),
	}, "\n")
	pdir, err := os.MkdirTemp("/private/var/tmp", "clux-rt-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(pdir)
	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>%s</string>
<key>UserName</key><string>%s</string><key>GroupName</key><string>%s</string><key>InitGroups</key><true/>
<key>ProgramArguments</key><array><string>/bin/sh</string><string>-c</string><string>%s</string></array>
<key>EnvironmentVariables</key><dict><key>HOME</key><string>%s</string></dict>
<key>RunAtLoad</key><true/><key>AbandonProcessGroup</key><true/>
</dict></plist>
`, plantLabel, s.User, s.User, xmlText(script), native.SlotHome(s.N))
	plistPath := filepath.Join(pdir, plantLabel+".plist")
	if err := os.WriteFile(plistPath, []byte(plist), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("/bin/launchctl", "bootstrap", "system", plistPath).CombinedOutput(); err != nil {
		t.Fatalf("starting the plant job: %v %s", err, out)
	}
	if err := waitUntil(20*time.Second, func() bool { _, err := os.Stat(markerFile("plant-done")); return err == nil }); err != nil {
		t.Fatal("the plant job did not finish")
	}
	_, _ = exec.Command("/bin/launchctl", "bootout", "system/"+plantLabel).CombinedOutput()
	if b, err := os.ReadFile(plantLog); err == nil {
		t.Logf("plant job output:\n%s", b)
	}
	cronPlanted := false
	if out, err := exec.Command("/usr/bin/crontab", "-u", s.User, "-l").CombinedOutput(); err == nil && strings.Contains(string(out), marker) {
		cronPlanted = true
	} else if _, err := os.Lstat("/private/var/at/tabs/" + s.User); err == nil {
		cronPlanted = true
	}
	t.Logf("crontab planted by the agent: %v", cronPlanted)

	detached := exec.Command("/bin/sh", "-c", loop("detached"))
	detached.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Credential: &syscall.Credential{Uid: uint32(s.UID), Gid: uint32(s.GID), Groups: []uint32{}}}
	detached.Dir = "/"
	if err := detached.Start(); err != nil {
		t.Fatal(err)
	}
	go detached.Wait()

	tmpOut, _ := as("/usr/bin/getconf", "DARWIN_USER_TEMP_DIR")
	userTemp := strings.TrimSpace(string(tmpOut))
	files := []string{
		native.SlotHome(s.N) + "/planted",
		native.SlotHome(s.N) + "/Library/LaunchAgents/evil.plist",
		filepath.Join(userTemp, "planted"),
		"/private/tmp/" + marker + "-file",
		"/private/var/tmp/" + marker + "-file",
	}
	for _, f := range files {
		if out, err := as("/bin/sh", "-c", "mkdir -p \"$(dirname '"+f+"')\" && echo x > '"+f+"'"); err != nil {
			t.Fatalf("planting %s: %v %s", f, err, out)
		}
	}
	// Wait until every persistence vector demonstrably runs.
	running := map[string]bool{}
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) && len(running) < 3 {
		for _, n := range []string{"submit", "escaped", "detached"} {
			if _, err := os.Stat(markerFile(n)); err == nil {
				running[n] = true
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	for _, dom := range []string{"user/" + uidS, "gui/" + uidS} {
		out, _ := exec.Command("/bin/launchctl", "print", dom+"/"+labels[0]).CombinedOutput()
		if strings.Contains(string(out), "state =") {
			t.Logf("submitted job is loaded in %s", dom)
		}
	}
	t.Logf("persistence running before the delete: %v (cron fires on the minute)", running)
	if !running["detached"] || !running["escaped"] {
		t.Fatal("the detached/escaped plants never ran")
	}
	if !running["submit"] {
		t.Log("the agent's launchctl submit job did not run; that vector is not available to it")
	}

	// --- STOP the supervisor, try to impersonate it -----------------------------
	supPID := supervisorPID(t, s)
	if supPID == 0 {
		t.Fatal("slot supervisor not running")
	}
	if out, err := as("/bin/kill", "-STOP", strconv.Itoa(supPID)); err != nil {
		t.Logf("SIGSTOP of the supervisor as the slot user failed: %v %s", err, out)
	} else {
		t.Logf("the slot user stopped its supervisor (pid %d): expected, same uid", supPID)
	}
	if _, err := as("/bin/rm", "-f", native.SlotSocket(s.N)); err == nil {
		if _, serr := os.Lstat(native.SlotSocket(s.N)); serr != nil {
			t.Error("the slot user unlinked its supervisor's socket")
		}
	}
	bindCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	bind := exec.CommandContext(bindCtx, "/usr/bin/nc", "-lU", native.SlotSocketDir(s.N)+"/fake.sock")
	bind.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(s.UID), Gid: uint32(s.GID), Groups: []uint32{}}}
	_ = bind.Run()
	cancel()
	if _, err := os.Lstat(native.SlotSocketDir(s.N) + "/fake.sock"); err == nil {
		t.Error("the slot user bound a socket in its supervisor's socket dir")
	}
	fake := "/private/tmp/" + marker + ".sock"
	var got bytes.Buffer
	fakeSrv := exec.Command("/usr/bin/nc", "-lU", fake)
	fakeSrv.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(s.UID), Gid: uint32(s.GID), Groups: []uint32{}}}
	fakeSrv.Stdout = &got
	if err := fakeSrv.Start(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 40; i++ {
		if _, err := os.Lstat(fake); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	cctx, ccancel := context.WithTimeout(ctx, 3*time.Second)
	_, err = (&supervisor.Client{Socket: fake, RootListener: true}).Call(cctx, supervisor.Request{
		Op: supervisor.OpStart, WorkspaceID: "990002", HMACSecret: "SECRET-hmac", GithubCloneURL: "https://x-access-token:SECRET-pat@github.com/o/r.git",
	})
	ccancel()
	if err == nil || !strings.Contains(err.Error(), "refusing to use it") {
		t.Errorf("client used the agent's fake supervisor socket: %v", err)
	}
	time.Sleep(200 * time.Millisecond)
	fakeSrv.Process.Kill()
	fakeSrv.Wait()
	if strings.Contains(got.String(), "SECRET") || got.Len() > 0 {
		t.Errorf("the fake supervisor received %q", got.String())
	}
	// The real (stopped) supervisor's socket passes the identity check:
	// root created it, also after the supervisor dropped to the slot uid.
	cctx, ccancel = context.WithTimeout(ctx, 2*time.Second)
	_, err = (&supervisor.Client{Socket: native.SlotSocket(s.N), RootListener: true}).Call(cctx, supervisor.Request{Op: supervisor.OpStatus})
	ccancel()
	if err != nil && strings.Contains(err.Error(), "refusing") {
		t.Errorf("the real supervisor socket failed the root-listener check: %v", err)
	}
	t.Logf("call to the stopped real supervisor: %v (identity check passed; no answer while stopped)", err)

	// --- delete through the normal path -------------------------------------------
	n := &NativeRuntime{
		Supervisor: func(i int) SupervisorCaller {
			return &supervisor.Client{Socket: native.SlotSocket(i), RootListener: true}
		},
		Slots: slots, Keeper: kc, Egress: egress.New([]byte("0123456789abcdef"), ""), ProxyPort: cfg.ProxyPort,
	}
	wipeStart := time.Now()
	res, err := n.Delete(ctx, map[string]any{"workspace_id": id})
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	t.Logf("delete took %s: %v", time.Since(wipeStart).Round(time.Millisecond), res)
	if _, ok := slots.Lookup(id); ok {
		t.Error("slot not released")
	}
	if st, err := kc.State(ctx, s.N); err != nil || !st.Free() {
		t.Errorf("keeper state after delete: %+v %v", st, err)
	}

	check := func(when string) {
		for _, p := range uidProcs(s.UID) {
			if p.start.Before(wipeStart) || strings.Contains(p.cmd, marker) || p.pid == supPID {
				t.Errorf("%s: process of uid %d survived: pid %d started %s: %s", when, s.UID, p.pid, p.start.Format(time.RFC3339), p.cmd)
			}
		}
		if out, err := exec.Command("/usr/bin/crontab", "-u", s.User, "-l").CombinedOutput(); err == nil && strings.Contains(string(out), marker) {
			t.Errorf("%s: crontab survived: %s", when, out)
		}
		if _, err := os.Lstat("/private/var/at/tabs/" + s.User); err == nil {
			t.Errorf("%s: /private/var/at/tabs/%s survived", when, s.User)
		}
		for _, dom := range []string{"user/" + uidS, "gui/" + uidS} {
			out, _ := exec.Command("/bin/launchctl", "print", dom).CombinedOutput()
			for _, l := range labels {
				if strings.Contains(string(out), l) {
					t.Errorf("%s: launchd job %s survived in %s", when, l, dom)
				}
			}
		}
	}
	time.Sleep(time.Second) // let this process reap its killed children
	check("right after the delete")
	for _, f := range files {
		if _, err := os.Lstat(f); err == nil {
			t.Errorf("%s survived the wipe", f)
		}
	}
	// A fresh supervisor serves the slot again, on a root-created socket.
	if err := waitUntil(20*time.Second, func() bool { return supervisorPID(t, s) != 0 }); err != nil {
		t.Error("no supervisor after the wipe")
	}
	cctx, ccancel = context.WithTimeout(ctx, 5*time.Second)
	_, err = (&supervisor.Client{Socket: native.SlotSocket(s.N), RootListener: true}).Call(cctx, supervisor.Request{Op: supervisor.OpStatus})
	ccancel()
	if err == nil || !strings.Contains(err.Error(), "only the machine owner") {
		t.Errorf("fresh supervisor: want its owner-only refusal of root (identity check passed), got %v", err)
	}

	// Nothing comes back: cron fires every minute, the jobs every 2 s.
	matches, _ := filepath.Glob("/private/tmp/" + marker + "-*")
	for _, m := range matches {
		os.Remove(m)
	}
	time.Sleep(70 * time.Second)
	matches, _ = filepath.Glob("/private/tmp/" + marker + "-*")
	if len(matches) > 0 {
		t.Errorf("persistence fired after the delete: %v", matches)
	}
	check("70 s after the delete")
}

func xmlText(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")
	return r.Replace(s)
}

type uidProc struct {
	pid   int
	start time.Time
	cmd   string
}

func uidProcs(uid int) []uidProc {
	seen := map[int]bool{}
	var out []uidProc
	for _, name := range []string{"kern.proc.uid", "kern.proc.ruid"} {
		procs, err := unix.SysctlKinfoProcSlice(name, uid)
		if err != nil {
			continue
		}
		for _, p := range procs {
			pid := int(p.Proc.P_pid)
			if pid <= 1 || seen[pid] {
				continue
			}
			seen[pid] = true
			cmd, _ := exec.Command("/bin/ps", "-ww", "-o", "command=", "-p", strconv.Itoa(pid)).Output()
			out = append(out, uidProc{pid: pid, start: time.Unix(p.Proc.P_starttime.Sec, int64(p.Proc.P_starttime.Usec)*1000), cmd: strings.TrimSpace(string(cmd))})
		}
	}
	return out
}

func supervisorPID(t *testing.T, s native.Slot) int {
	for _, p := range uidProcs(s.UID) {
		if strings.Contains(p.cmd, "native supervise --slot "+strconv.Itoa(s.N)) {
			return p.pid
		}
	}
	return 0
}

func waitUntil(d time.Duration, cond func() bool) error {
	deadline := time.Now().Add(d)
	for !cond() {
		if time.Now().After(deadline) {
			return fmt.Errorf("timeout")
		}
		time.Sleep(250 * time.Millisecond)
	}
	return nil
}
