//go:build darwin

package native

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// TestRootReinstallRefusesAgentSymlinks is a real-system test: it needs
// root, an installed slot pool and the clux binary to install with
// (CLUX_NATIVE_ROOT_TEST_BIN), and it re-runs `clux native install`.
//
// As slot users it plants symlinks and hard links everywhere the
// single-user installer used to write, chown or chmod as root (inside the
// agent's home, the old run dir names, the socket dir), pointing at
// root-owned victims, then reinstalls and checks that no victim changed and
// that the slots can't write where root keeps pf state.
func TestRootReinstallRefusesAgentSymlinks(t *testing.T) {
	bin := os.Getenv("CLUX_NATIVE_ROOT_TEST_BIN")
	if bin == "" || os.Geteuid() != 0 {
		t.Skip("real-system test: run as root with CLUX_NATIVE_ROOT_TEST_BIN=<clux binary>")
	}
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("native mode must be installed: %v", err)
	}
	if len(cfg.Slots) < 2 {
		t.Fatal("need at least 2 slots")
	}
	s1, s2 := cfg.Slots[0], cfg.Slots[1]

	// Root-owned victims (a stand-in for /etc/periodic/daily and the like).
	vroot, err := os.MkdirTemp("/private/var/tmp", "clux-victim-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(vroot)
	os.Chmod(vroot, 0o755)
	vdir := filepath.Join(vroot, "dir")
	vfile := filepath.Join(vroot, "file")
	os.Mkdir(vdir, 0o755)
	os.WriteFile(vfile, []byte("victim\n"), 0o644)
	snapshot := func() map[string][3]uint32 {
		out := map[string][3]uint32{}
		for _, p := range []string{vroot, vdir, vfile} {
			st, err := os.Lstat(p)
			if err != nil {
				t.Fatal(err)
			}
			sys := st.Sys().(*syscall.Stat_t)
			out[p] = [3]uint32{sys.Uid, sys.Gid, uint32(st.Mode())}
		}
		return out
	}
	before := snapshot()

	as := func(s Slot, args ...string) error {
		return runAs(s.UID, s.GID, nil, args[0], args[1:]...)
	}
	home1, home2 := SlotHome(s1.N), SlotHome(s2.N)
	plants := [][]string{
		// Old root ensureDir targets inside the agent home.
		{"/bin/mkdir", "-p", home1 + "/Library/Developer"},
		{"/bin/rm", "-rf", home1 + "/Library/Developer/Xcode", home1 + "/Library/Logs"},
		{"/bin/ln", "-s", vdir, home1 + "/Library/Developer/Xcode"},
		{"/bin/ln", "-s", vdir, home1 + "/Library/Logs"},
		// Old root writeOwned target: the simulator mapping.
		{"/bin/mkdir", "-p", home2 + "/Library/Developer/Xcode"},
		{"/bin/rm", "-f", home2 + "/Library/Developer/Xcode/SDKToSimulatorIndexMapping.plist"},
		{"/bin/ln", "-s", vfile, home2 + "/Library/Developer/Xcode/SDKToSimulatorIndexMapping.plist"},
		// Hard link to a root file in the agent's home.
		{"/bin/ln", "-f", vfile, home2 + "/hardlink"},
		// The slot's own socket dir: names root used to write in the run dir.
		{"/bin/ln", "-sf", vfile, SlotSocketDir(s1.N) + "/pf.json"},
		{"/bin/ln", "-sf", vfile, SlotSocketDir(s1.N) + "/pf.json.tmp"},
		{"/bin/ln", "-sf", vfile, SlotSocketDir(s1.N) + "/pf.token.tmp"},
	}
	for _, p := range plants {
		s := s1
		if bytes.Contains([]byte(p[len(p)-1]), []byte(home2)) {
			s = s2
		}
		if err := as(s, p...); err != nil {
			t.Fatalf("planting %v: %v", p, err)
		}
	}
	defer func() {
		_ = as(s1, "/bin/rm", "-rf", home1+"/Library/Developer/Xcode", home1+"/Library/Logs",
			SlotSocketDir(s1.N)+"/pf.json", SlotSocketDir(s1.N)+"/pf.json.tmp", SlotSocketDir(s1.N)+"/pf.token.tmp")
		_ = as(s2, "/bin/rm", "-f", home2+"/Library/Developer/Xcode/SDKToSimulatorIndexMapping.plist", home2+"/hardlink")
		for _, s := range []Slot{s1, s2} {
			_, _ = run("/bin/launchctl", "kickstart", "-k", "system/"+SupervisorLabel(s.N))
		}
	}()

	// What a slot must never manage to do.
	for _, try := range []struct {
		s    Slot
		args []string
	}{
		{s1, []string{"/usr/bin/touch", RunDir + "/pf.json.tmp"}},
		{s1, []string{"/usr/bin/touch", PFStatusPath}},
		{s1, []string{"/bin/mkdir", RunDir + "/x"}},
		{s1, []string{"/bin/mkdir", SlotsDir + "/99"}},
		{s1, []string{"/usr/bin/touch", SlotSocketDir(s2.N) + "/supervisor.sock.x"}},
		{s1, []string{"/bin/ls", home2}},
		{s1, []string{"/usr/bin/touch", RuntimeRoot + "/sidecar/x"}},
	} {
		if err := as(try.s, try.args...); err == nil {
			t.Errorf("slot %d could %v", try.s.N, try.args)
		}
	}

	out, err := exec.Command(bin, "native", "install", "--owner", cfg.OwnerUser).CombinedOutput()
	t.Logf("install:\n%s", out)
	if err != nil {
		t.Errorf("reinstall: %v", err)
	}
	time.Sleep(3 * time.Second) // supervisors restart and prepare their homes

	after := snapshot()
	for p, b := range before {
		if a := after[p]; a != b {
			t.Errorf("%s changed: uid/gid/mode %v -> %v", p, b, a)
		}
	}
	if b, _ := os.ReadFile(vfile); string(b) != "victim\n" {
		t.Errorf("victim file content changed: %q", b)
	}
	entries, _ := os.ReadDir(vdir)
	if len(entries) != 0 {
		t.Errorf("something was created in the victim dir: %v", entries)
	}
	for _, p := range []string{RunDir, PFStatusPath, PFTokenPath, PFEffectivePath, SlotRunDir} {
		st, err := os.Lstat(p)
		if err != nil {
			t.Errorf("%s: %v", p, err)
			continue
		}
		sys := st.Sys().(*syscall.Stat_t)
		if sys.Uid != 0 || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm()&0o022 != 0 {
			t.Errorf("%s: uid %d mode %v; want root-owned, writable by root only", p, sys.Uid, st.Mode())
		}
	}
	if _, err := ReadPFStatus(); err != nil {
		t.Errorf("pf status not trusted after reinstall: %v", err)
	}
}
