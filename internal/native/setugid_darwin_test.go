//go:build darwin

package native

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func kp(ruid, euid, svuid, rgid, svgid uint32, groups ...uint32) *unix.KinfoProc {
	var p unix.KinfoProc
	p.Proc.P_pid = 1234
	p.Eproc.Pcred.P_ruid, p.Eproc.Ucred.Uid, p.Eproc.Pcred.P_svuid = ruid, euid, svuid
	p.Eproc.Pcred.P_rgid, p.Eproc.Pcred.P_svgid = rgid, svgid
	p.Eproc.Ucred.Ngroups = int16(len(groups))
	copy(p.Eproc.Ucred.Groups[:], groups)
	return &p
}

func TestHoldsIDsSeesSavedAndGroupIDs(t *testing.T) {
	const a, ag, b, bg = 404, 404, 405, 405
	for _, c := range []struct {
		name string
		p    *unix.KinfoProc
		want bool
	}{
		{"real", kp(a, b, b, bg, bg, bg), true},
		{"effective", kp(b, a, b, bg, bg, bg), true},
		{"saved only (seteuid back after a setuid exec)", kp(b, b, a, bg, bg, bg), true},
		{"saved gid only", kp(b, b, b, bg, ag, bg), true},
		{"real gid", kp(b, b, b, ag, bg, bg), true},
		{"effective gid", kp(b, b, b, bg, bg, ag), true},
		{"supplementary gid", kp(b, b, b, bg, bg, bg, 20, ag), true},
		{"gid beyond ngroups is ignored", func() *unix.KinfoProc { p := kp(b, b, b, bg, bg, bg); p.Eproc.Ucred.Groups[3] = ag; return p }(), false},
		{"another slot", kp(b, b, b, bg, bg, bg, 12), false},
	} {
		if got := holdsIDs(c.p, a, ag); got != c.want {
			t.Errorf("%s: holdsIDs = %v, want %v", c.name, got, c.want)
		}
	}
	// gid 0 (a Slot without a gid) or one outside the slot range matches no gid.
	if holdsIDs(kp(b, b, b, 0, 0, 0), a, 0) {
		t.Error("gid 0 matched")
	}
	ids := &slotIDs{uids: map[uint32]bool{a: true}, gids: map[uint32]bool{ag: true}}
	if !ids.holdsAny(kp(b, b, a, bg, bg, bg)) || ids.holdsAny(kp(b, b, b, bg, bg, bg)) {
		t.Error("holdsAny")
	}
}

func TestKillAllResumesAReusedPID(t *testing.T) {
	alive := map[int]bool{100: true, 101: true}
	var sigs []string
	list := func() []int {
		var out []int
		for p, ok := range alive {
			if ok {
				out = append(out, p)
			}
		}
		return out
	}
	// 101 is reused by an innocent process between the listing and the kill.
	still := func(pid int) bool {
		if pid == 101 {
			alive[101] = false
			return false
		}
		return alive[pid]
	}
	kill := func(pid int, sig syscall.Signal) error {
		sigs = append(sigs, sig.String()+"@"+map[int]string{100: "100", 101: "101"}[pid])
		if sig == syscall.SIGKILL {
			alive[pid] = false
		}
		return nil
	}
	if n := killAll(list, still, kill, -1, 5, time.Millisecond); n != 1 {
		t.Fatalf("killed %d, want 1 (%v)", n, sigs)
	}
	for _, s := range sigs {
		if s == syscall.SIGKILL.String()+"@101" {
			t.Fatalf("killed the reused pid: %v", sigs)
		}
	}
	found := false
	for _, s := range sigs {
		found = found || s == syscall.SIGCONT.String()+"@101"
	}
	if !found {
		t.Fatalf("the reused pid was left stopped: %v", sigs)
	}
}

// The test user plays the slot user: its setuid files are stripped where
// they can be reached, and nothing is followed through a symlink.
func TestStripSlotSetugid(t *testing.T) {
	root := resolved(t, t.TempDir())
	outside := resolved(t, t.TempDir())
	os.Chmod(root, 0o755)
	mk := func(p string, mode os.FileMode) string {
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		st, _ := os.Stat(p)
		if st.Mode()&os.ModeSetuid == 0 && mode&os.ModeSetuid != 0 {
			t.Skipf("can't set setuid bits here (%s)", st.Mode())
		}
		return p
	}
	top := mk(filepath.Join(root, "su"), 0o755|os.ModeSetuid)
	deep := mk(filepath.Join(root, "a", "b", "c", "su"), 0o711|os.ModeSetuid)
	locked := mk(filepath.Join(root, "ro", "su"), 0o755|os.ModeSetuid)
	os.Chmod(filepath.Join(root, "ro"), 0o555) // the slot owns it: still swept
	flagged := mk(filepath.Join(root, "flagged"), 0o755|os.ModeSetuid)
	if err := unix.Chflags(flagged, unix.UF_IMMUTABLE); err != nil {
		t.Logf("chflags uchg: %v", err)
	}
	plain := mk(filepath.Join(root, "plain"), 0o755)
	target := mk(filepath.Join(outside, "target"), 0o755|os.ModeSetuid)
	os.Symlink(target, filepath.Join(root, "link"))
	os.Symlink(outside, filepath.Join(root, "dirlink"))
	t.Cleanup(func() {
		os.Chmod(filepath.Join(root, "ro"), 0o755)
		unix.Chflags(flagged, 0)
	})

	ids := &slotIDs{uids: map[uint32]bool{uint32(os.Getuid()): true}, gids: map[uint32]bool{}}
	res, writable := stripSlotSetugid(ids, []string{root})
	t.Logf("%+v", res)
	if len(writable) != 1 || writable[0] != root {
		t.Errorf("writable roots %v, want just %s (everything below is inside it)", writable, root)
	}
	for _, p := range []string{top, deep, locked, flagged} {
		st, err := os.Lstat(p)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 {
			t.Errorf("%s still %s", p, st.Mode())
		}
		if st.Mode().Perm() == 0 {
			t.Errorf("%s lost its permission bits", p)
		}
	}
	if st, _ := os.Lstat(plain); st.Mode() != 0o755 {
		t.Errorf("plain file changed: %s", st.Mode())
	}
	if st, _ := os.Lstat(target); st.Mode()&os.ModeSetuid == 0 {
		t.Error("the sweep followed a symlink out of the tree")
	}
	if len(res.Stripped) != 4 {
		t.Errorf("stripped %v, want 4", res.Stripped)
	}

	// A uid that is not a slot's is left alone.
	again := mk(filepath.Join(root, "again"), 0o755|os.ModeSetuid)
	other := &slotIDs{uids: map[uint32]bool{499: true}, gids: map[uint32]bool{}}
	stripSlotSetugid(other, []string{root})
	if st, _ := os.Lstat(again); st.Mode()&os.ModeSetuid == 0 {
		t.Error("stripped a file of a uid that is not a slot's")
	}
}

func TestSweepRootsSkipReadOnlyAndNosuid(t *testing.T) {
	roots := sweepRoots()
	t.Logf("sweep roots: %v", roots)
	for _, r := range roots {
		if r == "/" {
			t.Error("the sealed (read-only) system volume is a sweep root")
		}
		if r == "/dev" {
			t.Error("devfs is a sweep root")
		}
	}
}
