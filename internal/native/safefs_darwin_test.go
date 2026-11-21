//go:build darwin

package native

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// trustedTemp returns a resolved temp dir that the helpers treat as
// root-controlled (the test's own uid is added to trustedUIDs).
func trustedTemp(t *testing.T) string {
	t.Helper()
	old, lu, lg := trustedUIDs, lockUID, lockGID
	trustedUIDs, lockUID, lockGID = []int{0, os.Getuid()}, os.Getuid(), os.Getgid()
	t.Cleanup(func() { trustedUIDs, lockUID, lockGID = old, lu, lg })
	d, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(d, 0o755); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestWriteFileSafeReplacesSymlinkInsteadOfFollowing(t *testing.T) {
	d := trustedTemp(t)
	victim := filepath.Join(d, "victim")
	os.WriteFile(victim, []byte("original"), 0o600)
	link := filepath.Join(d, "pf.json")
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}
	// The old fixed temp name, planted as a symlink too.
	os.Symlink(victim, link+".tmp")
	if err := writeFileSafe(link, []byte("new"), 0o644, os.Getuid(), os.Getgid()); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(victim); string(b) != "original" {
		t.Fatalf("write followed the symlink: victim = %q", b)
	}
	st, err := os.Lstat(link)
	if err != nil || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm() != 0o644 {
		t.Fatalf("result is not a 0644 regular file: %v %v", st.Mode(), err)
	}
	entries, _ := os.ReadDir(d)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".pf.json.") {
			t.Errorf("temp file left behind: %s", e.Name())
		}
	}
}

func TestWriteFileSafeRefusesUntrustedDirectory(t *testing.T) {
	d := trustedTemp(t)
	open := filepath.Join(d, "agentdir")
	os.Mkdir(open, 0o777)
	os.Chmod(open, 0o777) // writable by others: not root-controlled
	if err := writeFileSafe(filepath.Join(open, "x"), []byte("x"), 0o644, os.Getuid(), os.Getgid()); err == nil {
		t.Fatal("wrote into a world-writable directory")
	}
	// A directory reached through a symlink is judged by its target.
	link := filepath.Join(d, "link")
	os.Symlink(open, link)
	if err := writeFileSafe(filepath.Join(link, "x"), []byte("x"), 0o644, os.Getuid(), os.Getgid()); err == nil {
		t.Fatal("wrote into a world-writable directory via a symlink")
	}
	trustedUIDs = []int{0} // the temp dir is the test user's, not root's
	if err := writeFileSafe(filepath.Join(d, "y"), []byte("y"), 0o644, os.Getuid(), os.Getgid()); err == nil {
		t.Fatal("wrote into a directory not owned by root")
	}
}

func TestEnsureDirInRefusesSymlinkAndForeignOwner(t *testing.T) {
	d := trustedTemp(t)
	target := filepath.Join(d, "etc-periodic-daily")
	os.Mkdir(target, 0o755)
	home := filepath.Join(d, "slot1")
	os.Symlink(target, home)
	if err := ensureDirIn(home, 0o700, os.Getuid(), os.Getgid()); err == nil {
		t.Fatal("accepted a symlink as the slot home")
	}
	if st, _ := os.Stat(target); st.Mode().Perm() != 0o755 {
		t.Fatalf("symlink target was modified: %v", st.Mode())
	}
	// An existing directory of a uid other than root/the wanted owner.
	other := filepath.Join(d, "slot2")
	os.Mkdir(other, 0o755)
	var foreign *ForeignOwnerError
	if err := ensureDirIn(other, 0o700, 4242, 4242); !errors.As(err, &foreign) || foreign.UID != os.Getuid() {
		t.Fatalf("foreign owner not refused: %v", err)
	}
	// A regular file in the way.
	f := filepath.Join(d, "slot3")
	os.WriteFile(f, nil, 0o600)
	if err := ensureDirIn(f, 0o700, os.Getuid(), os.Getgid()); err == nil {
		t.Fatal("accepted a file as a directory")
	}
	// Normal case: created and moded.
	ok := filepath.Join(d, "slot4")
	if err := ensureDirIn(ok, 0o700, os.Getuid(), os.Getgid()); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Lstat(ok); !st.IsDir() || st.Mode().Perm() != 0o700 {
		t.Fatalf("slot4: %v", st.Mode())
	}
}

func TestEnsureFileInRefusesLinks(t *testing.T) {
	d := trustedTemp(t)
	victim := filepath.Join(d, "victim")
	os.WriteFile(victim, []byte("v"), 0o644)
	sym := filepath.Join(d, "supervisor-1.log")
	os.Symlink(victim, sym)
	if err := ensureFileIn(sym, 0o640, os.Getuid(), os.Getgid()); err == nil {
		t.Fatal("followed a symlinked log file")
	}
	hard := filepath.Join(d, "supervisor-2.log")
	if err := os.Link(victim, hard); err != nil {
		t.Fatal(err)
	}
	if err := ensureFileIn(hard, 0o640, os.Getuid(), os.Getgid()); err == nil {
		t.Fatal("accepted a hard-linked log file")
	}
	if st, _ := os.Stat(victim); st.Mode().Perm() != 0o644 {
		t.Fatalf("victim modified: %v", st.Mode())
	}
}

func TestQuarantineLocksAndRemoves(t *testing.T) {
	d := trustedTemp(t)
	victim := filepath.Join(d, "victim")
	os.WriteFile(victim, []byte("keep"), 0o600)
	old := filepath.Join(d, "run")
	os.MkdirAll(filepath.Join(old, "sub"), 0o755)
	os.Symlink(victim, filepath.Join(old, "sub", "pf.json"))
	q, err := quarantine(old)
	if err != nil || q == "" {
		t.Fatalf("quarantine: %q %v", q, err)
	}
	if st, _ := os.Lstat(q); st.Mode().Perm() != 0o700 {
		t.Fatalf("quarantined dir mode %v", st.Mode())
	}
	if _, err := os.Lstat(old); !os.IsNotExist(err) {
		t.Fatal("original name still present")
	}
	if err := os.RemoveAll(q); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(victim); string(b) != "keep" {
		t.Fatal("removal followed a symlink")
	}
	if q, err := quarantine(filepath.Join(d, "missing")); q != "" || err != nil {
		t.Fatalf("missing: %q %v", q, err)
	}
	os.Mkdir(filepath.Join(d, "home"), 0o755)
	q, err = quarantineAs(filepath.Join(d, "home"), "home-legacy-1")
	if err != nil || q != filepath.Join(d, "home-legacy-1") {
		t.Fatalf("quarantineAs: %q %v", q, err)
	}
	if st, _ := os.Lstat(q); st.Mode().Perm() != 0o700 {
		t.Fatalf("legacy dir mode %v", st.Mode())
	}
	os.Mkdir(filepath.Join(d, "home"), 0o755)
	if _, err := quarantineAs(filepath.Join(d, "home"), "home-legacy-1"); err == nil {
		t.Fatal("overwrote an existing quarantine dir")
	}
	if _, err := quarantineAs(filepath.Join(d, "home"), "../escape"); err == nil {
		t.Fatal("accepted a name outside the directory")
	}
}

func TestReadRootFileRejectsUntrusted(t *testing.T) {
	d := trustedTemp(t)
	good := filepath.Join(d, "pf.json")
	os.WriteFile(good, []byte(`{"enabled":true}`), 0o644)
	if b, err := readRootFile(good); err != nil || string(b) != `{"enabled":true}` {
		t.Fatalf("good: %q %v", b, err)
	}
	ww := filepath.Join(d, "ww.json")
	os.WriteFile(ww, []byte(`{}`), 0o666)
	os.Chmod(ww, 0o666)
	if _, err := readRootFile(ww); err == nil {
		t.Fatal("accepted a group/world-writable status file")
	}
	link := filepath.Join(d, "link.json")
	os.Symlink(good, link)
	if _, err := readRootFile(link); err == nil {
		t.Fatal("accepted a symlinked status file")
	}
	trustedUIDs = []int{0}
	if _, err := readRootFile(good); err == nil {
		t.Fatal("accepted a status file not owned by root")
	}
}

func TestKillAllStopsThenKillsUntilEmpty(t *testing.T) {
	alive := map[int]bool{100: true, 101: true, 7: true, 1: true}
	var sigs []string
	forked := false
	list := func() []int {
		var out []int
		for p, ok := range alive {
			if ok {
				out = append(out, p)
			}
		}
		return out
	}
	kill := func(pid int, sig syscall.Signal) error {
		sigs = append(sigs, sig.String())
		if sig == syscall.SIGKILL {
			alive[pid] = false
			if pid == 100 && !forked { // a child appears during the sweep
				forked = true
				alive[102] = true
			}
		}
		return nil
	}
	n := killAll(list, func(pid int) bool { return alive[pid] }, kill, 7, 10, time.Millisecond)
	if alive[100] || alive[101] || alive[102] {
		t.Fatalf("survivors: %v", alive)
	}
	if !alive[7] || !alive[1] {
		t.Fatal("killed the excluded pid or launchd")
	}
	if n != 3 {
		t.Fatalf("killed %d, want 3", n)
	}
	if sigs[0] != syscall.SIGSTOP.String() {
		t.Fatalf("first signal %s, want SIGSTOP", sigs[0])
	}
}
