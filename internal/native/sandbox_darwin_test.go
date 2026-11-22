//go:build darwin

package native

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func resolved(t *testing.T, p string) string {
	t.Helper()
	r, err := filepath.EvalSymlinks(p)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func getconf(t *testing.T, name string) string {
	t.Helper()
	out, err := exec.Command("/usr/bin/getconf", name).Output()
	if err != nil {
		t.Skip("getconf:", err)
	}
	return resolved(t, strings.TrimSuffix(strings.TrimSpace(string(out)), "/"))
}

// Runs the generated profile through the real sandbox-exec: it must parse,
// allow the workspace, and deny a sibling directory (another workspace).
func TestSandboxProfileEnforced(t *testing.T) {
	if _, err := os.Stat("/usr/bin/sandbox-exec"); err != nil {
		t.Skip("no sandbox-exec")
	}
	// Not t.TempDir(): that lives in this user's confstr temp dir, which the
	// profile opens whole (it's the agent's own; workspaces never live there).
	tmp, err := os.MkdirTemp("/private/tmp", "clux-sb-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(tmp) })
	root := resolved(t, tmp)
	ws := filepath.Join(root, "workspaces", "12")
	other := filepath.Join(root, "workspaces", "13")
	home := filepath.Join(root, "home")
	rt := filepath.Join(root, "runtime")
	for _, d := range []string{ws, other, filepath.Join(home, "Library"), rt} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	os.WriteFile(filepath.Join(other, "secret"), []byte("other workspace"), 0o600)
	os.WriteFile(filepath.Join(ws, "mine"), []byte("ok"), 0o600)
	os.MkdirAll(filepath.Join(ws, "repo", ".git", "hooks"), 0o700)

	prof, err := SandboxProfile(ProfileParams{
		WorkspaceDir: ws, AgentHome: home, RuntimeDir: rt,
		UserCache: getconf(t, "DARWIN_USER_CACHE_DIR"), UserTemp: getconf(t, "DARWIN_USER_TEMP_DIR"),
	})
	if err != nil {
		t.Fatal(err)
	}
	pf := filepath.Join(root, "p.sb")
	os.WriteFile(pf, []byte(prof), 0o600)
	run := func(args ...string) error {
		cmd := exec.Command("/usr/bin/sandbox-exec", append([]string{"-f", pf}, args...)...)
		cmd.Dir = ws
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Logf("%v: %s", args, out)
		}
		return err
	}
	if err := run("/bin/cat", filepath.Join(ws, "mine")); err != nil {
		t.Fatalf("workspace file not readable: %v", err)
	}
	if err := run("/usr/bin/touch", filepath.Join(ws, "new")); err != nil {
		t.Fatalf("workspace not writable: %v", err)
	}
	// SwiftPM/Xcode temp files in the confstr temp dir ("unable to make
	// temporary file" otherwise).
	probe := filepath.Join(getconf(t, "DARWIN_USER_TEMP_DIR"), filepath.Base(root)+".probe")
	t.Cleanup(func() { os.Remove(probe) })
	if err := run("/usr/bin/touch", probe); err != nil {
		t.Fatalf("confstr temp dir not writable: %v", err)
	}
	if run("/bin/cat", filepath.Join(other, "secret")) == nil {
		t.Fatal("another workspace's file was readable")
	}
	if run("/usr/bin/touch", filepath.Join(ws, "repo", ".git", "hooks", "pre-commit")) == nil {
		t.Fatal("git hook write allowed")
	}
	home0, _ := os.UserHomeDir()
	if run("/bin/ls", home0) == nil {
		t.Fatal("owner home listable")
	}
	// No setuid/setgid bits from inside, and no exec of a setuid file (the
	// kernel's own rule for sandboxed processes).
	bin := filepath.Join(ws, "tool")
	if b, err := os.ReadFile("/usr/bin/true"); err == nil {
		os.WriteFile(bin, b, 0o755)
	}
	if run("/bin/chmod", "u+s", bin) == nil {
		t.Fatal("chmod u+s allowed in the sandbox")
	}
	if st, _ := os.Stat(bin); st != nil && st.Mode()&os.ModeSetuid != 0 {
		t.Fatal("the sandbox set a setuid bit")
	}
	if run("/bin/chmod", "755", bin) != nil {
		t.Fatal("plain chmod denied")
	}
	if run(bin) != nil {
		t.Fatal("the plain copy does not run in the sandbox")
	}
	os.Chmod(bin, 0o755|os.ModeSetuid) // outside the sandbox: the owner may
	if st, _ := os.Stat(bin); st != nil && st.Mode()&os.ModeSetuid != 0 {
		if run(bin) == nil {
			t.Fatal("a sandboxed process executed a setuid file")
		}
	}
}

// A supervisor whose getconf failed passes the /private/var/empty
// fallbacks; the agent's real confstr temp dir must still be writable.
func TestSandboxProfileAllowsConfstrDirsWithoutResolvedPaths(t *testing.T) {
	if _, err := os.Stat("/usr/bin/sandbox-exec"); err != nil {
		t.Skip("no sandbox-exec")
	}
	tmp, err := os.MkdirTemp("/private/tmp", "clux-sb-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(tmp) })
	root := resolved(t, tmp)
	ws, home, rt := filepath.Join(root, "ws"), filepath.Join(root, "home"), filepath.Join(root, "rt")
	for _, d := range []string{ws, filepath.Join(home, "Library"), rt} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	prof, err := SandboxProfile(ProfileParams{
		WorkspaceDir: ws, AgentHome: home, RuntimeDir: rt,
		UserCache: "/private/var/empty/cache", UserTemp: "/private/var/empty/temp",
	})
	if err != nil {
		t.Fatal(err)
	}
	pf := filepath.Join(root, "p.sb")
	os.WriteFile(pf, []byte(prof), 0o600)
	probe := filepath.Join(getconf(t, "DARWIN_USER_TEMP_DIR"), filepath.Base(root)+".probe")
	t.Cleanup(func() { os.Remove(probe) })
	out, err := exec.Command("/usr/bin/sandbox-exec", "-f", pf, "/usr/bin/touch", probe).CombinedOutput()
	if err != nil {
		t.Fatalf("confstr temp dir not writable with fallback params: %v %s", err, out)
	}
}
