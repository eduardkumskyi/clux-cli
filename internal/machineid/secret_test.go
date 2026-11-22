package machineid

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestSecretCreatedOnceWithStrictMode(t *testing.T) {
	dir := filepath.Join(t.TempDir(), ".clux")
	a, err := loadOrCreateSecret(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !ValidSecret(a) || len(a) != 43 {
		t.Fatalf("secret %q is not 43 base64url chars", a)
	}
	b, err := loadOrCreateSecret(dir)
	if err != nil || b != a {
		t.Fatalf("second load = %q, %v; want the same key", b, err)
	}
	if runtime.GOOS != "windows" {
		st, _ := os.Stat(filepath.Join(dir, keyFile))
		if st.Mode().Perm() != 0o600 {
			t.Fatalf("mode %v, want 0600", st.Mode().Perm())
		}
		dst, _ := os.Stat(dir)
		if dst.Mode().Perm() != 0o700 {
			t.Fatalf("dir mode %v, want 0700", dst.Mode().Perm())
		}
	}
}

func TestSecretTightensLooseMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file modes")
	}
	dir := t.TempDir()
	p := filepath.Join(dir, keyFile)
	_ = os.WriteFile(p, []byte(strings.Repeat("A", 43)+"\n"), 0o644)
	_ = os.Chmod(p, 0o644)
	if _, err := loadOrCreateSecret(dir); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v, want 0600", st.Mode().Perm())
	}
}

func TestCorruptSecretIsAnErrorNotReplaced(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, keyFile)
	_ = os.WriteFile(p, []byte("short"), 0o600)
	_, err := loadOrCreateSecret(dir)
	if err == nil || strings.Contains(err.Error(), "short") {
		t.Fatalf("err = %v (must fail without echoing the content)", err)
	}
	if b, _ := os.ReadFile(p); string(b) != "short" {
		t.Fatal("a corrupt key must not be silently replaced")
	}
}

func TestValidSecret(t *testing.T) {
	for s, want := range map[string]bool{
		strings.Repeat("a", 43):        true,
		strings.Repeat("-_", 21) + "Z": true,
		strings.Repeat("a", 42):        false,
		strings.Repeat("a", 42) + "=":  false,
		strings.Repeat("a", 42) + "+":  false,
	} {
		if ValidSecret(s) != want {
			t.Errorf("ValidSecret(%q) != %v", s, want)
		}
	}
}
