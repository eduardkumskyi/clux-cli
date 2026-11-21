package machineid

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestComputeFormula(t *testing.T) {
	got := Compute("ABC", "501")
	if !Valid(got) {
		t.Fatalf("not 64 lowercase hex: %q", got)
	}
	if got == Compute("ABC", "502") || got == Compute("ABD", "501") {
		t.Fatal("platform id and user must both change the id")
	}
}

// knownDigest = printf 'clux-machine-v1:abc:0' | shasum -a 256, pinned so a
// future CLI keeps recognizing the same machine.
const knownDigest = "6d2d133210cd3f7db159358ef33aa083755baa92368a6750d774aba070d88bbd"

func TestComputeKnownDigest(t *testing.T) {
	if got := Compute("abc", "0"); got != knownDigest {
		t.Fatalf("Compute = %s, want %s", got, knownDigest)
	}
}

func TestComputeUsesPlatformAndUser(t *testing.T) {
	dir := t.TempDir()
	id, err := compute(dir, func() (string, error) { return "PLAT", nil }, func() (string, error) { return "501", nil })
	if err != nil {
		t.Fatal(err)
	}
	if id != Compute("PLAT", "501") {
		t.Fatal("id must be Compute(platform, user)")
	}
	if _, err := os.Stat(filepath.Join(dir, fallbackFile)); !os.IsNotExist(err) {
		t.Fatal("no fallback file when the platform id is readable")
	}
}

func TestFallbackIsPersistedOnce(t *testing.T) {
	dir := t.TempDir()
	none := func() (string, error) { return "", errors.New("none") }
	who := func() (string, error) { return "501", nil }
	a, err := compute(dir, none, who)
	if err != nil {
		t.Fatal(err)
	}
	b, err := compute(dir, none, who)
	if err != nil {
		t.Fatal(err)
	}
	if a != b || !Valid(a) {
		t.Fatalf("fallback id must be stable and valid: %q %q", a, b)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, fallbackFile))
	if len(strings.TrimSpace(string(raw))) != 36 {
		t.Fatalf("fallback file should hold a UUID, got %q", raw)
	}
}

func TestValid(t *testing.T) {
	for s, want := range map[string]bool{
		strings.Repeat("a", 64): true,
		strings.Repeat("A", 64): false,
		strings.Repeat("a", 63): false,
		"":                      false,
	} {
		if Valid(s) != want {
			t.Errorf("Valid(%q) != %v", s, want)
		}
	}
}
