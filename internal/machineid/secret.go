package machineid

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
)

// keyFile holds the machine secret: 32 random bytes, base64url without
// padding (43 chars), mode 0600.
const keyFile = "machine-key"

var validSecret = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

// ValidSecret reports whether s has the wire format.
func ValidSecret(s string) bool { return validSecret.MatchString(s) }

var (
	secretOnce   sync.Once
	secretCached string
	secretErr    error
)

// Secret returns this machine's secret, creating ~/.clux/machine-key on
// first use. Never log the result.
func Secret(stateDir string) (string, error) {
	secretOnce.Do(func() { secretCached, secretErr = loadOrCreateSecret(stateDir) })
	return secretCached, secretErr
}

func loadOrCreateSecret(stateDir string) (string, error) {
	p := filepath.Join(stateDir, keyFile)
	if s, err := readSecret(p); err == nil || !os.IsNotExist(err) {
		return s, err
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return "", err
	}
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	s := base64.RawURLEncoding.EncodeToString(b[:])
	// O_EXCL: a concurrent first run (login + service) must not end up
	// with two different keys; the loser reads the winner's.
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if os.IsExist(err) {
			return readSecret(p)
		}
		return "", err
	}
	if _, err := f.WriteString(s + "\n"); err != nil {
		f.Close()
		os.Remove(p)
		return "", err
	}
	if err := f.Close(); err != nil {
		os.Remove(p)
		return "", err
	}
	return s, nil
}

func readSecret(p string) (string, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return "", err
	}
	s := strings.TrimSpace(string(b))
	if !ValidSecret(s) {
		// Never regenerate silently: a new key means the backend no longer
		// recognizes this computer. The content is not echoed.
		return "", fmt.Errorf("%s is not a valid machine key (delete it to make a new one; this computer then connects as a new host)", p)
	}
	if runtime.GOOS != "windows" {
		if st, err := os.Stat(p); err == nil && st.Mode().Perm()&0o077 != 0 {
			_ = os.Chmod(p, 0o600)
		}
	}
	return s, nil
}
