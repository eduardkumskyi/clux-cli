// Package machineid derives the stable id that lets the backend recognize
// "the same computer as before": one machine (per OS user) = one host, so a
// re-login on a known machine gets its old host and projects back instead
// of a fresh duplicate.
//
// The id is sha256("clux-machine-v1:" + platform id + ":" + OS user) in
// lowercase hex -- always 64 characters. The platform id is the OS's own
// machine identifier (macOS IOPlatformUUID, Linux /etc/machine-id, Windows
// MachineGuid); when none is readable a random UUID is generated once and
// kept in ~/.clux/machine-id. The hash is not a secret, but the raw
// platform id is never logged or sent.
//
// Because the id is derived from guessable inputs, it alone never proves
// "same computer": the backend reuses a host only when the request also
// carries the host's machine secret (Secret), 32 random bytes kept in
// ~/.clux/machine-key. The key survives `clux logout` (that is what lets
// the next login get the old host back) and is never logged.
package machineid

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

const prefix = "clux-machine-v1:"

// fallbackFile holds the random platform id for machines without one.
const fallbackFile = "machine-id"

var valid = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Valid reports whether s has the wire format (64 lowercase hex chars).
func Valid(s string) bool { return valid.MatchString(s) }

// Compute is the pure formula, exposed for tests.
func Compute(platformID, osUser string) string {
	sum := sha256.Sum256([]byte(prefix + platformID + ":" + osUser))
	return hex.EncodeToString(sum[:])
}

var (
	once   sync.Once
	cached string
	cerr   error
)

// Get returns this machine's id, computing it once per process (macOS shells
// out to ioreg, which is too slow to repeat on every reconnect). stateDir is
// ~/.clux, where the fallback id lives.
func Get(stateDir string) (string, error) {
	once.Do(func() { cached, cerr = compute(stateDir, platformID, osUser) })
	return cached, cerr
}

func compute(stateDir string, platform func() (string, error), who func() (string, error)) (string, error) {
	pid, err := platform()
	if err != nil || pid == "" {
		pid, err = fallbackID(stateDir)
		if err != nil {
			return "", fmt.Errorf("no platform machine id and no fallback: %w", err)
		}
	}
	u, err := who()
	if err != nil {
		return "", fmt.Errorf("resolving the OS user: %w", err)
	}
	return Compute(pid, u), nil
}

// osUser is the uid on POSIX systems (stable across renames) and the
// account name on Windows, where there is no numeric uid.
func osUser() (string, error) {
	if uid := os.Getuid(); uid >= 0 {
		return strconv.Itoa(uid), nil
	}
	u, err := user.Current()
	if err != nil {
		return "", err
	}
	return u.Username, nil
}

// fallbackID reads, or creates once, a random UUID in stateDir.
func fallbackID(stateDir string) (string, error) {
	p := filepath.Join(stateDir, fallbackFile)
	if b, err := os.ReadFile(p); err == nil {
		if s := strings.TrimSpace(string(b)); s != "" {
			return s, nil
		}
	}
	id, err := randomUUID()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return "", err
	}
	// O_EXCL: if another process raced us here, use its id, not ours.
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if os.IsExist(err) {
			if b, rerr := os.ReadFile(p); rerr == nil && strings.TrimSpace(string(b)) != "" {
				return strings.TrimSpace(string(b)), nil
			}
		}
		return "", err
	}
	defer f.Close()
	if _, err := f.WriteString(id + "\n"); err != nil {
		return "", err
	}
	return id, nil
}

func randomUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = b[6]&0x0f | 0x40 // version 4
	b[8] = b[8]&0x3f | 0x80 // RFC 4122 variant
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:], nil
}
