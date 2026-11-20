// Package native implements the "native_macos" runtime's machine setup:
// `clux native install|uninstall|status`, the root pf daemon (`clux native
// pfd`), and the pure generators both use (pf anchor rules, Seatbelt
// profiles, launchd plists).
//
// Isolation model, in order of strength:
//
//  1. A hidden dedicated user (_clux, own primary group, not in staff) runs
//     the sidecar, the claude CLI and everything they start, from a
//     LaunchDaemon (not the owner's GUI session). Owner homes are 750 staff,
//     so file access, Keychain, clipboard, Apple Events and the owner's iOS
//     Simulator device set are all out of reach -- enforced by macOS itself.
//  2. pf, in anchor com.apple/clux, refuses every TCP/UDP packet the agent
//     user sends except to the owner's egress proxy (127.0.0.1:P, see
//     internal/egress) and to the agent's own loopback listeners. pf can't
//     tell who sent a loopback packet once it comes back in on lo0 (tags
//     don't survive the hop; verified), so "own listeners" is a list the
//     root pf daemon keeps current from the kernel's socket table.
//  3. Seatbelt (sandbox-exec), per workspace: a secondary layer, because the
//     iOS Simulator runs outside it and Apple has deprecated it.
package native

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Names and paths. They are fixed (not configurable) because the pf
// rules, plists and the sandbox profile all embed them, and a mistake in
// any of them is a hole.
const (
	AgentUser  = "_clux"
	AgentGroup = "_clux"
	CtlGroup   = "_cluxctl"

	// AgentHome is _clux's home (0700): workspaces, Xcode/Simulator state.
	AgentHome     = "/private/var/clux"
	WorkspacesDir = AgentHome + "/workspaces"
	// AgentRunDir holds the supervisor's per-workspace state + profiles.
	AgentRunDir = AgentHome + "/run"
	AgentLogDir = AgentHome + "/logs"

	// RuntimeRoot holds sidecar bundles, the Python venvs and uv. It is
	// written by the owner (`clux host start` installs runtimes there) and
	// only readable by the agent (owner:_clux 0750), so a compromised agent
	// can't plant code into the runtime later workspaces start from.
	RuntimeRoot = "/private/var/clux-runtime"

	ConfigDir   = "/etc/clux"
	ConfigPath  = ConfigDir + "/native.json"
	PFRulesPath = ConfigDir + "/pf.rules"

	// RunDir is recreated at every boot by the pf daemon (root):
	// _clux:_cluxctl 0750, so files created in it get group _cluxctl.
	RunDir           = "/private/var/run/clux-native"
	SupervisorSocket = RunDir + "/supervisor.sock"
	PFStatusPath     = RunDir + "/pf.json"
	PFTokenPath      = RunDir + "/pf.token"

	LogDir = "/private/var/log/clux-native"

	PFLabel         = "space.clux.native.pf"
	SupervisorLabel = "space.clux.native.supervisor"
	PFAnchor        = "com.apple/clux"

	LaunchDaemonsDir = "/Library/LaunchDaemons"

	// Candidate homes for the root-owned copy of this binary the daemons
	// run; the first whose whole parent chain is root-owned and not
	// group/world-writable wins (on Intel Macs /usr/local is Homebrew's,
	// i.e. owner-writable, which would let any owner process become root).
	primaryLibexec  = "/usr/local/libexec/clux-native"
	fallbackLibexec = "/Library/Application Support/clux-native"

	// uid/gid range for _clux and _cluxctl (system-style accounts).
	idRangeLo = 400
	idRangeHi = 499

	DefaultProxyPort = 47821
)

// Config is /etc/clux/native.json (root:wheel 0644), written by install and
// read by the daemons and `clux host start`.
type Config struct {
	Version    int    `json:"version"`
	OwnerUID   int    `json:"owner_uid"`
	OwnerUser  string `json:"owner_user"`
	OwnerHome  string `json:"owner_home"`
	AgentUser  string `json:"agent_user"`
	AgentUID   int    `json:"agent_uid"`
	AgentGID   int    `json:"agent_gid"`
	CtlGID     int    `json:"ctl_gid"`
	ProxyPort  int    `json:"proxy_port"`
	BinaryPath string `json:"binary_path"`
	// CLIVersion is the clux version whose binary the daemons run
	// (= supervisor_version).
	CLIVersion  string `json:"cli_version"`
	InstalledAt string `json:"installed_at"`
}

const configVersion = 1

// LoadConfig reads native.json. os.IsNotExist(err) means "not installed".
func LoadConfig() (*Config, error) { return loadConfig(ConfigPath) }

func loadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &c, nil
}

// Validate rejects a config the daemons must not act on.
func (c *Config) Validate() error {
	switch {
	case c.Version != configVersion:
		return fmt.Errorf("unsupported config version %d", c.Version)
	case c.AgentUser != AgentUser:
		return fmt.Errorf("agent_user must be %s", AgentUser)
	case c.AgentUID < idRangeLo || c.AgentUID > idRangeHi:
		return fmt.Errorf("agent_uid %d outside %d-%d", c.AgentUID, idRangeLo, idRangeHi)
	case c.OwnerUID <= 0 || c.OwnerUID == c.AgentUID:
		return fmt.Errorf("invalid owner_uid %d", c.OwnerUID)
	case c.ProxyPort < 1024 || c.ProxyPort > 65535:
		return fmt.Errorf("invalid proxy_port %d", c.ProxyPort)
	case c.BinaryPath == "" || !filepath.IsAbs(c.BinaryPath):
		return fmt.Errorf("invalid binary_path %q", c.BinaryPath)
	}
	return nil
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// sbString quotes s as an SBPL / plist-safe string literal body. Paths here
// come from constants and validated ids, but a stray quote would silently
// change a profile's meaning, so refuse rather than escape.
func sbString(s string) string {
	if strings.ContainsAny(s, "\"\\\n\x00") {
		panic(fmt.Sprintf("native: refusing unsafe path %q", s))
	}
	return `"` + s + `"`
}
