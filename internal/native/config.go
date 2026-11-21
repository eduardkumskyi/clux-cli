// Package native implements the "native_macos" runtime's machine setup:
// `clux native install|uninstall|status`, the root pf daemon (`clux native
// pfd`), and the pure generators both use (pf anchor rules, Seatbelt
// profiles, launchd plists).
//
// Isolation model, in order of strength:
//
//  1. A pool of hidden dedicated users ("slots": _clux1.._cluxN, each with
//     its own primary group, not in staff). A workspace is assigned one
//     slot for its whole life, so every workspace runs as a uid of its own:
//     the sidecar, the claude CLI and everything they start (builds,
//     simulators, apps) run as that slot user, from a LaunchDaemon (not the
//     owner's GUI session). Owner homes are 750 staff and slot homes 700, so
//     the owner's files, Keychain, clipboard, Apple Events, the owner's iOS
//     Simulator device set, and every other workspace's files and process
//     environments are out of reach -- enforced by macOS itself.
//  2. pf, in anchor com.apple/clux, refuses every packet a slot user sends
//     except TCP to the owner's egress proxy (127.0.0.1:P, see
//     internal/egress) and to that slot's own loopback listeners. pf can't
//     tell who sent a loopback packet once it comes back in on lo0 (tags
//     don't survive the hop; verified), so "own listeners" is a list the
//     root pf daemon keeps current from the kernel's socket table.
//  3. Seatbelt (sandbox-exec), per workspace: a secondary layer, because the
//     iOS Simulator runs outside it and Apple has deprecated it.
//
// Root never acts on paths a slot user can write: it creates each slot's
// home and socket directory as entries of root-owned directories (checked
// with lstat + O_NOFOLLOW, see safefs_darwin.go) and leaves everything
// inside them to the slot's own supervisor.
package native

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Names and paths. They are fixed (not configurable) because the pf
// rules, plists and the sandbox profile all embed them, and a mistake in
// any of them is a hole.
const (
	// SlotUserPrefix + n is slot n's user and its primary group.
	SlotUserPrefix = "_clux"
	// SlotsGroup has every slot user as a member: the group of RuntimeRoot,
	// which the slots may read but not write.
	SlotsGroup = "_cluxslots"
	CtlGroup   = "_cluxctl"
	// LegacyAgentUser is the single shared agent account of the first
	// native layout (config version 1); install migrates away from it.
	LegacyAgentUser = "_clux"

	// AgentRoot (root:wheel 0755) holds the slot homes and the files root
	// shares read-only with every slot.
	AgentRoot = "/private/var/clux"
	// SlotsDir (root:wheel 0755) holds one home per slot (<n>, 0700, owned
	// by the slot user): its workspace, Xcode/Simulator state, logs.
	SlotsDir = AgentRoot + "/slots"
	// SharedDir (root:wheel 0755): read-only inputs for every slot.
	SharedDir = AgentRoot + "/shared"
	// SimMappingPath is the owner's SDKToSimulatorIndexMapping.plist, which
	// each slot's supervisor copies into its own Library.
	SimMappingPath = SharedDir + "/SDKToSimulatorIndexMapping.plist"

	// RuntimeRoot holds sidecar bundles, the Python venvs and uv. It is
	// written by the owner (`clux host start` installs runtimes there) and
	// only readable by the slots (owner:_cluxslots 0750), so a compromised
	// agent can't plant code into the runtime later workspaces start from.
	RuntimeRoot = "/private/var/clux-runtime"

	ConfigDir   = "/etc/clux"
	ConfigPath  = ConfigDir + "/native.json"
	PFRulesPath = ConfigDir + "/pf.rules"

	// RunDir is recreated at every boot by the pf daemon: root:wheel 0755.
	// Only root writes the pf state in it, so a status or token read from
	// here can be trusted.
	RunDir          = "/private/var/run/clux-native"
	PFStatusPath    = RunDir + "/pf.json"
	PFTokenPath     = RunDir + "/pf.token"
	PFEffectivePath = RunDir + "/pf.effective.rules"
	// SlotRunDir (root:wheel 0755) holds one socket directory per slot
	// (<n>, slot user:_cluxctl 0750).
	SlotRunDir = RunDir + "/slots"

	LogDir = "/private/var/log/clux-native"

	PFLabel = "space.clux.native.pf"
	// SupervisorLabelPrefix + "." + n is slot n's supervisor; the bare
	// prefix is the legacy single supervisor.
	SupervisorLabelPrefix = "space.clux.native.supervisor"
	PFAnchor              = "com.apple/clux"

	LaunchDaemonsDir = "/Library/LaunchDaemons"

	// Candidate homes for the root-owned copy of this binary the daemons
	// run; the first whose whole parent chain is root-owned and not
	// group/world-writable wins (on Intel Macs /usr/local is Homebrew's,
	// i.e. owner-writable, which would let any owner process become root).
	primaryLibexec  = "/usr/local/libexec/clux-native"
	fallbackLibexec = "/Library/Application Support/clux-native"

	// uid/gid range for the slot users and groups (system-style accounts).
	idRangeLo = 400
	idRangeHi = 499

	DefaultSlots = 4
	MaxSlots     = 32

	DefaultProxyPort = 47821
)

// SlotUser is slot n's user (and primary group) name.
func SlotUser(n int) string { return SlotUserPrefix + strconv.Itoa(n) }

// SlotHome is slot n's home directory.
func SlotHome(n int) string { return SlotsDir + "/" + strconv.Itoa(n) }

// SlotSocketDir is the directory of slot n's supervisor socket.
func SlotSocketDir(n int) string { return SlotRunDir + "/" + strconv.Itoa(n) }

// SlotSocket is slot n's supervisor socket.
func SlotSocket(n int) string { return SlotSocketDir(n) + "/supervisor.sock" }

// SupervisorLabel is slot n's LaunchDaemon label.
func SupervisorLabel(n int) string { return SupervisorLabelPrefix + "." + strconv.Itoa(n) }

// SupervisorLog is slot n's supervisor log.
func SupervisorLog(n int) string { return LogDir + "/supervisor-" + strconv.Itoa(n) + ".log" }

// Slot is one agent user of the pool.
type Slot struct {
	N    int    `json:"n"`
	User string `json:"user"`
	UID  int    `json:"uid"`
	GID  int    `json:"gid"`
}

// Config is /etc/clux/native.json (root:wheel 0644), written by install and
// read by the daemons and `clux host start`.
type Config struct {
	Version   int    `json:"version"`
	OwnerUID  int    `json:"owner_uid"`
	OwnerUser string `json:"owner_user"`
	OwnerHome string `json:"owner_home"`
	// Slots are the agent users, Slots[i].N == i+1.
	Slots      []Slot `json:"slots"`
	SlotsGID   int    `json:"slots_gid"`
	CtlGID     int    `json:"ctl_gid"`
	ProxyPort  int    `json:"proxy_port"`
	BinaryPath string `json:"binary_path"`
	// CLIVersion is the clux version whose binary the daemons run
	// (= supervisor_version).
	CLIVersion  string `json:"cli_version"`
	InstalledAt string `json:"installed_at"`
}

// configVersion 2 = slot pool (1 was the single shared _clux user).
const configVersion = 2

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
	if c.Version < configVersion {
		return nil, fmt.Errorf("%s is from an older clux (single agent user); re-run `sudo clux native install`", path)
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
	case c.OwnerUID <= 0:
		return fmt.Errorf("invalid owner_uid %d", c.OwnerUID)
	case len(c.Slots) < 1 || len(c.Slots) > MaxSlots:
		return fmt.Errorf("%d slots (want 1-%d)", len(c.Slots), MaxSlots)
	case !inIDRange(c.SlotsGID) || !inIDRange(c.CtlGID) || c.SlotsGID == c.CtlGID:
		return fmt.Errorf("invalid slots_gid %d / ctl_gid %d", c.SlotsGID, c.CtlGID)
	case c.ProxyPort < 1024 || c.ProxyPort > 65535:
		return fmt.Errorf("invalid proxy_port %d", c.ProxyPort)
	case c.BinaryPath == "" || !filepath.IsAbs(c.BinaryPath):
		return fmt.Errorf("invalid binary_path %q", c.BinaryPath)
	}
	uids, gids := map[int]bool{}, map[int]bool{c.SlotsGID: true, c.CtlGID: true}
	for i, s := range c.Slots {
		switch {
		case s.N != i+1 || s.User != SlotUser(s.N):
			return fmt.Errorf("slot %d: want n=%d user=%s, got n=%d user=%q", i, i+1, SlotUser(i+1), s.N, s.User)
		case !inIDRange(s.UID) || !inIDRange(s.GID):
			return fmt.Errorf("slot %d: uid %d / gid %d outside %d-%d", s.N, s.UID, s.GID, idRangeLo, idRangeHi)
		case s.UID == c.OwnerUID || uids[s.UID] || gids[s.GID]:
			return fmt.Errorf("slot %d: uid %d / gid %d is not unique", s.N, s.UID, s.GID)
		}
		uids[s.UID], gids[s.GID] = true, true
	}
	return nil
}

// Slot returns slot n.
func (c *Config) Slot(n int) (Slot, bool) {
	if n < 1 || n > len(c.Slots) {
		return Slot{}, false
	}
	return c.Slots[n-1], true
}

// AgentUIDs lists every slot uid.
func (c *Config) AgentUIDs() []int {
	out := make([]int, len(c.Slots))
	for i, s := range c.Slots {
		out[i] = s.UID
	}
	return out
}

func inIDRange(id int) bool { return id >= idRangeLo && id <= idRangeHi }

// sbString quotes s as an SBPL / plist-safe string literal body. Paths here
// come from constants and validated ids, but a stray quote would silently
// change a profile's meaning, so refuse rather than escape.
func sbString(s string) string {
	if strings.ContainsAny(s, "\"\\\n\x00") {
		panic(fmt.Sprintf("native: refusing unsafe path %q", s))
	}
	return `"` + s + `"`
}
