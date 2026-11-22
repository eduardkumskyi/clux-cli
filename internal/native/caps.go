package native

import (
	"context"
	"encoding/json"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

// xcodeTTL: Xcode and simulator runtimes change rarely and are slow to
// query (simctl starts CoreSimulatorService), so heartbeats reuse a probe.
const xcodeTTL = 10 * time.Minute

// Capabilities builds the register/heartbeat "capabilities" object.
type Capabilities struct {
	// Supervisor reports the slot supervisors' version and sandbox state
	// (err only when none answers).
	Supervisor func(ctx context.Context) (version, sandbox string, err error)
	// FreeSlots reports how many slots no workspace holds (nil: all free).
	FreeSlots func() int

	loadConfig func() (*Config, error)
	pfStatus   func() (PFStatus, error)
	xcodeProbe func(ctx context.Context) (string, []string)
	now        func() time.Time

	mu       sync.Mutex
	xcAt     time.Time
	xcode    string
	runtimes []string
}

// Collect returns {"runtimes": [...], "native_macos": {...}}. "native_macos"
// is listed as a runtime only while it can actually run a workspace
// (installed, supervisor answering, pf active); "installed" alone tells the
// UI to show what's wrong.
func (c *Capabilities) Collect(ctx context.Context) map[string]any {
	caps := map[string]any{"runtimes": []string{"docker"}}
	if runtime.GOOS != "darwin" {
		return caps
	}
	load := c.loadConfig
	if load == nil {
		load = LoadConfig
	}
	cfg, err := load()
	if err != nil {
		return caps
	}
	now := time.Now
	if c.now != nil {
		now = c.now
	}
	version, sandbox := "", "unavailable"
	supOK := false
	if c.Supervisor != nil {
		sctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		v, s, err := c.Supervisor(sctx)
		cancel()
		if err == nil {
			version, sandbox, supOK = v, s, true
		}
	}
	readPF := c.pfStatus
	if readPF == nil {
		readPF = ReadPFStatus
	}
	pf := "inactive"
	if st, err := readPF(); err == nil && st.Active(now()) {
		pf = "active"
	}
	xc, rts := c.xcodeInfo(ctx, now())
	total := len(cfg.Slots)
	free := total
	if c.FreeSlots != nil {
		free = c.FreeSlots()
	}
	agentUser := ""
	if total > 0 {
		agentUser = cfg.Slots[0].User
		if total > 1 {
			agentUser += ".." + cfg.Slots[total-1].User
		}
	}
	caps["native_macos"] = map[string]any{
		"installed":          true,
		"agent_user":         agentUser,
		"xcode_version":      xc,
		"simulator_runtimes": rts,
		"sandbox":            sandbox,
		"pf":                 pf,
		"supervisor_version": version,
		// The clux version the daemons' own copy of the binary came from
		// (`sudo clux native install` refreshes it): the backend tells the
		// owner when it is behind the CLI, even while no supervisor answers.
		"daemon_version": cfg.CLIVersion,
		// Each native workspace holds one slot (agent user) while it
		// exists; with none free, workspace.start fails.
		"slots_total": total,
		"slots_free":  free,
	}
	if supOK && pf == "active" {
		caps["runtimes"] = []string{"docker", "native_macos"}
	}
	return caps
}

func (c *Capabilities) xcodeInfo(ctx context.Context, now time.Time) (string, []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.xcAt.IsZero() && now.Sub(c.xcAt) < xcodeTTL {
		return c.xcode, c.runtimes
	}
	probe := c.xcodeProbe
	if probe == nil {
		probe = probeXcode
	}
	c.xcode, c.runtimes = probe(ctx)
	if c.runtimes == nil {
		c.runtimes = []string{}
	}
	c.xcAt = now
	return c.xcode, c.runtimes
}

func probeXcode(ctx context.Context) (string, []string) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var version string
	if out, err := exec.CommandContext(ctx, "/usr/bin/xcodebuild", "-version").Output(); err == nil {
		version = ParseXcodeVersion(string(out))
	}
	var rts []string
	if out, err := exec.CommandContext(ctx, "/usr/bin/xcrun", "simctl", "list", "runtimes", "-j").Output(); err == nil {
		rts = ParseSimRuntimes(out)
	}
	return version, rts
}

// ParseXcodeVersion reads "Xcode 16.4\nBuild version 16F6" -> "16.4".
func ParseXcodeVersion(out string) string {
	first, _, _ := strings.Cut(strings.TrimSpace(out), "\n")
	v, ok := strings.CutPrefix(strings.TrimSpace(first), "Xcode ")
	if !ok {
		return ""
	}
	return strings.TrimSpace(v)
}

// ParseSimRuntimes reads `simctl list runtimes -j` -> available runtime
// names ("iOS 18.6"), sorted.
func ParseSimRuntimes(out []byte) []string {
	var doc struct {
		Runtimes []struct {
			Name        string `json:"name"`
			IsAvailable bool   `json:"isAvailable"`
		} `json:"runtimes"`
	}
	if json.Unmarshal(out, &doc) != nil {
		return nil
	}
	names := []string{}
	for _, r := range doc.Runtimes {
		if r.IsAvailable && r.Name != "" {
			names = append(names, r.Name)
		}
	}
	sort.Strings(names)
	return names
}
