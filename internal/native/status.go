package native

import (
	"encoding/json"
	"strings"
	"time"
)

// PFStatus is what the pf daemon publishes in PFStatusPath (0644) for
// unprivileged readers (`clux host start` capabilities, `clux doctor`).
type PFStatus struct {
	Enabled bool `json:"enabled"`
	// RulesLoaded: the anchor's rules, as pf reports them, are the ones
	// the daemon last loaded (re-checked every few seconds).
	RulesLoaded bool `json:"rules_loaded"`
	// MainAnchor: the main ruleset evaluates com.apple/* (else the anchor,
	// however loaded, is never consulted).
	MainAnchor    bool   `json:"main_anchor"`
	Anchor        string `json:"anchor"`
	UIDs          []int  `json:"uids"`
	ListenerPorts int    `json:"listener_ports"`
	// ProxyPassed: the slots may reach the egress proxy port (only while
	// every listener on it is the owner's, i.e. `clux host start` runs).
	ProxyPassed bool   `json:"proxy_passed"`
	Updated     string `json:"updated"`
	Error       string `json:"error,omitempty"`
}

// pfStatusStale: the daemon rewrites the file every few seconds; an older
// file means it is not running, so nothing keeps the anchor current.
const pfStatusStale = 30 * time.Second

// ReadPFStatus reads the pf daemon's status file. On macOS it is only
// accepted from a root-owned file in a root-owned directory: a slot user
// must not be able to fake "firewall active".
func ReadPFStatus() (PFStatus, error) {
	var st PFStatus
	b, err := readRootFile(PFStatusPath)
	if err != nil {
		return st, err
	}
	err = json.Unmarshal(b, &st)
	return st, err
}

// Active reports whether pf is enabled with our anchor loaded and
// evaluated, and the daemon alive.
func (s PFStatus) Active(now time.Time) bool {
	t, err := time.Parse(time.RFC3339, s.Updated)
	return err == nil && s.Enabled && s.RulesLoaded && s.MainAnchor && now.Sub(t) < pfStatusStale && now.Sub(t) > -pfStatusStale
}

// Covers reports whether the loaded rules confine uid.
func (s PFStatus) Covers(uid int) bool {
	for _, u := range s.UIDs {
		if u == uid {
			return true
		}
	}
	return false
}

// parseDSAttr reads `dscl . -read <record> <key>` output: "UniqueID: 401",
// "dsAttrTypeNative:IsHidden: 1", or a long value on the next line
// ("RealName:\n Clux agent").
func parseDSAttr(out string) (string, bool) {
	lines := strings.Split(strings.TrimSpace(out), "\n")
	i := strings.LastIndex(lines[0], ":")
	if i < 0 {
		return "", false
	}
	v := strings.TrimSpace(lines[0][i+1:])
	if v == "" && len(lines) > 1 {
		v = strings.TrimSpace(lines[1])
	}
	return v, true
}

// parseDSList reads a multi-value `dscl . -read` attribute
// ("GroupMembership: a b").
func parseDSList(out string) []string {
	_, v, ok := strings.Cut(strings.TrimSpace(out), ":")
	if !ok {
		return nil
	}
	return strings.Fields(v)
}

// parseToken extracts the reference token from `pfctl -E` output
// ("Token : 10657851713038665265").
func parseToken(out string) string {
	for _, line := range strings.Split(out, "\n") {
		if k, v, ok := strings.Cut(line, ":"); ok && strings.TrimSpace(k) == "Token" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
