package native

import (
	"encoding/json"
	"os"
	"strings"
)

// prevConfig is the part of an installed config (any version) install
// reuses: the proxy port (kept across the single-user -> slots migration,
// so running `clux host start`s keep their proxy URL) and the slots.
type prevConfig struct {
	Version   int    `json:"version"`
	ProxyPort int    `json:"proxy_port"`
	Slots     []Slot `json:"slots"`
}

func readPrevConfig(path string) prevConfig {
	var p prevConfig
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &p)
	}
	p.Slots = nil
	if p.Version == configVersion {
		if c, err := loadConfig(path); err == nil {
			p.Slots = c.Slots
		}
	}
	return p
}

// launchdOverride reads `launchctl print-disabled` output for label:
// "enabled", "disabled" or "" (no override).
func launchdOverride(out, label string) string {
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=>")
		if !ok || strings.Trim(strings.TrimSpace(k), `"`) != label {
			continue
		}
		switch strings.TrimSpace(v) {
		case "disabled", "true":
			return "disabled"
		case "enabled", "false":
			return "enabled"
		}
	}
	return ""
}
