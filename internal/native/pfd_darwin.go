//go:build darwin

package native

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// RunPFD is `clux native pfd`, the root LaunchDaemon. At start it recreates
// RunDir (gone after every reboot), loads the anchor and takes a pf enable
// reference (pf is reference-counted and off by default; the token is
// kept so uninstall can release exactly ours). Then, every second, it
// re-renders the anchor from the socket table and reloads it when the
// agent's listeners changed. On SIGTERM it reloads the base rules (no
// listener passes): with the daemon gone nothing would remove a stale
// pass, so it fails closed.
func RunPFD(ctx context.Context, logf func(string, ...any)) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("pfd must run as root")
	}
	cfg, err := LoadConfig()
	if err != nil {
		return err
	}
	if err := ensureDir(RunDir, 0o750, cfg.AgentUID, cfg.CtlGID); err != nil {
		return err
	}
	if out, err := run("/sbin/pfctl", "-s", "rules"); err != nil || !strings.Contains(out, "com.apple") {
		// The main ruleset (with the com.apple/* anchor point) is normally
		// loaded at boot from /etc/pf.conf; restore it if something flushed it.
		if _, err := run("/sbin/pfctl", "-f", "/etc/pf.conf"); err != nil {
			logf("loading /etc/pf.conf: %v", err)
		}
	}

	d := &pfd{cfg: cfg, logf: logf}
	d.load(PFRules(cfg.AgentUID, cfg.ProxyPort, nil))
	d.enable()
	logf("pf daemon running (agent uid %d, proxy port %d)", cfg.AgentUID, cfg.ProxyPort)

	t := time.NewTicker(time.Second)
	defer t.Stop()
	for tick := 0; ; tick++ {
		select {
		case <-ctx.Done():
			d.load(PFRules(cfg.AgentUID, cfg.ProxyPort, nil))
			d.ports = 0
			d.writeStatus()
			logf("pf daemon stopping; listener rules removed")
			return nil
		case <-t.C:
		}
		ls, err := TCPListeners()
		if err != nil {
			d.lastErr = err.Error()
			ls = nil
		}
		v4, v6 := agentLoopbackPorts(cfg.AgentUID, cfg.ProxyPort, ls)
		d.ports = len(v4) + len(v6)
		d.load(PFRules(cfg.AgentUID, cfg.ProxyPort, ls))
		if tick%10 == 9 && !d.isEnabled() {
			logf("pf was disabled by something else; enabling it again")
			d.enable()
		}
		if tick%3 == 0 {
			d.writeStatus()
		}
	}
}

type pfd struct {
	cfg     *Config
	logf    func(string, ...any)
	current string
	loaded  bool
	enabled bool
	ports   int
	lastErr string
}

func (d *pfd) load(rules string) {
	if rules == d.current && d.loaded {
		return
	}
	if _, err := runIn(strings.NewReader(rules), "/sbin/pfctl", "-a", PFAnchor, "-f", "-"); err != nil {
		d.lastErr = err.Error()
		d.logf("loading anchor: %v", err)
		return
	}
	d.current, d.loaded, d.lastErr = rules, true, ""
	_ = writeFileAtomic(RunDir+"/pf.effective.rules", []byte(rules), 0o644)
}

// enable takes a fresh pf reference, then releases the one a previous run
// of this daemon held (in that order, so pf never drops to zero refs).
func (d *pfd) enable() {
	out, err := run("/sbin/pfctl", "-E")
	if err != nil {
		d.lastErr = err.Error()
		d.logf("pfctl -E: %v", err)
		return
	}
	tok := parseToken(out)
	old, _ := os.ReadFile(PFTokenPath)
	if tok != "" {
		_ = writeFileAtomic(PFTokenPath, []byte(tok+"\n"), 0o600)
	}
	if o := strings.TrimSpace(string(old)); o != "" && o != tok {
		_, _ = run("/sbin/pfctl", "-X", o)
	}
	d.enabled = d.isEnabled()
}

func (d *pfd) isEnabled() bool {
	out, err := run("/sbin/pfctl", "-s", "info")
	d.enabled = err == nil && strings.Contains(out, "Status: Enabled")
	return d.enabled
}

func (d *pfd) writeStatus() {
	st := PFStatus{
		Enabled: d.enabled, RulesLoaded: d.loaded, Anchor: PFAnchor, ListenerPorts: d.ports,
		Updated: time.Now().UTC().Format(time.RFC3339), Error: d.lastErr,
	}
	b, _ := json.Marshal(st)
	_ = writeFileAtomic(PFStatusPath, b, 0o644)
}
