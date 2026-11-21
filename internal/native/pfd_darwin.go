//go:build darwin

package native

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// verifyEvery: how often (in daemon ticks of 1 s) the daemon checks that pf
// still holds what it loaded and that the main ruleset still evaluates
// com.apple/*, and republishes its status.
const verifyEvery = 3

// RunPFD is `clux native pfd`, the root LaunchDaemon. At start it recreates
// RunDir (gone after every reboot) and the slots' socket directories, loads
// the anchor and takes a pf enable reference (pf is reference-counted and
// off by default; the token is kept so uninstall can release exactly ours).
// Then, every second, it re-renders the anchor from the socket table and
// reloads it when a slot's listeners changed; every few seconds it checks
// that pf really holds those rules (something may have flushed the anchor
// or reloaded the main ruleset without the com.apple anchor point) and
// repairs it, publishing what it found. On SIGTERM it reloads the base
// rules (no listener passes): with the daemon gone nothing would remove a
// stale pass, so it fails closed.
func RunPFD(ctx context.Context, logf func(string, ...any)) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("pfd must run as root")
	}
	cfg, err := LoadConfig()
	if err != nil {
		return err
	}
	if err := ensureRunDirs(cfg, logf); err != nil {
		return err
	}
	d := &pfd{cfg: cfg, uids: cfg.AgentUIDs(), logf: logf, pf: execPfctl}
	d.verifyMain()
	base := PFRules(d.uids, cfg.OwnerUID, cfg.ProxyPort, nil)
	d.load(base, true)
	d.enable()
	logf("pf daemon running (agent uids %v, proxy port %d)", d.uids, cfg.ProxyPort)

	t := time.NewTicker(time.Second)
	defer t.Stop()
	for tick := 0; ; tick++ {
		select {
		case <-ctx.Done():
			d.load(base, true)
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
		d.ports = 0
		for _, u := range d.uids {
			v4, v6 := agentLoopbackPorts(u, cfg.ProxyPort, ls)
			d.ports += len(v4) + len(v6)
		}
		d.proxyUp = ownerOnlyListens(cfg.OwnerUID, cfg.ProxyPort, ls)
		d.load(PFRules(d.uids, cfg.OwnerUID, cfg.ProxyPort, ls), false)
		if tick%10 == 9 && !d.isEnabled() {
			logf("pf was disabled by something else; enabling it again")
			d.enable()
		}
		if tick%verifyEvery == 0 {
			d.verify()
			d.writeStatus()
		}
	}
}

// pfctlFunc runs pfctl with args (and stdin, if any), returning stdout and,
// on failure, an error carrying stderr.
type pfctlFunc func(stdin string, args ...string) (string, error)

func execPfctl(stdin string, args ...string) (string, error) {
	cmd := exec.Command("/sbin/pfctl", args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return out.String(), fmt.Errorf("pfctl %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(errb.String()))
	}
	return out.String(), nil
}

type pfd struct {
	cfg  *Config
	uids []int
	logf func(string, ...any)
	pf   pfctlFunc
	// writeStatusFile publishes the status (tests capture it).
	writeStatusFile func(PFStatus)

	current    string // rules text last loaded
	shown      string // `pfctl -a anchor -s rules` right after that load
	loaded     bool   // current is what pf holds (as of the last check)
	mainAnchor bool   // main ruleset evaluates com.apple/*
	enabled    bool
	ports      int
	proxyUp    bool // the proxy pass rules are in (owner listens on the port)
	lastErr    string
}

func (d *pfd) load(rules string, force bool) {
	if !force && rules == d.current && d.loaded {
		return
	}
	if _, err := d.pf(rules, "-a", PFAnchor, "-f", "-"); err != nil {
		d.loaded, d.lastErr = false, err.Error()
		d.logf("loading anchor: %v", err)
		return
	}
	shown, err := d.pf("", "-a", PFAnchor, "-s", "rules")
	if err != nil || strings.TrimSpace(shown) == "" {
		d.loaded, d.lastErr = false, fmt.Sprintf("anchor %s empty after loading (%v)", PFAnchor, err)
		d.logf("%s", d.lastErr)
		return
	}
	d.current, d.shown, d.loaded, d.lastErr = rules, shown, true, ""
	if err := writeFileSafe(PFEffectivePath, []byte(rules), 0o644, 0, 0); err != nil {
		d.logf("writing %s: %v", PFEffectivePath, err)
	}
}

// verify checks that pf still evaluates and holds our rules, repairing
// what it can. Until a repair succeeds the status says not loaded, which
// stops the supervisors from starting workspaces.
func (d *pfd) verify() {
	d.verifyMain()
	shown, err := d.pf("", "-a", PFAnchor, "-s", "rules")
	if err == nil && d.loaded && shown == d.shown {
		return
	}
	d.logf("anchor %s does not hold the rules clux loaded (flushed or replaced); reloading", PFAnchor)
	d.load(d.current, true)
}

// verifyMain checks that the main ruleset has the com.apple/* anchor point
// (normally loaded at boot from /etc/pf.conf) and restores it if not.
func (d *pfd) verifyMain() {
	if d.hasMainAnchor() {
		d.mainAnchor = true
		return
	}
	d.logf("main pf ruleset lacks anchor \"com.apple/*\"; reloading /etc/pf.conf")
	if _, err := d.pf("", "-f", "/etc/pf.conf"); err != nil {
		d.lastErr = err.Error()
		d.logf("loading /etc/pf.conf: %v", err)
	}
	d.mainAnchor = d.hasMainAnchor()
	d.loaded = false // the anchor's contents must be re-checked/reloaded
}

func (d *pfd) hasMainAnchor() bool {
	out, err := d.pf("", "-s", "rules")
	return err == nil && strings.Contains(out, `anchor "com.apple/*"`)
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
	old, _ := readPFToken()
	if tok != "" {
		if err := writeFileSafe(PFTokenPath, []byte(tok+"\n"), 0o600, 0, 0); err != nil {
			d.logf("writing %s: %v", PFTokenPath, err)
		}
	}
	if old != "" && old != tok {
		_, _ = run("/sbin/pfctl", "-X", old)
	}
	d.enabled = d.isEnabled()
}

// readPFToken reads our pf enable token from the root-owned run dir; only a
// plain number is accepted.
func readPFToken() (string, error) {
	b, err := readRootFile(PFTokenPath)
	if err != nil {
		return "", err
	}
	tok := strings.TrimSpace(string(b))
	if _, err := strconv.ParseUint(tok, 10, 64); err != nil {
		return "", errors.New("malformed pf token")
	}
	return tok, nil
}

func (d *pfd) isEnabled() bool {
	out, err := d.pf("", "-s", "info")
	d.enabled = err == nil && strings.Contains(out, "Status: Enabled")
	return d.enabled
}

func (d *pfd) status() PFStatus {
	return PFStatus{
		Enabled: d.enabled, RulesLoaded: d.loaded, MainAnchor: d.mainAnchor, Anchor: PFAnchor,
		UIDs: d.uids, ListenerPorts: d.ports, ProxyPassed: d.proxyUp, Updated: time.Now().UTC().Format(time.RFC3339), Error: d.lastErr,
	}
}

func (d *pfd) writeStatus() {
	st := d.status()
	if d.writeStatusFile != nil {
		d.writeStatusFile(st)
		return
	}
	b, _ := json.Marshal(st)
	if err := writeFileSafe(PFStatusPath, b, 0o644, 0, 0); err != nil {
		d.logf("writing %s: %v", PFStatusPath, err)
	}
}

// ensureRunDirs makes RunDir root:wheel 0755 (an older layout's RunDir was
// owned by the agent: it is moved aside and deleted), SlotRunDir root:wheel
// 0755 and one socket directory per slot (slot user:_cluxctl 0750); socket
// directories of slots that no longer exist are removed.
func ensureRunDirs(cfg *Config, logf func(string, ...any)) error {
	if err := ensureDirReplacing(RunDir, 0o755, 0, 0, logf); err != nil {
		return err
	}
	if err := ensureDirReplacing(SlotRunDir, 0o755, 0, 0, logf); err != nil {
		return err
	}
	want := map[string]bool{}
	for _, s := range cfg.Slots {
		want[strconv.Itoa(s.N)] = true
		if err := ensureDirReplacing(SlotSocketDir(s.N), 0o750, s.UID, cfg.CtlGID, logf); err != nil {
			return err
		}
	}
	entries, _ := os.ReadDir(SlotRunDir)
	for _, e := range entries {
		if !want[e.Name()] {
			if err := removeQuarantined(SlotRunDir + "/" + e.Name()); err != nil {
				logf("removing stale %s/%s: %v", SlotRunDir, e.Name(), err)
			}
		}
	}
	// Leftovers of the single-user layout.
	for _, name := range []string{"supervisor.sock", "pf.json.tmp", "pf.token.tmp", "pf.effective.rules.tmp"} {
		_ = os.Remove(RunDir + "/" + name)
	}
	return nil
}

// ensureDirReplacing is ensureDirIn for directories root may recreate: an
// entry owned by someone else, or one that is not a directory, is moved
// aside and deleted first.
func ensureDirReplacing(path string, mode os.FileMode, uid, gid int, logf func(string, ...any)) error {
	err := ensureDirIn(path, mode, uid, gid)
	if err == nil {
		return nil
	}
	var foreign *ForeignOwnerError
	if !errors.As(err, &foreign) && !strings.Contains(err.Error(), "not a directory") {
		return err
	}
	logf("replacing %s: %v", path, err)
	if err := removeQuarantined(path); err != nil {
		return err
	}
	return ensureDirIn(path, mode, uid, gid)
}
