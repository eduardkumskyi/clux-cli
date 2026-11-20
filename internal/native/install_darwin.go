//go:build darwin

package native

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// InstallOptions configures Install.
type InstallOptions struct {
	// Owner is the account that runs `clux host start`; empty = SUDO_USER.
	Owner      string
	CLIVersion string
	Out        io.Writer
}

// Install sets the machine up for native workspaces. Idempotent: every step
// converges an existing installation (same uid/gid/port) instead of
// failing, so re-running it after an update is also how the daemons get
// the new binary.
func Install(opts InstallOptions) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("`clux native install` must run as root: sudo clux native install")
	}
	out := opts.Out
	step := func(format string, args ...any) { fmt.Fprintf(out, "[ OK ] "+format+"\n", args...) }

	owner, err := resolveOwner(opts.Owner)
	if err != nil {
		return err
	}
	ownerUID, _ := strconv.Atoi(owner.Uid)
	if ownerUID == 0 {
		return fmt.Errorf("the owner must be a regular user, not root (pass --owner <user> or run via sudo)")
	}
	if _, err := os.Stat("/usr/bin/sandbox-exec"); err != nil {
		fmt.Fprintln(out, "[WARN] /usr/bin/sandbox-exec is missing: workspaces will run without the Seatbelt layer")
	}

	prev, _ := LoadConfig()

	// --- accounts -------------------------------------------------------------
	uids, gids, err := usedIDs()
	if err != nil {
		return err
	}
	agentUID, haveUser := dsID("/Users/"+AgentUser, "UniqueID")
	agentGID, haveGroup := dsID("/Groups/"+AgentGroup, "PrimaryGroupID")
	if haveUser && (agentUID < idRangeLo || agentUID > idRangeHi) {
		return fmt.Errorf("an account %s already exists with uid %d (outside %d-%d); refusing to reuse it", AgentUser, agentUID, idRangeLo, idRangeHi)
	}
	// Prefer uid == gid (like system accounts); fall back to any free id.
	switch {
	case !haveUser && !haveGroup:
		if agentUID, err = freeID(uids, gids); err != nil {
			return err
		}
		agentGID = agentUID
	case haveUser && !haveGroup:
		agentGID = agentUID
		if gids[agentGID] {
			if agentGID, err = freeID(gids); err != nil {
				return err
			}
		}
	case !haveUser && haveGroup:
		agentUID = agentGID
		if uids[agentUID] {
			if agentUID, err = freeID(uids); err != nil {
				return err
			}
		}
	}
	if !haveGroup {
		if err := dsCreate("/Groups/"+AgentGroup, map[string]string{
			"PrimaryGroupID": strconv.Itoa(agentGID), "RealName": "Clux agent", "Password": "*",
		}); err != nil {
			return err
		}
		gids[agentGID] = true
	}
	if !haveUser {
		if err := dsCreate("/Users/"+AgentUser, map[string]string{
			"UniqueID": strconv.Itoa(agentUID), "PrimaryGroupID": strconv.Itoa(agentGID),
			"UserShell": "/bin/zsh", "NFSHomeDirectory": AgentHome, "RealName": "Clux agent",
			"IsHidden": "1", "Password": "*",
		}); err != nil {
			return err
		}
	} else {
		// Converge the attributes the isolation depends on. Only write what
		// differs: changing an existing account record needs Full Disk
		// Access (eDSPermissionError), creating one doesn't.
		for k, v := range map[string]string{"PrimaryGroupID": strconv.Itoa(agentGID), "NFSHomeDirectory": AgentHome, "IsHidden": "1", "Password": "*"} {
			if cur, ok := dsAttr("/Users/"+AgentUser, k); ok && cur == v {
				continue
			}
			if _, err := run("/usr/bin/dscl", ".", "-create", "/Users/"+AgentUser, k, v); err != nil {
				return fmt.Errorf("%w (fixing an existing account needs Full Disk Access for this terminal)", err)
			}
		}
	}
	if _, err := run("/usr/sbin/dseditgroup", "-o", "checkmember", "-m", AgentUser, "staff"); err == nil {
		if _, err := run("/usr/sbin/dseditgroup", "-o", "edit", "-d", AgentUser, "-t", "user", "staff"); err != nil {
			return fmt.Errorf("removing %s from staff: %w", AgentUser, err)
		}
	}
	step("hidden user %s (uid %d, group %s gid %d, not in staff)", AgentUser, agentUID, AgentGroup, agentGID)

	ctlGID, haveCtl := dsID("/Groups/"+CtlGroup, "PrimaryGroupID")
	if !haveCtl {
		if ctlGID, err = freeID(gids); err != nil {
			return err
		}
		if err := dsCreate("/Groups/"+CtlGroup, map[string]string{
			"PrimaryGroupID": strconv.Itoa(ctlGID), "RealName": "Clux native control", "Password": "*",
		}); err != nil {
			return err
		}
	}
	if _, err := run("/usr/sbin/dseditgroup", "-o", "edit", "-a", owner.Username, "-t", "user", CtlGroup); err != nil {
		return fmt.Errorf("adding %s to %s: %w", owner.Username, CtlGroup, err)
	}
	_, _ = run("/usr/bin/dscacheutil", "-flushcache")
	step("control group %s (gid %d) = {%s}", CtlGroup, ctlGID, owner.Username)

	// --- directories ------------------------------------------------------------
	type dir struct {
		path     string
		mode     os.FileMode
		uid, gid int
	}
	dirs := []dir{
		{AgentHome, 0o700, agentUID, agentGID},
		{WorkspacesDir, 0o700, agentUID, agentGID},
		{AgentRunDir, 0o700, agentUID, agentGID},
		{AgentLogDir, 0o700, agentUID, agentGID},
		{AgentHome + "/Library", 0o700, agentUID, agentGID},
		{AgentHome + "/Library/Caches", 0o700, agentUID, agentGID},
		{AgentHome + "/Library/Preferences", 0o700, agentUID, agentGID},
		{AgentHome + "/Library/Logs", 0o700, agentUID, agentGID},
		{AgentHome + "/Library/Developer", 0o700, agentUID, agentGID},
		{AgentHome + "/Library/Developer/Xcode", 0o700, agentUID, agentGID},
		{RuntimeRoot, 0o750, ownerUID, agentGID},
		{RuntimeRoot + "/sidecar", 0o750, ownerUID, agentGID},
		{RuntimeRoot + "/python", 0o750, ownerUID, agentGID},
		{RuntimeRoot + "/uv", 0o750, ownerUID, agentGID},
		{RuntimeRoot + "/cache", 0o700, ownerUID, agentGID},
		{RunDir, 0o750, agentUID, ctlGID},
		// 0755: launchd opens the supervisor's log as _clux, which is not in
		// _cluxctl; the log files themselves are 0640 group _cluxctl.
		{LogDir, 0o755, 0, ctlGID},
		{ConfigDir, 0o755, 0, 0},
	}
	for _, d := range dirs {
		if err := ensureDir(d.path, d.mode, d.uid, d.gid); err != nil {
			return fmt.Errorf("%s: %w", d.path, err)
		}
	}
	for _, f := range []struct {
		path string
		uid  int
	}{{LogDir + "/pf.log", 0}, {LogDir + "/supervisor.log", agentUID}} {
		fd, err := os.OpenFile(f.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
		if err != nil {
			return err
		}
		fd.Close()
		_ = os.Chown(f.path, f.uid, ctlGID)
		_ = os.Chmod(f.path, 0o640)
	}
	step("directories (%s 0700, runtime %s owner:%s 0750)", AgentHome, RuntimeRoot, AgentGroup)

	ensureSimulatorMapping(out, owner.HomeDir, agentUID, agentGID)

	// --- binary + config ------------------------------------------------------------
	libexec, err := libexecDir()
	if err != nil {
		return err
	}
	if err := ensureDir(libexec, 0o755, 0, 0); err != nil {
		return err
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	if self, err = filepath.EvalSymlinks(self); err != nil {
		return err
	}
	bin := filepath.Join(libexec, "clux")
	if self != bin {
		if err := copyFile(self, bin, 0o755); err != nil {
			return fmt.Errorf("installing %s: %w", bin, err)
		}
	}
	_ = os.Chown(bin, 0, 0)
	step("daemon binary %s (root:wheel 0755)", bin)

	port := 0
	if prev != nil {
		port = prev.ProxyPort
	} else if port, err = pickProxyPort(); err != nil {
		return err
	}
	cfg := Config{
		Version: configVersion, OwnerUID: ownerUID, OwnerUser: owner.Username, OwnerHome: owner.HomeDir,
		AgentUser: AgentUser, AgentUID: agentUID, AgentGID: agentGID, CtlGID: ctlGID,
		ProxyPort: port, BinaryPath: bin, CLIVersion: opts.CLIVersion,
		InstalledAt: time.Now().UTC().Format(time.RFC3339),
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(cfg, "", "  ")
	if err := writeOwned(ConfigPath, append(b, '\n'), 0o644, 0, 0); err != nil {
		return err
	}
	if err := writeOwned(PFRulesPath, []byte(PFRules(agentUID, port, nil)), 0o644, 0, 0); err != nil {
		return err
	}
	step("config %s (egress proxy port %d), pf rules %s", ConfigPath, port, PFRulesPath)

	// --- daemons --------------------------------------------------------------------
	for _, d := range []struct{ label, plist string }{
		{PFLabel, PFDaemonPlist(bin)},
		{SupervisorLabel, SupervisorPlist(bin)},
	} {
		path := filepath.Join(LaunchDaemonsDir, d.label+".plist")
		if err := writeOwned(path, []byte(d.plist), 0o644, 0, 0); err != nil {
			return err
		}
		_, _ = run("/bin/launchctl", "bootout", "system/"+d.label)
		_, _ = run("/bin/launchctl", "enable", "system/"+d.label)
		var lerr error
		for i := 0; i < 5; i++ { // bootout is asynchronous; bootstrap can race it
			if _, lerr = run("/bin/launchctl", "bootstrap", "system", path); lerr == nil {
				break
			}
			time.Sleep(time.Second)
		}
		if lerr != nil {
			return lerr
		}
		step("LaunchDaemon %s", d.label)
	}

	if err := waitFor(20*time.Second, func() bool {
		st, err := ReadPFStatus()
		return err == nil && st.Enabled && st.RulesLoaded
	}); err != nil {
		return fmt.Errorf("pf daemon did not report an enabled firewall (see %s/pf.log)", LogDir)
	}
	step("pf enabled, anchor %s loaded", PFAnchor)
	if err := waitFor(20*time.Second, func() bool {
		_, err := os.Stat(SupervisorSocket)
		return err == nil
	}); err != nil {
		return fmt.Errorf("supervisor did not open %s (see %s/supervisor.log)", SupervisorSocket, LogDir)
	}
	step("supervisor listening on %s", SupervisorSocket)
	fmt.Fprintf(out, "\nNative macOS runtime installed. Restart `clux host start` (as %s) to offer it.\n", owner.Username)
	return nil
}

func resolveOwner(name string) (*user.User, error) {
	if name == "" {
		name = os.Getenv("SUDO_USER")
	}
	if name == "" {
		if uid := os.Getenv("SUDO_UID"); uid != "" {
			u, err := user.LookupId(uid)
			if err != nil {
				return nil, err
			}
			return u, nil
		}
		return nil, fmt.Errorf("can't tell who owns this machine: run `sudo clux native install` from your own account, or pass --owner <user>")
	}
	return user.Lookup(name)
}

func dsCreate(record string, attrs map[string]string) error {
	if _, err := run("/usr/bin/dscl", ".", "-create", record); err != nil {
		return err
	}
	// Deterministic order keeps failures reproducible.
	keys := make([]string, 0, len(attrs))
	for k := range attrs {
		keys = append(keys, k)
	}
	for _, k := range sortStrings(keys) {
		if _, err := run("/usr/bin/dscl", ".", "-create", record, k, attrs[k]); err != nil {
			return err
		}
	}
	return nil
}

// ensureSimulatorMapping puts SDKToSimulatorIndexMapping.plist into the
// agent's home: without it xcodebuild finds no simulator destination for a
// fresh account (spike fact 6). It's a pure SDK -> runtime index (no user
// data), so the owner's copy is used when present.
func ensureSimulatorMapping(out io.Writer, ownerHome string, uid, gid int) {
	const rel = "Library/Developer/Xcode/SDKToSimulatorIndexMapping.plist"
	dst := filepath.Join(AgentHome, rel)
	src := filepath.Join(ownerHome, rel)
	data, err := os.ReadFile(src)
	if err != nil {
		if _, derr := os.Stat(dst); derr == nil {
			fmt.Fprintf(out, "[ OK ] %s present\n", dst)
			return
		}
		fmt.Fprintf(out, "[WARN] %s not found. Open Xcode once (as %s), let it finish installing components,\n"+
			"       then re-run `sudo clux native install`; until then xcodebuild in workspaces may find no simulator.\n", src, filepath.Base(ownerHome))
		return
	}
	if old, err := os.ReadFile(dst); err == nil && bytes.Equal(old, data) {
		fmt.Fprintf(out, "[ OK ] simulator SDK mapping up to date\n")
		return
	}
	if err := writeOwned(dst, data, 0o644, uid, gid); err != nil {
		fmt.Fprintf(out, "[WARN] copying %s: %v\n", src, err)
		return
	}
	fmt.Fprintf(out, "[ OK ] simulator SDK mapping copied from %s\n", src)
}

func waitFor(d time.Duration, cond func() bool) error {
	deadline := time.Now().Add(d)
	for !cond() {
		if time.Now().After(deadline) {
			return fmt.Errorf("timeout")
		}
		time.Sleep(250 * time.Millisecond)
	}
	return nil
}

func sortStrings(s []string) []string {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
	return s
}

// --- uninstall ------------------------------------------------------------------

// UninstallOptions configures Uninstall.
type UninstallOptions struct {
	// Purge also deletes /private/var/clux (workspace files, simulators).
	Purge bool
	Out   io.Writer
}

// Uninstall removes native mode. Deleting the account records needs Full
// Disk Access for the calling process (eDSPermissionError otherwise); if
// that's missing, everything else is still removed and the exact commands
// to finish are printed.
func Uninstall(opts UninstallOptions) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("`clux native uninstall` must run as root: sudo clux native uninstall")
	}
	out := opts.Out
	step := func(format string, args ...any) { fmt.Fprintf(out, "[ OK ] "+format+"\n", args...) }
	cfg, _ := LoadConfig()
	agentUID, haveUser := dsID("/Users/"+AgentUser, "UniqueID")
	if cfg != nil && !haveUser {
		agentUID, haveUser = cfg.AgentUID, true
	}

	_, _ = run("/bin/launchctl", "bootout", "system/"+SupervisorLabel)
	if haveUser && agentUID >= idRangeLo && agentUID <= idRangeHi {
		killUser(agentUID)
		_, _ = run("/bin/launchctl", "bootout", "user/"+strconv.Itoa(agentUID))
		_, _ = run("/bin/launchctl", "bootout", "gui/"+strconv.Itoa(agentUID))
		step("stopped the supervisor and every %s process", AgentUser)
	}

	_, _ = run("/bin/launchctl", "bootout", "system/"+PFLabel)
	time.Sleep(500 * time.Millisecond)
	_, _ = run("/sbin/pfctl", "-a", PFAnchor, "-F", "all")
	if tok, err := os.ReadFile(PFTokenPath); err == nil && strings.TrimSpace(string(tok)) != "" {
		_, _ = run("/sbin/pfctl", "-X", strings.TrimSpace(string(tok)))
	}
	step("pf anchor %s flushed, enable reference released", PFAnchor)

	paths := []string{
		filepath.Join(LaunchDaemonsDir, PFLabel+".plist"),
		filepath.Join(LaunchDaemonsDir, SupervisorLabel+".plist"),
		ConfigDir, RunDir, LogDir, RuntimeRoot,
	}
	if cfg != nil && filepath.Base(filepath.Dir(cfg.BinaryPath)) == "clux-native" {
		paths = append(paths, filepath.Dir(cfg.BinaryPath))
	} else {
		paths = append(paths, primaryLibexec, fallbackLibexec)
	}
	if opts.Purge {
		paths = append(paths, AgentHome)
	}
	for _, p := range paths {
		if err := os.RemoveAll(p); err != nil {
			fmt.Fprintf(out, "[WARN] removing %s: %v\n", p, err)
		}
	}
	step("removed daemons, config, runtime and logs")
	if !opts.Purge {
		fmt.Fprintf(out, "[INFO] workspace files kept in %s (delete with `sudo rm -rf %s`, or uninstall with --purge)\n", WorkspacesDir, AgentHome)
	}

	var manual []string
	for _, rec := range []string{"/Users/" + AgentUser, "/Groups/" + AgentGroup, "/Groups/" + CtlGroup} {
		if _, ok := dsAttr(rec, "RecordName"); !ok {
			continue
		}
		if err := dsDelete(rec); err != nil {
			manual = append(manual, rec)
			fmt.Fprintf(out, "[WARN] could not delete %s: %v\n", rec, err)
			continue
		}
		step("deleted %s", rec)
	}
	_, _ = run("/usr/bin/dscacheutil", "-flushcache")
	if len(manual) > 0 {
		fmt.Fprint(out, "\nmacOS only lets a process with Full Disk Access delete account records.\n"+
			"To finish: System Settings > Privacy & Security > Full Disk Access > enable your terminal app,\n"+
			"open a NEW terminal window, then run:\n")
		for _, rec := range manual {
			fmt.Fprintf(out, "  sudo dscl . -delete %s\n", rec)
		}
		fmt.Fprintln(out, "(The account is hidden, has no password and nothing runs as it any more; leaving it is harmless.)")
		return nil
	}
	fmt.Fprintln(out, "\nNative macOS runtime uninstalled.")
	return nil
}

func dsDelete(record string) error {
	_, err := run("/usr/bin/dscl", ".", "-delete", record)
	if err == nil {
		return nil
	}
	if strings.HasPrefix(record, "/Users/") {
		if _, serr := run("/usr/sbin/sysadminctl", "-deleteUser", strings.TrimPrefix(record, "/Users/"), "-keepHome"); serr == nil {
			if _, still := dsAttr(record, "RecordName"); !still {
				return nil
			}
		}
	}
	if strings.Contains(err.Error(), "eDSPermissionError") {
		return fmt.Errorf("eDSPermissionError (needs Full Disk Access)")
	}
	return err
}
