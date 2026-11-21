//go:build darwin

package native

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// InstallOptions configures Install.
type InstallOptions struct {
	// Owner is the account that runs `clux host start`; empty = SUDO_USER.
	Owner string
	// Slots is the number of agent users (concurrently existing native
	// workspaces); 0 keeps the installed count (DefaultSlots at first).
	Slots      int
	CLIVersion string
	Out        io.Writer
}

// OwnerSlotMapFile is where `clux host start` keeps the workspace -> slot
// assignments, relative to the owner's home (uninstall removes it).
const OwnerSlotMapFile = ".clux/native-slots.json"

// Install sets the machine up for native workspaces. Idempotent: every step
// converges an existing installation (same uids/gids/port) instead of
// failing, so re-running it after an update is also how the daemons get
// the new binary, and re-running it with another --slots grows or shrinks
// the pool. An installation of the single-user layout is migrated.
func Install(opts InstallOptions) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("`clux native install` must run as root: sudo clux native install")
	}
	out := opts.Out
	step := func(format string, args ...any) { fmt.Fprintf(out, "[ OK ] "+format+"\n", args...) }
	warn := func(format string, args ...any) { fmt.Fprintf(out, "[WARN] "+format+"\n", args...) }

	owner, err := resolveOwner(opts.Owner)
	if err != nil {
		return err
	}
	ownerUID, _ := strconv.Atoi(owner.Uid)
	ownerGID, _ := strconv.Atoi(owner.Gid)
	if ownerUID == 0 {
		return fmt.Errorf("the owner must be a regular user, not root (pass --owner <user> or run via sudo)")
	}
	if _, err := os.Stat("/usr/bin/sandbox-exec"); err != nil {
		warn("/usr/bin/sandbox-exec is missing: workspaces will run without the Seatbelt layer")
	}

	prev := readPrevConfig(ConfigPath)
	nSlots := opts.Slots
	if nSlots == 0 {
		nSlots = DefaultSlots
		if prev.Version == configVersion && len(prev.Slots) > 0 {
			nSlots = len(prev.Slots)
		}
	}
	if nSlots < 1 || nSlots > MaxSlots {
		return fmt.Errorf("--slots must be 1-%d", MaxSlots)
	}

	// --- shrinking: never take a slot away from a workspace ---------------------
	var removed []Slot
	if prev.Version == configVersion && len(prev.Slots) > nSlots {
		removed = prev.Slots[nSlots:]
		for _, s := range removed {
			if ids := slotWorkspaces(s); len(ids) > 0 {
				return fmt.Errorf("slot %d (%s) still holds workspace(s) %s: delete them first, or keep --slots %d or more",
					s.N, s.User, strings.Join(ids, ", "), s.N)
			}
		}
	}

	// --- the single-user layout (config version 1) --------------------------------
	legacyUID := migrateLegacy(out)

	// --- accounts -------------------------------------------------------------------
	uids, gids, err := usedIDs()
	if err != nil {
		return err
	}
	if legacyUID > 0 { // don't hand the old account's leftover files to a slot
		uids[legacyUID], gids[legacyUID] = true, true
	}
	slotsGID, err := ensureGroup(SlotsGroup, "Clux agent slots", gids)
	if err != nil {
		return err
	}
	ctlGID, err := ensureGroup(CtlGroup, "Clux native control", gids)
	if err != nil {
		return err
	}
	if slotsGID == ctlGID {
		return fmt.Errorf("%s and %s share gid %d; delete one of the groups and re-run", SlotsGroup, CtlGroup, slotsGID)
	}
	slots := make([]Slot, 0, nSlots)
	for n := 1; n <= nSlots; n++ {
		s, err := ensureSlotUser(n, uids, gids)
		if err != nil {
			return err
		}
		slots = append(slots, s)
	}
	if err := ensureMembers(SlotsGroup, slotUserNames(slots)); err != nil {
		return err
	}
	if err := ensureMembers(CtlGroup, []string{owner.Username}); err != nil {
		return err
	}
	_, _ = run("/usr/bin/dscacheutil", "-flushcache")
	step("%d slot user(s) %s..%s (own groups, not in staff/admin), group %s (gid %d)",
		nSlots, slots[0].User, slots[len(slots)-1].User, SlotsGroup, slotsGID)
	step("control group %s (gid %d) = {%s}", CtlGroup, ctlGID, owner.Username)

	for _, s := range removed {
		removeSlot(out, s)
	}

	// --- directories ------------------------------------------------------------------
	// Only entries of root-owned directories, opened without following
	// links; nothing inside a slot home (its supervisor fills it).
	for _, d := range []struct {
		path     string
		mode     os.FileMode
		uid, gid int
	}{
		{AgentRoot, 0o755, 0, 0},
		{SlotsDir, 0o755, 0, 0},
		{SharedDir, 0o755, 0, 0},
		{LogDir, 0o755, 0, ctlGID}, // 0755: launchd opens each supervisor's log as its slot user
		{ConfigDir, 0o755, 0, 0},
	} {
		if err := ensureDirIn(d.path, d.mode, d.uid, d.gid); err != nil {
			return fmt.Errorf("%s: %w", d.path, err)
		}
	}
	for _, s := range slots {
		if err := ensureDirIn(SlotHome(s.N), 0o700, s.UID, s.GID); err != nil {
			return fmt.Errorf("slot %d home: %w", s.N, err)
		}
	}
	if err := ensureRuntimeRoot(ownerUID, ownerGID, slotsGID, step); err != nil {
		return err
	}
	if err := ensureFileIn(LogDir+"/pf.log", 0o640, 0, ctlGID); err != nil {
		return err
	}
	for _, s := range slots {
		if err := ensureFileIn(SupervisorLog(s.N), 0o640, s.UID, ctlGID); err != nil {
			return err
		}
	}
	_ = os.Remove(LogDir + "/supervisor.log") // single-user layout
	step("directories (slot homes %s/<n> 0700, runtime %s owner:%s 0750)", SlotsDir, RuntimeRoot, SlotsGroup)

	ensureSimulatorMapping(out, owner.HomeDir, ownerUID, ownerGID)

	// --- binary + config ------------------------------------------------------------
	libexec, err := libexecDir()
	if err != nil {
		return err
	}
	if err := ensureDirIn(libexec, 0o755, 0, 0); err != nil {
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
		data, err := os.ReadFile(self)
		if err != nil {
			return err
		}
		if err := writeFileSafe(bin, data, 0o755, 0, 0); err != nil {
			return fmt.Errorf("installing %s: %w", bin, err)
		}
	}
	step("daemon binary %s (root:wheel 0755)", bin)

	port := prev.ProxyPort
	if port < 1024 || port > 65535 {
		if port, err = pickProxyPort(); err != nil {
			return err
		}
	}
	cfg := Config{
		Version: configVersion, OwnerUID: ownerUID, OwnerUser: owner.Username, OwnerHome: owner.HomeDir,
		Slots: slots, SlotsGID: slotsGID, CtlGID: ctlGID,
		ProxyPort: port, BinaryPath: bin, CLIVersion: opts.CLIVersion,
		InstalledAt: time.Now().UTC().Format(time.RFC3339),
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	if err := ensureRunDirs(&cfg, func(f string, a ...any) { warn(f, a...) }); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(cfg, "", "  ")
	if err := writeFileSafe(ConfigPath, append(b, '\n'), 0o644, 0, 0); err != nil {
		return err
	}
	if err := writeFileSafe(PFRulesPath, []byte(PFRules(cfg.AgentUIDs(), cfg.OwnerUID, port, nil)), 0o644, 0, 0); err != nil {
		return err
	}
	step("config %s (egress proxy port %d), pf rules %s", ConfigPath, port, PFRulesPath)

	// --- daemons --------------------------------------------------------------------
	// pf first: a supervisor refuses workspace starts until the pf status
	// covers its uid.
	daemons := []struct{ label, plist string }{{PFLabel, PFDaemonPlist(bin)}}
	for _, s := range slots {
		daemons = append(daemons, struct{ label, plist string }{SupervisorLabel(s.N), SupervisorPlist(bin, s.N)})
	}
	for _, d := range daemons {
		if err := bootstrapDaemon(d.label, d.plist); err != nil {
			return err
		}
	}
	step("LaunchDaemons %s and %d supervisor(s)", PFLabel, len(slots))

	if err := waitFor(20*time.Second, func() bool {
		st, err := ReadPFStatus()
		if err != nil || !st.Active(time.Now()) {
			return false
		}
		for _, u := range cfg.AgentUIDs() {
			if !st.Covers(u) {
				return false
			}
		}
		return true
	}); err != nil {
		return fmt.Errorf("pf daemon did not report an enabled firewall covering every slot (see %s/pf.log)", LogDir)
	}
	step("pf enabled, anchor %s loaded and evaluated", PFAnchor)
	for _, s := range slots {
		if err := waitFor(20*time.Second, func() bool {
			_, err := os.Stat(SlotSocket(s.N))
			return err == nil
		}); err != nil {
			return fmt.Errorf("slot %d supervisor did not open %s (see %s)", s.N, SlotSocket(s.N), SupervisorLog(s.N))
		}
	}
	step("supervisors listening on %s/<n>/supervisor.sock", SlotRunDir)
	fmt.Fprintf(out, "\nNative macOS runtime installed with %d slot(s). Restart `clux host start` (as %s) to offer it.\n", nSlots, owner.Username)
	return nil
}

// migrateLegacy dismantles the single-user layout: its supervisor daemon is
// removed, every _clux process killed, the old home (the shared workspaces)
// moved aside root-only, and the account deleted when macOS allows it.
// Returns the legacy uid (0 if none).
func migrateLegacy(out io.Writer) int {
	legacyUID, haveUser := dsID("/Users/"+LegacyAgentUser, "UniqueID")
	plist := filepath.Join(LaunchDaemonsDir, SupervisorLabelPrefix+".plist")
	_, plistErr := os.Lstat(plist)
	root, _, rootErr := ownerOf(AgentRoot)
	if !haveUser && plistErr != nil && (rootErr != nil || root == 0) {
		return 0
	}
	if plistErr == nil || rootErr == nil && root != 0 {
		fmt.Fprintf(out, "[INFO] migrating the single-user native layout (%s) to per-workspace slots\n", LegacyAgentUser)
	} // else only the account record is left (it needs Full Disk Access to delete)
	_, _ = run("/bin/launchctl", "bootout", "system/"+SupervisorLabelPrefix)
	// The old pf daemon kept its enable token in a run dir the agent owned;
	// release that reference now (the new daemon takes its own), or it
	// would leak when the old dir is replaced.
	if ru, _, err := ownerOf(RunDir); err == nil && ru != 0 {
		_, _ = run("/bin/launchctl", "bootout", "system/"+PFLabel)
		if tok := readLegacyPFToken(RunDir + "/pf.token"); tok != "" {
			_, _ = run("/sbin/pfctl", "-X", tok)
		}
	}
	if plistErr == nil {
		if p, err := inTrustedDir(plist); err == nil {
			_ = os.Remove(p)
		}
	}
	if haveUser && inIDRange(legacyUID) {
		killUser(legacyUID)
		_, _ = run("/bin/launchctl", "bootout", "user/"+strconv.Itoa(legacyUID))
		_, _ = run("/bin/launchctl", "bootout", "gui/"+strconv.Itoa(legacyUID))
	}
	if rootErr == nil && root != 0 {
		kept, err := quarantineAs(AgentRoot, filepath.Base(AgentRoot)+"-legacy-"+time.Now().UTC().Format("20060102T150405"))
		if err != nil {
			// Seen on macOS 15.6: renaming to a new visible name fails with
			// EPERM where a dot-name works.
			kept, err = quarantine(AgentRoot)
		}
		if err != nil {
			fmt.Fprintf(out, "[WARN] moving the old %s aside: %v\n", AgentRoot, err)
		} else {
			fmt.Fprintf(out, "[ OK ] old workspace files kept root-only in %s (delete with `sudo rm -rf %s`)\n", kept, kept)
		}
	}
	if haveUser {
		for _, rec := range []string{"/Users/" + LegacyAgentUser, "/Groups/" + LegacyAgentUser} {
			if _, ok := dsAttr(rec, "RecordName"); !ok {
				continue
			}
			if err := dsDelete(rec); err != nil {
				fmt.Fprintf(out, "[WARN] could not delete %s (%v); it is hidden, has no password and nothing runs as it any more\n", rec, err)
			} else {
				fmt.Fprintf(out, "[ OK ] deleted %s\n", rec)
			}
		}
	}
	if !inIDRange(legacyUID) {
		return 0
	}
	return legacyUID
}

// readLegacyPFToken reads the token the single-user pf daemon wrote into
// its (agent-owned) run dir. Only a root-owned single-link regular file
// holding a plain number is believed: the agent can't create root files,
// and pfctl -X with a number releases at most one pf reference.
func readLegacyPFToken(path string) string {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return ""
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return ""
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok || !st.Mode().IsRegular() || sys.Uid != 0 || sys.Nlink != 1 || st.Size() > 64 {
		return ""
	}
	b, _ := io.ReadAll(f)
	tok := strings.TrimSpace(string(b))
	if _, err := strconv.ParseUint(tok, 10, 64); err != nil {
		return ""
	}
	return tok
}

// ensureGroup returns the gid of group name, creating it if needed.
func ensureGroup(name, realName string, gids map[int]bool) (int, error) {
	gid, ok := dsID("/Groups/"+name, "PrimaryGroupID")
	if ok {
		if !inIDRange(gid) {
			return 0, fmt.Errorf("group %s exists with gid %d (outside %d-%d); refusing to reuse it", name, gid, idRangeLo, idRangeHi)
		}
		return gid, nil
	}
	gid, err := freeID(gids)
	if err != nil {
		return 0, err
	}
	return gid, dsCreate("/Groups/"+name, map[string]string{"PrimaryGroupID": strconv.Itoa(gid), "RealName": realName, "Password": "*"})
}

// ensureSlotUser creates or converges slot n's user and primary group.
func ensureSlotUser(n int, uids, gids map[int]bool) (Slot, error) {
	name := SlotUser(n)
	uid, haveUser := dsID("/Users/"+name, "UniqueID")
	gid, haveGroup := dsID("/Groups/"+name, "PrimaryGroupID")
	if haveUser && !inIDRange(uid) {
		return Slot{}, fmt.Errorf("an account %s already exists with uid %d (outside %d-%d); refusing to reuse it", name, uid, idRangeLo, idRangeHi)
	}
	if haveGroup && !inIDRange(gid) {
		return Slot{}, fmt.Errorf("a group %s already exists with gid %d (outside %d-%d); refusing to reuse it", name, gid, idRangeLo, idRangeHi)
	}
	var err error
	// Prefer uid == gid (like system accounts); fall back to any free id.
	switch {
	case !haveUser && !haveGroup:
		if uid, err = freeID(uids, gids); err != nil {
			return Slot{}, err
		}
		gid = uid
	case haveUser && !haveGroup:
		gid = uid
		if gids[gid] {
			if gid, err = freeID(gids); err != nil {
				return Slot{}, err
			}
		}
		gids[gid] = true
	case !haveUser && haveGroup:
		uid = gid
		if uids[uid] {
			if uid, err = freeID(uids); err != nil {
				return Slot{}, err
			}
		}
		uids[uid] = true
	}
	if !haveGroup {
		if err := dsCreate("/Groups/"+name, map[string]string{
			"PrimaryGroupID": strconv.Itoa(gid), "RealName": "Clux agent slot " + strconv.Itoa(n), "Password": "*",
		}); err != nil {
			return Slot{}, err
		}
	}
	want := map[string]string{
		"UniqueID": strconv.Itoa(uid), "PrimaryGroupID": strconv.Itoa(gid), "UserShell": "/bin/zsh",
		"NFSHomeDirectory": SlotHome(n), "RealName": "Clux agent slot " + strconv.Itoa(n), "IsHidden": "1", "Password": "*",
	}
	if !haveUser {
		if err := dsCreate("/Users/"+name, want); err != nil {
			return Slot{}, err
		}
	} else {
		// Converge the attributes the isolation depends on. Only write what
		// differs: changing an existing account record needs Full Disk
		// Access (eDSPermissionError), creating one doesn't.
		for _, k := range []string{"PrimaryGroupID", "NFSHomeDirectory", "IsHidden", "Password"} {
			if cur, ok := dsAttr("/Users/"+name, k); ok && cur == want[k] {
				continue
			}
			if _, err := run("/usr/bin/dscl", ".", "-create", "/Users/"+name, k, want[k]); err != nil {
				return Slot{}, fmt.Errorf("%w (fixing an existing account needs Full Disk Access for this terminal)", err)
			}
		}
	}
	for _, g := range []string{"staff", "admin"} {
		if _, err := run("/usr/sbin/dseditgroup", "-o", "checkmember", "-m", name, g); err == nil {
			if _, err := run("/usr/sbin/dseditgroup", "-o", "edit", "-d", name, "-t", "user", g); err != nil {
				return Slot{}, fmt.Errorf("removing %s from %s: %w", name, g, err)
			}
		}
	}
	return Slot{N: n, User: name, UID: uid, GID: gid}, nil
}

func slotUserNames(slots []Slot) []string {
	out := make([]string, len(slots))
	for i, s := range slots {
		out[i] = s.User
	}
	return out
}

// ensureMembers makes group's member list exactly members (a previous
// owner leaves _cluxctl; removed slots leave _cluxslots).
func ensureMembers(group string, members []string) error {
	want := map[string]bool{}
	for _, m := range members {
		want[m] = true
		if _, err := run("/usr/sbin/dseditgroup", "-o", "checkmember", "-m", m, group); err != nil {
			if _, err := run("/usr/sbin/dseditgroup", "-o", "edit", "-a", m, "-t", "user", group); err != nil {
				return fmt.Errorf("adding %s to %s: %w", m, group, err)
			}
		}
	}
	cur, _ := run("/usr/bin/dscl", ".", "-read", "/Groups/"+group, "GroupMembership")
	for _, m := range parseDSList(cur) {
		if !want[m] {
			if _, err := run("/usr/sbin/dseditgroup", "-o", "edit", "-d", m, "-t", "user", group); err != nil {
				return fmt.Errorf("removing %s from %s: %w", m, group, err)
			}
		}
	}
	return nil
}

// ensureRuntimeRoot makes RuntimeRoot owner:_cluxslots 0750 with its
// subdirectories. A runtime dir of another owner or group (owner change,
// single-user layout) is deleted: it's a cache, reinstalled on the next
// workspace start, and its files would carry the wrong group.
func ensureRuntimeRoot(ownerUID, ownerGID, slotsGID int, step func(string, ...any)) error {
	if uid, gid, err := ownerOf(RuntimeRoot); err == nil && (uid != ownerUID || gid != slotsGID) || err != nil && !os.IsNotExist(err) {
		if err := removeQuarantined(RuntimeRoot); err != nil {
			return fmt.Errorf("resetting %s: %w", RuntimeRoot, err)
		}
		step("reset %s (owner/group changed); runtimes are reinstalled on the next workspace start", RuntimeRoot)
	}
	if err := ensureDirIn(RuntimeRoot, 0o750, ownerUID, slotsGID); err != nil {
		return fmt.Errorf("%s: %w", RuntimeRoot, err)
	}
	// Inside the owner's directory: as the owner (new entries take the
	// directory's group, BSD semantics).
	if err := runAs(ownerUID, ownerGID, nil, "/bin/mkdir", "-p", "-m", "0750",
		RuntimeRoot+"/sidecar", RuntimeRoot+"/python", RuntimeRoot+"/uv"); err != nil {
		return err
	}
	return runAs(ownerUID, ownerGID, nil, "/bin/mkdir", "-p", "-m", "0700", RuntimeRoot+"/cache")
}

// slotWorkspaces lists the workspace dirs in slot s's home, read with the
// slot user's own privileges.
func slotWorkspaces(s Slot) []string {
	var b bytes.Buffer
	if err := runAs(s.UID, s.GID, &b, "/bin/ls", "-A", SlotHome(s.N)+"/workspaces"); err != nil {
		return nil
	}
	return strings.Fields(b.String())
}

// removeSlot takes a slot out of the pool (shrinking): daemon, processes,
// files, socket dir and, when macOS allows, the account.
func removeSlot(out io.Writer, s Slot) {
	stopSlot(s.N, s.UID)
	if p, err := inTrustedDir(filepath.Join(LaunchDaemonsDir, SupervisorLabel(s.N)+".plist")); err == nil {
		_ = os.Remove(p)
	}
	for _, p := range []string{SlotHome(s.N), SlotSocketDir(s.N)} {
		if err := removeQuarantined(p); err != nil {
			fmt.Fprintf(out, "[WARN] removing %s: %v\n", p, err)
		}
	}
	if p, err := inTrustedDir(SupervisorLog(s.N)); err == nil {
		_ = os.Remove(p)
	}
	for _, rec := range []string{"/Users/" + s.User, "/Groups/" + s.User} {
		if err := dsDelete(rec); err != nil {
			fmt.Fprintf(out, "[WARN] could not delete %s (%v); it is hidden and nothing runs as it\n", rec, err)
		}
	}
	fmt.Fprintf(out, "[ OK ] removed slot %d (%s)\n", s.N, s.User)
}

// stopSlot stops slot n's supervisor and every process of its user.
func stopSlot(n, uid int) {
	_, _ = run("/bin/launchctl", "bootout", "system/"+SupervisorLabel(n))
	if inIDRange(uid) {
		killUser(uid)
		_, _ = run("/bin/launchctl", "bootout", "user/"+strconv.Itoa(uid))
		_, _ = run("/bin/launchctl", "bootout", "gui/"+strconv.Itoa(uid))
	}
}

// bootstrapDaemon (re)writes a LaunchDaemon plist and (re)loads it.
func bootstrapDaemon(label, plistText string) error {
	path := filepath.Join(LaunchDaemonsDir, label+".plist")
	if err := writeFileSafe(path, []byte(plistText), 0o644, 0, 0); err != nil {
		return err
	}
	_, _ = run("/bin/launchctl", "bootout", "system/"+label)
	// Only clear a "disabled" override; never add an override of our own.
	if launchdDisabled(label) {
		_, _ = run("/bin/launchctl", "enable", "system/"+label)
	}
	var lerr error
	for i := 0; i < 5; i++ { // bootout is asynchronous; bootstrap can race it
		if _, lerr = run("/bin/launchctl", "bootstrap", "system", path); lerr == nil {
			return nil
		}
		time.Sleep(time.Second)
	}
	return lerr
}

func launchdDisabled(label string) bool {
	out, err := run("/bin/launchctl", "print-disabled", "system")
	if err != nil {
		return false
	}
	return launchdOverride(out, label) == "disabled"
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

// ensureSimulatorMapping publishes SDKToSimulatorIndexMapping.plist in
// SharedDir for every slot's supervisor to copy into its own Library:
// without it xcodebuild finds no simulator destination for a fresh account
// (spike fact 6). It's a pure SDK -> runtime index (no user data). It is
// read from the owner's home with the owner's privileges (root must not be
// steered into copying some other file there).
func ensureSimulatorMapping(out io.Writer, ownerHome string, ownerUID, ownerGID int) {
	const rel = "Library/Developer/Xcode/SDKToSimulatorIndexMapping.plist"
	src := filepath.Join(ownerHome, rel)
	data, err := readFileAs(ownerUID, ownerGID, src, 4<<20)
	if err != nil {
		if _, derr := os.Stat(SimMappingPath); derr == nil {
			fmt.Fprintf(out, "[ OK ] %s present\n", SimMappingPath)
			return
		}
		fmt.Fprintf(out, "[WARN] %s not found. Open Xcode once (as %s), let it finish installing components,\n"+
			"       then re-run `sudo clux native install`; until then xcodebuild in workspaces may find no simulator.\n", src, filepath.Base(ownerHome))
		return
	}
	if !isPlist(data) {
		fmt.Fprintf(out, "[WARN] %s is not a property list; not copied\n", src)
		return
	}
	if old, err := os.ReadFile(SimMappingPath); err == nil && bytes.Equal(old, data) {
		fmt.Fprintf(out, "[ OK ] simulator SDK mapping up to date\n")
		return
	}
	if err := writeFileSafe(SimMappingPath, data, 0o644, 0, 0); err != nil {
		fmt.Fprintf(out, "[WARN] copying %s: %v\n", src, err)
		return
	}
	fmt.Fprintf(out, "[ OK ] simulator SDK mapping copied from %s\n", src)
}

func isPlist(b []byte) bool {
	t := bytes.TrimLeft(b, " \t\r\n")
	return bytes.HasPrefix(t, []byte("bplist")) || bytes.HasPrefix(t, []byte("<?xml")) || bytes.HasPrefix(t, []byte("<plist"))
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
	// Purge also deletes the slot homes (workspace files, simulators).
	Purge bool
	Out   io.Writer
}

// Uninstall removes native mode: every slot's daemon and processes, the pf
// anchor and our pf reference, config, runtime, logs, the owner-side egress
// and slot state. Without --purge the slot homes are kept, made root:wheel
// 0700 so no leftover uid owns reachable files. Deleting the account
// records needs Full Disk Access for the calling process
// (eDSPermissionError otherwise); if that's missing, everything else is
// still removed and the exact commands to finish are printed.
func Uninstall(opts UninstallOptions) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("`clux native uninstall` must run as root: sudo clux native uninstall")
	}
	out := opts.Out
	step := func(format string, args ...any) { fmt.Fprintf(out, "[ OK ] "+format+"\n", args...) }
	warn := func(format string, args ...any) { fmt.Fprintf(out, "[WARN] "+format+"\n", args...) }
	cfg, _ := LoadConfig()

	// Every supervisor (slots and the legacy one) and every agent process.
	_, _ = run("/bin/launchctl", "bootout", "system/"+SupervisorLabelPrefix)
	var accounts []string
	for n := 1; n <= MaxSlots; n++ {
		uid, ok := dsID("/Users/"+SlotUser(n), "UniqueID")
		if !ok && cfg != nil {
			if s, sok := cfg.Slot(n); sok {
				uid, ok = s.UID, true
			}
		}
		_, plistErr := os.Lstat(filepath.Join(LaunchDaemonsDir, SupervisorLabel(n)+".plist"))
		if !ok && plistErr != nil {
			continue
		}
		stopSlot(n, uid)
		accounts = append(accounts, SlotUser(n))
	}
	if uid, ok := dsID("/Users/"+LegacyAgentUser, "UniqueID"); ok && inIDRange(uid) {
		killUser(uid)
		_, _ = run("/bin/launchctl", "bootout", "user/"+strconv.Itoa(uid))
		_, _ = run("/bin/launchctl", "bootout", "gui/"+strconv.Itoa(uid))
		accounts = append(accounts, LegacyAgentUser)
	}
	step("stopped the supervisors and every agent process")

	_, _ = run("/bin/launchctl", "bootout", "system/"+PFLabel)
	time.Sleep(500 * time.Millisecond)
	_, _ = run("/sbin/pfctl", "-a", PFAnchor, "-F", "all")
	if tok, err := readPFToken(); err == nil {
		_, _ = run("/sbin/pfctl", "-X", tok)
	}
	step("pf anchor %s flushed, enable reference released", PFAnchor)

	if entries, err := os.ReadDir(LaunchDaemonsDir); err == nil {
		for _, e := range entries {
			if name := e.Name(); name == PFLabel+".plist" || strings.HasPrefix(name, SupervisorLabelPrefix) && strings.HasSuffix(name, ".plist") {
				if p, err := inTrustedDir(filepath.Join(LaunchDaemonsDir, name)); err == nil {
					_ = os.Remove(p)
				}
			}
		}
	}
	paths := []string{ConfigDir, RunDir, LogDir, RuntimeRoot}
	if cfg != nil && filepath.Base(filepath.Dir(cfg.BinaryPath)) == "clux-native" {
		paths = append(paths, filepath.Dir(cfg.BinaryPath))
	} else {
		paths = append(paths, primaryLibexec, fallbackLibexec)
	}
	for _, p := range paths {
		if err := removeQuarantined(p); err != nil && !os.IsNotExist(err) {
			warn("removing %s: %v", p, err)
		}
	}
	step("removed daemons, config, runtime and logs")

	// The owner's egress proxy key, policies and slot assignments, removed
	// with the owner's privileges (root never deletes inside a home by name).
	if cfg != nil && cfg.OwnerUID > 0 && filepath.IsAbs(cfg.OwnerHome) {
		gid := cfg.OwnerUID
		if u, err := user.LookupId(strconv.Itoa(cfg.OwnerUID)); err == nil {
			gid, _ = strconv.Atoi(u.Gid)
		}
		st := filepath.Join(cfg.OwnerHome, ".clux")
		if err := runAs(cfg.OwnerUID, gid, nil, "/bin/rm", "-rf", "--",
			st+"/egress", st+"/egress.key", filepath.Join(cfg.OwnerHome, OwnerSlotMapFile)); err != nil {
			warn("removing the egress proxy state in %s: %v", st, err)
		} else {
			step("removed the egress proxy key, policies and slot assignments in %s", st)
		}
	}

	if opts.Purge {
		if err := removeQuarantined(AgentRoot); err != nil && !os.IsNotExist(err) {
			warn("removing %s: %v", AgentRoot, err)
		}
		legacy, _ := filepath.Glob(AgentRoot + "-legacy-*")
		for _, p := range legacy {
			if err := removeQuarantined(p); err != nil {
				warn("removing %s: %v", p, err)
			}
		}
		step("deleted workspace files (%s)", AgentRoot)
	} else if entries, err := os.ReadDir(SlotsDir); err == nil {
		for _, e := range entries {
			if err := lockDir(filepath.Join(SlotsDir, e.Name())); err != nil {
				warn("locking %s/%s: %v", SlotsDir, e.Name(), err)
			}
		}
		fmt.Fprintf(out, "[INFO] workspace files kept root-only in %s (delete with `sudo rm -rf %s`, or uninstall with --purge)\n", SlotsDir, AgentRoot)
	}

	var manual []string
	records := []string{}
	for _, a := range accounts {
		records = append(records, "/Users/"+a, "/Groups/"+a)
	}
	records = append(records, "/Groups/"+SlotsGroup, "/Groups/"+CtlGroup)
	for _, rec := range records {
		if _, ok := dsAttr(rec, "RecordName"); !ok {
			continue
		}
		if err := dsDelete(rec); err != nil {
			manual = append(manual, rec)
			warn("could not delete %s: %v", rec, err)
			continue
		}
		step("deleted %s", rec)
	}
	_, _ = run("/usr/bin/dscacheutil", "-flushcache")
	fmt.Fprintf(out, "[INFO] launchd keeps an \"enabled\" entry per label in `launchctl print-disabled system`; it has no effect without the plist\n")
	if len(manual) > 0 {
		fmt.Fprint(out, "\nmacOS only lets a process with Full Disk Access delete account records.\n"+
			"To finish: System Settings > Privacy & Security > Full Disk Access > enable your terminal app,\n"+
			"open a NEW terminal window, then run:\n")
		for _, rec := range manual {
			fmt.Fprintf(out, "  sudo dscl . -delete %s\n", rec)
		}
		fmt.Fprintln(out, "(The accounts are hidden, have no password and nothing runs as them any more; leaving them is harmless.)")
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
	if _, ok := dsAttr(record, "RecordName"); !ok {
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
		return errors.New("eDSPermissionError (needs Full Disk Access)")
	}
	return err
}
