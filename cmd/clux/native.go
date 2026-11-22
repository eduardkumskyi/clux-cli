package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/eduardkumskyi/clux-cli/internal/config"
	"github.com/eduardkumskyi/clux-cli/internal/egress"
	"github.com/eduardkumskyi/clux-cli/internal/hostsession"
	"github.com/eduardkumskyi/clux-cli/internal/native"
	"github.com/eduardkumskyi/clux-cli/internal/sidecarrt"
	"github.com/eduardkumskyi/clux-cli/internal/supervisor"
)

func runNative(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: clux native <install|uninstall|status>")
	}
	switch args[0] {
	case "install":
		fs := flag.NewFlagSet("native install", flag.ExitOnError)
		owner := fs.String("owner", "", "account that runs `clux host start` (default: the user who ran sudo)")
		slots := fs.Int("slots", 0, fmt.Sprintf("number of agent users = native workspaces that can exist at once (1-%d; default: keep the installed count, %d at first)", native.MaxSlots, native.DefaultSlots))
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *slots < 0 || *slots > native.MaxSlots {
			return fmt.Errorf("--slots must be 1-%d", native.MaxSlots)
		}
		return native.Install(native.InstallOptions{Owner: *owner, Slots: *slots, CLIVersion: version, Out: os.Stdout})
	case "uninstall":
		fs := flag.NewFlagSet("native uninstall", flag.ExitOnError)
		purge := fs.Bool("purge", false, "also delete workspace files and simulators in "+native.SlotsDir)
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		return native.Uninstall(native.UninstallOptions{Purge: *purge, Out: os.Stdout})
	case "status":
		return runNativeStatus()
	case "supervise": // LaunchDaemon entry point (runs as the slot user)
		fs := flag.NewFlagSet("native supervise", flag.ExitOnError)
		slot := fs.Int("slot", 0, "slot to serve")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		return runSupervise(*slot)
	case "pfd": // LaunchDaemon entry point (runs as root)
		return runPFD()
	case "daemon-check":
		// Run by the root daemon on a freshly downloaded release before it
		// replaces itself: prints this version if it can run this
		// installation (reads its config).
		if _, err := native.LoadConfig(); err != nil {
			return err
		}
		fmt.Println(version)
		return nil
	default:
		return fmt.Errorf("unknown native subcommand %q", args[0])
	}
}

func daemonContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

func runSupervise(slot int) error {
	logger := log.New(os.Stderr, fmt.Sprintf("supervisor[%d]: ", slot), log.LstdFlags)
	cfg, err := native.LoadConfig()
	if err != nil {
		return err
	}
	s, ok := cfg.Slot(slot)
	if !ok {
		return fmt.Errorf("no slot %d in %s", slot, native.ConfigPath)
	}
	// The root half: bind the socket where only root can, then become the
	// slot user for good, before anything else runs.
	if os.Geteuid() != 0 {
		return fmt.Errorf("`clux native supervise` is started as root by its LaunchDaemon (re-run `sudo clux native install`)")
	}
	l, err := native.ListenSlotSocket(cfg, s, logger.Printf)
	if err != nil {
		return fmt.Errorf("supervisor socket: %w", err)
	}
	if err := native.DropToSlot(cfg, s); err != nil {
		return fmt.Errorf("dropping to %s: %w", s.User, err)
	}
	ctx, stop := daemonContext()
	defer stop()
	srv, err := supervisor.NewServer(supervisor.Options{Config: cfg, Slot: slot, Version: version, Logf: logger.Printf, Listener: l})
	if err != nil {
		return err
	}
	return srv.Serve(ctx)
}

func runPFD() error {
	logger := log.New(os.Stderr, "pfd: ", log.LstdFlags)
	ctx, stop := daemonContext()
	defer stop()
	return native.RunPFD(ctx, native.PFDOptions{Logf: logger.Printf, Version: version, SlotStatus: slotVersionBusy})
}

// slotVersionBusy (as root, for the self-update): the version slot n's
// supervisor runs and whether it runs a workspace.
func slotVersionBusy(ctx context.Context, n int) (string, bool, error) {
	r, err := slotClient(native.Slot{N: n}).Call(ctx, supervisor.Request{Op: supervisor.OpStatus})
	if err != nil {
		return "", false, err
	}
	for _, w := range r.Workspaces {
		if w.Running {
			return r.Version, true, nil
		}
	}
	return r.Version, false, nil
}

// slotClient is the owner's client for slot n's supervisor; it refuses a
// socket root did not create (anything the agent binds).
func slotClient(s native.Slot) *supervisor.Client {
	return &supervisor.Client{Socket: native.SlotSocket(s.N), RootListener: true}
}

type slotStatus struct {
	slot native.Slot
	resp supervisor.Response
	err  error
}

// slotsStatus asks every slot's supervisor for its status.
func slotsStatus(ctx context.Context, cfg *native.Config) []slotStatus {
	out := make([]slotStatus, len(cfg.Slots))
	for i, s := range cfg.Slots {
		sctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		r, err := slotClient(s).Call(sctx, supervisor.Request{Op: supervisor.OpStatus})
		cancel()
		out[i] = slotStatus{slot: s, resp: r, err: err}
	}
	return out
}

// supervisorsSummary folds the slots' answers into one version + sandbox
// state for the capabilities: the sandbox is "active" only if every
// answering slot says so; an error only if no slot answers.
func supervisorsSummary(st []slotStatus) (version, sandbox string, err error) {
	sandbox = supervisor.SandboxActive
	ok := 0
	for _, s := range st {
		if s.err != nil {
			err = s.err
			continue
		}
		ok++
		if version == "" {
			version = s.resp.Version
		}
		if s.resp.Sandbox != supervisor.SandboxActive {
			sandbox = supervisor.SandboxUnavailable
		}
	}
	if ok == 0 {
		if err == nil {
			err = errors.New("no native slots")
		}
		return "", supervisor.SandboxUnavailable, err
	}
	return version, sandbox, nil
}

func runNativeStatus() error {
	if runtime.GOOS != "darwin" {
		fmt.Println("native macOS runtime: not available on", runtime.GOOS)
		return nil
	}
	cfg, err := native.LoadConfig()
	if errors.Is(err, os.ErrNotExist) {
		fmt.Println("native macOS runtime: not installed (sudo clux native install)")
		return nil
	}
	if err != nil {
		return err
	}
	fmt.Printf("native macOS runtime: installed %s by clux %s (%s)\n", cfg.InstalledAt, cfg.CLIVersion, native.ConfigPath)
	fmt.Printf("  owner:         %s (uid %d)\n", cfg.OwnerUser, cfg.OwnerUID)
	fmt.Printf("  egress proxy:  127.0.0.1:%d and [::1]:%d (served by `clux host start`)\n", cfg.ProxyPort, cfg.ProxyPort)
	fmt.Printf("  %-29s %s\n", native.PFLabel+":", launchdState(native.PFLabel))
	if st, err := native.ReadPFStatus(); err != nil {
		fmt.Printf("  pf:            unknown (%v)\n", err)
	} else {
		state := "INACTIVE"
		if st.Active(time.Now()) {
			state = "active"
		}
		fmt.Printf("  pf:            %s (enabled=%v, anchor %s loaded=%v, main ruleset evaluates it=%v, uids %v, %d listener port(s), updated %s)\n",
			state, st.Enabled, st.Anchor, st.RulesLoaded, st.MainAnchor, st.UIDs, st.ListenerPorts, st.Updated)
		if st.Error != "" {
			fmt.Printf("                 last error: %s\n", st.Error)
		}
	}
	fmt.Printf("  slots:         %d (agent users, one workspace each; homes %s/<n>)\n", len(cfg.Slots), native.SlotsDir)
	for _, s := range slotsStatus(context.Background(), cfg) {
		acct := "MISSING"
		if u, err := user.Lookup(s.slot.User); err == nil && u.Uid == fmt.Sprint(s.slot.UID) {
			acct = "uid " + u.Uid
		}
		fmt.Printf("    slot %d %s (%s), %s: ", s.slot.N, s.slot.User, acct, launchdState(native.SupervisorLabel(s.slot.N)))
		if s.err != nil {
			fmt.Printf("supervisor not reachable: %v\n", s.err)
			continue
		}
		holds := "free"
		if len(s.resp.Resident) > 0 {
			holds = "workspace " + strings.Join(s.resp.Resident, ", ")
		}
		fmt.Printf("version %s, sandbox %s, %s\n", s.resp.Version, s.resp.Sandbox, holds)
		fmt.Printf("      root slot keeper: %s\n", keeperSummary(s.slot.N))
		for _, w := range s.resp.Workspaces {
			fmt.Printf("      workspace %s: running=%v pid=%d port=%d runtime=%s\n", w.ID, w.Running, w.PID, w.Port, w.RuntimeVersion)
		}
	}
	return nil
}

// keeperSummary describes root's record of slot n.
func keeperSummary(n int) string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	st, err := (&native.KeeperClient{Socket: native.KeeperSocket}).State(ctx, n)
	switch {
	case err != nil:
		return "unknown (" + err.Error() + ")"
	case st.Busy:
		return "wiping"
	case st.ClaimedBy != "":
		return "held by workspace " + st.ClaimedBy
	case st.Free():
		return "wiped, free"
	case !st.Known:
		return "no record yet (wiped before its first workspace)"
	default:
		return "NOT wiped since its last workspace (" + st.LastError + ")"
	}
}

func launchdState(label string) string {
	out, err := exec.Command("/bin/launchctl", "print", "system/"+label).CombinedOutput()
	if err != nil {
		return "not loaded"
	}
	for _, line := range strings.Split(string(out), "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "state = "); ok {
			return "loaded, " + v
		}
	}
	return "loaded"
}

// nativeDoctor adds the native runtime's checks to `clux doctor`.
func nativeDoctor(check func(name string, err error)) {
	if runtime.GOOS != "darwin" {
		return
	}
	cfg, err := native.LoadConfig()
	if errors.Is(err, os.ErrNotExist) {
		fmt.Println("[INFO] native macOS runtime not installed (optional, for iOS/Xcode: sudo clux native install)")
		return
	}
	check("native: config "+native.ConfigPath, err)
	if err != nil {
		return
	}
	if cfg.OwnerUID != os.Getuid() {
		check("native: installed for this user", fmt.Errorf("installed for %s (uid %d); run `sudo clux native install` from this account", cfg.OwnerUser, cfg.OwnerUID))
		return
	}
	st, perr := native.ReadPFStatus()
	if perr == nil && !st.Active(time.Now()) {
		perr = fmt.Errorf("pf daemon not keeping the firewall active (enabled=%v, anchor loaded=%v, main ruleset evaluates it=%v, updated %s); see %s/pf.log",
			st.Enabled, st.RulesLoaded, st.MainAnchor, st.Updated, native.LogDir)
	}
	if perr == nil {
		for _, u := range cfg.AgentUIDs() {
			if !st.Covers(u) {
				perr = fmt.Errorf("pf rules don't cover agent uid %d; re-run `sudo clux native install`", u)
				break
			}
		}
	}
	check("native: pf firewall active for every agent user", perr)
	for _, s := range slotsStatus(context.Background(), cfg) {
		name := fmt.Sprintf("native: slot %d (%s)", s.slot.N, s.slot.User)
		if u, err := user.Lookup(s.slot.User); err != nil || u.Uid != fmt.Sprint(s.slot.UID) {
			check(name+" account", fmt.Errorf("account missing or uid changed; re-run `sudo clux native install`"))
			continue
		}
		check(name+" supervisor reachable", s.err)
		if s.err == nil {
			var sbErr error
			if s.resp.Sandbox != supervisor.SandboxActive {
				sbErr = fmt.Errorf("Seatbelt self-check failed; workspaces run with user + pf isolation only (see %s)", native.SupervisorLog(s.slot.N))
			}
			check(name+" Seatbelt sandbox active", sbErr)
		}
	}
	f, werr := os.CreateTemp(filepath.Join(native.RuntimeRoot, "sidecar"), ".doctor-")
	if werr == nil {
		f.Close()
		os.Remove(f.Name())
	}
	check("native: runtime dir writable by you", werr)
}

// nativeHost is the owner-side half of the native runtime inside `clux host
// start`: the egress proxy, the runtime installer, the slot assignments and
// the supervisor clients.
type nativeHost struct {
	cfg     *native.Config
	proxy   *egress.Proxy
	runtime *hostsession.NativeRuntime
}

// setupNative starts the egress proxy when native mode is installed for
// this user. It returns nil (docker only) otherwise, logging why.
func setupNative(ctx context.Context, creds *config.Credentials, stateDir string) *nativeHost {
	if runtime.GOOS != "darwin" {
		return nil
	}
	ncfg, err := native.LoadConfig()
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		log.Printf("native runtime disabled: %v", err)
		return nil
	}
	if ncfg.OwnerUID != os.Getuid() {
		log.Printf("native runtime disabled: installed for %s (uid %d), not this user", ncfg.OwnerUser, ncfg.OwnerUID)
		return nil
	}
	slots, err := hostsession.LoadSlotMap(filepath.Join(stateDir, filepath.Base(native.OwnerSlotMapFile)), len(ncfg.Slots))
	if err != nil {
		log.Printf("native runtime disabled: slot assignments: %v", err)
		return nil
	}
	key, err := egress.LoadOrCreateKey(filepath.Join(stateDir, "egress.key"))
	if err != nil {
		log.Printf("native runtime disabled: egress proxy key: %v", err)
		return nil
	}
	proxy := egress.New(key, filepath.Join(stateDir, "egress"))
	proxy.Logf = log.Printf
	if err := proxy.ListenAndServe(ctx, ncfg.ProxyPort); err != nil {
		log.Printf("native runtime disabled: %v (is another `clux host start` running?)", err)
		return nil
	}
	go proxy.Run(ctx)
	clients := map[int]hostsession.SupervisorCaller{}
	for _, s := range ncfg.Slots {
		clients[s.N] = slotClient(s)
	}
	log.Printf("native macOS runtime enabled (%d slot(s), %d free; egress proxy on 127.0.0.1:%d)", slots.Total(), slots.Free(), ncfg.ProxyPort)
	return &nativeHost{
		cfg:   ncfg,
		proxy: proxy,
		runtime: &hostsession.NativeRuntime{
			Supervisor: func(n int) hostsession.SupervisorCaller {
				if c, ok := clients[n]; ok {
					return c
				}
				return missingSlot(n)
			},
			Slots:     slots,
			Keeper:    &native.KeeperClient{Socket: native.KeeperSocket},
			Installer: newSidecarInstaller(native.RuntimeRoot, creds),
			Egress:    proxy,
			ProxyPort: ncfg.ProxyPort,
		},
	}
}

// newSidecarInstaller installs native sidecar runtimes under root. Bundle
// downloads authenticate with creds as they are at download time: a
// re-login in `clux host start` must reach them (a copied token kept
// sending the old one: 401 on every workspace.start after a re-login).
func newSidecarInstaller(root string, creds *config.Credentials) *sidecarrt.Installer {
	return &sidecarrt.Installer{Root: root, Credentials: creds.Get, Logf: log.Printf}
}

// missingSlot answers for a slot the install no longer has (pool shrunk
// while a workspace still held it).
type missingSlot int

func (m missingSlot) Call(context.Context, supervisor.Request) (supervisor.Response, error) {
	return supervisor.Response{}, fmt.Errorf("native slot %d is not installed any more; re-run `sudo clux native install --slots %d`", int(m), int(m))
}
