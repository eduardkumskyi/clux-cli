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
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		return native.Install(native.InstallOptions{Owner: *owner, CLIVersion: version, Out: os.Stdout})
	case "uninstall":
		fs := flag.NewFlagSet("native uninstall", flag.ExitOnError)
		purge := fs.Bool("purge", false, "also delete workspace files and simulators in "+native.AgentHome)
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		return native.Uninstall(native.UninstallOptions{Purge: *purge, Out: os.Stdout})
	case "status":
		return runNativeStatus()
	case "supervise": // LaunchDaemon entry point (runs as _clux)
		return runSupervise()
	case "pfd": // LaunchDaemon entry point (runs as root)
		return runPFD()
	default:
		return fmt.Errorf("unknown native subcommand %q", args[0])
	}
}

func daemonContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

func runSupervise() error {
	logger := log.New(os.Stderr, "supervisor: ", log.LstdFlags)
	cfg, err := native.LoadConfig()
	if err != nil {
		return err
	}
	ctx, stop := daemonContext()
	defer stop()
	srv, err := supervisor.NewServer(supervisor.Options{Config: cfg, Version: version, Logf: logger.Printf})
	if err != nil {
		return err
	}
	return srv.Serve(ctx)
}

func runPFD() error {
	logger := log.New(os.Stderr, "pfd: ", log.LstdFlags)
	ctx, stop := daemonContext()
	defer stop()
	return native.RunPFD(ctx, logger.Printf)
}

func supervisorStatus(ctx context.Context) (supervisor.Response, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return (&supervisor.Client{Socket: native.SupervisorSocket}).Call(ctx, supervisor.Request{Op: supervisor.OpStatus})
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
	agent := "missing"
	if u, err := user.Lookup(cfg.AgentUser); err == nil {
		agent = "uid " + u.Uid
	}
	fmt.Printf("  agent user:    %s (%s), home %s\n", cfg.AgentUser, agent, native.AgentHome)
	fmt.Printf("  egress proxy:  127.0.0.1:%d and [::1]:%d (served by `clux host start`)\n", cfg.ProxyPort, cfg.ProxyPort)
	for _, label := range []string{native.PFLabel, native.SupervisorLabel} {
		fmt.Printf("  %-29s %s\n", label+":", launchdState(label))
	}
	if st, err := native.ReadPFStatus(); err != nil {
		fmt.Printf("  pf:            unknown (%v)\n", err)
	} else {
		state := "INACTIVE"
		if st.Active(time.Now()) {
			state = "active"
		}
		fmt.Printf("  pf:            %s (enabled=%v, anchor %s loaded=%v, %d agent listener port(s), updated %s)\n",
			state, st.Enabled, st.Anchor, st.RulesLoaded, st.ListenerPorts, st.Updated)
		if st.Error != "" {
			fmt.Printf("                 last error: %s\n", st.Error)
		}
	}
	resp, err := supervisorStatus(context.Background())
	if err != nil {
		fmt.Printf("  supervisor:    not reachable: %v\n", err)
		return nil
	}
	fmt.Printf("  supervisor:    version %s, sandbox %s, %d workspace(s)\n", resp.Version, resp.Sandbox, len(resp.Workspaces))
	for _, w := range resp.Workspaces {
		fmt.Printf("    workspace %s: running=%v pid=%d port=%d runtime=%s\n", w.ID, w.Running, w.PID, w.Port, w.RuntimeVersion)
	}
	return nil
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
	_, uerr := user.Lookup(cfg.AgentUser)
	check("native: agent user "+cfg.AgentUser+" exists", uerr)
	st, perr := native.ReadPFStatus()
	if perr == nil && !st.Active(time.Now()) {
		perr = fmt.Errorf("pf daemon not keeping the firewall active (enabled=%v, anchor loaded=%v, updated %s); see %s/pf.log", st.Enabled, st.RulesLoaded, st.Updated, native.LogDir)
	}
	check("native: pf firewall active for the agent user", perr)
	resp, serr := supervisorStatus(context.Background())
	check("native: supervisor reachable", serr)
	if serr == nil {
		var sbErr error
		if resp.Sandbox != supervisor.SandboxActive {
			sbErr = fmt.Errorf("Seatbelt self-check failed; workspaces run with user + pf isolation only (see %s/supervisor.log)", native.LogDir)
		}
		check("native: Seatbelt sandbox active", sbErr)
	}
	f, werr := os.CreateTemp(filepath.Join(native.RuntimeRoot, "sidecar"), ".doctor-")
	if werr == nil {
		f.Close()
		os.Remove(f.Name())
	}
	check("native: runtime dir writable by you", werr)
}

// nativeHost is the owner-side half of the native runtime inside `clux host
// start`: the egress proxy, the runtime installer and the supervisor client.
type nativeHost struct {
	proxy   *egress.Proxy
	runtime *hostsession.NativeRuntime
}

// setupNative starts the egress proxy when native mode is installed for
// this user. It returns nil (docker only) otherwise, logging why.
func setupNative(ctx context.Context, cfg *config.Config, stateDir string) *nativeHost {
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
	log.Printf("native macOS runtime enabled (egress proxy on 127.0.0.1:%d)", ncfg.ProxyPort)
	return &nativeHost{
		proxy: proxy,
		runtime: &hostsession.NativeRuntime{
			Supervisor: &supervisor.Client{Socket: native.SupervisorSocket},
			Installer: &sidecarrt.Installer{
				Root: native.RuntimeRoot, BackendURL: cfg.BackendURL, Token: cfg.Token, Logf: log.Printf,
			},
			Egress:    proxy,
			ProxyPort: ncfg.ProxyPort,
		},
	}
}
