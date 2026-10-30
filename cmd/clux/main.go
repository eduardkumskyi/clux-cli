// clux is the BYOC (bring-your-own-compute) host agent: it registers this
// machine's CPU/memory/storage with a Clux backend and keeps it marked
// online over a long-lived tunnel connection. Once registered, `host start`
// also answers workspace.start/stop/delete lifecycle commands (docker
// run/stop/rm against this machine's own Docker daemon, see
// internal/dockerhost) and proxies dial.open/data/close stream frames to
// locally-published container ports (internal/dialproxy), all multiplexed
// over that same connection -- see internal/tunnel for the wire protocol
// and internal/sysinfo for the capacity numbers reported.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/eduardkumskyi/clux-cli/internal/config"
	"github.com/eduardkumskyi/clux-cli/internal/sysinfo"
	"github.com/eduardkumskyi/clux-cli/internal/tunnel"
)

// version is overridden at release time via -ldflags "-X main.version=...".
var version = "0.3.0"

const (
	// The backend (Django/Channels) is served at api.clux.space via the
	// Cloudflare tunnel; app.clux.space is the SPA only and answers every
	// /ws/ path with index.html (-> "bad handshake").
	defaultBackendURL = "https://api.clux.space"
	defaultHeartbeat  = 30 * time.Second
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd, args := os.Args[1], os.Args[2:]
	var err error

	switch cmd {
	case "login":
		err = runLogin(args)
	case "logout":
		err = runLogout(args)
	case "whoami":
		err = runWhoami(args)
	case "doctor":
		err = runDoctor(args)
	case "version":
		fmt.Println("clux version", version)
	case "host":
		if len(args) < 1 {
			err = fmt.Errorf("usage: clux host <start>")
			break
		}
		switch args[0] {
		case "start":
			err = runHostStart(args[1:])
		default:
			err = fmt.Errorf("unknown host subcommand %q", args[0])
		}
	case "help", "-h", "--help":
		printUsage()
		return
	default:
		printUsage()
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, "clux:", err)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, `usage: clux <command> [flags]

commands:
  login --token <PAT> [--backend-url <url>]   store credentials, verified against the backend
  logout                                      remove stored credentials
  whoami                                      show the identity of the currently configured host
  doctor                                      check local environment (docker, config, connectivity)
  host start [--interval <duration>]          connect and keep this host registered (foreground)
  version                                     print the CLI version`)
}

func runLogin(args []string) error {
	fs := flag.NewFlagSet("login", flag.ExitOnError)
	token := fs.String("token", "", "personal access token issued for this host (required)")
	backendURL := fs.String("backend-url", defaultBackendURL, "backend base URL")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *token == "" {
		return fmt.Errorf("--token is required (create a host and copy its token from the Clux dashboard)")
	}

	info, err := sysinfo.Collect(config.DefaultStorageRoot())
	if err != nil {
		return fmt.Errorf("collecting system info: %w", err)
	}

	sess, err := tunnel.Dial(context.Background(), *backendURL, *token, version, info)
	if err != nil {
		return fmt.Errorf("could not verify token: %w", err)
	}
	defer sess.Close()

	cfg := &config.Config{BackendURL: *backendURL, Token: *token, HostName: sess.Name}
	if err := config.Save(cfg); err != nil {
		return fmt.Errorf("saving credentials: %w", err)
	}

	fmt.Printf("Logged in as host %q (id=%d)\n", sess.Name, sess.HostID)
	return nil
}

func runLogout(args []string) error {
	if err := config.Remove(); err != nil {
		return fmt.Errorf("removing credentials: %w", err)
	}
	fmt.Println("Logged out.")
	return nil
}

func runWhoami(args []string) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	info, err := sysinfo.Collect(config.DefaultStorageRoot())
	if err != nil {
		return fmt.Errorf("collecting system info: %w", err)
	}

	sess, err := tunnel.Dial(context.Background(), cfg.BackendURL, cfg.Token, version, info)
	if err != nil {
		return fmt.Errorf("backend rejected stored credentials: %w", err)
	}
	defer sess.Close()

	fmt.Printf("host %q (id=%d) backend=%s\n", sess.Name, sess.HostID, cfg.BackendURL)
	return nil
}

func runDoctor(args []string) error {
	allOK := true
	check := func(name string, err error) {
		if err != nil {
			fmt.Printf("[FAIL] %s: %v\n", name, err)
			allOK = false
			return
		}
		fmt.Printf("[ OK ] %s\n", name)
	}

	check("docker CLI reachable", exec.Command("docker", "version").Run())
	check("docker can run resource-limited containers", checkDockerResourceLimits())

	cfg, cfgErr := config.Load()
	check("credentials configured", cfgErr)

	if cfgErr == nil {
		info, infoErr := sysinfo.Collect(config.DefaultStorageRoot())
		check("system info collection", infoErr)
		if infoErr == nil {
			sess, dialErr := tunnel.Dial(context.Background(), cfg.BackendURL, cfg.Token, version, info)
			check("backend connectivity", dialErr)
			if dialErr == nil {
				sess.Close()
			}
		}
	}

	if !allOK {
		return fmt.Errorf("one or more checks failed")
	}
	fmt.Println("all checks passed")
	return nil
}

// checkDockerResourceLimits verifies the Docker daemon will actually honor
// --cpus/--memory, the exact flags dockerhost.Start passes on every
// workspace.start (see internal/dockerhost/lifecycle.go). Some nested/
// sandboxed Docker setups run cgroup v2 in "threaded" mode, which rejects
// these flags outright -- and since every workspace start uses them, that
// failure mode would otherwise only surface the first time a user tries to
// start a workspace, not here at doctor time where it's actionable.
func checkDockerResourceLimits() error {
	out, err := exec.Command("docker", "run", "--rm", "--cpus", "0.1", "--memory", "64m", "busybox", "true").CombinedOutput()
	if err == nil {
		return nil
	}

	msg := string(out)
	if strings.Contains(msg, "cgroup") && (strings.Contains(msg, "threaded mode") || strings.Contains(msg, "domain controllers")) {
		return fmt.Errorf("docker daemon's cgroup v2 is in \"threaded\" mode and rejects --cpus/--memory -- every workspace start will fail the same way (docker said: %s)", strings.TrimSpace(msg))
	}

	return fmt.Errorf("docker run with --cpus/--memory failed -- either the busybox test image couldn't be pulled, or this docker daemon doesn't support CPU/memory resource limits (both would break every workspace start): %s", strings.TrimSpace(msg))
}
