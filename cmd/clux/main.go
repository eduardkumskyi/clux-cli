// clux is the BYOC (bring-your-own-compute) host agent: it registers this
// machine's CPU/memory/storage with a Clux backend and keeps it marked
// online over a long-lived tunnel connection. Once registered, `host start`
// also answers workspace.start/stop/delete lifecycle commands (docker
// run/stop/rm against this machine's own Docker daemon, see
// internal/dockerhost; or, on a Mac with `clux native install`, the native
// macOS runtime, see internal/native) and proxies dial.open/data/close stream frames to
// locally-published container ports (internal/dialproxy), all multiplexed
// over that same connection -- see internal/tunnel for the wire protocol
// and internal/sysinfo for the capacity numbers reported.
package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/eduardkumskyi/clux-cli/internal/config"
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
			err = fmt.Errorf("usage: clux host <start|stop|status|logs>")
			break
		}
		switch args[0] {
		case "start":
			err = runHostStart(args[1:])
		case "stop":
			err = runHostStop(args[1:])
		case "status":
			err = runHostStatus(args[1:])
		case "logs":
			err = runHostLogs(args[1:])
		default:
			err = fmt.Errorf("unknown host subcommand %q", args[0])
		}
	case "native":
		err = runNative(args)
	case "help", "-h", "--help":
		printUsage()
		return
	default:
		printUsage()
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, "clux:", err)
		var ee *exitError
		if errors.As(err, &ee) {
			os.Exit(ee.code)
		}
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, `usage: clux <command> [flags]

commands:
  login [--backend-url <url>]                 connect this computer: confirm a code in the browser
  login --token <PAT> [--backend-url <url>]   connect with a token from the dashboard (servers/CI)
  logout                                      stop the background service and remove stored credentials
  whoami                                      show the identity of the currently configured host
  doctor                                      check local environment (docker, config, connectivity)
  host start [--foreground | --background] [--interval <duration>] [--no-native-prompt]
                                              keep this computer online; in a terminal it offers
                                              (once) to run in the background, starting at login
  host stop                                   stop the background service (and keep it from starting at login)
  host status                                 background service, connected host, backend, native runtime
  host logs [-f] [-n N]                       print (or follow) ~/.clux/logs/host.log
  native install [--owner <user>] [--slots N] (macOS, root) set up the native runtime for iOS/Xcode workspaces
  native uninstall [--purge]                  (macOS, root) remove the native runtime
  native status                               show the native runtime's state
  version                                     print the CLI version`)
}

func runWhoami(args []string) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	// A register would replace the running agent's tunnel (the backend keeps
	// one per host): answer from local state instead.
	if who, live := liveAgent(); live {
		fmt.Printf("host %q (id=%d) backend=%s (from local config; %s holds the connection, see `clux host status`)\n",
			cfg.HostName, cfg.HostID, cfg.BackendURL, who)
		return nil
	}
	info, err := collectInfo()
	if err != nil {
		return err
	}

	sess, err := tunnel.Dial(context.Background(), cfg.BackendURL, cfg.Token, version, info, nil)
	if err != nil {
		return fmt.Errorf("backend rejected stored credentials: %w", err)
	}
	defer sess.Close()

	fmt.Printf("host %q (id=%d) backend=%s\n", sess.Name, sess.HostID, cfg.BackendURL)
	return nil
}

// liveAgent reports whether a `clux host start` (background service or a
// terminal) is running on this machine, and which.
func liveAgent() (string, bool) {
	return describeLiveAgent(
		func() (int, bool) {
			if svc, err := newService(); err == nil && svc.Supported() {
				if st, err := svc.Status(); err == nil && st.Running {
					return st.PID, true
				}
			}
			return 0, false
		},
		func() (int, bool) {
			dir, err := config.Dir()
			if err != nil {
				return 0, false
			}
			pid, held, _ := hostlockHolder(dir)
			return pid, held
		})
}

// describeLiveAgent checks the service first (to name it), then the host
// lock, which any running `clux host start` holds.
func describeLiveAgent(service, lock func() (int, bool)) (string, bool) {
	if pid, ok := service(); ok {
		return fmt.Sprintf("the background service (pid %d)", pid), true
	}
	if pid, ok := lock(); ok {
		return fmt.Sprintf("`clux host start` (pid %d)", pid), true
	}
	return "", false
}

// backendReachable is a connectivity check that does not register: any
// HTTP answer from the backend counts.
func backendReachable(backendURL string) error {
	c := &http.Client{Timeout: 10 * time.Second}
	resp, err := c.Get(strings.TrimRight(backendURL, "/") + "/")
	if err != nil {
		return err
	}
	resp.Body.Close()
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
		info, infoErr := collectInfo()
		check("system info collection", infoErr)
		if who, live := liveAgent(); live {
			// Registering again would replace the live tunnel.
			check(fmt.Sprintf("backend reachable (credentials not re-checked: %s is connected with them)", who),
				backendReachable(cfg.BackendURL))
		} else if infoErr == nil {
			sess, dialErr := tunnel.Dial(context.Background(), cfg.BackendURL, cfg.Token, version, info, nil)
			check("backend connectivity", dialErr)
			if dialErr == nil {
				sess.Close()
			}
		}
	}

	nativeDoctor(check)

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
