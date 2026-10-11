// clux is the BYOC (bring-your-own-compute) host agent: it registers this
// machine's CPU/memory/storage with a Clux backend and keeps it marked
// online over a long-lived tunnel connection. See internal/tunnel for the
// wire protocol and internal/sysinfo for the capacity numbers reported.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/eduardkumskyi/clux-cli/internal/config"
	"github.com/eduardkumskyi/clux-cli/internal/sysinfo"
	"github.com/eduardkumskyi/clux-cli/internal/tunnel"
)

const (
	version           = "0.1.0"
	defaultBackendURL = "https://app.clux.space"
	defaultHeartbeat  = 30 * time.Second
	reconnectBackoff  = 5 * time.Second
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

func runHostStart(args []string) error {
	fs := flag.NewFlagSet("host start", flag.ExitOnError)
	interval := fs.Duration("interval", defaultHeartbeat, "heartbeat interval")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load()
	if err != nil {
		return err
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	for {
		if err := runSession(ctx, cfg, *interval); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			fmt.Fprintln(os.Stderr, "clux: session error, reconnecting:", err)
			select {
			case <-time.After(reconnectBackoff):
			case <-ctx.Done():
				return nil
			}
		}
	}
}

func runSession(ctx context.Context, cfg *config.Config, interval time.Duration) error {
	info, err := sysinfo.Collect(config.DefaultStorageRoot())
	if err != nil {
		return fmt.Errorf("collecting system info: %w", err)
	}

	sess, err := tunnel.Dial(ctx, cfg.BackendURL, cfg.Token, version, info)
	if err != nil {
		return err
	}
	defer sess.Close()
	fmt.Printf("registered as host %q (id=%d)\n", sess.Name, sess.HostID)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			info, err := sysinfo.Collect(config.DefaultStorageRoot())
			if err != nil {
				return fmt.Errorf("collecting system info: %w", err)
			}
			if err := sess.Heartbeat(info, version); err != nil {
				return err
			}
		}
	}
}
