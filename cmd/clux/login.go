package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"unicode/utf8"

	"github.com/eduardkumskyi/clux-cli/internal/config"
	"github.com/eduardkumskyi/clux-cli/internal/devicelogin"
	"github.com/eduardkumskyi/clux-cli/internal/machineid"
	"github.com/eduardkumskyi/clux-cli/internal/service"
	"github.com/eduardkumskyi/clux-cli/internal/sysinfo"
	"github.com/eduardkumskyi/clux-cli/internal/tunnel"
)

var errLoginCancelled = errors.New("login cancelled")

func runLogin(args []string) error {
	fs := flag.NewFlagSet("login", flag.ExitOnError)
	token := fs.String("token", "", "host token from the dashboard, for servers/CI without a browser (default: confirm in the browser)")
	backendURL := fs.String("backend-url", defaultBackendURL, "backend base URL")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Read()
	if err != nil {
		return err
	}
	// After a logout the stored backend is kept; an explicit flag wins.
	url := *backendURL
	if !flagSet(fs, "backend-url") && cfg.BackendURL != "" {
		url = cfg.BackendURL
	}

	ctx, stop := interruptContext()
	defer stop()

	if *token == "" {
		if _, err := browserLogin(ctx, cfg, url, os.Stdout); err != nil {
			return err
		}
	} else if err := tokenLogin(cfg, url, *token); err != nil {
		return err
	}
	restartServiceAfterLogin(os.Stdout)
	return nil
}

// tokenLogin is the manual path: verify the token by registering once.
func tokenLogin(cfg *config.Config, backendURL, token string) error {
	info, err := collectInfo()
	if err != nil {
		return err
	}
	sess, err := tunnel.Dial(context.Background(), backendURL, token, version, info, nil)
	if err != nil {
		return fmt.Errorf("could not verify token: %w", err)
	}
	defer sess.Close()

	cfg.BackendURL, cfg.Token, cfg.HostName, cfg.HostID = backendURL, token, sess.Name, sess.HostID
	if err := config.Save(cfg); err != nil {
		return fmt.Errorf("saving credentials: %w", err)
	}
	fmt.Printf("Logged in as host %q (id=%d)\n", sess.Name, sess.HostID)
	return nil
}

// browserLogin runs the device flow and stores the credentials it yields
// in cfg (keeping the user's other answers).
func browserLogin(ctx context.Context, cfg *config.Config, backendURL string, out io.Writer) (*devicelogin.Result, error) {
	stateDir, err := config.Dir()
	if err != nil {
		return nil, err
	}
	mid, err := machineid.Get(stateDir)
	if err != nil {
		return nil, fmt.Errorf("identifying this computer: %w", err)
	}
	flow := &loginFlow{
		client: &devicelogin.Client{BaseURL: backendURL, UserAgent: "clux/" + version},
		req: devicelogin.Request{
			MachineID:  mid,
			Name:       suggestedHostName(),
			OS:         runtime.GOOS,
			Arch:       runtime.GOARCH,
			CLIVersion: version,
		},
		out:  out,
		open: browserOpener(),
	}
	res, err := flow.run(ctx)
	if err != nil {
		return nil, err
	}
	cfg.BackendURL, cfg.Token, cfg.HostName, cfg.HostID = backendURL, res.Token, res.Host.Name, res.Host.ID
	if err := config.Save(cfg); err != nil {
		return nil, fmt.Errorf("saving credentials: %w", err)
	}
	fmt.Fprintln(out, connectedLine(res))
	return res, nil
}

// loginFlow is the interactive part of the device flow, separated so
// tests can drive it against a fake backend.
type loginFlow struct {
	client *devicelogin.Client
	req    devicelogin.Request
	out    io.Writer
	open   func(string) error // nil: never open a browser
}

func (f *loginFlow) run(ctx context.Context) (*devicelogin.Result, error) {
	code, err := f.client.Start(ctx, f.req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, errLoginCancelled
		}
		return nil, err
	}
	fmt.Fprintf(f.out, "To connect this computer, open:\n  %s\nand confirm the code %s. Waiting...\n",
		code.VerificationURL, code.UserCode)
	if f.open != nil {
		_ = f.open(code.VerificationURL)
	}
	res, err := f.client.Wait(ctx, code)
	switch {
	case err == nil:
		return res, nil
	case ctx.Err() != nil:
		fmt.Fprintln(f.out)
		return nil, errLoginCancelled
	case errors.Is(err, devicelogin.ErrDenied):
		return nil, fmt.Errorf("%w; nothing was changed on this computer", err)
	}
	return nil, err
}

func connectedLine(res *devicelogin.Result) string {
	s := fmt.Sprintf("Connected as %q (id %d)", res.Host.Name, res.Host.ID)
	if res.Reused {
		s += " (the same computer as before - its projects are kept)"
	}
	return s
}

// browserOpener opens the confirmation page, except over SSH where the
// browser would pop up on the remote machine's screen (or nowhere).
func browserOpener() func(string) error {
	if os.Getenv("SSH_CONNECTION") != "" || os.Getenv("SSH_TTY") != "" {
		return nil
	}
	return devicelogin.OpenBrowser
}

// suggestedHostName is the name offered for a new host: the Mac's
// "Computer Name" (e.g. "Eduard's MacBook Pro"), else the hostname.
func suggestedHostName() string {
	name := ""
	if runtime.GOOS == "darwin" {
		if out, err := exec.Command("/usr/sbin/scutil", "--get", "ComputerName").Output(); err == nil {
			name = strings.TrimSpace(string(out))
		}
	}
	if name == "" {
		if h, err := os.Hostname(); err == nil {
			name = strings.TrimSuffix(h, ".local")
		}
	}
	return truncateRunes(name, 100)
}

func truncateRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n])
}

// collectInfo is sysinfo plus this machine's id for the register frame. A
// missing id is not fatal: the host still works, the backend just cannot
// recognize the machine later.
func collectInfo() (sysinfo.Info, error) {
	info, err := sysinfo.Collect(config.DefaultStorageRoot())
	if err != nil {
		return info, fmt.Errorf("collecting system info: %w", err)
	}
	if dir, err := config.Dir(); err == nil {
		if id, err := machineid.Get(dir); err == nil {
			info.MachineID = id
		}
	}
	return info, nil
}

// restartServiceAfterLogin makes a running background service pick up the
// new token now instead of failing with the old one.
func restartServiceAfterLogin(out io.Writer) {
	const next = "Run `clux host start` to bring this computer online."
	svc, err := newService()
	if err != nil || !svc.Supported() {
		fmt.Fprintln(out, next)
		return
	}
	st, err := svc.Status()
	if err != nil || !st.Loaded {
		fmt.Fprintln(out, next)
		return
	}
	if err := svc.Restart(); err != nil {
		fmt.Fprintf(out, "Could not restart the background service (%v); run `clux host stop` and `clux host start`.\n", err)
		return
	}
	fmt.Fprintln(out, "Restarted the background service with the new login.")
}

func newService() (*service.Manager, error) {
	dir, err := config.Dir()
	if err != nil {
		return nil, err
	}
	return service.New(runtime.GOOS, dir)
}

func flagSet(fs *flag.FlagSet, name string) bool {
	set := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			set = true
		}
	})
	return set
}
