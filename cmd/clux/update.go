package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/eduardkumskyi/clux-cli/internal/config"
	"github.com/eduardkumskyi/clux-cli/internal/native"
	"github.com/eduardkumskyi/clux-cli/internal/selfupdate"
	"github.com/eduardkumskyi/clux-cli/internal/service"
)

// updateNotice is the one-line "a newer clux exists" notice, or "" when
// current is not older than latest (or latest is unknown).
func updateNotice(current, latest string) string {
	if latest == "" || !selfupdate.Older(current, latest) {
		return ""
	}
	return fmt.Sprintf("clux %s is available (this is %s): run `clux update`", selfupdate.Tag(latest), current)
}

// nativeBehindNotice says the native runtime's daemons run an older clux
// than `than` (their own root-owned copy, refreshed only by `sudo clux
// native install`); "" when not installed or current.
func nativeBehindNotice(than string) string {
	if runtime.GOOS != "darwin" {
		return ""
	}
	cfg, err := native.LoadConfig()
	if err != nil || !selfupdate.Older(cfg.CLIVersion, than) {
		return ""
	}
	return fmt.Sprintf("The native macOS runtime still runs clux %s (its own copy); refresh it with: sudo clux native install", cfg.CLIVersion)
}

// updater holds what `clux update` depends on, so tests can fake it.
type updater struct {
	current     string
	interactive bool
	client      *selfupdate.Client
	exe         func() (string, error)
	// temporary reports a binary that will disappear (a `go run` build).
	temporary func(exe string) bool
	// sudoReplace installs the verified binary at exe via sudo (the
	// directory is not writable by this user).
	sudoReplace func(binary []byte, exe string) error
	// restart restarts the background service if one is installed, and
	// says what it did (or what the user must do).
	restart func(out io.Writer)
	// nativeBehind / nativeRefresh: the native runtime's copy of clux.
	nativeBehind  func(than string) string
	nativeRefresh func() error
	in            io.Reader
	out           io.Writer
}

func runUpdate(args []string) error {
	fs := flag.NewFlagSet("update", flag.ExitOnError)
	check := fs.Bool("check", false, "only say whether a newer version exists; change nothing")
	want := fs.String("version", "", "install this release (e.g. v0.6.0) instead of the latest")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ctx, stop := interruptContext()
	defer stop()
	u := &updater{
		current:     version,
		interactive: isTerminal(os.Stdin) && isTerminal(os.Stdout),
		client:      &selfupdate.Client{GOOS: runtime.GOOS, GOARCH: runtime.GOARCH},
		exe:         realExecutable,
		temporary: func(exe string) bool {
			return service.TemporaryBinary(exe, os.TempDir(), os.Getenv("GOCACHE"))
		},
		sudoReplace:   sudoReplace,
		restart:       restartBackgroundService,
		nativeBehind:  nativeBehindNotice,
		nativeRefresh: sudoNativeInstall,
		in:            os.Stdin,
		out:           os.Stdout,
	}
	return u.run(ctx, *check, *want)
}

func (u *updater) run(ctx context.Context, check bool, want string) error {
	tag := selfupdate.Tag(want)
	if tag != "" {
		if _, ok := selfupdate.Parse(tag); !ok {
			return fmt.Errorf("--version %q is not a release version (e.g. v0.6.0)", want)
		}
	} else {
		latest, err := u.client.Latest(ctx)
		if err != nil {
			return err
		}
		tag = latest
	}

	if check {
		if notice := updateNotice(u.current, tag); notice != "" && want == "" {
			fmt.Fprintln(u.out, notice)
		} else if want != "" {
			fmt.Fprintf(u.out, "clux %s exists (this is %s); install it with: clux update --version %s\n", tag, u.current, tag)
		} else {
			fmt.Fprintf(u.out, "clux %s is up to date.\n", u.current)
		}
		if notice := u.nativeBehind(u.current); notice != "" {
			fmt.Fprintln(u.out, notice)
		}
		return nil
	}

	if want == "" && !selfupdate.Older(u.current, tag) {
		fmt.Fprintf(u.out, "clux %s is up to date.\n", u.current)
		u.offerNativeRefresh(u.current)
		return nil
	}

	exe, err := u.exe()
	if err != nil {
		return err
	}
	if strings.Contains(filepath.ToSlash(exe), "/Cellar/") {
		return errors.New("this clux was installed with Homebrew; update it with: brew upgrade clux")
	}
	if u.temporary(exe) {
		return fmt.Errorf("this clux is a temporary build (%s); install clux with: curl -fsSL https://clux.space/install.sh | sh", exe)
	}

	fmt.Fprintf(u.out, "Downloading clux %s for %s/%s...\n", tag, u.client.GOOS, u.client.GOARCH)
	binary, err := u.client.Download(ctx, tag)
	if err != nil {
		return err
	}
	if err := selfupdate.Replace(exe, binary, u.client.GOOS); err != nil {
		var perm *selfupdate.PermissionError
		if !errors.As(err, &perm) {
			return fmt.Errorf("replacing %s: %w", exe, err)
		}
		if !u.interactive {
			return fmt.Errorf("%s is not writable by you, so clux can't replace %s. Run `clux update` in a terminal "+
				"(it asks for your password), or: curl -fsSL https://clux.space/install.sh | sh", perm.Dir, exe)
		}
		fmt.Fprintf(u.out, "%s needs admin rights; replacing %s with sudo.\n", perm.Dir, exe)
		if err := u.sudoReplace(binary, exe); err != nil {
			return fmt.Errorf("replacing %s with sudo failed (%v); nothing was changed. "+
				"Or install with: curl -fsSL https://clux.space/install.sh | sh", exe, err)
		}
	}
	fmt.Fprintf(u.out, "Updated clux %s -> %s (%s).\n", u.current, tag, exe)
	u.restart(u.out)
	u.offerNativeRefresh(tag)
	return nil
}

// offerNativeRefresh: the native daemons run their own copy of clux. On a
// terminal, offer to refresh it now (sudo asks for the password); otherwise
// print the command.
func (u *updater) offerNativeRefresh(than string) {
	notice := u.nativeBehind(than)
	if notice == "" {
		return
	}
	fmt.Fprintln(u.out, notice)
	if !u.interactive || os.Geteuid() == 0 {
		return
	}
	fmt.Fprint(u.out, "Refresh it now? [Y/n] ")
	line, _ := bufio.NewReader(u.in).ReadString('\n')
	if yes, ok := parseYesNo(line); !ok || !yes {
		fmt.Fprintln(u.out, "OK. Run it later: sudo clux native install")
		return
	}
	if err := u.nativeRefresh(); err != nil {
		fmt.Fprintf(u.out, "Native runtime refresh failed: %v\nRetry with: sudo clux native install\n", err)
	}
}

// realExecutable is the file to replace: the running binary with symlinks
// resolved (replacing a symlink would leave its target old).
func realExecutable() (string, error) {
	self, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("locating the clux binary: %w", err)
	}
	if p, err := filepath.EvalSymlinks(self); err == nil {
		self = p
	}
	return self, nil
}

// sudoReplace copies the binary next to exe and renames it over exe, as
// root: still atomic (same directory), and sudo asks on this terminal.
func sudoReplace(binary []byte, exe string) error {
	if _, err := exec.LookPath("sudo"); err != nil {
		return errors.New("sudo is not available")
	}
	tmp, err := os.CreateTemp("", "clux-update-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(binary); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	const script = `set -e; cp "$1" "$2.clux-new"; chmod 755 "$2.clux-new"; mv -f "$2.clux-new" "$2"`
	cmd := exec.Command("sudo", "sh", "-c", script, "clux-update", tmp.Name(), exe)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return cmd.Run()
}

// restartBackgroundService restarts an installed background service so it
// runs the new binary; a `clux host start` in a terminal is only pointed out.
func restartBackgroundService(out io.Writer) {
	svc, err := newService()
	if err == nil && svc.Supported() {
		if st, _ := svc.Status(); st.Loaded || st.Running {
			if os.Geteuid() == 0 {
				// Under sudo the service belongs to the user, not root.
				fmt.Fprintln(out, "Restart the background service as yourself (without sudo) to use the new version: "+restartCommand(svc.GOOS))
				return
			}
			if err := svc.Restart(); err != nil {
				fmt.Fprintf(out, "Could not restart the background service (%v); run: %s\n", err, restartCommand(svc.GOOS))
				return
			}
			fmt.Fprintln(out, "Restarted the background service; this computer reconnects in a few seconds.")
			return
		}
	}
	if dir, err := config.Dir(); err == nil {
		if pid, held, _ := hostlockHolder(dir); held {
			fmt.Fprintf(out, "`clux host start` is running in a terminal (pid %d): press Ctrl+C there and start it again to use the new version.\n", pid)
		}
	}
}

func restartCommand(goos string) string {
	if goos == "darwin" {
		return fmt.Sprintf("launchctl kickstart -k gui/$(id -u)/%s", service.Label)
	}
	return "systemctl --user restart " + service.Unit
}
