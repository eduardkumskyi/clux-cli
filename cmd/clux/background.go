package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/eduardkumskyi/clux-cli/internal/config"
	"github.com/eduardkumskyi/clux-cli/internal/service"
)

const backgroundPromptText = "Keep this computer online in the background (starts when you log in)? [Y/n] "

const alreadyInBackground = "Already running in the background. `clux host status` / `clux host logs`."

// backgroundAction is what `clux host start` does about the service.
type backgroundAction int

const (
	bgForeground  backgroundAction = iota // today's behavior: run here
	bgPrompt                              // ask once [Y/n]
	bgInstall                             // remembered yes, or --background
	bgUnsupported                         // interactive on an OS without a service
)

// backgroundOffer holds everything the offer depends on, so tests can fake
// it (like nativeOffer).
type backgroundOffer struct {
	interactive bool   // stdin and stdout are terminals
	foreground  bool   // --foreground
	background  bool   // --background: install even after an earlier "no"
	supported   bool   // this OS has a user service
	answer      string // remembered config.Service
	install     func() error
	save        func(answer string) error
	in          io.Reader
	out         io.Writer
}

func (o *backgroundOffer) decide() backgroundAction {
	if o.foreground {
		return bgForeground
	}
	if o.background {
		if !o.supported {
			return bgUnsupported
		}
		return bgInstall
	}
	if !o.interactive {
		return bgForeground
	}
	if !o.supported {
		return bgUnsupported
	}
	switch o.answer {
	case config.ServiceYes:
		return bgInstall
	case config.ServiceNo:
		return bgForeground
	}
	return bgPrompt
}

// run carries out the decision; true means the service took over and host
// start should exit.
func (o *backgroundOffer) run() bool {
	switch o.decide() {
	case bgUnsupported:
		fmt.Fprintln(o.out, "Running in the background is not supported on this OS yet; staying in the foreground (Ctrl+C stops it).")
		return false
	case bgInstall:
		if o.background && o.answer != config.ServiceYes {
			o.remember(config.ServiceYes)
		}
		return o.doInstall()
	case bgPrompt:
		yes, answered := o.ask()
		if !answered {
			return false
		}
		if !yes {
			o.remember(config.ServiceNo)
			fmt.Fprintln(o.out, "OK, running in this terminal. To run in the background later: clux host start --background")
			return false
		}
		o.remember(config.ServiceYes)
		return o.doInstall()
	}
	return false
}

func (o *backgroundOffer) remember(answer string) {
	if err := o.save(answer); err != nil {
		fmt.Fprintf(o.out, "(could not remember this choice: %v)\n", err)
	}
}

func (o *backgroundOffer) doInstall() bool {
	if err := o.install(); err != nil {
		fmt.Fprintf(o.out, "Could not start the background service: %v\nStaying in the foreground instead.\n", err)
		return false
	}
	return true
}

// ask reads one [Y/n] answer; answered=false on EOF (skip, ask next time).
func (o *backgroundOffer) ask() (yes, answered bool) {
	r := bufio.NewReader(o.in)
	fmt.Fprint(o.out, backgroundPromptText)
	for {
		line, err := r.ReadString('\n')
		if err != nil && strings.TrimSpace(line) == "" {
			fmt.Fprintln(o.out)
			return false, false
		}
		yes, ok := parseYesNo(line)
		if ok {
			return yes, true
		}
		if err != nil {
			fmt.Fprintln(o.out)
			return false, false
		}
		fmt.Fprint(o.out, "Please answer y or n: ")
	}
}

// installService installs/restarts the service and reports what happened.
// The caller has released the host lock: the service needs it.
func installService(svc *service.Manager, cfg *config.Config, out io.Writer) error {
	if service.TemporaryBinary(svc.Exe, os.TempDir(), os.Getenv("GOCACHE")) {
		// A service pointing here would break as soon as it is cleaned up.
		return fmt.Errorf("this clux binary is in a temporary location (%s); install clux permanently "+
			"(curl -fsSL https://clux.space/install.sh | sh) and run `clux host start` again", svc.Exe)
	}
	if err := svc.Install(); err != nil {
		return err
	}
	running := false
	for i := 0; i < 10 && !running; i++ {
		if st, err := svc.Status(); err == nil && st.Running {
			running = true
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	name := cfg.HostName
	if name == "" {
		name = "this computer"
	} else {
		name = fmt.Sprintf("%q", name)
	}
	if running {
		fmt.Fprintf(out, "Running %s in the background (%s); it starts again when you log in.\n", name, svc.Description())
	} else {
		fmt.Fprintf(out, "Installed the background service (%s), but it is not running yet; check `clux host logs`.\n", svc.Description())
	}
	if svc.GOOS == "linux" {
		fmt.Fprintln(out, "It runs while you are logged in; to keep it online after logout: loginctl enable-linger $USER")
	}
	fmt.Fprintln(out, "`clux host status` / `clux host logs` / `clux host stop`")
	return nil
}

// runHostStop stops and removes the background service; a foreground
// `clux host start` is the user's own terminal, so it is only pointed out.
func runHostStop(args []string) error {
	stateDir, err := config.Dir()
	if err != nil {
		return err
	}
	stopped := false
	if svc, err := newService(); err == nil && svc.Supported() {
		st, _ := svc.Status()
		if st.Installed || st.Loaded {
			if err := svc.Uninstall(); err != nil {
				return fmt.Errorf("stopping the background service: %w", err)
			}
			stopped = true
			fmt.Println("Stopped the background service; it no longer starts when you log in.")
		}
	}
	// The service may need a moment to exit and drop the lock.
	pid, held, _ := lockHolder(stateDir, stopped)
	if held {
		fmt.Printf("A `clux host start` is still running in a terminal (pid %d); press Ctrl+C there to stop it.\n", pid)
		return nil
	}
	if !stopped {
		fmt.Println("Not running.")
	}
	return nil
}

func lockHolder(stateDir string, settle bool) (pid int, held bool, err error) {
	tries := 1
	if settle {
		tries = 20
	}
	for i := 0; i < tries; i++ {
		pid, held, err = hostlockHolder(stateDir)
		if !held || err != nil {
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	return
}

// waitForCredentials is the service's answer to "nothing to do until the
// user logs in": instead of exiting (and being restarted every 10 s,
// filling the log), wait until config.json carries a token other than
// oldToken, or the binary is replaced (an update fixes "CLI too old"), or
// a while has passed. Returns false if ctx ended first.
func waitForCredentials(ctx context.Context, oldToken string, logf func(string, ...any)) bool {
	exe, _ := os.Executable()
	exeMod := modTime(exe)
	deadline := time.Now().Add(30 * time.Minute)
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return false
		case <-t.C:
		}
		if cfg, err := config.Read(); err == nil && cfg.LoggedIn() && cfg.Token != oldToken {
			logf("new login found; restarting")
			return true
		}
		if m := modTime(exe); !m.Equal(exeMod) {
			logf("clux binary was updated; restarting")
			return true
		}
		if time.Now().After(deadline) {
			return true
		}
	}
}

func modTime(p string) time.Time {
	if p == "" {
		return time.Time{}
	}
	st, err := os.Stat(p)
	if err != nil {
		return time.Time{}
	}
	return st.ModTime()
}

// exitRestart tells the service manager to start us again (any non-zero
// exit restarts under KeepAlive.SuccessfulExit=false / Restart=on-failure).
const exitRestart = 75 // EX_TEMPFAIL

// interruptContext is cancelled by the first Ctrl+C/SIGTERM; a second one
// kills the process with the default signal behavior.
func interruptContext() (context.Context, context.CancelFunc) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	go func() {
		<-ctx.Done()
		stop()
	}()
	return ctx, stop
}

func runLogout(args []string) error {
	if svc, err := newService(); err == nil && svc.Supported() {
		if st, _ := svc.Status(); st.Installed || st.Loaded {
			if err := svc.Uninstall(); err != nil {
				return fmt.Errorf("stopping the background service: %w", err)
			}
			fmt.Println("Stopped the background service.")
		}
	}
	cfg, err := config.Read()
	if err != nil {
		// Unreadable config: removing it is the only way to log out.
		if rerr := config.Remove(); rerr != nil {
			return fmt.Errorf("removing credentials: %w", rerr)
		}
		fmt.Println("Logged out.")
		return nil
	}
	if cfg.LoggedIn() {
		cfg.ClearCredentials()
		if err := config.Save(cfg); err != nil {
			return fmt.Errorf("removing credentials: %w", err)
		}
	}
	fmt.Println("Logged out.")
	return nil
}

var errNoServiceForLogs = errors.New("no log yet (start the host with `clux host start`)")
