package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/eduardkumskyi/clux-cli/internal/config"
	"github.com/eduardkumskyi/clux-cli/internal/native"
)

// nativeOfferAction is what `clux host start` does about native mode.
type nativeOfferAction int

const (
	offerNothing     nativeOfferAction = iota
	offerHint                          // non-interactive: one log line
	offerPrompt                        // ask [Y/n]
	offerNeedsXcode                    // interactive, but Xcode is missing
	offerCheckHealth                   // installed: warn if unhealthy
)

const nativeHintLine = "native macOS runtime (iOS/Xcode workspaces) not installed; to enable it run: sudo clux native install"

const nativePromptText = `Enable the native macOS runtime for iOS/Xcode development?
This creates a hidden macOS user "_clux", a background service and a
network rule that only lets that user reach the internet through clux.
macOS asks for your admin password once. Remove it any time with
"sudo clux native uninstall".
Enable now? [Y/n] `

// nativeOffer holds everything the offer depends on, so tests can fake it.
type nativeOffer struct {
	goos        string
	interactive bool         // stdin and stdout are terminals
	noPrompt    bool         // --no-native-prompt
	declined    bool         // remembered "no" in ~/.clux/config.json
	installed   func() bool  // /etc/clux/native.json exists
	xcodeOK     func() bool  // `xcode-select -p` succeeds
	health      func() error // supervisor + pf check (installed only)
	install     func() error // sudo <self> native install
	saveDecline func() error // persist the "no"
	in          io.Reader    // answers
	out         io.Writer    // prompt and messages
	logf        func(string, ...any)
}

// decide is the pure decision: no prompting, no side effects beyond the
// probes it is given.
func (o *nativeOffer) decide() nativeOfferAction {
	if o.goos != "darwin" {
		return offerNothing
	}
	if o.installed() {
		return offerCheckHealth
	}
	if o.noPrompt || o.declined {
		return offerNothing
	}
	if !o.interactive {
		return offerHint
	}
	if !o.xcodeOK() {
		return offerNeedsXcode
	}
	return offerPrompt
}

// run carries out the decision. It never fails host start: any problem
// leaves the host in docker-only mode.
func (o *nativeOffer) run() {
	switch o.decide() {
	case offerHint:
		o.logf("%s", nativeHintLine)
	case offerNeedsXcode:
		fmt.Fprintln(o.out, "Native macOS runtime (iOS development) needs Xcode; install it, then run: sudo clux native install")
	case offerCheckHealth:
		if err := o.health(); err != nil {
			o.logf("WARNING: native macOS runtime is installed but not healthy: %v (run `clux doctor`)", err)
		}
	case offerPrompt:
		o.prompt()
	}
}

func (o *nativeOffer) prompt() {
	r := bufio.NewReader(o.in)
	fmt.Fprint(o.out, nativePromptText)
	for {
		line, err := r.ReadString('\n')
		if err != nil && strings.TrimSpace(line) == "" {
			// EOF/Ctrl-D without an answer: skip now, ask next time.
			fmt.Fprintln(o.out)
			return
		}
		yes, ok := parseYesNo(line)
		if !ok {
			if err != nil {
				fmt.Fprintln(o.out)
				return
			}
			fmt.Fprint(o.out, "Please answer y or n: ")
			continue
		}
		if !yes {
			if err := o.saveDecline(); err != nil {
				fmt.Fprintf(o.out, "(could not remember this choice: %v)\n", err)
			}
			fmt.Fprintln(o.out, "OK, not asking again. Enable it later with: sudo clux native install")
			return
		}
		if err := o.install(); err != nil {
			fmt.Fprintf(o.out, "Native runtime install failed: %v\nContinuing with Docker workspaces only. Retry with: sudo clux native install\n", err)
		}
		return
	}
}

// parseYesNo: empty means the default (yes); ok=false means unrecognized.
func parseYesNo(line string) (yes, ok bool) {
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "", "y", "yes":
		return true, true
	case "n", "no":
		return false, true
	}
	return false, false
}

// newNativeOffer wires the real probes for `clux host start`.
func newNativeOffer(cfg *config.Config, noPrompt bool, logf func(string, ...any)) *nativeOffer {
	return &nativeOffer{
		goos:        runtime.GOOS,
		interactive: isTerminal(os.Stdin) && isTerminal(os.Stdout),
		noPrompt:    noPrompt,
		declined:    cfg.NativePromptDeclined,
		installed: func() bool {
			_, err := native.LoadConfig()
			return !errors.Is(err, os.ErrNotExist)
		},
		xcodeOK: func() bool { return exec.Command("xcode-select", "-p").Run() == nil },
		health:  nativeHealth,
		install: sudoNativeInstall,
		saveDecline: func() error {
			cfg.NativePromptDeclined = true
			return config.Save(cfg)
		},
		in:   os.Stdin,
		out:  os.Stdout,
		logf: logf,
	}
}

// sudoNativeInstall runs `sudo <self> native install` on the user's
// terminal so sudo can ask for the password.
func sudoNativeInstall() error {
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locating the clux binary: %w", err)
	}
	if p, err := filepath.EvalSymlinks(self); err == nil {
		self = p
	}
	cmd := exec.Command("sudo", self, "native", "install")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return cmd.Run()
}

// nativeHealth is the short form of the doctor checks, for an install owned
// by this user (setupNative already logs the other-owner case).
func nativeHealth() error {
	cfg, err := native.LoadConfig()
	if err != nil {
		return err
	}
	if cfg.OwnerUID != os.Getuid() {
		return nil
	}
	st, err := native.ReadPFStatus()
	if err != nil {
		return fmt.Errorf("pf status: %w", err)
	}
	if !st.Active(time.Now()) {
		return errors.New("pf firewall not active")
	}
	if _, err := supervisorStatus(context.Background()); err != nil {
		return fmt.Errorf("supervisor not reachable: %w", err)
	}
	return nil
}
