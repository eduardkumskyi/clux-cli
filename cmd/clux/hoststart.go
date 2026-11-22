package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/eduardkumskyi/clux-cli/internal/backoff"
	"github.com/eduardkumskyi/clux-cli/internal/config"
	"github.com/eduardkumskyi/clux-cli/internal/egress"
	"github.com/eduardkumskyi/clux-cli/internal/hostlock"
	"github.com/eduardkumskyi/clux-cli/internal/hostsession"
	"github.com/eduardkumskyi/clux-cli/internal/logx"
	"github.com/eduardkumskyi/clux-cli/internal/native"
	"github.com/eduardkumskyi/clux-cli/internal/netwatch"
	"github.com/eduardkumskyi/clux-cli/internal/service"
	"github.com/eduardkumskyi/clux-cli/internal/sysinfo"
	"github.com/eduardkumskyi/clux-cli/internal/tunnel"
)

// Exit codes for `clux host start`, so a supervisor (the launchd/systemd
// service, internal/service) can tell "restart me" from "restarting won't
// help"; exitRestart (background.go) asks for a restart.
const (
	exitFatalConfig    = 3 // token revoked/invalid, CLI too old: needs the user
	exitAlreadyRunning = 4
)

// probeAfterNetworkChange bounds how long a tunnel that survived a network
// change (its local IP still exists) may stay silent before it is declared
// dead.
const probeAfterNetworkChange = 5 * time.Second

// exitError carries a specific process exit code up to main.
type exitError struct {
	code int
	err  error
}

func (e *exitError) Error() string { return e.err.Error() }
func (e *exitError) Unwrap() error { return e.err }

// logWriter routes the stdlib logger (used by hostsession) through logx so
// every line shares one timestamp format.
type logWriter struct{ l *logx.Logger }

func (w logWriter) Write(p []byte) (int, error) {
	w.l.Printf("%s", strings.TrimRight(string(p), "\n"))
	return len(p), nil
}

func runHostStart(args []string) error {
	fs := flag.NewFlagSet("host start", flag.ExitOnError)
	interval := fs.Duration("interval", defaultHeartbeat, "heartbeat interval")
	noNativePrompt := fs.Bool("no-native-prompt", false, "macOS: don't offer to install the native runtime (set it up later with `sudo clux native install`)")
	foreground := fs.Bool("foreground", false, "run in this terminal; never offer or hand over to the background service (what the service itself runs)")
	background := fs.Bool("background", false, "run as the background service, even if you answered no before")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *foreground && *background {
		return errors.New("--foreground and --background exclude each other")
	}

	ctx, stop := interruptContext()
	defer stop()

	stateDir, err := config.Dir()
	if err != nil {
		return err
	}
	// Prompts only on a terminal; scripts (`< /dev/null`) and the service
	// behave exactly as before: foreground, no questions.
	interactive := isTerminal(os.Stdin) && isTerminal(os.Stdout)
	asService := os.Getenv(service.EnvService) == "1"

	cfg, err := config.Read()
	if err != nil {
		return err
	}
	login := func(ctx context.Context) error {
		backend := cfg.BackendURL
		if backend == "" {
			backend = defaultBackendURL
		}
		_, err := browserLogin(ctx, cfg, backend, os.Stdout)
		return err
	}
	relogin := &reloginOnce{interactive: interactive, login: login, out: os.Stdout}
	justLoggedIn := false
	if !cfg.LoggedIn() {
		switch {
		case asService:
			fmt.Fprintln(os.Stderr, "clux: not logged in; waiting for a login (run `clux host start` in a terminal)")
			if waitForCredentials(ctx, "", func(f string, a ...any) { fmt.Fprintf(os.Stderr, "clux: "+f+"\n", a...) }) {
				return &exitError{code: exitRestart, err: errors.New("restarting with the new login")}
			}
			return nil
		case interactive:
			if err := login(ctx); err != nil {
				return err
			}
			justLoggedIn = true
		default:
			return config.ErrNotLoggedIn
		}
	}

	svc, svcErr := newService()
	if svcErr != nil {
		svc = nil
	}
	if interactive && !*foreground && svc != nil && svc.Supported() {
		if st, _ := svc.Status(); st.Running {
			fmt.Println(alreadyInBackground)
			return nil
		}
	}

	lock, err := hostlock.Acquire(stateDir)
	if err != nil {
		if hostlock.IsHeld(err) {
			if interactive && !*foreground {
				// Only a terminal run can hold it here: a running service was
				// handled above.
				err = fmt.Errorf("%w; it runs in another terminal: press Ctrl+C there first, then run `clux host start` again to keep this computer online in the background", err)
			}
			return &exitError{code: exitAlreadyRunning, err: err}
		}
		return err
	}
	// A closure: install may swap the lock (released, then re-taken).
	defer func() { lock.Release() }()

	// Log to stderr and to a rotating file, so an outage can be diagnosed
	// after the fact (`~/.clux/logs/host.log`, 5 MB, 3 old files kept). The
	// service writes the file only: its stderr is service.log, kept for
	// crashes.
	var out io.Writer = os.Stderr
	logPath := hostLogPath(stateDir)
	if lf, ferr := logx.OpenRotating(logPath, 5<<20, 3); ferr == nil {
		defer lf.Close()
		if asService {
			out = lf
		} else {
			out = logx.Tee{Primary: os.Stderr, Secondary: []interface{ Write([]byte) (int, error) }{lf}}
		}
	} else {
		fmt.Fprintf(os.Stderr, "clux: not writing a log file (%v)\n", ferr)
	}
	logger := logx.New(out)
	log.SetFlags(0)
	log.SetOutput(logWriter{logger})
	defer logger.Flush()
	logger.Printf("clux %s starting (log: %s)", version, logPath)

	// The background service: asked once (interactive), remembered.
	bg := &backgroundOffer{
		interactive: interactive,
		foreground:  *foreground,
		background:  *background,
		supported:   svc != nil && svc.Supported(),
		answer:      cfg.Service,
		save: func(answer string) error {
			cfg.Service = answer
			return config.Save(cfg)
		},
		install: func() error {
			if svc == nil {
				return svcErr
			}
			// The service takes the host lock itself.
			lock.Release()
			if err := installService(svc, cfg, os.Stdout); err != nil {
				if l, lerr := hostlock.Acquire(stateDir); lerr == nil {
					lock = l
				} else {
					return fmt.Errorf("%w (and %v)", err, lerr)
				}
				return err
			}
			return nil
		},
		in:  os.Stdin,
		out: os.Stdout,
	}

	// About to hand over to the service: check the stored token here
	// first, where a rejected one can still be replaced by logging in
	// again (the service never prompts). A foreground run finds out on
	// its first register instead.
	if a := bg.decide(); interactive && !justLoggedIn && (a == bgInstall || a == bgPrompt) {
		if err := relogin.do(ctx, verifyToken(cfg)); err != nil {
			if tunnel.IsFatal(err) {
				logger.Printf("fatal: %v", err)
				return &exitError{code: exitFatalConfig, err: err}
			}
			return err
		}
	}

	// macOS: offer the native runtime once (interactive only), or warn if
	// it is installed but unhealthy. Never blocks docker-only mode.
	newNativeOffer(cfg, *noNativePrompt, log.Printf).run()

	if bg.run() {
		logger.Printf("handed over to the background service")
		return nil
	}

	h := newHostLoop(cfg, *interval, logger)
	h.caps = &native.Capabilities{Supervisor: func(ctx context.Context) (string, string, error) {
		ncfg, err := native.LoadConfig()
		if err != nil {
			return "", "", err
		}
		return supervisorsSummary(slotsStatus(ctx, ncfg))
	}}
	if nh := setupNative(ctx, cfg, stateDir); nh != nil {
		h.proxy = nh.proxy
		h.opts.Runtimes = map[string]hostsession.Runtime{hostsession.RuntimeNativeMacOS: nh.runtime}
		h.opts.Egress = nh.proxy
		h.caps.FreeSlots = nh.runtime.Slots.Free
	}
	go h.dispatch(ctx, netwatch.Watch(ctx, netwatch.Options{}))
	// h.cfg is cfg: a re-login inside relogin.do hands h the new token.
	err = relogin.do(ctx, func(ctx context.Context) error {
		logger.Flush()
		return h.run(ctx)
	})
	if err != nil && tunnel.IsFatal(err) {
		// Into host.log too, before exiting: after-the-fact diagnosis is the
		// whole point of the file.
		return fatalExit(ctx, err, asService, logger.Printf, func(ctx context.Context) bool {
			logger.Flush()
			return waitForCredentials(ctx, cfg.Token, logger.Printf)
		})
	}
	return err
}

// verifyToken registers once with the stored token and hangs up, so a
// rejected token shows up while the user is still at the terminal. Only
// fatal errors count; anything else (offline, backend down) is left to the
// agent's own retries.
func verifyToken(cfg *config.Config) func(context.Context) error {
	return func(ctx context.Context) error {
		info, err := collectInfo()
		if err != nil {
			return nil
		}
		sess, err := tunnel.Dial(ctx, cfg.BackendURL, cfg.Token, version, info, nil)
		if err != nil {
			if tunnel.IsFatal(err) {
				return err
			}
			return nil
		}
		_ = sess.Close()
		return nil
	}
}

type hostLoop struct {
	cfg      *config.Config
	interval time.Duration
	log      *logx.Logger
	results  *hostsession.Results
	// opts are the workspace runtimes + egress proxy every session's
	// handler dispatches to; caps describes them in register/heartbeat.
	opts  hostsession.Options
	caps  *native.Capabilities
	proxy *egress.Proxy // nil without native mode

	// Network/sleep events are consumed by ONE goroutine (dispatch). It
	// routes them to the live session (cur) if there is one, else raises
	// wake so a pending reconnect wait ends early.
	mu   sync.Mutex
	cur  *tunnel.Session
	wake chan struct{}

	bo        backoff.Policy
	downSince time.Time // zero while connected
	attempts  int
}

func newHostLoop(cfg *config.Config, interval time.Duration, l *logx.Logger) *hostLoop {
	return &hostLoop{
		cfg:      cfg,
		interval: interval,
		log:      l,
		results:  hostsession.NewResults(),
		caps:     &native.Capabilities{},
		wake:     make(chan struct{}, 1),
	}
}

// capsKey makes capabilities comparable, so heartbeats carry them only when
// they changed.
func capsKey(c map[string]any) string {
	b, _ := json.Marshal(c)
	return string(b)
}

func (h *hostLoop) run(ctx context.Context) error {
	for {
		lived, immediate, err := h.session(ctx)
		if ctx.Err() != nil {
			h.log.Printf("stopped (containers keep running; `clux host start` reattaches them)")
			return nil
		}
		if tunnel.IsFatal(err) {
			return err
		}
		if h.downSince.IsZero() {
			h.downSince = time.Now()
			h.attempts = 0
		}
		h.attempts++
		delay := h.bo.SessionEnded(lived, immediate)
		if errors.Is(err, tunnel.ErrSuperseded) {
			// Two agents on one token keep replacing each other; reconnecting
			// fast would just continue the fight. Say so loudly, back off long.
			h.log.Printf("WARNING: %v. Stop the other `clux host start` (another terminal or machine), "+
				"or create a separate host for it. Retrying in %s.", err, h.bo.Max)
			delay = h.bo.Max
			if delay <= 0 {
				delay = 30 * time.Second
			}
		} else {
			h.log.Repeatable("tunnel down: %s", summarize(err))
		}
		if !h.wait(ctx, delay) {
			h.log.Printf("stopped (containers keep running; `clux host start` reattaches them)")
			return nil
		}
	}
}

// wait sleeps for d, returning early (true) when the network comes back or
// the machine wakes -- that is exactly when a retry is most likely to work.
// Returns false if ctx was cancelled.
func (h *hostLoop) wait(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	case <-h.wake:
		h.bo.Reset()
		return true
	}
}

// dispatch is the single consumer of netwatch events.
func (h *hostLoop) dispatch(ctx context.Context, events <-chan netwatch.Event) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-events:
			if !ok {
				return
			}
			h.mu.Lock()
			sess := h.cur
			h.mu.Unlock()
			if sess == nil {
				select {
				case h.wake <- struct{}{}:
				default:
				}
				continue
			}
			h.applyToSession(sess, ev)
		}
	}
}

// applyToSession turns a sleep/wake or network-change event into either an
// immediate reconnect (the tunnel is certainly dead) or a fast liveness
// probe (it may have survived).
func (h *hostLoop) applyToSession(sess *tunnel.Session, ev netwatch.Event) {
	switch ev.Kind {
	case netwatch.Woke:
		sess.Kick(fmt.Errorf("machine woke up or was suspended (%s unaccounted)", ev.Gap.Round(time.Second)))
	case netwatch.NetworkChanged:
		local := sess.LocalAddr()
		if isLoopback(local) {
			// Tunnel goes through a local proxy: our own address says
			// nothing about the path, so just verify liveness.
			sess.Probe(probeAfterNetworkChange)
			return
		}
		if !netwatch.HasIP(ev.Addrs, local) {
			sess.Kick(fmt.Errorf("network changed (local address %s is gone)", local))
			return
		}
		h.log.Printf("network changed; checking the tunnel")
		sess.Probe(probeAfterNetworkChange)
	}
}

func isLoopback(a net.Addr) bool {
	if a == nil {
		return false
	}
	host := a.String()
	if hh, _, err := net.SplitHostPort(host); err == nil {
		host = hh
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

func (h *hostLoop) setCurrent(s *tunnel.Session) {
	h.mu.Lock()
	h.cur = s
	h.mu.Unlock()
	if s != nil {
		// Events seen while dialing were about the old path; this fresh
		// connection was made after them.
		select {
		case <-h.wake:
		default:
		}
	}
}

// session dials, registers and runs one tunnel session. lived is how long
// the session stayed registered (0 if it never registered); immediate means
// the next attempt should not wait (sleep/wake, network change).
func (h *hostLoop) session(ctx context.Context) (lived time.Duration, immediate bool, err error) {
	info, err := collectInfo()
	if err != nil {
		return 0, false, err
	}

	caps := h.caps.Collect(ctx)
	sess, err := tunnel.Dial(ctx, h.cfg.BackendURL, h.cfg.Token, version, info, caps)
	if err != nil {
		return 0, false, err
	}
	sentCaps := capsKey(caps)
	registeredAt := time.Now()
	h.log.Flush()
	if h.downSince.IsZero() {
		h.log.Printf("registered as host %q (id=%d)", sess.Name, sess.HostID)
	} else {
		h.log.Printf("reconnected as host %q after %s (%d attempt(s))",
			sess.Name, time.Since(h.downSince).Round(time.Second), h.attempts)
		h.downSince = time.Time{}
	}

	sessionCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	go func() {
		ticker := time.NewTicker(h.interval)
		defer ticker.Stop()
		for {
			select {
			case <-sessionCtx.Done():
				return
			case <-ticker.C:
				info, err := sysinfo.Collect(config.DefaultStorageRoot())
				if err != nil {
					h.log.Printf("collecting system info for heartbeat: %v", err)
					continue
				}
				// Capabilities ride along only when they changed (e.g. the
				// supervisor came up, or Xcode was updated).
				var changed map[string]any
				if c := h.caps.Collect(sessionCtx); capsKey(c) != sentCaps {
					changed, sentCaps = c, capsKey(c)
				}
				sess.SendHeartbeat(info, version, changed)
			}
		}
	}()

	if n := h.results.Attach(sess); n > 0 {
		h.log.Printf("re-sent %d command result(s) from the previous connection", n)
	}
	handler := hostsession.New(ctx, sess, h.results, h.opts)
	h.setCurrent(sess)
	if h.proxy != nil {
		h.proxy.SetSender(sess)
	}
	runErr := sess.Run(sessionCtx, handler)
	if h.proxy != nil {
		h.proxy.SetSender(nil)
	}
	h.setCurrent(nil)
	h.results.Detach(sess)
	handler.Close()

	lived = time.Since(registeredAt)
	return lived, errors.Is(runErr, tunnel.ErrReconnectRequested), runErr
}

var ephemeralPort = regexp.MustCompile(`((?:\d{1,3}\.){3}\d{1,3}|\[[0-9a-fA-F:]+\]):\d+->`)

// summarize makes an error line stable across retries (drops the local
// ephemeral port) so identical failures collapse in the log.
func summarize(err error) string {
	if err == nil {
		return "session ended"
	}
	return ephemeralPort.ReplaceAllString(err.Error(), "$1->")
}
