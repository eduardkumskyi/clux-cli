package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/eduardkumskyi/clux-cli/internal/backoff"
	"github.com/eduardkumskyi/clux-cli/internal/config"
	"github.com/eduardkumskyi/clux-cli/internal/hostlock"
	"github.com/eduardkumskyi/clux-cli/internal/hostsession"
	"github.com/eduardkumskyi/clux-cli/internal/logx"
	"github.com/eduardkumskyi/clux-cli/internal/netwatch"
	"github.com/eduardkumskyi/clux-cli/internal/sysinfo"
	"github.com/eduardkumskyi/clux-cli/internal/tunnel"
)

// Exit codes for `clux host start`, so a supervisor (a future launchd /
// systemd unit) can tell "restart me" from "restarting won't help".
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
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load()
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// After the first Ctrl-C starts a graceful shutdown, restore the default
	// signal behavior so a second Ctrl-C kills the process immediately.
	go func() {
		<-ctx.Done()
		stop()
	}()

	stateDir, err := config.Dir()
	if err != nil {
		return err
	}
	lock, err := hostlock.Acquire(stateDir)
	if err != nil {
		if hostlock.IsHeld(err) {
			return &exitError{code: exitAlreadyRunning, err: err}
		}
		return err
	}
	defer lock.Release()

	// Log to stderr and to a rotating file, so an outage can be diagnosed
	// after the fact (`~/.clux/logs/host.log`, 5 MB, 3 old files kept).
	var out io.Writer = os.Stderr
	logPath := filepath.Join(stateDir, "logs", "host.log")
	if lf, ferr := logx.OpenRotating(logPath, 5<<20, 3); ferr == nil {
		defer lf.Close()
		out = logx.Tee{Primary: os.Stderr, Secondary: []interface{ Write([]byte) (int, error) }{lf}}
	} else {
		fmt.Fprintf(os.Stderr, "clux: not writing a log file (%v)\n", ferr)
	}
	logger := logx.New(out)
	log.SetFlags(0)
	log.SetOutput(logWriter{logger})
	defer logger.Flush()
	logger.Printf("clux %s starting (log: %s)", version, logPath)

	h := newHostLoop(cfg, *interval, logger)
	go h.dispatch(ctx, netwatch.Watch(ctx, netwatch.Options{}))
	err = h.run(ctx)
	if err != nil && tunnel.IsFatal(err) {
		// Into host.log too, before exiting: after-the-fact diagnosis is the
		// whole point of the file.
		logger.Printf("fatal: %v", err)
		return &exitError{code: exitFatalConfig, err: err}
	}
	return err
}

type hostLoop struct {
	cfg      *config.Config
	interval time.Duration
	log      *logx.Logger
	results  *hostsession.Results

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
		wake:     make(chan struct{}, 1),
	}
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
	info, err := sysinfo.Collect(config.DefaultStorageRoot())
	if err != nil {
		return 0, false, fmt.Errorf("collecting system info: %w", err)
	}

	sess, err := tunnel.Dial(ctx, h.cfg.BackendURL, h.cfg.Token, version, info)
	if err != nil {
		return 0, false, err
	}
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
				sess.SendHeartbeat(info, version)
			}
		}
	}()

	if n := h.results.Attach(sess); n > 0 {
		h.log.Printf("re-sent %d command result(s) from the previous connection", n)
	}
	handler := hostsession.New(ctx, sess, h.results)
	h.setCurrent(sess)
	runErr := sess.Run(sessionCtx, handler)
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
