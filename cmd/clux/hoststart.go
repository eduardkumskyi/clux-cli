package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
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

// probeAfterNetworkChange bounds how long a tunnel that survived a network
// change (its local IP still exists) may stay silent before it is declared
// dead.
const probeAfterNetworkChange = 5 * time.Second

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

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	stateDir, err := config.Dir()
	if err != nil {
		return err
	}
	lock, err := hostlock.Acquire(stateDir)
	if err != nil {
		return err
	}
	defer lock.Release()

	// Log to stderr and to a rotating file, so an outage can be diagnosed
	// after the fact (`~/.clux/logs/host.log`, 5 MB x 4 files).
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

	events := netwatch.Watch(ctx, netwatch.Options{})
	h := &hostLoop{cfg: cfg, interval: *interval, log: logger, events: events, results: hostsession.NewResults()}
	return h.run(ctx)
}

type hostLoop struct {
	cfg      *config.Config
	interval time.Duration
	log      *logx.Logger
	events   <-chan netwatch.Event
	results  *hostsession.Results

	bo        backoff.Policy
	downSince time.Time // zero while connected
	attempts  int
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
		h.log.Repeatable("tunnel down: %s", summarize(err))
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
	for {
		select {
		case <-ctx.Done():
			return false
		case <-t.C:
			return true
		case ev, ok := <-h.events:
			if !ok {
				h.events = nil
				continue
			}
			if ev.Kind == netwatch.NetworkChanged || ev.Kind == netwatch.Woke {
				h.bo.Reset()
				return true
			}
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

	go h.watchSession(sessionCtx, sess)

	if n := h.results.Attach(sess); n > 0 {
		h.log.Printf("re-sent %d command result(s) from the previous connection", n)
	}
	handler := hostsession.New(ctx, sess, h.results)
	runErr := sess.Run(sessionCtx, handler)
	h.results.Detach(sess)
	handler.Close()
	_ = sess.Close()

	lived = time.Since(registeredAt)
	return lived, errors.Is(runErr, tunnel.ErrReconnectRequested), runErr
}

// watchSession turns sleep/wake and network-change events into either an
// immediate reconnect (the tunnel is certainly dead) or a fast liveness
// probe (it may have survived).
func (h *hostLoop) watchSession(ctx context.Context, sess *tunnel.Session) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-h.events:
			if !ok {
				return
			}
			switch ev.Kind {
			case netwatch.Woke:
				sess.Kick(fmt.Errorf("machine woke up or was suspended (%s unaccounted)", ev.Gap.Round(time.Second)))
			case netwatch.NetworkChanged:
				if !netwatch.HasIP(ev.Addrs, sess.LocalAddr()) {
					sess.Kick(fmt.Errorf("network changed (local address %s is gone)", sess.LocalAddr()))
				} else {
					h.log.Printf("network changed; checking the tunnel")
					sess.Probe(probeAfterNetworkChange)
				}
			}
		}
	}
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
