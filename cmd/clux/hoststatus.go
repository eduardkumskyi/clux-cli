package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/eduardkumskyi/clux-cli/internal/config"
	"github.com/eduardkumskyi/clux-cli/internal/hostlock"
	"github.com/eduardkumskyi/clux-cli/internal/native"
	"github.com/eduardkumskyi/clux-cli/internal/tunnel"
)

var hostlockHolder = hostlock.Holder

func hostLogPath(stateDir string) string { return filepath.Join(stateDir, "logs", "host.log") }

// runHostStatus is a local summary: it never dials the backend (a second
// register would replace the running agent's tunnel).
func runHostStatus(args []string) error {
	stateDir, err := config.Dir()
	if err != nil {
		return err
	}
	row := func(k, v string) { fmt.Printf("%-20s %s\n", k+":", v) }

	svcPID := 0
	svc, svcErr := newService()
	switch {
	case svcErr != nil:
		row("Background service", "unknown ("+svcErr.Error()+")")
	case !svc.Supported():
		row("Background service", "not supported on "+runtime.GOOS+" yet")
	default:
		st, _ := svc.Status()
		switch {
		case st.Running:
			svcPID = st.PID
			row("Background service", fmt.Sprintf("running (%s, pid %d)", svc.Description(), st.PID))
		case st.Installed || st.Loaded:
			row("Background service", fmt.Sprintf("installed, not running (%s); see `clux host logs`", svc.Description()))
		default:
			row("Background service", "not installed")
		}
	}
	if pid, held, _ := hostlockHolder(stateDir); held && (svcPID == 0 || pid != svcPID) {
		row("In a terminal", fmt.Sprintf("running (pid %d)", pid))
	}

	cfg, err := config.Read()
	if err != nil {
		return err
	}
	if cfg.LoggedIn() {
		host := fmt.Sprintf("%q", cfg.HostName)
		if cfg.HostID != 0 {
			host += fmt.Sprintf(" (id %d)", cfg.HostID)
		}
		row("Host", host)
	} else {
		row("Host", "not logged in (run `clux host start` in a terminal, or `clux login`)")
	}
	backend := cfg.BackendURL
	if backend == "" {
		backend = defaultBackendURL
	}
	row("Backend", backend)
	row("CLI", version)
	if last := lastConnectionEvent(hostLogPath(stateDir)); last != "" {
		row("Last event", last)
		if tokenRejectedEvent(last) {
			row("Action", tunnel.TokenRejectedHint)
		}
	}
	if runtime.GOOS == "darwin" {
		row("Native runtime", nativeSummary())
	}
	row("Log", hostLogPath(stateDir))
	return nil
}

// lastConnectionEvent is the newest connect/disconnect line in host.log.
func lastConnectionEvent(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	// Only the tail matters; the file is capped at 5 MB.
	if st, err := f.Stat(); err == nil && st.Size() > 256<<10 {
		_, _ = f.Seek(-256<<10, io.SeekEnd)
	}
	last := ""
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		for _, m := range []string{"registered as host", "reconnected as host", "tunnel down", "stopped (", "fatal:", "token rejected:"} {
			if strings.Contains(line, m) {
				last = line
				break
			}
		}
	}
	return last
}

// tokenRejectedEvent: the agent stopped because the backend no longer
// accepts this computer's token (see tunnel.ErrTokenRejected).
func tokenRejectedEvent(line string) bool {
	return strings.Contains(line, "token rejected:") ||
		(strings.Contains(line, "fatal:") && strings.Contains(line, tunnel.ErrTokenRejected.Error())) ||
		strings.Contains(line, "fatal: backend revoked this host's token")
}

// nativeSummary: installed state and which slots hold workspaces (the
// native workspaces this machine is running).
func nativeSummary() string {
	cfg, err := native.LoadConfig()
	if errors.Is(err, os.ErrNotExist) {
		return "not installed (sudo clux native install)"
	}
	if err != nil {
		return "unknown (" + err.Error() + ")"
	}
	if cfg.OwnerUID != os.Getuid() {
		return fmt.Sprintf("installed for %s, not this user", cfg.OwnerUser)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	free, held, down := 0, []string{}, 0
	for _, s := range slotsStatus(ctx, cfg) {
		switch {
		case s.err != nil:
			down++
		case len(s.resp.Resident) == 0:
			free++
		default:
			held = append(held, fmt.Sprintf("slot %d: workspace %s", s.slot.N, strings.Join(s.resp.Resident, ", ")))
		}
	}
	out := fmt.Sprintf("installed, %d slot(s), %d free", len(cfg.Slots), free)
	if down > 0 {
		out += fmt.Sprintf(", %d not answering (clux doctor)", down)
	}
	if len(held) > 0 {
		out += "; " + strings.Join(held, "; ")
	}
	return out
}

// runHostLogs prints the tail of host.log, and with -f keeps following it
// across rotations (host.log -> host.log.1) until Ctrl+C.
func runHostLogs(args []string) error {
	fs := flag.NewFlagSet("host logs", flag.ExitOnError)
	follow := fs.Bool("f", false, "keep printing new lines (Ctrl+C stops)")
	lines := fs.Int("n", 100, "number of lines to show")
	if err := fs.Parse(args); err != nil {
		return err
	}
	stateDir, err := config.Dir()
	if err != nil {
		return err
	}
	path := hostLogPath(stateDir)
	ctx, stop := interruptContext()
	defer stop()
	return printLog(ctx, path, *lines, *follow, os.Stdout, 500*time.Millisecond)
}

func printLog(ctx context.Context, path string, n int, follow bool, out io.Writer, poll time.Duration) error {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) && !follow {
			return errNoServiceForLogs
		}
		if !os.IsNotExist(err) {
			return err
		}
	}
	var off int64
	if f != nil {
		off, err = printTail(f, n, out)
		f.Close()
		if err != nil {
			return err
		}
	}
	if !follow {
		return nil
	}
	t := time.NewTicker(poll)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
		st, err := os.Stat(path)
		if err != nil {
			continue
		}
		if st.Size() < off {
			off = 0 // rotated or truncated: the new file starts over
		}
		if st.Size() == off {
			continue
		}
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		if _, err := f.Seek(off, io.SeekStart); err == nil {
			w, _ := io.Copy(out, f)
			off += w
		}
		f.Close()
	}
}

// printTail writes the last n lines of f and returns the end offset.
func printTail(f *os.File, n int, out io.Writer) (int64, error) {
	st, err := f.Stat()
	if err != nil {
		return 0, err
	}
	size := st.Size()
	const chunk = 64 << 10
	start := size
	var buf []byte
	for start > 0 && strings.Count(string(buf), "\n") <= n {
		step := int64(chunk)
		if start < step {
			step = start
		}
		start -= step
		b := make([]byte, step)
		if _, err := f.ReadAt(b, start); err != nil && err != io.EOF {
			return 0, err
		}
		buf = append(b, buf...)
	}
	text := string(buf)
	ls := strings.SplitAfter(text, "\n")
	if len(ls) > 0 && ls[len(ls)-1] == "" {
		ls = ls[:len(ls)-1]
	}
	if n >= 0 && len(ls) > n {
		ls = ls[len(ls)-n:]
	}
	_, err = io.WriteString(out, strings.Join(ls, ""))
	return size, err
}
