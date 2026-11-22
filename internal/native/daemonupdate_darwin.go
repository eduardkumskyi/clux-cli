//go:build darwin

package native

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/eduardkumskyi/clux-cli/internal/selfupdate"
)

// daemonUpdater is the root half of the self-update, inside the pf daemon.
//
// Restarts are reconciled, not scheduled: every few seconds (while
// something is outdated) each supervisor whose version differs from
// Config.CLIVersion is restarted if its slot runs no workspace, and the pf
// daemon itself exits (launchd's KeepAlive starts the new binary) once an
// update it applied is in place on every supervisor and no slot is busy. A
// running workspace is therefore never cut off by an update; it gets the
// new supervisor when it stops. Each slot is restarted at most once per
// version, so a supervisor that keeps answering an unexpected version
// can't cause a restart loop.
type daemonUpdater struct {
	version    string // this process's clux version
	logf       func(string, ...any)
	slotStatus SlotStatusFunc

	// Seams (tests): where config/binary live and who owns what root writes.
	client             *selfupdate.Client
	configPath         string
	fileUID, fileGID   int
	loadConfig         func() (*Config, error)
	restartSupervisor  func(n int) error
	updateMu           sync.Mutex // one update at a time
	mu                 sync.Mutex // the fields below
	outdated           bool
	restartSelf        bool
	restartedFor       map[int]string
	lastReconcileError string
}

func newDaemonUpdater(version string, slotStatus SlotStatusFunc, logf func(string, ...any)) *daemonUpdater {
	return &daemonUpdater{
		version: version, logf: logf, slotStatus: slotStatus,
		client:     &selfupdate.Client{GOOS: "darwin", GOARCH: runtime.GOARCH},
		configPath: ConfigPath,
		loadConfig: LoadConfig,
		restartSupervisor: func(n int) error {
			_, err := run("/bin/launchctl", "kickstart", "-k", "system/"+SupervisorLabel(n))
			return err
		},
		// At start: a supervisor may still run an older binary (the daemon
		// was restarted half-way through an earlier update).
		outdated:     slotStatus != nil,
		restartedFor: map[int]string{},
	}
}

// update handles KeeperOpUpdate.
func (u *daemonUpdater) update(ctx context.Context, req KeeperRequest) KeeperResponse {
	if !u.updateMu.TryLock() {
		return KeeperResponse{Error: "a native daemon update is already running"}
	}
	defer u.updateMu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, updateTimeout)
	defer cancel()

	cfg, err := u.loadConfig()
	if err != nil {
		return KeeperResponse{Error: err.Error()}
	}
	res := UpdateResult{From: cfg.CLIVersion, To: req.Version}
	upToDate, err := checkUpdateTarget(cfg.CLIVersion, req.Version, req.AllowDowngrade)
	if err != nil {
		return KeeperResponse{Error: err.Error()}
	}
	if upToDate {
		res.UpToDate = true
		return KeeperResponse{OK: true, Update: &res}
	}

	u.logf("self-update: %s -> %s: downloading", cfg.CLIVersion, req.Version)
	// The root path never accepts an unsigned release.
	binary, _, err := u.client.Download(ctx, req.Version, false)
	if err != nil {
		u.logf("self-update to %s failed: %v", req.Version, err)
		return KeeperResponse{Error: fmt.Sprintf("updating the native daemons to %s: %v", req.Version, err)}
	}
	if err := u.install(ctx, cfg, req.Version, binary); err != nil {
		u.logf("self-update to %s failed: %v", req.Version, err)
		return KeeperResponse{Error: fmt.Sprintf("updating the native daemons to %s: %v", req.Version, err)}
	}
	u.logf("self-update: %s installed at %s", req.Version, cfg.BinaryPath)

	u.mu.Lock()
	u.outdated, u.restartSelf = true, true
	u.mu.Unlock()
	res.Restarted, res.Deferred, res.DaemonRestarting = u.reconcile(ctx)
	return KeeperResponse{OK: true, Update: &res}
}

// install puts the verified binary in place of cfg.BinaryPath and records
// tag in the config. The binary is staged next to the old one (same
// root-owned directory), run once to check it is the release asked for and
// can read this installation's config (a release that changed the layout
// must not replace daemons it can't run), then renamed over it.
func (u *daemonUpdater) install(ctx context.Context, cfg *Config, tag string, binary []byte) error {
	final, err := inTrustedDir(cfg.BinaryPath)
	if err != nil {
		return err
	}
	staged := filepath.Join(filepath.Dir(final), ".clux-next")
	if err := writeFileSafe(staged, binary, 0o755, u.fileUID, u.fileGID); err != nil {
		return fmt.Errorf("staging the new binary: %w", err)
	}
	defer os.Remove(staged) // a no-op after the rename
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, staged, "native", "daemon-check")
	cmd.Dir, cmd.Env = "/", []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin"}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("the new binary can't run this installation (%v: %s); re-run `sudo clux native install` with clux %s", err, strings.TrimSpace(stderr.String()), tag)
	}
	if got := strings.TrimSpace(stdout.String()); got != tag {
		return fmt.Errorf("the downloaded binary reports version %q, not %s; refusing it", got, tag)
	}
	if err := os.Rename(staged, final); err != nil {
		return fmt.Errorf("installing %s: %w", final, err)
	}
	next := *cfg
	next.CLIVersion = tag
	b, _ := json.MarshalIndent(next, "", "  ")
	if err := writeFileSafe(u.configPath, append(b, '\n'), 0o644, u.fileUID, u.fileGID); err != nil {
		return fmt.Errorf("recording %s in %s: %w", tag, u.configPath, err)
	}
	return nil
}

// reconcileEvery: how often outdated supervisors are looked at (a no-op
// once everything runs the installed binary).
const reconcileEvery = 2 * time.Second

// run reconciles in the background, apart from the pf loop (a supervisor
// that doesn't answer must not hold up the firewall). The returned channel
// closes when this process should exit to be replaced by the new binary.
func (u *daemonUpdater) run(ctx context.Context) <-chan struct{} {
	restart := make(chan struct{})
	go func() {
		t := time.NewTicker(reconcileEvery)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			if _, _, due := u.reconcile(ctx); due {
				// An update call still in flight sends its reply first.
				u.updateMu.Lock()
				time.Sleep(time.Second)
				close(restart)
				return
			}
		}
	}()
	return restart
}

// reconcile restarts every outdated, idle supervisor. daemonDue: this
// process should exit now so launchd starts the new binary.
func (u *daemonUpdater) reconcile(ctx context.Context) (restarted, deferred []int, daemonDue bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if !u.outdated {
		return nil, nil, false
	}
	cfg, err := u.loadConfig()
	if err != nil {
		if msg := err.Error(); msg != u.lastReconcileError {
			u.logf("self-update: reading the config: %v", err)
			u.lastReconcileError = msg
		}
		return nil, nil, false
	}
	busyAny := false
	for _, s := range cfg.Slots {
		sctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		v, busy, err := u.slotStatus(sctx, s.N)
		cancel()
		if err != nil {
			// Not answering (starting, or crashed): launchd starts it from
			// the new binary anyway; never restart what we can't see.
			continue
		}
		busyAny = busyAny || busy
		if v == cfg.CLIVersion || u.restartedFor[s.N] == cfg.CLIVersion {
			continue
		}
		if busy {
			deferred = append(deferred, s.N)
			continue
		}
		if err := u.restartSupervisor(s.N); err != nil {
			u.logf("self-update: restarting slot %d's supervisor: %v", s.N, err)
			deferred = append(deferred, s.N)
			continue
		}
		u.restartedFor[s.N] = cfg.CLIVersion
		u.logf("self-update: slot %d's supervisor restarted onto %s", s.N, cfg.CLIVersion)
		restarted = append(restarted, s.N)
	}
	selfDue := u.restartSelf && u.version != cfg.CLIVersion
	if len(deferred) == 0 && !selfDue {
		u.outdated = false
	}
	daemonDue = selfDue && len(deferred) == 0 && !busyAny
	return restarted, deferred, daemonDue
}
