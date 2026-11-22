package native

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/eduardkumskyi/clux-cli/internal/selfupdate"
)

// Daemon self-update. The daemons run their own root-owned copy of clux
// (Config.BinaryPath). The owner's CLI never hands root a binary: it asks
// the root pf daemon, over the slot keeper's socket (owner-only, see
// keeper.go), to move to a release tag, and root downloads that release
// itself, requires a valid signature and checksum (selfupdate), swaps the
// binary atomically and restarts its LaunchDaemons as soon as no workspace
// is running on them (daemonupdate_darwin.go).

// Keeper ops for the self-update.
const (
	// KeeperOpUpdate moves the daemons to KeeperRequest.Version.
	KeeperOpUpdate = "update"
	// KeeperOpVersion reports the running root daemon's version.
	KeeperOpVersion = "version"
)

// FirstSelfUpdatingVersion is the first clux whose daemons update
// themselves. An older installation needs one `sudo clux native install`.
const FirstSelfUpdatingVersion = selfupdate.FirstSignedRelease

// CanSelfUpdate reports whether daemons installed by clux `installed` take
// KeeperOpUpdate.
func CanSelfUpdate(installed string) bool {
	return !selfupdate.Older(installed, FirstSelfUpdatingVersion)
}

// PFDOptions configures RunPFD.
type PFDOptions struct {
	Logf func(string, ...any)
	// Version is this binary's clux version.
	Version string
	// SlotStatus asks a slot's supervisor for its version and whether it
	// runs a workspace; nil disables the self-update.
	SlotStatus SlotStatusFunc
}

// SlotStatusFunc reports the clux version slot n's supervisor runs and
// whether it is running a workspace (the supervisor's status op; the pf
// daemon gets it from cmd/clux, since package supervisor imports this one).
type SlotStatusFunc func(ctx context.Context, n int) (version string, busy bool, err error)

// UpdateResult is the keeper's answer to KeeperOpUpdate.
type UpdateResult struct {
	From string `json:"from"`
	To   string `json:"to"`
	// UpToDate: the daemons' binary already is To; nothing was changed.
	UpToDate bool `json:"up_to_date,omitempty"`
	// Restarted: slots whose supervisor was restarted onto To. Deferred:
	// slots running a workspace, restarted once it stops.
	Restarted []int `json:"restarted,omitempty"`
	Deferred  []int `json:"deferred,omitempty"`
	// DaemonRestarting: the root daemon itself restarts onto To within
	// seconds (otherwise once no workspace runs).
	DaemonRestarting bool `json:"daemon_restarting,omitempty"`
}

// checkUpdateTarget decides whether daemons on installed may move to
// target: target must be a release tag; moving to an older release needs
// allowDowngrade (an explicit `clux update --version`).
func checkUpdateTarget(installed, target string, allowDowngrade bool) (upToDate bool, err error) {
	if !selfupdate.ValidTag(target) {
		return false, fmt.Errorf("%q is not a release tag (e.g. v0.7.0)", target)
	}
	if installed == target {
		return true, nil
	}
	if selfupdate.Older(target, installed) && !allowDowngrade {
		return false, fmt.Errorf("the native daemons run clux %s, newer than %s; refusing to downgrade (pass an explicit --version to `clux update` to force it)", installed, target)
	}
	return false, nil
}

// updateTimeout bounds one update (download + verification + swap).
const updateTimeout = 5 * time.Minute

// Update asks the root daemon to move to release tag version.
func (k *KeeperClient) Update(ctx context.Context, version string, allowDowngrade bool) (UpdateResult, error) {
	r, err := k.call(ctx, KeeperRequest{Op: KeeperOpUpdate, Version: version, AllowDowngrade: allowDowngrade})
	if err != nil {
		return UpdateResult{}, err
	}
	if r.Update == nil {
		return UpdateResult{}, errors.New("slot keeper: no update result in reply")
	}
	return *r.Update, nil
}

// DaemonVersion is the clux version the root daemon is running.
func (k *KeeperClient) DaemonVersion(ctx context.Context) (string, error) {
	r, err := k.call(ctx, KeeperRequest{Op: KeeperOpVersion})
	return r.Version, err
}

// WaitForDaemon waits (bounded by ctx) until the root daemon answers as
// version, i.e. it has restarted onto it.
func (k *KeeperClient) WaitForDaemon(ctx context.Context, version string) error {
	for {
		v, err := k.DaemonVersion(ctx)
		if err == nil && v == version {
			return nil
		}
		select {
		case <-ctx.Done():
			if err == nil {
				err = fmt.Errorf("still running clux %s", v)
			}
			return fmt.Errorf("the native root daemon did not come back on clux %s: %v", version, err)
		case <-time.After(time.Second):
		}
	}
}
