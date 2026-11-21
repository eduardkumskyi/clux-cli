//go:build !darwin

package native

import (
	"context"
	"errors"
	"io"
)

var errMacOnly = errors.New("the native runtime is only available on macOS")

// InstallOptions configures Install (macOS only).
type InstallOptions struct {
	Owner      string
	Slots      int
	CLIVersion string
	Out        io.Writer
}

// OwnerSlotMapFile is where `clux host start` keeps the workspace -> slot
// assignments, relative to the owner's home.
const OwnerSlotMapFile = ".clux/native-slots.json"

// KillUID is macOS-only.
func KillUID(uid, except int) int { return 0 }

// KillIDs is macOS-only.
func KillIDs(uid, gid, except int) int { return 0 }

// UninstallOptions configures Uninstall (macOS only).
type UninstallOptions struct {
	Purge bool
	Out   io.Writer
}

// Install is macOS-only.
func Install(InstallOptions) error { return errMacOnly }

// Uninstall is macOS-only.
func Uninstall(UninstallOptions) error { return errMacOnly }

// RunPFD is macOS-only.
func RunPFD(context.Context, func(string, ...any)) error { return errMacOnly }

// TCPListeners is macOS-only.
func TCPListeners() ([]Listener, error) { return nil, errMacOnly }
