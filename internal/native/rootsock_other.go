//go:build !darwin

package native

import "net"

// PeerUID is macOS-only.
func PeerUID(*net.UnixConn) (int, error) { return -1, errMacOnly }

// VerifyRootListener is macOS-only.
func VerifyRootListener(net.Conn, string) error { return errMacOnly }

// ListenSlotSocket is macOS-only.
func ListenSlotSocket(*Config, Slot, func(string, ...any)) (*net.UnixListener, error) {
	return nil, errMacOnly
}

// DropToSlot is macOS-only.
func DropToSlot(*Config, Slot) error { return errMacOnly }

// ReadSlotState is macOS-only.
func ReadSlotState(int) (SlotState, error) { return SlotState{}, errMacOnly }
