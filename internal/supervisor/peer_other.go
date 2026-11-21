//go:build !darwin

package supervisor

import (
	"errors"
	"net"
)

// connPeerUID: the native supervisor exists on macOS only.
func connPeerUID(net.Conn) (int, error) { return -1, errors.New("macOS only") }
