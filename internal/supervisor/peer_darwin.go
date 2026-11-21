//go:build darwin

package supervisor

import (
	"errors"
	"net"
)

// connPeerUID is the uid of the process at the other end of a unix socket.
func connPeerUID(c net.Conn) (int, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return -1, errors.New("not a unix socket")
	}
	return peerUID(uc)
}
