//go:build darwin

package native

import (
	"net"
	"os"
	"testing"
)

// Validates the hard-coded XNU struct offsets against the running kernel:
// a listener we open must show up with our uid, port and family.
func TestTCPListenersSeesOwnSocket(t *testing.T) {
	l4, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l4.Close()
	l6, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skip("no IPv6 loopback:", err)
	}
	defer l6.Close()
	p4 := l4.Addr().(*net.TCPAddr).Port
	p6 := l6.Addr().(*net.TCPAddr).Port

	ls, err := TCPListeners()
	if err != nil {
		t.Fatal(err)
	}
	var got4, got6 bool
	for _, l := range ls {
		if l.Port == p4 && l.IPv4 && !l.IPv6 && l.Addr.Equal(net.IPv4(127, 0, 0, 1)) {
			if l.UID != os.Getuid() {
				t.Fatalf("v4 listener uid %d, want %d", l.UID, os.Getuid())
			}
			got4 = true
		}
		if l.Port == p6 && l.IPv6 && l.Addr.Equal(net.IPv6loopback) {
			if l.UID != os.Getuid() {
				t.Fatalf("v6 listener uid %d, want %d", l.UID, os.Getuid())
			}
			got6 = true
		}
	}
	if !got4 || !got6 {
		t.Fatalf("own listeners not found (v4 %v, v6 %v) among %d", got4, got6, len(ls))
	}
	// A connected (non-listening) socket must not be reported.
	c, err := net.Dial("tcp4", l4.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	cp := c.LocalAddr().(*net.TCPAddr).Port
	ls, _ = TCPListeners()
	for _, l := range ls {
		if l.Port == cp {
			t.Fatalf("client socket reported as listener: %+v", l)
		}
	}
}
