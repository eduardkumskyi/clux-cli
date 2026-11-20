//go:build darwin

package native

import "golang.org/x/sys/unix"

// TCPListeners returns every listening TCP socket on the machine (IPv4 and
// IPv6 share one pcb table). Readable without privileges, like netstat.
func TCPListeners() ([]Listener, error) {
	buf, err := unix.SysctlRaw("net.inet.tcp.pcblist_n")
	if err != nil {
		return nil, err
	}
	return ParsePCBList(buf)
}
