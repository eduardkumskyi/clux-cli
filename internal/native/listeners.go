package native

import (
	"encoding/binary"
	"errors"
	"net"
)

// Record kinds and layouts of the net.inet.tcp.pcblist_n sysctl (XNU
// bsd/netinet/in_pcb.h struct xinpcb_n, bsd/sys/socketvar.h struct
// xsocket_n) -- what netstat reads. Every record starts with
// {u32 len, u32 kind} and is padded to 8 bytes, so unknown kinds are
// skipped safely; only the leading fields used here are relied on.
const (
	xsoSocket = 0x001
	xsoInpcb  = 0x010

	xinpgenSize = 24

	inpLportOff = 18 // u16, network order
	inpVflagOff = 44 // u8 (records are #pragma pack(4): no padding before u64s)
	inpLaddrOff = 64 // 16 bytes; IPv4 in the last 4 (in_addr_4in6)
	inpMinLen   = inpLaddrOff + 16

	soOptionsOff = 20 // u32
	soUIDOff     = 64 // u32
	soMinLen     = soUIDOff + 4

	inpIPv4      = 0x1
	inpIPv6      = 0x2
	soAcceptConn = 0x2
)

// ParsePCBList extracts listening sockets from a pcblist_n buffer.
func ParsePCBList(buf []byte) ([]Listener, error) {
	if len(buf) < xinpgenSize {
		return nil, errors.New("pcblist: short buffer")
	}
	le := binary.LittleEndian
	off := roundup8(int(le.Uint32(buf)))
	if off < xinpgenSize || off > len(buf) {
		return nil, errors.New("pcblist: bad header length")
	}
	var out []Listener
	var cur *Listener // inpcb seen, waiting for its socket record
	for off+8 <= len(buf) {
		n := int(le.Uint32(buf[off:]))
		kind := le.Uint32(buf[off+4:])
		if n <= xinpgenSize { // trailing xinpgen
			break
		}
		if off+n > len(buf) {
			return out, errors.New("pcblist: truncated record")
		}
		rec := buf[off : off+n]
		switch kind {
		case xsoInpcb:
			cur = nil
			if n >= inpMinLen {
				vflag := rec[inpVflagOff]
				l := Listener{
					Port: int(binary.BigEndian.Uint16(rec[inpLportOff:])),
					IPv4: vflag&inpIPv4 != 0,
					IPv6: vflag&inpIPv6 != 0,
				}
				addr := rec[inpLaddrOff : inpLaddrOff+16]
				if l.IPv6 {
					ip := net.IP(append([]byte(nil), addr...))
					if !ip.IsUnspecified() {
						l.Addr = ip
					}
				} else {
					ip := net.IP(append([]byte(nil), addr[12:16]...))
					if !ip.IsUnspecified() {
						l.Addr = ip.To16()
					}
				}
				cur = &l
			}
		case xsoSocket:
			if cur != nil && n >= soMinLen {
				if le.Uint32(rec[soOptionsOff:])&soAcceptConn != 0 {
					cur.UID = int(le.Uint32(rec[soUIDOff:]))
					out = append(out, *cur)
				}
			}
			cur = nil
		}
		off += roundup8(n)
	}
	return out, nil
}

func roundup8(n int) int { return (n + 7) &^ 7 }
