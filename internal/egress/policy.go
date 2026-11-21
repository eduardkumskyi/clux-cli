// Package egress is the owner-side outbound proxy for native macOS
// workspaces (`clux host start`, listening on 127.0.0.1:P). The agent user
// can only open TCP connections to that port (pf, see internal/native), so
// every request the agent, its tools or a simulator app make to the outside
// world comes through here and is checked against the workspace's policy.
// Hosts not on the allow list are held while the owner is asked
// (egress.request / egress.decision frames over the tunnel), and every
// connection is reported back in batched egress.log frames.
//
// Workspaces are told apart by credentials in the proxy URL
// (http://ws-<id>:<password>@127.0.0.1:P): all agent traffic arrives from
// the same uid, so the source address says nothing about which workspace it
// belongs to, and a port per workspace would need a pf rule per workspace.
// The password is derived from a per-host secret, so it survives a restart
// of `clux host start` without being re-sent to running sidecars.
package egress

import (
	"net"
	"strconv"
	"strings"
)

// Mode is a workspace's egress mode, as sent by the backend.
type Mode string

const (
	// ModeAllowlist allows only hosts matching Allow; anything else is held
	// for an owner decision.
	ModeAllowlist Mode = "allowlist"
	// ModeOpen allows any public host: the internet, not the owner's LAN.
	// Private addresses still need an explicit IP/CIDR entry (see
	// Policy.allowsPrivateIP); loopback is never reachable.
	ModeOpen Mode = "open"
)

// Policy is one workspace's egress policy (workspace.start "egress" /
// egress.policy).
type Policy struct {
	Mode  Mode     `json:"mode"`
	Allow []string `json:"allow"`
}

// PolicyFromFrame reads {"mode", "allow"} out of a decoded frame field.
// Anything unparseable falls back to an empty allow list: unknown input must
// never widen access.
func PolicyFromFrame(v any) Policy {
	m, _ := v.(map[string]any)
	p := Policy{Mode: ModeAllowlist}
	if m == nil {
		return p
	}
	if mode, _ := m["mode"].(string); mode == string(ModeOpen) {
		p.Mode = ModeOpen
	}
	list, _ := m["allow"].([]any)
	for _, e := range list {
		if s, ok := e.(string); ok {
			if s = strings.TrimSpace(s); s != "" {
				p.Allow = append(p.Allow, s)
			}
		}
	}
	return p
}

// Allows reports whether the policy lets host:port through without asking.
func (p Policy) Allows(host string, port int) bool {
	host = NormalizeHost(host)
	if host == "" {
		return false
	}
	for _, pat := range p.Allow {
		if matchPattern(pat, host, port) {
			return true
		}
	}
	return p.Mode == ModeOpen
}

// allowsPrivateIP reports whether ip:port is covered by an IP or CIDR entry
// ("10.0.0.5", "192.168.1.0/24:5432", "[fd00::1]:443"). Only such entries,
// written by the owner, open a private/LAN/link-local destination: a host
// name -- exact or wildcard, listed, approved in a prompt or added with
// allow_project -- and "open" mode only ever reach public addresses, so a
// DNS answer (rebinding) can never point the agent at the owner's network.
func (p Policy) allowsPrivateIP(ip net.IP, port int) bool {
	for _, pat := range p.Allow {
		h := strings.ToLower(strings.TrimSpace(pat))
		if ph, pp, ok := splitPatternPort(h); ok {
			if pp != port {
				continue
			}
			h = ph
		}
		h = strings.Trim(h, "[]")
		if e := net.ParseIP(h); e != nil {
			if e.Equal(ip) {
				return true
			}
			continue
		}
		if _, n, err := net.ParseCIDR(h); err == nil && n.Contains(ip) {
			return true
		}
	}
	return false
}

// with returns a copy of p that also allows host (allow_project).
func (p Policy) with(host string) Policy {
	host = NormalizeHost(host)
	for _, pat := range p.Allow {
		if NormalizeHost(pat) == host {
			return p
		}
	}
	out := Policy{Mode: p.Mode, Allow: append(append([]string(nil), p.Allow...), host)}
	return out
}

// matchPattern matches one allow entry: "example.com" (exact),
// "*.example.com" (any subdomain, at any depth, but not the apex), an IP
// literal or a CIDR ("10.0.0.0/8"), each optionally with ":port" (IPv6 in
// brackets). Entries without a port match every port.
func matchPattern(pattern, host string, port int) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	if pattern == "" {
		return false
	}
	if h, p, ok := splitPatternPort(pattern); ok {
		if p != port {
			return false
		}
		pattern = h
	}
	pattern = strings.TrimSuffix(strings.Trim(pattern, "[]"), ".")
	if _, n, err := net.ParseCIDR(pattern); err == nil {
		ip := net.ParseIP(host)
		return ip != nil && n.Contains(ip)
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // ".example.com"
		return len(host) > len(suffix) && strings.HasSuffix(host, suffix)
	}
	return host == pattern
}

// splitPatternPort splits "host:443" / "[::1]:443". A bare IPv6 literal has
// colons but no port.
func splitPatternPort(pattern string) (string, int, bool) {
	if strings.HasPrefix(pattern, "[") {
		h, p, err := net.SplitHostPort(pattern)
		if err != nil {
			return "", 0, false
		}
		n, err := strconv.Atoi(p)
		return h, n, err == nil
	}
	if strings.Count(pattern, ":") != 1 {
		return "", 0, false
	}
	h, p, _ := strings.Cut(pattern, ":")
	n, err := strconv.Atoi(p)
	if err != nil {
		return "", 0, false
	}
	return h, n, true
}

// NormalizeHost lower-cases a host name, strips brackets and a trailing dot,
// and rejects anything that is not a plausible DNS name or IP literal (so a
// crafted CONNECT target can't smuggle wildcard or path characters into a
// prompt or a policy entry).
func NormalizeHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	h = strings.TrimSuffix(strings.Trim(h, "[]"), ".")
	if h == "" || len(h) > 253 {
		return ""
	}
	if net.ParseIP(h) != nil {
		return h
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" || len(label) > 63 {
			return ""
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return ""
			}
		}
	}
	return h
}
