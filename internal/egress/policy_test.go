package egress

import (
	"net"
	"testing"
)

func TestMatchPattern(t *testing.T) {
	cases := []struct {
		pattern, host string
		port          int
		want          bool
	}{
		{"api.anthropic.com", "api.anthropic.com", 443, true},
		{"API.Anthropic.com.", "api.anthropic.com", 443, true},
		{"api.anthropic.com", "evil-api.anthropic.com", 443, false},
		{"*.github.com", "api.github.com", 443, true},
		{"*.github.com", "a.b.github.com", 443, true},
		{"*.github.com", "github.com", 443, false}, // apex is its own entry
		{"*.github.com", "github.com.evil.io", 443, false},
		{"*.github.com", "notgithub.com", 443, false},
		{"registry.npmjs.org:443", "registry.npmjs.org", 443, true},
		{"registry.npmjs.org:443", "registry.npmjs.org", 80, false},
		{"10.0.0.5", "10.0.0.5", 5432, true},
		{"[2001:db8::1]:443", "2001:db8::1", 443, true},
		{"2001:db8::1", "2001:db8::1", 443, true},
		{"10.0.0.0/8", "10.9.8.7", 22, true},
		{"10.0.0.0/8:22", "10.9.8.7", 23, false},
		{"10.0.0.0/8", "11.0.0.1", 22, false},
		{"10.0.0.0/8", "ten.example.com", 22, false},
		{"", "example.com", 443, false},
	}
	for _, c := range cases {
		if got := matchPattern(c.pattern, c.host, c.port); got != c.want {
			t.Errorf("matchPattern(%q, %q, %d) = %v, want %v", c.pattern, c.host, c.port, got, c.want)
		}
	}
}

func TestPolicyAllows(t *testing.T) {
	p := Policy{Mode: ModeAllowlist, Allow: []string{"*.github.com", "pypi.org"}}
	if !p.Allows("api.github.com", 443) || !p.Allows("PyPI.org", 443) {
		t.Fatal("listed hosts must be allowed")
	}
	if p.Allows("example.com", 443) {
		t.Fatal("unlisted host allowed in allowlist mode")
	}
	if !(Policy{Mode: ModeOpen}).Allows("example.com", 443) {
		t.Fatal("open mode must allow any host")
	}
	if (Policy{Mode: ModeOpen}).Allows("bad host", 443) {
		t.Fatal("invalid host allowed")
	}
}

func TestAllowsPrivateIPOnlyByAddressEntries(t *testing.T) {
	p := Policy{Mode: ModeOpen, Allow: []string{
		"*.corp.lan", "db.corp.lan", "10.0.0.5", "192.168.1.0/24:5432", "[fd00::7]:443", "fd12::/16",
	}}
	cases := []struct {
		ip   string
		port int
		want bool
	}{
		{"10.0.0.5", 22, true},
		{"10.0.0.6", 22, false},
		{"192.168.1.9", 5432, true},
		{"192.168.1.9", 80, false}, // CIDR entry is port-restricted
		{"fd00::7", 443, true},
		{"fd00::7", 80, false},
		{"fd12::1", 1, true},
		{"172.16.0.1", 443, false}, // names (exact or wildcard) never count
	}
	for _, c := range cases {
		if got := p.allowsPrivateIP(net.ParseIP(c.ip), c.port); got != c.want {
			t.Errorf("allowsPrivateIP(%s, %d) = %v, want %v", c.ip, c.port, got, c.want)
		}
	}
}

func TestIsPublic(t *testing.T) {
	for ip, want := range map[string]bool{
		"93.184.216.34": true, "2606:4700::1111": true,
		"10.1.2.3": false, "172.20.0.1": false, "192.168.0.1": false, "100.64.1.1": false,
		"169.254.169.254": false, "127.0.0.1": false, "0.0.0.0": false, "224.0.0.1": false,
		"::1": false, "fe80::1": false, "fd00::1": false, "ff02::1": false,
		"::ffff:10.0.0.1": false, "64:ff9b::a00:1": false, "64:ff9b::5db8:d822": true,
		"2002:c0a8:0101::1": false, "2001:db8::1": false, "2001:0::1": false,
	} {
		if got := isPublic(net.ParseIP(ip)); got != want {
			t.Errorf("isPublic(%s) = %v, want %v", ip, got, want)
		}
	}
}

func TestPolicyFromFrame(t *testing.T) {
	p := PolicyFromFrame(map[string]any{"mode": "open", "allow": []any{"a.com", " ", 3, "*.b.com"}})
	if p.Mode != ModeOpen || len(p.Allow) != 2 || p.Allow[1] != "*.b.com" {
		t.Fatalf("got %+v", p)
	}
	if p := PolicyFromFrame(nil); p.Mode != ModeAllowlist || len(p.Allow) != 0 {
		t.Fatalf("missing egress must be an empty allow list, got %+v", p)
	}
	if p := PolicyFromFrame(map[string]any{"mode": "everything"}); p.Mode != ModeAllowlist {
		t.Fatalf("unknown mode must not widen access, got %+v", p)
	}
}

func TestNormalizeHost(t *testing.T) {
	good := map[string]string{"Example.COM.": "example.com", "[::1]": "::1", "a_b.c": "a_b.c"}
	for in, want := range good {
		if got := NormalizeHost(in); got != want {
			t.Errorf("NormalizeHost(%q) = %q, want %q", in, got, want)
		}
	}
	for _, bad := range []string{"", "a..b", "*.x.com", "a/b", "a b", "x\ny"} {
		if got := NormalizeHost(bad); got != "" {
			t.Errorf("NormalizeHost(%q) = %q, want rejection", bad, got)
		}
	}
}

func TestWithDeduplicates(t *testing.T) {
	p := Policy{Allow: []string{"a.com"}}
	if got := p.with("A.com").Allow; len(got) != 1 {
		t.Fatalf("duplicate added: %v", got)
	}
	q := p.with("b.com")
	if len(q.Allow) != 2 || len(p.Allow) != 1 {
		t.Fatalf("with must copy: p=%v q=%v", p.Allow, q.Allow)
	}
}
