package egress

import "testing"

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

func TestListsExactlyIgnoresWildcards(t *testing.T) {
	p := Policy{Mode: ModeOpen, Allow: []string{"*.corp.lan", "db.corp.lan:5432"}}
	if p.listsExactly("x.corp.lan", 443) {
		t.Fatal("wildcard must not count as an explicit entry")
	}
	if !p.listsExactly("db.corp.lan", 5432) {
		t.Fatal("explicit host:port entry not found")
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
