package native

import (
	"encoding/binary"
	"encoding/xml"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPFRulesBaseShape(t *testing.T) {
	r := PFRules(431, 47821, nil)
	want := []string{
		"pass out quick on lo0 inet proto tcp from any to 127.0.0.1 port 47821 user 431 flags S/SA keep state",
		"pass out quick on lo0 inet6 proto tcp from any to ::1 port 47821 user 431 flags S/SA keep state",
		"pass in quick on lo0 proto tcp from any to any user 431 flags S/SA keep state",
		"block return out quick inet proto { tcp udp } from any to any user 431",
		"block return out quick inet6 proto { tcp udp } from any to any user 431",
	}
	for _, w := range want {
		if !strings.Contains(r, w+"\n") {
			t.Errorf("missing rule %q in:\n%s", w, r)
		}
	}
	// Order matters (quick): every pass must come before the blocks.
	if strings.LastIndex(r, "\npass ") > strings.Index(r, "\nblock ") {
		t.Fatalf("a pass rule follows the block rules:\n%s", r)
	}
}

func TestPFRulesAgentListeners(t *testing.T) {
	const agent, owner = 431, 501
	ls := []Listener{
		{IPv4: true, Port: 3000, UID: agent},                                  // *:3000 (v4)
		{IPv6: true, IPv4: true, Port: 5173, UID: agent},                      // dual-stack wildcard
		{IPv4: true, Addr: net.IPv4(127, 0, 0, 1), Port: 8080, UID: agent},    // loopback only
		{IPv4: true, Addr: net.IPv4(192, 168, 1, 42), Port: 9000, UID: agent}, // LAN address only: not loopback
		{IPv4: true, Port: 5433, UID: owner},                                  // owner's Postgres
		{IPv4: true, Addr: net.IPv4(127, 0, 0, 1), Port: 4000, UID: agent},    // agent v4 ...
		{IPv6: true, Addr: net.IPv6loopback, Port: 4000, UID: owner},          // ... but owner on ::1:4000
		{IPv4: true, Addr: net.IPv4(127, 0, 0, 1), Port: 47821, UID: agent},   // proxy port is never "own"
	}
	r := PFRules(agent, 47821, ls)
	has := func(fam, dst string, port string) bool {
		return strings.Contains(r, "pass out quick on lo0 "+fam+" proto tcp from any to "+dst+" port "+port+" user 431 ")
	}
	if !has("inet", "127.0.0.1", "3000") || has("inet6", "::1", "3000") {
		t.Errorf("v4 wildcard listener:\n%s", r)
	}
	if !has("inet", "127.0.0.1", "5173") || !has("inet6", "::1", "5173") {
		t.Errorf("dual-stack listener:\n%s", r)
	}
	if !has("inet", "127.0.0.1", "8080") {
		t.Errorf("loopback listener:\n%s", r)
	}
	for _, p := range []string{"9000", "5433", "4000"} {
		if strings.Contains(r, "port "+p+" ") {
			t.Errorf("port %s must stay blocked:\n%s", p, r)
		}
	}
	if strings.Count(r, "port 47821 ") != 2 {
		t.Errorf("proxy port duplicated:\n%s", r)
	}
	// Deterministic output, so the pf daemon only reloads on real changes.
	if r != PFRules(agent, 47821, append([]Listener{ls[2], ls[0]}, ls[1:]...)) {
		t.Error("output depends on listener order")
	}
}

func TestPFRulesCapsListenerRules(t *testing.T) {
	var ls []Listener
	for p := 10000; p < 11000; p++ {
		ls = append(ls, Listener{IPv4: true, Port: p, UID: 431})
	}
	if n := strings.Count(PFRules(431, 47821, ls), "\npass out "); n > maxListenerRules+2 {
		t.Fatalf("%d pass rules", n)
	}
}

// pcbRecord builds one {len, kind, ...} record of the given size.
func pcbRecord(kind uint32, size int, fill func([]byte)) []byte {
	b := make([]byte, roundup8(size))
	binary.LittleEndian.PutUint32(b, uint32(size))
	binary.LittleEndian.PutUint32(b[4:], kind)
	fill(b)
	return b
}

func TestParsePCBListSynthetic(t *testing.T) {
	hdr := make([]byte, xinpgenSize)
	binary.LittleEndian.PutUint32(hdr, xinpgenSize)
	inp := func(port uint16, vflag byte, addr net.IP) []byte {
		return pcbRecord(xsoInpcb, 104, func(b []byte) {
			binary.BigEndian.PutUint16(b[inpLportOff:], port)
			b[inpVflagOff] = vflag
			if v4 := addr.To4(); v4 != nil && vflag == inpIPv4 {
				copy(b[inpLaddrOff+12:], v4)
			} else if addr != nil {
				copy(b[inpLaddrOff:], addr.To16())
			}
		})
	}
	sock := func(opts, uid uint32) []byte {
		return pcbRecord(xsoSocket, 104, func(b []byte) {
			binary.LittleEndian.PutUint32(b[soOptionsOff:], opts)
			binary.LittleEndian.PutUint32(b[soUIDOff:], uid)
		})
	}
	other := pcbRecord(0x020, 60, func([]byte) {}) // tcpcb etc. are skipped
	var buf []byte
	buf = append(buf, hdr...)
	buf = append(buf, inp(3000, inpIPv4, net.IPv4(127, 0, 0, 1))...)
	buf = append(buf, sock(soAcceptConn|0x4, 431)...)
	buf = append(buf, other...)
	buf = append(buf, inp(50000, inpIPv4, net.IPv4(127, 0, 0, 1))...)
	buf = append(buf, sock(0, 501)...) // connected, not listening
	buf = append(buf, inp(5173, inpIPv6|inpIPv4, nil)...)
	buf = append(buf, sock(soAcceptConn, 431)...)
	buf = append(buf, hdr...) // trailer
	ls, err := ParsePCBList(buf)
	if err != nil {
		t.Fatal(err)
	}
	if len(ls) != 2 {
		t.Fatalf("got %+v", ls)
	}
	if ls[0].Port != 3000 || !ls[0].IPv4 || ls[0].IPv6 || !ls[0].Addr.Equal(net.IPv4(127, 0, 0, 1)) || ls[0].UID != 431 {
		t.Errorf("first: %+v", ls[0])
	}
	if ls[1].Port != 5173 || !ls[1].IPv6 || !ls[1].IPv4 || ls[1].Addr != nil {
		t.Errorf("second: %+v", ls[1])
	}
	if _, err := ParsePCBList(buf[:len(buf)-40]); err == nil {
		t.Error("truncated buffer not reported")
	}
}

func testProfileParams(t *testing.T) ProfileParams {
	return ProfileParams{
		WorkspaceDir: "/private/var/clux/workspaces/12",
		AgentHome:    "/private/var/clux",
		RuntimeDir:   "/private/var/clux-runtime",
		UserCache:    "/private/var/folders/xx/yy/C",
		UserTemp:     "/private/var/folders/xx/yy/T",
		DeveloperDir: "/Applications/Xcode-16.4.app/Contents/Developer",
	}
}

func TestSandboxProfileContents(t *testing.T) {
	p, err := SandboxProfile(testProfileParams(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"(deny default)",
		`(subpath "/private/var/clux/workspaces/12")`,
		`(subpath "/private/var/clux/Library")`,
		`(subpath "/private/var/clux-runtime")`,
		`(subpath "/Applications/Xcode-16.4.app")`,
		`(allow network-outbound (remote ip "localhost:*"))`,
		`com.apple.CoreSimulator.CoreSimulatorService`,
		`(deny file-write* (regex #"^/private/var/clux/workspaces/12/(.*/)?\.git/hooks(/|$)"))`,
	} {
		if !strings.Contains(p, want) {
			t.Errorf("profile lacks %s", want)
		}
	}
	// Other workspaces and the owner's homes are never named.
	for _, bad := range []string{`(subpath "/private/var/clux/workspaces")`, `"/Users`, "mDNSResponder", "dnssd", `"com.apple.bsd.dirhelper"`} {
		if strings.Contains(p, bad) {
			t.Errorf("profile must not contain %s", bad)
		}
	}
	// The hooks deny must come after the workspace allow (last match wins).
	if strings.Index(p, ".git/hooks") < strings.Index(p, `(subpath "/private/var/clux/workspaces/12")`) {
		t.Error("hooks deny precedes the workspace allow")
	}
}

func TestSandboxProfileRejectsUnsafePaths(t *testing.T) {
	for _, mut := range []func(*ProfileParams){
		func(p *ProfileParams) { p.WorkspaceDir = `/private/var/clux/workspaces/1") (allow default` },
		func(p *ProfileParams) { p.WorkspaceDir = "relative/dir" },
		func(p *ProfileParams) { p.WorkspaceDir = "/private/var/clux/workspaces/../.." },
		func(p *ProfileParams) { p.RuntimeDir = "/" },
	} {
		pp := testProfileParams(t)
		mut(&pp)
		if _, err := SandboxProfile(pp); err == nil {
			t.Errorf("accepted %+v", pp)
		}
	}
}

func TestPlistsAreWellFormed(t *testing.T) {
	for name, s := range map[string]string{
		"pf":         PFDaemonPlist("/usr/local/libexec/clux-native/clux"),
		"supervisor": SupervisorPlist("/Library/Application Support/clux-native/clux"),
	} {
		d := xml.NewDecoder(strings.NewReader(s))
		d.Strict = true
		for {
			if _, err := d.Token(); err != nil {
				if err.Error() != "EOF" {
					t.Fatalf("%s plist: %v\n%s", name, err, s)
				}
				break
			}
		}
	}
	s := SupervisorPlist("/x/clux")
	for _, want := range []string{"<key>UserName</key><string>_clux</string>", "<string>supervise</string>", "<key>KeepAlive</key><true/>"} {
		if !strings.Contains(s, want) {
			t.Errorf("supervisor plist lacks %s", want)
		}
	}
	if strings.Contains(PFDaemonPlist("/x/clux"), "UserName") {
		t.Error("pf daemon must run as root")
	}
}

func TestConfigValidate(t *testing.T) {
	good := Config{Version: 1, OwnerUID: 501, AgentUser: AgentUser, AgentUID: 431, AgentGID: 431,
		CtlGID: 432, ProxyPort: 47821, BinaryPath: "/usr/local/libexec/clux-native/clux"}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, mut := range []func(*Config){
		func(c *Config) { c.AgentUID = 501 },
		func(c *Config) { c.AgentUID = 0 },
		func(c *Config) { c.OwnerUID = 431 },
		func(c *Config) { c.ProxyPort = 80 },
		func(c *Config) { c.AgentUser = "root" },
		func(c *Config) { c.BinaryPath = "clux" },
	} {
		c := good
		mut(&c)
		if c.Validate() == nil {
			t.Errorf("accepted %+v", c)
		}
	}
	path := filepath.Join(t.TempDir(), "native.json")
	if err := writeFileAtomic(path, []byte(`{"version":1,"owner_uid":501,"agent_user":"_clux","agent_uid":431,"proxy_port":47821,"binary_path":"/x/clux"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := loadConfig(path)
	if err != nil || c.AgentUID != 431 {
		t.Fatalf("loadConfig: %+v %v", c, err)
	}
	if _, err := loadConfig(filepath.Join(t.TempDir(), "missing.json")); !os.IsNotExist(err) {
		t.Fatalf("missing config: %v", err)
	}
}

func TestXcodeApp(t *testing.T) {
	cases := map[string]string{
		"/Applications/Xcode.app/Contents/Developer":      "/Applications/Xcode.app",
		"/Applications/Xcode-beta.app/Contents/Developer": "/Applications/Xcode-beta.app",
		"/Library/Developer/CommandLineTools":             "",
		"":                                                "",
	}
	for in, want := range cases {
		if got := xcodeApp(in); got != want {
			t.Errorf("xcodeApp(%q) = %q, want %q", in, got, want)
		}
	}
}
