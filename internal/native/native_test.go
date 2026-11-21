package native

import (
	"encoding/binary"
	"encoding/json"
	"encoding/xml"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPFRulesBaseShape(t *testing.T) {
	r := PFRules([]int{432, 431}, 47821, nil)
	want := []string{
		"pass out quick on lo0 inet proto tcp from any to 127.0.0.1 port 47821 user 431 flags S/SA keep state",
		"pass out quick on lo0 inet6 proto tcp from any to ::1 port 47821 user 431 flags S/SA keep state",
		"pass out quick on lo0 inet proto tcp from any to 127.0.0.1 port 47821 user 432 flags S/SA keep state",
		"pass in quick on lo0 proto tcp from any to any user { 431, 432 } flags S/SA keep state",
		"block return out quick inet proto { tcp udp } from any to any user { 431, 432 }",
		"block return out quick inet6 proto { tcp udp } from any to any user { 431, 432 }",
		"block drop out quick inet proto icmp from any to any user { 431, 432 }",
		"block drop out quick inet6 proto icmp6 from any to any user { 431, 432 }",
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
	r := PFRules([]int{agent}, 47821, ls)
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
	if r != PFRules([]int{agent}, 47821, append([]Listener{ls[2], ls[0]}, ls[1:]...)) {
		t.Error("output depends on listener order")
	}
}

// One slot must never get a pass rule for another slot's listener.
func TestPFRulesSlotsAreSeparated(t *testing.T) {
	const a, b = 431, 432
	ls := []Listener{
		{IPv4: true, Port: 3000, UID: a},
		{IPv4: true, Port: 4000, UID: b},
		{IPv4: true, Port: 5000, UID: a}, {IPv4: true, Port: 5000, UID: b}, // shared port: nobody's
	}
	r := PFRules([]int{a, b}, 47821, ls)
	for _, c := range []struct {
		port string
		uid  string
		want bool
	}{{"3000", "431", true}, {"3000", "432", false}, {"4000", "432", true}, {"4000", "431", false}, {"5000", "431", false}, {"5000", "432", false}} {
		got := strings.Contains(r, "to 127.0.0.1 port "+c.port+" user "+c.uid+" ")
		if got != c.want {
			t.Errorf("port %s uid %s: pass=%v, want %v\n%s", c.port, c.uid, got, c.want, r)
		}
	}
	if r != PFRules([]int{b, a}, 47821, ls) {
		t.Error("output depends on uid order")
	}
}

func TestPFRulesCapsListenerRules(t *testing.T) {
	var ls []Listener
	for p := 10000; p < 11000; p++ {
		ls = append(ls, Listener{IPv4: true, Port: p, UID: 431})
	}
	if n := strings.Count(PFRules([]int{431}, 47821, ls), "\npass out "); n > maxListenerRules+2 {
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
		WorkspaceDir: "/private/var/clux/slots/2/workspaces/12",
		AgentHome:    "/private/var/clux/slots/2",
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
		`(subpath "/private/var/clux/slots/2/workspaces/12")`,
		`(subpath "/private/var/clux/slots/2/Library")`,
		`(subpath "/private/var/clux-runtime")`,
		`(subpath "/Applications/Xcode-16.4.app")`,
		`(allow network-outbound (remote ip "localhost:*"))`,
		`com.apple.CoreSimulator.CoreSimulatorService`,
		`(deny file-write* (regex #"^/private/var/clux/slots/2/workspaces/12/(.*/)?\.git/hooks(/|$)"))`,
		`(deny mach-lookup (global-name "com.apple.dnssd.service"))`,
		`(deny network-outbound (literal "/private/var/run/mDNSResponder"))`,
	} {
		if !strings.Contains(p, want) {
			t.Errorf("profile lacks %s", want)
		}
	}
	// Other workspaces and the owner's homes are never named; the resolver
	// only ever appears in deny rules.
	for _, bad := range []string{`(subpath "/private/var/clux/slots/2/workspaces")`, `(subpath "/private/var/clux/slots")`, `"/Users`, `"com.apple.bsd.dirhelper"`} {
		if strings.Contains(p, bad) {
			t.Errorf("profile must not contain %s", bad)
		}
	}
	for _, line := range strings.Split(p, "\n") {
		if strings.HasPrefix(line, "(allow") && (strings.Contains(line, "dnssd") || strings.Contains(line, "mDNSResponder")) {
			t.Errorf("resolver allowed: %s", line)
		}
	}
	// The hooks deny must come after the workspace allow (last match wins).
	if strings.Index(p, ".git/hooks") < strings.Index(p, `(subpath "/private/var/clux/slots/2/workspaces/12")`) {
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
		"supervisor": SupervisorPlist("/Library/Application Support/clux-native/clux", 3),
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
	s := SupervisorPlist("/x/clux", 3)
	for _, want := range []string{
		"<key>Label</key><string>space.clux.native.supervisor.3</string>",
		"<key>UserName</key><string>_clux3</string>", "<key>GroupName</key><string>_clux3</string>",
		"<string>supervise</string>", "<string>--slot</string>\n    <string>3</string>",
		"<key>HOME</key><string>/private/var/clux/slots/3</string>",
		"<string>/private/var/log/clux-native/supervisor-3.log</string>", "<key>KeepAlive</key><true/>",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("supervisor plist lacks %s", want)
		}
	}
	if strings.Contains(PFDaemonPlist("/x/clux"), "UserName") {
		t.Error("pf daemon must run as root")
	}
}

func TestConfigValidate(t *testing.T) {
	slots := func() []Slot {
		return []Slot{{1, "_clux1", 431, 431}, {2, "_clux2", 433, 433}}
	}
	good := Config{Version: 2, OwnerUID: 501, Slots: slots(), SlotsGID: 435, CtlGID: 432,
		ProxyPort: 47821, BinaryPath: "/usr/local/libexec/clux-native/clux"}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(*Config){
		"slot uid = owner":   func(c *Config) { c.OwnerUID = 431 },
		"slot uid 0":         func(c *Config) { c.Slots[0].UID = 0 },
		"slot uid in staff":  func(c *Config) { c.Slots[1].UID = 501 },
		"duplicate uid":      func(c *Config) { c.Slots[1].UID = 431 },
		"duplicate gid":      func(c *Config) { c.Slots[1].GID = 431 },
		"gid = ctl":          func(c *Config) { c.Slots[0].GID = 432 },
		"wrong user name":    func(c *Config) { c.Slots[0].User = "root" },
		"slots out of order": func(c *Config) { c.Slots[0], c.Slots[1] = c.Slots[1], c.Slots[0] },
		"no slots":           func(c *Config) { c.Slots = nil },
		"low port":           func(c *Config) { c.ProxyPort = 80 },
		"relative binary":    func(c *Config) { c.BinaryPath = "clux" },
		"old version":        func(c *Config) { c.Version = 1 },
		"slots gid = ctl":    func(c *Config) { c.SlotsGID = 432 },
	} {
		c := good
		c.Slots = slots()
		mut(&c)
		if c.Validate() == nil {
			t.Errorf("%s: accepted %+v", name, c)
		}
	}
	if s, ok := good.Slot(2); !ok || s.UID != 433 {
		t.Fatalf("Slot(2) = %+v %v", s, ok)
	}
	if _, ok := good.Slot(3); ok {
		t.Fatal("Slot(3) exists")
	}
	path := filepath.Join(t.TempDir(), "native.json")
	b, _ := json.Marshal(good)
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := loadConfig(path)
	if err != nil || len(c.Slots) != 2 || c.Slots[1].User != "_clux2" {
		t.Fatalf("loadConfig: %+v %v", c, err)
	}
	legacy := filepath.Join(t.TempDir(), "legacy.json")
	os.WriteFile(legacy, []byte(`{"version":1,"owner_uid":501,"agent_user":"_clux","agent_uid":431,"proxy_port":47821,"binary_path":"/x/clux"}`), 0o644)
	if _, err := loadConfig(legacy); err == nil || !strings.Contains(err.Error(), "re-run `sudo clux native install`") {
		t.Fatalf("legacy config: %v", err)
	}
	if p := readPrevConfig(legacy); p.Version != 1 || p.ProxyPort != 47821 {
		t.Fatalf("legacy proxy port not kept: %+v", p)
	}
	if _, err := loadConfig(filepath.Join(t.TempDir(), "missing.json")); !os.IsNotExist(err) {
		t.Fatalf("missing config: %v", err)
	}
}

func TestSlotPaths(t *testing.T) {
	if SlotUser(3) != "_clux3" || SlotHome(3) != "/private/var/clux/slots/3" ||
		SlotSocket(3) != "/private/var/run/clux-native/slots/3/supervisor.sock" ||
		SupervisorLabel(3) != "space.clux.native.supervisor.3" {
		t.Fatal("slot paths changed: pf rules, plists and profiles depend on them")
	}
}

func TestParseDSListAndOverride(t *testing.T) {
	if got := parseDSList("GroupMembership: alice _clux1\n"); len(got) != 2 || got[1] != "_clux1" {
		t.Fatalf("parseDSList: %v", got)
	}
	if parseDSList("") != nil {
		t.Fatal("empty")
	}
	out := "disabled services = {\n\t\"space.clux.native.pf\" => enabled\n\t\"space.clux.native.supervisor.1\" => disabled\n}\n"
	if launchdOverride(out, "space.clux.native.pf") != "enabled" || launchdOverride(out, "space.clux.native.supervisor.1") != "disabled" ||
		launchdOverride(out, "space.clux.native.supervisor.2") != "" {
		t.Fatal("launchdOverride")
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
