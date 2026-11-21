package service

import (
	"encoding/xml"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// fakeRunner records commands and answers from a table keyed by the
// command line ("launchctl print gui/501/space.clux.host").
type fakeRunner struct {
	calls   []string
	answers map[string]fakeAnswer
}

type fakeAnswer struct {
	out string
	err error
}

func (f *fakeRunner) run(name string, args ...string) ([]byte, error) {
	line := strings.Join(append([]string{name}, args...), " ")
	f.calls = append(f.calls, line)
	if a, ok := f.answers[line]; ok {
		return []byte(a.out), a.err
	}
	return nil, nil
}

func newManager(t *testing.T, goos string) (*Manager, *fakeRunner) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("service definitions use POSIX paths; no service on Windows")
	}
	home := t.TempDir()
	f := &fakeRunner{answers: map[string]fakeAnswer{}}
	return &Manager{
		GOOS:     goos,
		Home:     home,
		UID:      501,
		Exe:      "/usr/local/bin/clux",
		StateDir: filepath.Join(home, ".clux"),
		Path:     "/opt/homebrew/bin:/usr/bin:/bin",
		Run:      f.run,
		Sleep:    func(time.Duration) {},
	}, f
}

var notLoaded = fakeAnswer{out: "Could not find service", err: errors.New("exit status 113")}

func TestPlistContent(t *testing.T) {
	m, _ := newManager(t, "darwin")
	p := m.Plist()
	if err := xml.Unmarshal([]byte(p), new(struct{})); err != nil {
		t.Fatalf("plist is not well-formed XML: %v", err)
	}
	for _, want := range []string{
		"<key>Label</key><string>space.clux.host</string>",
		"<string>/usr/local/bin/clux</string>\n    <string>host</string>\n    <string>start</string>\n    <string>--foreground</string>\n    <string>--no-native-prompt</string>",
		"<key>CLUX_SERVICE</key><string>1</string>",
		"<key>PATH</key><string>/opt/homebrew/bin:/usr/bin:/bin</string>",
		"<key>RunAtLoad</key><true/>",
		"<key>KeepAlive</key>\n  <dict>\n    <key>SuccessfulExit</key><false/>",
		"<key>ThrottleInterval</key><integer>10</integer>",
		"<key>StandardOutPath</key><string>" + filepath.Join(m.Home, ".clux", "logs", "service.log") + "</string>",
		"<key>StandardErrorPath</key>",
	} {
		if !strings.Contains(p, want) {
			t.Errorf("plist lacks %q:\n%s", want, p)
		}
	}
	if strings.Contains(p, "UserName") {
		t.Error("a per-user agent must not set UserName")
	}
}

func TestPlistEscapes(t *testing.T) {
	m, _ := newManager(t, "darwin")
	m.Exe = "/Users/a&b/<bin>/clux"
	if !strings.Contains(m.Plist(), "/Users/a&amp;b/&lt;bin&gt;/clux") {
		t.Fatal("binary path must be XML-escaped")
	}
}

func TestLaunchdInstallFreshAndReinstall(t *testing.T) {
	m, f := newManager(t, "darwin")
	f.answers["launchctl print gui/501/space.clux.host"] = notLoaded
	if err := m.Install(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(m.Home, "Library", "LaunchAgents", "space.clux.host.plist"))
	if err != nil || string(b) != m.Plist() {
		t.Fatalf("plist not written: %v", err)
	}
	if _, err := os.Stat(filepath.Join(m.Home, ".clux", "logs")); err != nil {
		t.Fatal("log dir must exist before launchd opens StandardOutPath")
	}
	want := []string{
		"launchctl print gui/501/space.clux.host",
		"launchctl enable gui/501/space.clux.host",
		"launchctl bootstrap gui/501 " + m.File(),
	}
	if strings.Join(f.calls, "\n") != strings.Join(want, "\n") {
		t.Fatalf("calls:\n%s\nwant:\n%s", strings.Join(f.calls, "\n"), strings.Join(want, "\n"))
	}

	// Loaded already: bootout first, bootstrap retried while launchd lags.
	f.calls = nil
	f.answers["launchctl print gui/501/space.clux.host"] = fakeAnswer{out: "state = running\npid = 77\n"}
	boot := "launchctl bootstrap gui/501 " + m.File()
	f.answers[boot] = fakeAnswer{out: "Bootstrap failed: 5: Input/output error", err: errors.New("exit status 5")}
	err = m.Install()
	if err == nil || !strings.Contains(err.Error(), "Input/output error") {
		t.Fatalf("err = %v", err)
	}
	if f.calls[1] != "launchctl bootout gui/501/space.clux.host" {
		t.Fatalf("calls = %v", f.calls)
	}
	n := 0
	for _, c := range f.calls {
		if c == boot {
			n++
		}
	}
	if n != 5 {
		t.Fatalf("bootstrap tried %d times, want 5", n)
	}
}

func TestLaunchdUninstall(t *testing.T) {
	m, f := newManager(t, "darwin")
	f.answers["launchctl print gui/501/space.clux.host"] = fakeAnswer{out: "state = running\npid = 77\n"}
	if err := m.Install(); err != nil {
		t.Fatal(err)
	}
	f.calls = nil
	if err := m.Uninstall(); err != nil {
		t.Fatal(err)
	}
	if f.calls[len(f.calls)-1] != "launchctl bootout gui/501/space.clux.host" {
		t.Fatalf("calls = %v", f.calls)
	}
	if _, err := os.Stat(m.File()); !os.IsNotExist(err) {
		t.Fatal("plist must be removed so it does not load at the next login")
	}

	// Nothing loaded, nothing installed: no bootout, no error.
	f.calls = nil
	f.answers["launchctl print gui/501/space.clux.host"] = notLoaded
	if err := m.Uninstall(); err != nil {
		t.Fatal(err)
	}
	for _, c := range f.calls {
		if strings.Contains(c, "bootout") {
			t.Fatalf("bootout of an unloaded service: %v", f.calls)
		}
	}
}

func TestLaunchdStatus(t *testing.T) {
	m, f := newManager(t, "darwin")
	f.answers["launchctl print gui/501/space.clux.host"] = fakeAnswer{out: "gui/501/space.clux.host = {\n\tactive count = 1\n\tstate = running\n\n\tprogram = /usr/local/bin/clux\n\tpid = 4242\n}\n"}
	st, err := m.Status()
	if err != nil || !st.Loaded || !st.Running || st.PID != 4242 || st.Installed {
		t.Fatalf("status = %+v, %v", st, err)
	}
	f.answers["launchctl print gui/501/space.clux.host"] = fakeAnswer{out: "\tstate = not running\n"}
	if st, _ := m.Status(); st.Running || !st.Loaded {
		t.Fatalf("status = %+v", st)
	}
	f.answers["launchctl print gui/501/space.clux.host"] = notLoaded
	if st, _ := m.Status(); st.Loaded || st.Running {
		t.Fatalf("status = %+v", st)
	}
}

func TestSystemdUnitContent(t *testing.T) {
	m, _ := newManager(t, "linux")
	u := m.SystemdUnit()
	for _, want := range []string{
		`ExecStart="/usr/local/bin/clux" "host" "start" "--foreground" "--no-native-prompt"`,
		`Environment="CLUX_SERVICE=1"`,
		`Environment="PATH=/opt/homebrew/bin:/usr/bin:/bin"`,
		"Restart=on-failure\n",
		"RestartSec=10\n",
		"StandardOutput=append:" + m.LogPath(),
		"WantedBy=default.target\n",
	} {
		if !strings.Contains(u, want) {
			t.Errorf("unit lacks %q:\n%s", want, u)
		}
	}
	if m.File() != filepath.Join(m.Home, ".config", "systemd", "user", "clux-host.service") {
		t.Fatal(m.File())
	}
	m.ConfigHome = "/xdg"
	if m.File() != "/xdg/systemd/user/clux-host.service" {
		t.Fatal(m.File())
	}
}

func TestSystemdQuote(t *testing.T) {
	if got := systemdQuote(`/a b/"x"/50%/$HOME\`); got != `"/a b/\"x\"/50%%/$$HOME\\"` {
		t.Fatal(got)
	}
}

func TestSystemdInstallUninstall(t *testing.T) {
	m, f := newManager(t, "linux")
	if err := m.Install(); err != nil {
		t.Fatal(err)
	}
	want := "systemctl --user daemon-reload\nsystemctl --user enable clux-host.service\nsystemctl --user restart clux-host.service"
	if strings.Join(f.calls, "\n") != want {
		t.Fatalf("calls:\n%s", strings.Join(f.calls, "\n"))
	}
	f.calls = nil
	f.answers["systemctl --user is-enabled clux-host.service"] = fakeAnswer{out: "enabled\n"}
	f.answers["systemctl --user is-active clux-host.service"] = fakeAnswer{out: "active\n"}
	f.answers["systemctl --user show --property=MainPID --value clux-host.service"] = fakeAnswer{out: "999\n"}
	st, _ := m.Status()
	if !st.Installed || !st.Loaded || !st.Running || st.PID != 999 {
		t.Fatalf("status = %+v", st)
	}
	f.calls = nil
	if err := m.Uninstall(); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(f.calls, "\n")
	if !strings.Contains(joined, "systemctl --user disable --now clux-host.service") || !strings.HasSuffix(joined, "systemctl --user daemon-reload") {
		t.Fatalf("calls:\n%s", joined)
	}
	if _, err := os.Stat(m.File()); !os.IsNotExist(err) {
		t.Fatal("unit file must be removed")
	}
}

func TestUnsupported(t *testing.T) {
	m := &Manager{GOOS: "windows"}
	if m.Supported() || !errors.Is(m.Install(), ErrUnsupported) {
		t.Fatal("windows has no service yet")
	}
}

func TestTemporaryBinary(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX paths")
	}
	cases := map[string]bool{
		"/usr/local/bin/clux":                              false,
		"/Users/me/Library/Caches/go-build/ab/cd/exe/clux": true,
		"/var/folders/xy/T/go-build123/b001/exe/clux":      true,
		"/tmp/clux":     true,
		"/tmp-not/clux": false,
		"/Users/me/go/pkg/mod/github.com/x/clux@v1/clux": true,
	}
	for p, want := range cases {
		if got := TemporaryBinary(p, "/tmp"); got != want {
			t.Errorf("TemporaryBinary(%q) = %v, want %v", p, got, want)
		}
	}
}
