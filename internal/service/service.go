// Package service runs `clux host start` in the background as a per-user
// service, so the computer stays online without a terminal: a launchd
// LaunchAgent in the user's gui/<uid> domain on macOS, a systemd --user unit
// on Linux. Both start at login and restart the agent if it dies. Windows is
// not supported yet.
//
// No root: this is the owner's own agent, separate from the native macOS
// runtime's root LaunchDaemons (internal/native), which it never touches.
//
// All launchctl/systemctl calls go through Runner, so tests check the exact
// command sequence and file contents without touching the real system.
package service

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	// Label is the launchd label (and plist file name) on macOS.
	Label = "space.clux.host"
	// Unit is the systemd --user unit name on Linux.
	Unit = "clux-host.service"
	// EnvService is set in the service's environment so `host start` knows
	// it runs unattended under a supervisor.
	EnvService = "CLUX_SERVICE"
)

// ErrUnsupported: no background service on this OS yet.
var ErrUnsupported = errors.New("running in the background is not supported on this OS yet")

// Runner runs one command and returns its combined output.
type Runner func(name string, args ...string) ([]byte, error)

// ExecRunner is the real Runner.
func ExecRunner(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).CombinedOutput()
}

// Manager installs, inspects and removes the service for one user.
type Manager struct {
	GOOS       string
	Home       string // the user's home directory
	UID        int    // for launchd's gui/<uid> domain
	Exe        string // absolute, symlink-free path of the clux binary
	StateDir   string // ~/.clux (logs live in StateDir/logs)
	Path       string // PATH for the service (docker etc. live outside launchd's default)
	ConfigHome string // $XDG_CONFIG_HOME, "" = Home/.config
	Run        Runner
	Sleep      func(time.Duration) // nil = time.Sleep; tests skip the waits
}

// New is the Manager for the current user and binary.
func New(goos, stateDir string) (*Manager, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	exe, err := Executable()
	if err != nil {
		return nil, err
	}
	return &Manager{
		GOOS:       goos,
		Home:       home,
		UID:        os.Getuid(),
		Exe:        exe,
		StateDir:   stateDir,
		Path:       os.Getenv("PATH"),
		ConfigHome: os.Getenv("XDG_CONFIG_HOME"),
		Run:        ExecRunner,
	}, nil
}

// Executable is the running binary's absolute path with symlinks resolved
// (a Homebrew-style symlink may later point at another version; the
// service should run what the user ran).
func Executable() (string, error) {
	self, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("locating the clux binary: %w", err)
	}
	if p, err := filepath.EvalSymlinks(self); err == nil {
		self = p
	}
	return filepath.Abs(self)
}

// TemporaryBinary reports whether exe looks like it will disappear (a
// `go run` build, a download in the temp dir): a service pointing at it
// breaks as soon as it is cleaned up.
func TemporaryBinary(exe string, tempDirs ...string) bool {
	clean := filepath.ToSlash(filepath.Clean(exe))
	if strings.Contains(clean, "/go-build") || strings.Contains(clean, "/go/pkg/mod/") {
		return true
	}
	for _, d := range tempDirs {
		if d == "" {
			continue
		}
		d = filepath.ToSlash(filepath.Clean(d))
		if real, err := filepath.EvalSymlinks(d); err == nil {
			if strings.HasPrefix(clean, filepath.ToSlash(real)+"/") {
				return true
			}
		}
		if strings.HasPrefix(clean, d+"/") {
			return true
		}
	}
	return false
}

// Args is what the service runs: always foreground, never prompting.
func (m *Manager) Args() []string {
	return []string{m.Exe, "host", "start", "--foreground", "--no-native-prompt"}
}

// LogPath is where the service's own stdout/stderr go (crashes, panics);
// the agent itself still writes StateDir/logs/host.log.
func (m *Manager) LogPath() string { return filepath.Join(m.StateDir, "logs", "service.log") }

// Supported reports whether this OS has a background service.
func (m *Manager) Supported() bool { return m.GOOS == "darwin" || m.GOOS == "linux" }

// Description names the service for messages.
func (m *Manager) Description() string {
	switch m.GOOS {
	case "darwin":
		return "launchd agent " + Label
	case "linux":
		return "systemd user unit " + Unit
	}
	return "background service"
}

// File is the service definition's path.
func (m *Manager) File() string {
	switch m.GOOS {
	case "darwin":
		return filepath.Join(m.Home, "Library", "LaunchAgents", Label+".plist")
	case "linux":
		ch := m.ConfigHome
		if ch == "" {
			ch = filepath.Join(m.Home, ".config")
		}
		return filepath.Join(ch, "systemd", "user", Unit)
	}
	return ""
}

// Status is what the service manager says about the service.
type Status struct {
	Installed bool // the definition file exists
	Loaded    bool // launchd/systemd knows it (enabled)
	Running   bool
	PID       int
}

// Install writes the definition and (re)starts the service. Re-installing
// is fine: it replaces the old definition (e.g. a new binary path) and
// restarts.
func (m *Manager) Install() error {
	if !m.Supported() {
		return ErrUnsupported
	}
	if err := os.MkdirAll(filepath.Dir(m.LogPath()), 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(m.File()), 0o755); err != nil {
		return err
	}
	var content string
	if m.GOOS == "darwin" {
		content = m.Plist()
	} else {
		content = m.SystemdUnit()
	}
	if err := writeFileAtomic(m.File(), []byte(content), 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", m.File(), err)
	}
	if m.GOOS == "darwin" {
		return m.launchdLoad()
	}
	return m.systemdEnable()
}

// Uninstall stops the service and removes its definition, so it does not
// come back at the next login. Not installed is not an error.
func (m *Manager) Uninstall() error {
	if !m.Supported() {
		return ErrUnsupported
	}
	var stopErr error
	if m.GOOS == "darwin" {
		stopErr = m.launchdUnload()
	} else {
		stopErr = m.systemdDisable()
	}
	if err := os.Remove(m.File()); err != nil && !os.IsNotExist(err) {
		return err
	}
	if m.GOOS == "linux" {
		_, _ = m.Run("systemctl", "--user", "daemon-reload")
	}
	return stopErr
}

// Restart restarts a running service (after a new login, so it picks up
// the new token).
func (m *Manager) Restart() error {
	switch m.GOOS {
	case "darwin":
		return m.run("launchctl", "kickstart", "-k", m.target())
	case "linux":
		return m.run("systemctl", "--user", "restart", Unit)
	}
	return ErrUnsupported
}

// Status inspects the service.
func (m *Manager) Status() (Status, error) {
	if !m.Supported() {
		return Status{}, ErrUnsupported
	}
	var st Status
	if _, err := os.Stat(m.File()); err == nil {
		st.Installed = true
	}
	if m.GOOS == "darwin" {
		out, err := m.Run("launchctl", "print", m.target())
		if err != nil {
			return st, nil // not loaded
		}
		st.Loaded = true
		st.Running, st.PID = parseLaunchctlPrint(string(out))
		return st, nil
	}
	if out, err := m.Run("systemctl", "--user", "is-enabled", Unit); err == nil && strings.TrimSpace(string(out)) == "enabled" {
		st.Loaded = true
	}
	if out, err := m.Run("systemctl", "--user", "is-active", Unit); err == nil && strings.TrimSpace(string(out)) == "active" {
		st.Running = true
		if out, err := m.Run("systemctl", "--user", "show", "--property=MainPID", "--value", Unit); err == nil {
			fmt.Sscanf(strings.TrimSpace(string(out)), "%d", &st.PID)
		}
	}
	return st, nil
}

func (m *Manager) run(name string, args ...string) error {
	out, err := m.Run(name, args...)
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg != "" {
			return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, msg)
		}
		return fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return nil
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
