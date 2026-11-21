package service

import (
	"encoding/xml"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// target is the service in the user's GUI login domain.
func (m *Manager) target() string { return fmt.Sprintf("gui/%d/%s", m.UID, Label) }

// Plist is the LaunchAgent: started at login (RunAtLoad), restarted when it
// exits with an error (KeepAlive.SuccessfulExit=false), but not after a
// clean exit (SIGTERM from bootout/logout) -- and not faster than every 10 s.
func (m *Manager) Plist() string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
`)
	kv := func(k, v string) { fmt.Fprintf(&b, "  <key>%s</key><string>%s</string>\n", k, xmlEscape(v)) }
	kv("Label", Label)
	b.WriteString("  <key>ProgramArguments</key>\n  <array>\n")
	for _, a := range m.Args() {
		fmt.Fprintf(&b, "    <string>%s</string>\n", xmlEscape(a))
	}
	b.WriteString("  </array>\n")
	b.WriteString("  <key>EnvironmentVariables</key>\n  <dict>\n")
	fmt.Fprintf(&b, "    <key>%s</key><string>1</string>\n", EnvService)
	if m.Path != "" {
		// launchd's default PATH has no /usr/local/bin or /opt/homebrew/bin,
		// where docker lives.
		fmt.Fprintf(&b, "    <key>PATH</key><string>%s</string>\n", xmlEscape(m.Path))
	}
	b.WriteString("  </dict>\n")
	kv("WorkingDirectory", m.Home)
	kv("StandardOutPath", m.LogPath())
	kv("StandardErrorPath", m.LogPath())
	b.WriteString("  <key>RunAtLoad</key><true/>\n")
	b.WriteString("  <key>KeepAlive</key>\n  <dict>\n    <key>SuccessfulExit</key><false/>\n  </dict>\n")
	b.WriteString("  <key>ThrottleInterval</key><integer>10</integer>\n")
	b.WriteString("</dict>\n</plist>\n")
	return b.String()
}

func (m *Manager) launchdLoad() error {
	// Replace a loaded older definition; enable clears a "disabled" flag
	// launchd may remember for the label.
	if st, _ := m.Status(); st.Loaded {
		if err := m.run("launchctl", "bootout", m.target()); err != nil {
			return err
		}
	}
	_, _ = m.Run("launchctl", "enable", m.target())
	domain := fmt.Sprintf("gui/%d", m.UID)
	var err error
	// bootout returns before the old job is fully gone; bootstrap then fails
	// with "Input/output error" for a moment.
	for i := 0; i < 5; i++ {
		if err = m.run("launchctl", "bootstrap", domain, m.File()); err == nil {
			return nil
		}
		m.pause(500 * time.Millisecond)
	}
	return err
}

func (m *Manager) launchdUnload() error {
	if st, _ := m.Status(); !st.Loaded {
		return nil
	}
	return m.run("launchctl", "bootout", m.target())
}

func (m *Manager) pause(d time.Duration) {
	if m.Sleep != nil {
		m.Sleep(d)
		return
	}
	time.Sleep(d)
}

// parseLaunchctlPrint reads `launchctl print gui/<uid>/<label>`.
func parseLaunchctlPrint(out string) (running bool, pid int) {
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), " = ")
		if !ok {
			continue
		}
		switch k {
		case "state":
			running = v == "running"
		case "pid":
			if n, err := strconv.Atoi(v); err == nil && pid == 0 {
				pid = n
			}
		}
	}
	return running, pid
}

func xmlEscape(s string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}
