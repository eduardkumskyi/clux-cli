package service

import (
	"fmt"
	"strings"
)

// SystemdUnit is the systemd --user unit: started with the user's session
// (default.target), restarted after an error exit but not after a clean
// stop, at most every 10 s.
func (m *Manager) SystemdUnit() string {
	quoted := make([]string, 0, len(m.Args()))
	for _, a := range m.Args() {
		quoted = append(quoted, systemdQuote(a))
	}
	var b strings.Builder
	b.WriteString("[Unit]\n")
	b.WriteString("Description=Clux host agent (keeps this computer online for Clux workspaces)\n")
	b.WriteString("Wants=network-online.target\n")
	b.WriteString("After=network-online.target\n\n")
	b.WriteString("[Service]\n")
	b.WriteString("Type=simple\n")
	fmt.Fprintf(&b, "ExecStart=%s\n", strings.Join(quoted, " "))
	fmt.Fprintf(&b, "Environment=%s\n", systemdQuote(EnvService+"=1"))
	if m.Path != "" {
		fmt.Fprintf(&b, "Environment=%s\n", systemdQuote("PATH="+m.Path))
	}
	fmt.Fprintf(&b, "WorkingDirectory=%s\n", systemdQuote(m.Home))
	b.WriteString("Restart=on-failure\n")
	b.WriteString("RestartSec=10\n")
	fmt.Fprintf(&b, "StandardOutput=append:%s\n", systemdEscapePath(m.LogPath()))
	fmt.Fprintf(&b, "StandardError=append:%s\n\n", systemdEscapePath(m.LogPath()))
	b.WriteString("[Install]\n")
	b.WriteString("WantedBy=default.target\n")
	return b.String()
}

func (m *Manager) systemdEnable() error {
	if err := m.run("systemctl", "--user", "daemon-reload"); err != nil {
		return err
	}
	if err := m.run("systemctl", "--user", "enable", Unit); err != nil {
		return err
	}
	// restart, not start: a re-install must pick up the new definition.
	return m.run("systemctl", "--user", "restart", Unit)
}

func (m *Manager) systemdDisable() error {
	if st, _ := m.Status(); !st.Loaded && !st.Running {
		return nil
	}
	return m.run("systemctl", "--user", "disable", "--now", Unit)
}

// systemdQuote double-quotes one word for ExecStart=/Environment=,
// escaping what systemd would otherwise interpret (quotes, backslashes,
// % specifiers, $ variables).
func systemdQuote(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "%", "%%", "$", "$$", "\n", `\n`)
	return `"` + r.Replace(s) + `"`
}

// systemdEscapePath escapes % specifiers in an unquoted path setting.
func systemdEscapePath(s string) string { return strings.ReplaceAll(s, "%", "%%") }
