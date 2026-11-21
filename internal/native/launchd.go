package native

import (
	"encoding/xml"
	"fmt"
	"strings"
)

// PFDaemonPlist is the root LaunchDaemon that, at every boot, recreates
// RunDir, loads the anchor, enables pf (keeping its reference token) and
// then keeps the agent-listener rules current.
func PFDaemonPlist(binary string) string {
	return plist(PFLabel, "", []string{binary, "native", "pfd"}, nil, "", LogDir+"/pf.log")
}

// SupervisorPlist runs `clux native supervise --slot n` as slot n's user.
// It has to be a LaunchDaemon with UserName (launchctl managername =
// System): started from the owner's GUI session (e.g. via sudo -u) the
// agent would keep the owner's Aqua bootstrap -- Finder Apple Events, the
// pasteboard and `open -a` all worked from there in the spike. launchd
// initializes the supplementary groups (_cluxslots: read access to the
// runtime).
func SupervisorPlist(binary string, n int) string {
	return plist(SupervisorLabel(n), SlotUser(n), []string{binary, "native", "supervise", "--slot", fmt.Sprint(n)},
		map[string]string{"HOME": SlotHome(n)}, SlotHome(n), SupervisorLog(n))
}

func plist(label, user string, args []string, env map[string]string, wd, logPath string) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
`)
	kv := func(k, v string) { fmt.Fprintf(&b, "  <key>%s</key><string>%s</string>\n", k, xmlEscape(v)) }
	kv("Label", label)
	if user != "" {
		kv("UserName", user)
		kv("GroupName", user)
		b.WriteString("  <key>InitGroups</key><true/>\n")
	}
	b.WriteString("  <key>ProgramArguments</key>\n  <array>\n")
	for _, a := range args {
		fmt.Fprintf(&b, "    <string>%s</string>\n", xmlEscape(a))
	}
	b.WriteString("  </array>\n")
	if len(env) > 0 {
		b.WriteString("  <key>EnvironmentVariables</key>\n  <dict>\n")
		for k, v := range env {
			fmt.Fprintf(&b, "    <key>%s</key><string>%s</string>\n", xmlEscape(k), xmlEscape(v))
		}
		b.WriteString("  </dict>\n")
	}
	if wd != "" {
		kv("WorkingDirectory", wd)
	}
	kv("StandardOutPath", logPath)
	kv("StandardErrorPath", logPath)
	b.WriteString("  <key>Umask</key><integer>63</integer>\n") // 077
	b.WriteString("  <key>RunAtLoad</key><true/>\n")
	b.WriteString("  <key>KeepAlive</key><true/>\n")
	b.WriteString("  <key>ThrottleInterval</key><integer>5</integer>\n")
	b.WriteString("</dict>\n</plist>\n")
	return b.String()
}

func xmlEscape(s string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}
