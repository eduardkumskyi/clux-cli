package native

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

// ProfileParams are the per-workspace inputs of the Seatbelt profile. All
// paths must be absolute and symlink-resolved (/private/var, not /var):
// Seatbelt matches the resolved path.
type ProfileParams struct {
	WorkspaceDir string // read+write
	AgentHome    string // its Library/ is read+write (Xcode, Simulator, caches)
	RuntimeDir   string // read-only (sidecar bundle, venv, python, claude)
	UserCache    string // confstr(_CS_DARWIN_USER_CACHE_DIR) of the agent, resolved
	UserTemp     string // confstr(_CS_DARWIN_USER_TEMP_DIR) of the agent, resolved
	DeveloperDir string // xcode-select -p (may be empty)
}

func (p ProfileParams) validate() error {
	for name, v := range map[string]string{
		"WorkspaceDir": p.WorkspaceDir, "AgentHome": p.AgentHome, "RuntimeDir": p.RuntimeDir,
		"UserCache": p.UserCache, "UserTemp": p.UserTemp,
	} {
		if !filepath.IsAbs(v) || filepath.Clean(v) != v || v == "/" {
			return fmt.Errorf("sandbox profile: %s must be a clean absolute path, got %q", name, v)
		}
		if strings.ContainsAny(v, "\"\\\n\x00#") {
			return fmt.Errorf("sandbox profile: unsafe %s %q", name, v)
		}
	}
	if p.DeveloperDir != "" && (!filepath.IsAbs(p.DeveloperDir) || strings.ContainsAny(p.DeveloperDir, "\"\\\n\x00#")) {
		return fmt.Errorf("sandbox profile: unsafe DeveloperDir %q", p.DeveloperDir)
	}
	return nil
}

// SandboxProfile renders the workspace's Seatbelt profile. It starts from
// the spike profile that confined xcodebuild + simctl (deny default), with:
// the private HOME/TMP replaced by the workspace dir (HOME and TMPDIR live
// inside it, like the Linux sidecar's /workspace/.home); the agent's
// Library/ shared across workspaces (DerivedData, Simulator devices and
// SDKToSimulatorIndexMapping.plist all key off the account's real home);
// TTYs for the sidecar's terminals; and network limited to loopback.
//
// Network: loopback only. The agent's connections to the egress proxy, to
// its own dev servers (the sidecar proxies previews to 127.0.0.1:<port>)
// and from simulator apps all go to localhost, so this layer can't be
// narrower than localhost:*; pf decides which loopback ports are the
// agent's. mDNSResponder is not reachable, so sandboxed tools can't use
// DNS as a side channel (the proxy resolves names).
func SandboxProfile(p ProfileParams) (string, error) {
	if err := p.validate(); err != nil {
		return "", err
	}
	q := sbString
	lib := filepath.Join(p.AgentHome, "Library")
	var b strings.Builder
	b.WriteString("(version 1)\n(deny default)\n")
	fmt.Fprintf(&b, ";; clux native workspace profile (generated): %s\n", p.WorkspaceDir)
	b.WriteString(`
;; processes
(allow process-fork)
(allow process-exec)
(allow signal (target same-sandbox))
(allow process-info* (target same-sandbox))
(allow sysctl-read)
(allow system-sched (target self))
(allow ipc-posix-shm)
(allow ipc-posix-sem)
(allow pseudo-tty)

;; stat() everywhere so path resolution works; grants no content
(allow file-read-metadata)

;; system, toolchains, runtime: read-only
(allow file-read*
  (literal "/")
  (subpath "/System")
  (subpath "/usr")
  (subpath "/bin")
  (subpath "/sbin")
  (subpath "/Library")
  (subpath "/opt/homebrew")
  (subpath "/private/etc")
  (subpath "/private/var/db/timezone")
  (subpath "/private/var/db/dyld")
  (literal "/private/var/db/xcode_select_link")
  (subpath "/private/var/select")
`)
	fmt.Fprintf(&b, "  (subpath %s)\n", q(p.RuntimeDir))
	if app := xcodeApp(p.DeveloperDir); app != "" {
		fmt.Fprintf(&b, "  (subpath %s)\n", q(app))
	} else {
		b.WriteString("  (subpath \"/Applications/Xcode.app\")\n")
	}
	fmt.Fprintf(&b, "  (literal %s)\n", q(filepath.Join(p.AgentHome, ".CFUserTextEncoding")))
	b.WriteString(`  (literal "/dev/null") (literal "/dev/zero") (literal "/dev/random") (literal "/dev/urandom")
  (literal "/dev/tty") (literal "/dev/dtracehelper"))

;; read+write: the workspace (incl. its HOME and TMPDIR) and the agent's Library
(allow file-read* file-write*
`)
	fmt.Fprintf(&b, "  (subpath %s)\n", q(p.WorkspaceDir))
	fmt.Fprintf(&b, "  (subpath %s)\n", q(lib))
	b.WriteString(`  (literal "/dev/null") (literal "/dev/tty") (literal "/dev/dtracehelper")
  (literal "/dev/ptmx") (regex #"^/dev/ttys[0-9]+$"))
(allow file-ioctl
  (literal "/dev/dtracehelper") (literal "/dev/tty") (literal "/dev/ptmx") (regex #"^/dev/ttys[0-9]+$"))

;; The agent's per-user confstr() temp and cache dirs. Xcode and SwiftPM
;; write there regardless of $TMPDIR (e.g. "unable to make temporary file"
;; when resolving packages). Both belong to the slot's uid alone and the
;; keeper wipes them when the slot changes hands, so they're opened whole.
(allow file-read* file-write*
`)
	fmt.Fprintf(&b, "  (subpath %s)\n", q(p.UserCache))
	fmt.Fprintf(&b, "  (subpath %s)\n", q(p.UserTemp))
	// Also by shape, not only by the dirs resolved at supervisor start: a
	// LaunchDaemon's getconf can miss them (then the explicit rules above
	// name /private/var/empty and every write here failed). Every per-user
	// folder's C/T/0/X is drwx------ for its own uid, so file permissions
	// still keep other slots' and the owner's folders out.
	b.WriteString("  (regex #\"^/private/var/folders/[^/]+/[^/]+/(C|T|0|X)(/|$)\"))\n")

	b.WriteString(`
;; mach services: logging, directory lookups, prefs, TLS trust, and the
;; iOS Simulator (CoreSimulatorService runs outside this sandbox, as the
;; agent user -- see the package doc for why that's acceptable).
(allow mach-lookup
  (global-name "com.apple.logd")
  (global-name "com.apple.diagnosticd")
  (global-name "com.apple.system.opendirectoryd.libinfo")
  (global-name "com.apple.system.opendirectoryd.membership")
  (global-name "com.apple.system.notification_center")
  (global-name "com.apple.cfprefsd.daemon")
  (global-name "com.apple.cfprefsd.agent")
  (global-name "com.apple.trustd")
  (global-name "com.apple.trustd.agent")
  (global-name "com.apple.SecurityServer")
  (global-name "com.apple.ocspd")
  (xpc-service-name "com.apple.CoreSimulator.CoreSimulatorService")
  (xpc-service-name "com.apple.CoreSimulator.SimLaunchHost-arm64")
  (xpc-service-name "com.apple.CoreSimulator.SimLaunchHost-x86")
  (global-name "com.apple.CoreSimulator.CoreSimulatorService")
  (global-name "com.apple.CoreSimulator.simdiskimaged")
  (xpc-service-name "com.apple.MTLCompilerService"))
(allow iokit-open-user-client
  (iokit-user-client-class "IOSurfaceRootUserClient")
  (iokit-user-client-class "AGXDeviceUserClient"))

;; network: listen anywhere (pf keeps the LAN out), connect to loopback only
(allow network-bind (local ip "*:*"))
(allow network-inbound (local ip "*:*"))
(allow network-outbound (remote ip "localhost:*"))
`)
	fmt.Fprintf(&b, "(allow network-outbound (remote unix-socket (subpath %s)))\n", q(p.WorkspaceDir))
	b.WriteString(`
;; no system resolver: pf can't confine DNS sent by mDNSResponder (root) on
;; the agent's behalf, so sandboxed tools must not reach it at all; they
;; resolve nothing themselves (the egress proxy does)
(deny mach-lookup (global-name "com.apple.dnssd.service"))
(deny network-outbound (literal "/private/var/run/mDNSResponder"))
`)

	b.WriteString(`
;; no setuid/setgid bits: a slot's setuid file, run by another slot's code
;; outside Seatbelt, would hand out this slot's uid (the kernel already
;; refuses sandboxed processes to exec setuid/setgid files at all)
(deny file-write-setugid)
`)
	b.WriteString("\n;; no git hooks: a hook planted in a repo would run on the next git command\n")
	fmt.Fprintf(&b, "(deny file-write* (regex #\"^%s/(.*/)?\\.git/hooks(/|$)\"))\n", regexp.QuoteMeta(p.WorkspaceDir))
	return b.String(), nil
}

// xcodeApp maps a developer dir inside an Xcode bundle
// (/Applications/Xcode-16.4.app/Contents/Developer) to the bundle.
func xcodeApp(devDir string) string {
	i := strings.Index(devDir, ".app/")
	if i < 0 {
		if strings.HasSuffix(devDir, ".app") {
			return devDir
		}
		return ""
	}
	return devDir[:i+4]
}
