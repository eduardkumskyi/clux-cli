# Security Policy

## Scope

In scope: the `clux-cli` binary itself, and its interaction with:

- the local Docker daemon (container/volume/network lifecycle in
  `internal/dockerhost`)
- the configured backend (the tunnel protocol in `internal/tunnel`, and
  anything reachable via `--backend-url`)

The trust boundary is intentional and by design: once a host runs
`clux login` against a backend URL, that backend can send it
workspace.start/stop/delete commands and have them executed against the
local Docker daemon. That IS the feature — a user who configures their
machine against a backend is choosing to trust that backend to run
container lifecycle commands on their behalf. We still want to hear about:

- a backend being able to do *more* than that (e.g. escape the sandbox
  network, run arbitrary non-Docker commands, read/write files outside
  what Docker itself allows, escalate privileges on the host)
- any way a third party (not the configured backend) can get `clux-cli` to
  execute commands or exfiltrate the stored token
- credential handling bugs (the PAT in `~/.clux/config.json` is stored in
  plaintext at 0600 — report ways that protection can be bypassed)
- tunnel protocol issues that let a man-in-the-middle tamper with frames

Out of scope: the inherent trust the user places in whatever backend they
configured with `--backend-url`. Pointing out "the backend can tell the
host to run containers" is the documented design, not a vulnerability.

## Native macOS runtime

`sudo clux native install` (opt-in, macOS) adds two LaunchDaemons: a root
one (`clux native pfd`: pf anchor `com.apple/clux` + its pf enable token)
and one running as the hidden user `_clux` (`clux native supervise`), plus
a unix socket only the installing owner may use (0660 `_clux:_cluxctl` and a
peer-uid check). Both run a root-owned copy of the binary in a directory
whose whole parent chain is root-owned and not group/world-writable.
Workspaces run as `_clux`; their network is forced through the egress
proxy in `clux host start`.

What we state to users (and treat as the security boundary):

**Enforced by macOS (supported mechanisms):** the agent runs as a separate
hidden user with no access to your home, files, Keychain, clipboard, apps or
desktop; network leaves only through the clux proxy you control. **Extra
layer:** Seatbelt sandbox (reported live). **Not covered:** macOS
kernel/privilege-escalation vulnerabilities; world-readable files outside
home (`/Users/Shared`, `/Applications`, `/opt/homebrew`); process names in
`ps`.

Further known limits (by design or documented, not vulnerabilities):

- Workspaces on one Mac share the `_clux` user. Separation between them is
  the Seatbelt layer; with `sandbox: unavailable`, one workspace's agent can
  reach another's files and processes (never the owner's).
- The iOS Simulator (CoreSimulatorService) runs outside Seatbelt as `_clux`;
  user + pf are what confine it.
- Outside Seatbelt, `_clux` can still resolve DNS names through the system
  resolver and send ICMP (pf's user rules cover TCP/UDP only). Inside the
  sandbox both are denied (verified).
- On stop, the supervisor kills the workspace's process group and every
  `_clux` process whose environment names the workspace. macOS hides the
  environment of Apple platform binaries, so one of those that left the
  process group (new session) survives until the next uninstall.
- The agent may connect to its own loopback listeners (pf allows each port
  only while every listener on it belongs to `_clux`, refreshed every
  second by the root daemon); a new listener is unreachable for up to ~1 s.

In scope for reports: anything that lets workspace code read or write the
owner's files, talk to the owner's localhost services or the network
without going through the proxy's policy, drive the supervisor socket
without being the owner, or gain root via the daemons.

## Reporting a vulnerability

**Please do not open a public GitHub issue for an unpatched
vulnerability.** Public issues are for everything else (bugs, feature
requests) — see `.github/ISSUE_TEMPLATE/`.

Instead, email:

```
security@clux.space
```

> **Placeholder.** This address is not live. The maintainer must replace
> it with a real, monitored address before public launch.

Please include:

- what component is affected (`clux-cli` itself, the Docker interaction,
  or the tunnel protocol)
- steps to reproduce, or a PoC if you have one
- what you think the impact is

We'll acknowledge reports and work with you on a fix and disclosure
timeline before any public write-up.
