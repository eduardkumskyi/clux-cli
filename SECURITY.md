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

`sudo clux native install` (opt-in, macOS) adds a root LaunchDaemon
(`clux native pfd`: pf anchor `com.apple/clux` + its pf enable token) and
one LaunchDaemon per *slot*: a pool of hidden agent users `_clux1`..`_cluxN`
(own primary groups, not in `staff`/`admin`, homes
`/private/var/clux/slots/<n>` 0700), each running `clux native supervise
--slot n` with a unix socket only the installing owner may use (0660 in a
`_cluxN:_cluxctl` 0750 directory, plus a peer-uid check; the owner's client
in turn checks the socket is served by the slot's uid). All daemons run a
root-owned copy of the binary in a directory whose whole parent chain is
root-owned and not group/world-writable. Each workspace holds one slot for
its whole life and runs as that slot's uid; its network is forced through
the egress proxy in `clux host start`.

Root never acts on paths an agent (or the owner) can write: it creates and
re-owns only entries of root-owned directories, opened with `O_NOFOLLOW`
(an existing entry that is a symlink, or owned by an unexpected uid, is
refused); its files are written to random `O_EXCL|O_NOFOLLOW` temp names,
owned/moded through the descriptor and renamed into place; slot homes are
populated by the slot's own supervisor; files in the owner's home are
read or removed with the owner's privileges. The pf daemon's state (status,
enable token, effective rules) lives in the root-owned
`/private/var/run/clux-native` and is only believed from root-owned files
there.

What we state to users (and treat as the security boundary):

**Enforced by macOS (supported mechanisms):** each workspace runs as its own
hidden user with no access to your home, files, Keychain, clipboard, apps or
desktop, or to other workspaces' files, processes and environments; network
leaves only through the clux proxy you control. **Extra layer:** Seatbelt
sandbox (reported live). **Not covered:** macOS kernel/privilege-escalation
vulnerabilities; world-readable files outside home (`/Users/Shared`,
`/Applications`, `/opt/homebrew`); process names in `ps`.

Further known limits (by design or documented, not vulnerabilities):

- The iOS Simulator (CoreSimulatorService) and the apps the agent builds
  run outside Seatbelt as the slot user; user + pf are what confine them.
- DNS through the system resolver: lookups are sent by `mDNSResponder`
  (root) on the caller's behalf, so pf can't attribute them to a slot user,
  and blocking them per user needs a system extension. Outside Seatbelt
  (simulator apps), a slot user can therefore resolve names, i.e. leak small
  amounts of data in DNS queries. This only matters in allow-list mode
  (default egress mode is the open internet). Inside the sandbox the
  resolver is denied (`com.apple.dnssd.service`, the `mDNSResponder`
  socket); sandboxed tools don't need it, the egress proxy resolves names.
- ICMP outside Seatbelt: pf's `user` match only works for TCP and UDP
  sockets. The anchor carries ICMP/ICMPv6 block rules for every slot uid, but
  on macOS 15.6 they don't match (verified: a slot user's unprivileged
  `ping` still gets out), and blocking ICMP for one user needs a system
  extension. So simulator apps and other unsandboxed slot processes can send
  ICMP echo, a low-bandwidth covert channel to any host. Inside the sandbox
  ICMP is denied (verified). Like DNS above, this matters only in allow-list
  mode.
- A slot user may connect to its own loopback listeners (pf allows each
  port only while every listener on it belongs to that slot, refreshed
  every second by the root daemon); a new listener is unreachable for up to
  ~1 s.
- On stop/delete, the supervisor kills the workspace's process tree, shuts
  down the slot's simulators, then kills every remaining process of the
  slot uid. Delete also wipes the slot's home (Library, simulators,
  keychains, caches) before the slot is reused.

In scope for reports: anything that lets workspace code read or write the
owner's files or another workspace's files, processes or secrets, talk to
the owner's localhost services, another workspace's listeners, private/LAN
addresses or the network without going through the proxy's policy, drive a
supervisor socket without being the owner, or gain root via the daemons or
`clux native install`.

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
