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
(`clux native pfd`: pf anchor `com.apple/clux` + its pf enable token, and
the *slot keeper*) and one LaunchDaemon per *slot*: a pool of hidden agent
users `_clux1`..`_cluxN` (own primary groups, not in `staff`/`admin`, homes
`/private/var/clux/slots/<n>` 0700), each running `clux native supervise
--slot n`. The supervisor starts as root, binds its unix socket in a
`root:_cluxctl` 0750 directory the slot user can't enter (socket
`root:_cluxctl` 0660), then drops to the slot user for good. The
supervisor and the keeper check the peer uid against the installing owner;
the owner's clients check that the socket was created by root (root-only
directory chain, root-owned socket, listen-time peer credentials uid 0),
which a slot user can't fake. All daemons run a root-owned copy of the
binary in a directory whose whole parent chain is root-owned and not
group/world-writable. A workspace holds one slot for its whole life and
runs as that slot's uid; its TCP/UDP is forced through the egress proxy in
`clux host start`.

Slots are reused: after a workspace is deleted, the next workspace gets
the same uid. The supervisor runs as that uid too, so the agent can stop
or kill it, and the supervisor's own cleanup is not what the reuse relies
on. Delete goes to the root keeper instead, which boots out the
supervisor, removes the uid's crontab and at jobs, shuts down its
simulators, boots out its launchd `user/` and `gui/` domains and kills
every process holding the slot's uid or gid as its real, effective or
saved id (all processes are scanned, so a process of another slot that
ran a setuid file of this one and dropped back with `seteuid()` dies too)
until none comes back, moves the home aside (inside the root-owned slots
directory) and deletes it, empties the uid's `/private/var/folders` dir,
deletes its files in `/private/tmp`, `/private/var/tmp`, `/Users/Shared`
and `/cores`, clears the setuid/setgid bits of every file of any slot
uid/gid that a slot can reach (below), and then records the slot clean in
a root-owned state file. The host only hands out slots root reports clean
(or has root wipe them first); handing one out, root resets the home to
0700 without ACL entries and kills any process of another user still
holding the slot's uid; and a supervisor refuses to start a workspace root
has not recorded as the slot's holder.

Setuid/setgid files: Seatbelt denies setting the bits
(`file-write-setugid`), and the kernel refuses sandboxed processes to
exec a setuid/setgid file at all, but simulator apps run outside Seatbelt
and can `chmod u+s` their own files anywhere they can write, and another
slot's unsandboxed code could run them or hard-link them into its own
home to keep for later. So the wipe walks every local writable file
system that honours setuid bits (not just a list of temp dirs: third-party
apps leave world-writable directories around), descending only into
directories a slot user can search and looking at files only in
directories a slot user can write, never following links (`openat` with
`O_NOFOLLOW` from the parent's descriptor; the bits are cleared through
the file's own descriptor). A second pass over just the trees a slot can
write runs with every slot process stopped (SIGSTOP, resumed right after;
measured on a dev Mac: ~0.7 s stopped, ~24 s for the whole sweep), so no slot
can move a file out of the walk's way. A nosuid APFS volume for the slot
homes was considered and not used: `/private/tmp`, the per-user
`/private/var/folders` dirs and other world-writable places stay on the
Data volume (which can't be nosuid without breaking the Mac), so it would
not remove the need for the sweep.

Root never acts on paths an agent (or the owner) can write while it can
still act: it creates and re-owns only entries of root-owned directories,
opened with `O_NOFOLLOW` (an existing entry that is a symlink, or owned by
an unexpected uid, is refused); its files are written to random
`O_EXCL|O_NOFOLLOW` temp names, owned/moded through the descriptor and
renamed into place; slot homes are populated by the slot's own supervisor
and wiped by root only after every process of the uid is gone, by renaming
them inside the root-owned parent first; files in the owner's home are
read or removed with the owner's privileges. The pf daemon's state
(status, enable token, effective rules, slot records) lives in root-owned
directories and is only believed from root-owned files there.

What we state to users (and treat as the security boundary):

**Enforced by macOS (supported mechanisms):** each workspace runs as a
hidden user of its own (no two existing workspaces share one; a deleted
workspace's user is wiped by root before reuse) with no access to your
home, files, Keychain, clipboard or desktop, or to other workspaces'
files, processes and environments; its TCP and UDP traffic leaves only
through the clux proxy you control, which refuses this Mac's own addresses
and loopback. **Extra layer:** Seatbelt sandbox (reported live). **Not
covered:** macOS kernel/privilege-escalation vulnerabilities; DNS and ICMP
outside Seatbelt (below); world-readable files and apps outside home
(`/Users/Shared`, `/Applications`, `/opt/homebrew`), which a workspace can
read and run as its own user; process names in `ps`; a workspace stopping
or killing its own supervisor (it only denies service to itself).

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
- A slot user may connect to its own loopback listeners (pf passes each
  port only while every listener on it belongs to that slot, refreshed
  every second by the root daemon); a new listener is unreachable for up to
  ~1 s. Every passed port also has an inbound guard (`block in ... port P
  user != <slot>`, matched per connection against the listener's owner), so
  when a slot's port is released and rebound by someone else before the
  next refresh, the slot's connection is refused, not delivered. The proxy
  port is passed only while every listener on it is the owner's, with the
  same kind of guard, so a slot that binds it while `clux host start` is
  down can't collect other workspaces' proxy credentials. Connections
  already established when a port leaves a slot's set keep their pf state
  (macOS `pfctl` can't kill states by port, and killing all loopback states
  would cut every live sidecar connection); they stay between the same two
  sockets and can't reach a new listener.
- Stop kills the workspace's process tree, its simulators and every other
  process of the slot uid (done by the supervisor, so a hostile workspace
  can keep its own leftovers alive until delete). Delete is root's wipe
  above. Not covered by the wipe: System V IPC objects and launchd
  enable/disable overrides of the uid, and non-setuid files the uid owns
  in other world-writable places than the ones listed (none can run code
  by themselves or carry the uid). The setuid sweep trusts POSIX
  permission bits: a directory a slot can reach only through an ACL entry
  granted by its (non-slot) owner is not walked.

In scope for reports: anything that lets workspace code read or write the
owner's files or another workspace's files, processes or secrets, talk to
the owner's localhost services, another workspace's listeners, private/LAN
addresses or the network without going through the proxy's policy, drive a
supervisor or keeper socket without being the owner, receive what the owner
sends a supervisor, survive a delete into the next workspace of its slot,
or gain root via the daemons or `clux native install`.

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
