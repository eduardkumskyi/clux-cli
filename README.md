# clux-cli

The BYOC ("bring your own compute") host agent for [Clux](https://app.clux.space).
Run it on any machine — a spare desktop, a home server, a cloud VM you
already pay for — to offer its CPU, memory, and disk as a workspace host.

## Install

No Go toolchain required — the install script grabs a prebuilt binary for your
OS and architecture (macOS/Linux, amd64/arm64):

```
curl -fsSL https://clux.space/install.sh | sh
```

It installs to `/usr/local/bin` (or `~/.local/bin` if that isn't writable).
Set `CLUX_INSTALL_DIR` to pick another location, or `CLUX_VERSION=vX.Y.Z` to
pin a release.

**Manual download:** grab the archive for your platform from the
[releases page](https://github.com/eduardkumskyi/clux-cli/releases), unpack it,
and move the `clux` binary onto your `PATH`. On Windows, download the `.zip`.

**From source** (needs Go 1.23+):

```
go install github.com/eduardkumskyi/clux-cli/cmd/clux@latest
```

## Usage

```
clux host start      # connect this computer (confirm in the browser) and keep it online
clux host status     # is it running, which host, which backend
clux host logs -f    # follow ~/.clux/logs/host.log
clux host stop       # stop the background service
```

The first `clux host start` in a terminal walks through everything once:

1. **Connect.** Without stored credentials it prints a link and a code,
   opens the browser, and waits while you confirm the code in the Clux app
   (Ctrl+C cancels). `clux login` does the same on its own. If the stored
   credentials no longer work (the computer was removed on the website, or
   its token revoked), it says so and runs the same login once, then carries
   on with the new token.
2. **Native runtime (Mac).** Offers to set up the native macOS runtime for
   iOS/Xcode workspaces (see *Native macOS runtime*).
3. **Background.** Asks "Keep this computer online in the background
   (starts when you log in)? [Y/n]". Yes installs a per-user service and
   returns your terminal; no keeps it in the foreground as before. The answer
   is remembered (`"service"` in `~/.clux/config.json`).

**One computer = one host.** The CLI identifies the machine with a
`machine_id` (a SHA-256 of the OS machine id and your OS user; the raw id is
never sent) plus a random `machine_secret` kept in `~/.clux/machine-key`
(0600, survives `clux logout`). Logging in again on the same computer gets
the same host back, with its projects, instead of a new one; the guessable
id alone is never enough. Deleting `machine-key` makes the computer connect
as a new host.

Servers and CI without a browser: create a host in the dashboard and run
`clux login --token <PAT>`, then `clux host start` (non-interactive runs
never prompt and stay in the foreground).

Run `clux help` for the full command list.

## Commands

| Command | Flags | Description |
| --- | --- | --- |
| `clux login` | `--token <PAT>` (optional)<br>`--backend-url <url>` (default `https://api.clux.space`, or the one stored before) | Without `--token`: browser login. Prints `To connect this computer, open: <url> and confirm the code ABCD-EFGH`, opens the browser (not over SSH), polls until you confirm, deny, or the code expires (10 min). On a computer that was connected before, the backend returns the same host. With `--token`: verifies the token by registering once. Either way it stores credentials in `~/.clux/config.json` and restarts the background service if it runs. |
| `clux logout` | none | Stops and removes the background service, then removes stored credentials (your answers to the one-time questions are kept). |
| `clux whoami` | none | Shows the identity of the currently configured host (dials the backend to re-verify stored credentials). While `clux host start` or the background service runs, it answers from local config instead, since a second register would replace the live tunnel; `clux doctor` then only checks that the backend is reachable. |
| `clux doctor` | none | Checks the local environment: Docker CLI reachability, whether the Docker daemon can actually run CPU/memory resource-limited containers (catches cgroup v2 "threaded mode" setups that reject `--cpus`/`--memory` before a workspace start fails the same way), stored credentials, system info collection, and backend connectivity. |
| `clux host start` | `--foreground` (stay in this terminal, never offer the service; what the service runs)<br>`--background` (use the service even after an earlier "no")<br>`--interval <duration>` (default `30s`)<br>`--no-native-prompt` (macOS: don't offer the native runtime) | Registers this machine and keeps it online: opens the tunnel, sends heartbeats on the given interval, and answers workspace lifecycle commands from the backend. Reconnects automatically (see *Connection resilience*). In a terminal it first logs in if needed and offers the background service (see *Usage*); if the service already runs it says so and exits 0. Only one instance runs per machine (`~/.clux/host.lock`). Exits cleanly on SIGINT/SIGTERM; running workspace containers are left running. |
| `clux host stop` | none | Stops the background service and removes it, so it does not start at the next login. If a `clux host start` runs in a terminal, says so (stop it with Ctrl+C there). |
| `clux host status` | none | Local summary (does not dial the backend): background service state and pid, a terminal instance if any, host name/id, backend, CLI version, last connection event from the log, native runtime slots and the workspaces they hold. |
| `clux host logs` | `-f` (follow, across log rotation)<br>`-n N` (default 100) | Prints the end of `~/.clux/logs/host.log`. |
| `clux native install` | `--owner <user>` (default: the account that ran `sudo`)<br>`--slots N` (agent users = native workspaces that can exist at once; default: keep, 4 at first) | macOS, root. Sets up the native runtime for iOS/Xcode workspaces (see *Native macOS runtime*). Idempotent; re-run it with another `--slots` to grow/shrink the pool. From v0.7.0 on the daemons follow `clux update` by themselves (see *Updates*); an older install needs this once. |
| `clux native uninstall` | `--purge` (also delete workspace files) | macOS, root. Removes the daemons, pf anchor, config and runtime. Deleting the hidden account needs Full Disk Access; without it the exact commands to finish are printed. |
| `clux native status` | none | Shows the native runtime's state: account, daemons, pf, Seatbelt self-check, running workspaces. |
| `clux update` | `--check` (only say whether a newer release exists)<br>`--version vX.Y.Z` (install that release, also to go back) | Downloads the release archive for this OS/architecture from GitHub, checks the release's signed `checksums.txt` (see *Release signing*) and the archive against it, and swaps the binary in place (temp file in the same directory, then rename, so a failure leaves the old one). If that directory needs admin rights (`/usr/local/bin`) it uses `sudo` in a terminal, or says what to run. Restarts the background service if installed; a `clux host start` in a terminal is pointed out. With the native runtime installed, it then has the root daemon update the native runtime's own copy too, without sudo (see *Native macOS runtime > Updates*). Homebrew installs: `brew upgrade clux`. `clux host start` prints a one-line notice when the backend reports a newer release. |
| `clux version` | none | Prints the CLI version. |
| `clux help` (also `-h`, `--help`) | none | Prints usage. |

Running `clux` with no arguments also prints usage and exits non-zero.

## How it works

`clux host start` dials out to the Clux backend over a WebSocket and keeps
it open — no inbound ports need to be exposed on your network. It reports
this machine's logical CPU count, total memory, and free disk space on
register, then again on every heartbeat, so the backend knows how much
capacity is actually available to schedule workspaces onto.

See [`internal/tunnel`](internal/tunnel) for the wire protocol.

## Background service

`clux host start` answered with "yes" (or `--background`) installs a
per-user service that runs `<clux binary> host start --foreground
--no-native-prompt` with a stable path to the binary you ran: the symlink
you started it by or `clux` on your `PATH` (e.g. `/opt/homebrew/bin/clux`,
which survives `brew upgrade`), not the versioned Cellar path behind it. A
binary in a temp dir or Go build cache is refused (the host keeps running
in the foreground):

- **macOS:** LaunchAgent `~/Library/LaunchAgents/space.clux.host.plist` in
  your `gui/<uid>` domain (`launchctl bootstrap`), no root. Starts at login
  (`RunAtLoad`), restarted after an error exit (`KeepAlive.SuccessfulExit =
  false`, at most every 10 s), not after a clean stop.
- **Linux:** systemd user unit `~/.config/systemd/user/clux-host.service`
  (`systemctl --user enable` + restart), `Restart=on-failure`,
  `RestartSec=10`. A user service runs while you are logged in; for a server
  that should stay online after logout, run `loginctl enable-linger $USER`.
- **Windows:** not supported yet; `clux host start` says so and runs in
  the foreground.

The service gets your `PATH` from install time (so it finds `docker`) and
`CLUX_SERVICE=1`. It writes `~/.clux/logs/host.log` (its raw stdout/stderr
go to `~/.clux/logs/service.log`). It never prompts. Not logged in or CLI
too old: it waits for a login or an updated binary instead of restarting in
a loop. Token rejected (computer removed or revoked): it logs `token
rejected: run "clux host start" in a terminal to connect this computer
again` and exits cleanly, so launchd/systemd leave it stopped; `clux host
status` shows the same hint, and the next `clux host start` in a terminal
logs in again and brings the service back. `clux host stop` and
`clux logout` remove it. It never touches the native runtime's root daemons.

## Native macOS runtime (iOS development)

By default a workspace is a Linux container on your Docker daemon, which
means no Xcode, no iOS Simulator. On a Mac you can additionally offer the
**native macOS runtime**: the workspace's sidecar and the claude CLI run
directly on macOS, can use `xcodebuild` and the iOS Simulator, and are
isolated by macOS itself.

```
sudo clux native install     # once; then restart `clux host start`
clux native status
clux doctor                  # includes native checks
```

**Setup from `clux host start`.** When native mode is not installed and
`clux host start` runs in a terminal (stdin and stdout are TTYs), it asks
once, default Yes (`[Y/n]`). Yes runs `sudo clux native install` on your
terminal (sudo asks for the password), then host start continues; if the
install fails, the error is printed and the host runs Docker workspaces
only. No is remembered in `~/.clux/config.json` (`native_prompt_declined`)
and not asked again; `--no-native-prompt` skips the question for one run.
Without Xcode (`xcode-select -p` fails) it says native mode needs Xcode and
does not ask. Non-interactive runs (launchd, CI) never prompt: they log one
line suggesting `sudo clux native install`. When native mode is installed
but the supervisor or pf firewall is not healthy, it logs one warning
pointing at `clux doctor`.

What `install` sets up:

- **A pool of hidden agent users ("slots")** `_clux1`..`_cluxN` (default 4,
  `--slots N`, up to 32; uid/gid from 400-499, each with its own primary
  group, not in `staff` or `admin`, no password, home
  `/private/var/clux/slots/<n>`, mode 700). Each native workspace is
  assigned a free slot on its first start and keeps it until it is deleted;
  everything it runs -- sidecar, claude CLI, builds, simulators and the apps
  in them -- runs as that slot's user, started by the slot's LaunchDaemon
  (`space.clux.native.supervisor.<n>`, outside your login session). So a
  workspace has no access to your home, Keychain, clipboard, apps or
  desktop, nor to another workspace's files, processes or environment.
  Its files live in `/private/var/clux/slots/<n>/workspaces/<id>`. With all
  slots held, a start fails with `all N native slots in use`; re-run
  `sudo clux native install --slots M` to grow the pool (shrinking refuses
  to remove a slot that still holds a workspace). Deleting a workspace
  wipes its slot (files, simulators, DerivedData, caches) before the slot
  is reused. Root never writes inside a slot's home: install only creates
  the home itself, the slot's supervisor fills it.
- **A pf firewall anchor** (`com.apple/clux`, root LaunchDaemon
  `space.clux.native.pf`, which also enables pf at boot and keeps its pf
  reference token): every TCP and UDP packet a slot user sends is refused,
  IPv4 and IPv6, except TCP to the egress proxy on
  `127.0.0.1:<port>` and to that slot's own loopback listeners (dev
  servers, the sidecar). Your own localhost services (databases, dev
  servers) and other workspaces' listeners are unreachable for it; you can
  still reach its listeners (port previews). Known limits (outside the
  Seatbelt sandbox only, i.e. simulator apps; see SECURITY.md): DNS
  lookups through the system resolver and ICMP can't be blocked per user
  without a system extension. The daemon re-checks every few
  seconds that pf still holds these rules and that the main ruleset still
  evaluates `com.apple/*`, repairs either, and publishes its status in the
  root-owned `/private/var/run/clux-native/`; a supervisor refuses to start
  a workspace unless that status is current and covers its uid.
- **An egress proxy** inside `clux host start` (running as you): the only
  way out. Each workspace has an allow list (from the project, e.g.
  `api.anthropic.com`, `*.github.com`); a request to any other host is held
  for up to 60 s while you're asked in the Clux UI (allow once / allow for
  the project / deny), then denied. Host names -- listed, wildcard, approved
  in a prompt or in "open" mode -- only ever reach public addresses (the
  resolved address is checked when dialing, so DNS rebinding can't point
  them at your network). Private/LAN, CGNAT, link-local (incl. cloud
  metadata) and ULA addresses are reachable only by an explicit IP or CIDR
  entry (`192.168.1.20`, `10.0.0.0/8:5432`); loopback never. Every
  connection is logged to the backend.
- **A Seatbelt sandbox** per workspace (generated profile, deny by default:
  read/write only the workspace and the slot's `Library`, no git hooks,
  network to localhost only, no system DNS resolver). A self-check runs at
  supervisor start; the result (`sandbox: active|unavailable`) is reported
  to the dashboard.
- `/etc/clux/native.json` (config), `/private/var/clux-runtime` (sidecar
  runtimes: bundle, Python 3.12 venv, claude CLI; written by you, read-only
  for the slots via group `_cluxslots`), logs in
  `/private/var/log/clux-native/` (`pf.log`, `supervisor-<n>.log`).

An install of the earlier single-user layout (`_clux`) is migrated by
re-running `sudo clux native install`: its daemon and processes are
stopped, its home (the old workspaces) is moved to
`/private/var/clux-legacy-<time>` (root only), and the account is deleted
when macOS allows it (otherwise it stays hidden, without password, with
nothing running). Native workspaces start fresh in their new slots.

The sidecar runtime is installed on the first native workspace start: the
backend's sidecar bundle (sha256-checked), a pinned and sha256-checked `uv`,
Python 3.12, and the bundle's hashed requirements lock (wheels only). The
two most recent runtimes are kept.

**Updates.** The daemons run their own root-owned copy of `clux`. You only
ever update the CLI: `clux update`, and `clux host start` whenever the
daemons run an older version than itself, ask the root pf daemon (over the
slot keeper's owner-only socket) to move to that release. Root never takes
a binary from you: it downloads the release from GitHub itself, requires a
valid signature and checksum, runs the new binary once to check it is that
release and can read this installation, then swaps it atomically and
records the version in `/etc/clux/native.json`. Supervisors of idle slots
restart onto it at once; a slot running a workspace switches when that
workspace stops, so no turn is cut off. The root daemon restarts itself last,
once no slot is busy. It only moves forward, unless you pass an explicit
`clux update --version` (still signed releases only). Daemons installed
before v0.7.0 can't do this yet: run `sudo clux native install` once.

**Uninstall:** `sudo clux native uninstall` (add `--purge` to also delete
workspace files). It stops every slot, releases pf, and removes the
daemons, config, runtime, logs and your egress proxy key/policies and slot
assignments in `~/.clux`. Without `--purge` the slot homes are kept but
made root-only (no leftover uid owns reachable files). macOS only lets a
process with Full Disk Access delete account records; without it
everything else is removed and the remaining `dscl` commands are printed.

## Connection resilience

`clux host start` is built for laptops on unreliable networks:

- **Dead-connection detection.** The agent pings the backend every 15s and
  treats 45s without any frame or pong as a dead connection (half-open TCP,
  captive portal, silent Wi-Fi loss), instead of waiting minutes for TCP.
- **Sleep / network switch.** A wake from sleep (wall clock jumping ahead of
  the monotonic clock) or a change of the machine's IP addresses triggers an
  immediate reconnect, or a 5s liveness probe if the tunnel's own address
  survived.
- **Backoff.** The first retry is immediate, then 1s, 2s, 4s ... capped at
  30s with ±20% jitter; a session that stayed up 60s resets it. A network
  change or wake cuts a pending wait short.
- **No half-done Docker work.** `workspace.start/stop/delete` keep running
  across a disconnect; their result is re-sent after the next registration if
  the connection died before it went out.
- **Logs.** Every line is timestamped, repeated identical errors collapse into
  one line, and everything is also written to `~/.clux/logs/host.log`
  (rotated at 5 MB, 3 old files kept).

## Release signing

Every release from v0.7.0 on has `checksums.txt.sig`: an ed25519 signature
over `"clux-release-v1\n" + tag + "\n" + checksums.txt`, so it also pins the
release it belongs to. The release workflow makes it with
`tools/releasesign` from the GitHub Actions secret `CLUX_RELEASE_SIGNING_KEY`
(base64 ed25519 seed). The public keys live in
`internal/selfupdate/signature.go` (`trustedKeysBase64`). `clux update`
refuses a release from v0.7.0 on with a missing or bad signature, and
accepts older releases on their checksum alone, with a warning. The native
root daemon never accepts an unsigned release. To check a release by hand:

```sh
go run ./tools/releasesign verify -tag vX.Y.Z -in checksums.txt -sig checksums.txt.sig
```

**Key rotation.** The old key has to sign the release that introduces the
new one, since installed binaries only trust the keys they embed.

1. `go run ./tools/releasesign keygen -out new.key` prints the new public
   key. Add it to `trustedKeysBase64` next to the old one, and release
   (still signed with the old secret).
2. Once most installs have that release, store the new key:
   `gh secret set CLUX_RELEASE_SIGNING_KEY < new.key`, then delete
   `new.key`. Release.
3. Later, remove the old key from `trustedKeysBase64` and release.

If the old key leaks, do steps 1 to 3 back to back and drop the old key in
the same release. If it is lost, binaries that only trust it can't take
signed releases any more: reinstall with `install.sh`, then run
`sudo clux native install` for the native runtime. `tools/releasesign sign`
refuses a key that the binary doesn't trust, so a wrong secret fails the
release before anything is published.

## License

MIT
