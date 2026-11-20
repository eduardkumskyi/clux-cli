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
clux login --token <PAT>     # from the "Add a host" screen in the Clux dashboard
clux doctor                  # sanity-check docker, credentials, connectivity
clux host start               # register this machine and keep it online (foreground)
```

On a Mac, the first interactive `clux host start` offers to set up the
native macOS runtime for iOS/Xcode workspaces (see *Native macOS runtime*);
answer `Y` and enter your admin password once, or `n` to keep Docker only.

Run `clux help` for the full command list.

## Commands

| Command | Flags | Description |
| --- | --- | --- |
| `clux login` | `--token <PAT>` (required)<br>`--backend-url <url>` (default `https://api.clux.space`) | Verifies the token against the backend and stores credentials locally. |
| `clux logout` | none | Removes stored credentials. |
| `clux whoami` | none | Shows the identity of the currently configured host (dials the backend to re-verify stored credentials). |
| `clux doctor` | none | Checks the local environment: Docker CLI reachability, whether the Docker daemon can actually run CPU/memory resource-limited containers (catches cgroup v2 "threaded mode" setups that reject `--cpus`/`--memory` before a workspace start fails the same way), stored credentials, system info collection, and backend connectivity. |
| `clux host start` | `--interval <duration>` (default `30s`)<br>`--no-native-prompt` (macOS: don't offer the native runtime) | Registers this machine and keeps it online in the foreground: opens the tunnel, sends heartbeats on the given interval, and answers workspace lifecycle commands from the backend. Reconnects automatically (see *Connection resilience*). Only one instance runs per machine (`~/.clux/host.lock`). Exits cleanly on SIGINT/SIGTERM; running workspace containers are left running. |
| `clux native install` | `--owner <user>` (default: the account that ran `sudo`) | macOS, root. Sets up the native runtime for iOS/Xcode workspaces (see *Native macOS runtime*). Idempotent; re-run it after updating `clux` to update the daemons. |
| `clux native uninstall` | `--purge` (also delete workspace files) | macOS, root. Removes the daemons, pf anchor, config and runtime. Deleting the hidden account needs Full Disk Access; without it the exact commands to finish are printed. |
| `clux native status` | none | Shows the native runtime's state: account, daemons, pf, Seatbelt self-check, running workspaces. |
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

- **A hidden user `_clux`** (uid/gid from 400-499, own primary group, not in
  `staff`, no password, home `/private/var/clux`, mode 700). Everything a
  workspace runs -- sidecar, claude CLI, builds, simulators -- runs as this
  user, started by a LaunchDaemon (`space.clux.native.supervisor`, outside
  your login session), so it has no access to your home, Keychain,
  clipboard, apps or desktop. Workspaces live in
  `/private/var/clux/workspaces/<id>`.
- **A pf firewall anchor** (`com.apple/clux`, root LaunchDaemon
  `space.clux.native.pf`, which also enables pf at boot and keeps its pf
  reference token): every TCP/UDP packet `_clux` sends is refused, IPv4 and
  IPv6, except to the egress proxy on `127.0.0.1:<port>` and to `_clux`'s
  own loopback listeners (dev servers, the sidecar). Your own localhost
  services (databases, dev servers) are unreachable for it; you can still
  reach its listeners (port previews).
- **An egress proxy** inside `clux host start` (running as you): the only
  way out. Each workspace has an allow list (from the project, e.g.
  `api.anthropic.com`, `*.github.com`); a request to any other host is held
  for up to 60 s while you're asked in the Clux UI (allow once / allow for
  the project / deny), then denied. Loopback addresses are never reachable
  through it, private/LAN addresses only when listed by exact name. Every
  connection is logged to the backend.
- **A Seatbelt sandbox** per workspace (generated profile, deny by default:
  read/write only the workspace and the agent's `Library`, no git hooks,
  network to localhost only). A self-check runs at supervisor start; the
  result (`sandbox: active|unavailable`) is reported to the dashboard.
- `/etc/clux/native.json` (config), `/private/var/clux-runtime` (sidecar
  runtimes: bundle, Python 3.12 venv, claude CLI; written by you, read-only
  for `_clux`), logs in `/private/var/log/clux-native/`.

The sidecar runtime is installed on the first native workspace start: the
backend's sidecar bundle (sha256-checked), a pinned and sha256-checked `uv`,
Python 3.12, and the bundle's hashed requirements lock (wheels only). The
two most recent runtimes are kept.

**Uninstall:** `sudo clux native uninstall` (add `--purge` to also delete
workspace files). macOS only lets a process with Full Disk Access delete an
account record; without it everything else is removed and the remaining
`dscl` commands are printed.

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

## License

MIT
