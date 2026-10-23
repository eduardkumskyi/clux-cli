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

Run `clux help` for the full command list.

## Commands

| Command | Flags | Description |
| --- | --- | --- |
| `clux login` | `--token <PAT>` (required)<br>`--backend-url <url>` (default `https://app.clux.space`) | Verifies the token against the backend and stores credentials locally. |
| `clux logout` | none | Removes stored credentials. |
| `clux whoami` | none | Shows the identity of the currently configured host (dials the backend to re-verify stored credentials). |
| `clux doctor` | none | Checks the local environment: Docker CLI reachability, whether the Docker daemon can actually run CPU/memory resource-limited containers (catches cgroup v2 "threaded mode" setups that reject `--cpus`/`--memory` before a workspace start fails the same way), stored credentials, system info collection, and backend connectivity. |
| `clux host start` | `--interval <duration>` (default `30s`) | Registers this machine and keeps it online in the foreground: opens the tunnel, sends heartbeats on the given interval, and answers workspace lifecycle commands from the backend. Reconnects automatically on a 5s backoff if the connection drops. Exits cleanly on SIGINT/SIGTERM. |
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

## License

MIT
