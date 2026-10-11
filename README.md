# clux-cli

The BYOC ("bring your own compute") host agent for [Clux](https://app.clux.space).
Run it on any machine — a spare desktop, a home server, a cloud VM you
already pay for — to offer its CPU, memory, and disk as a workspace host.

## Install

```
go install github.com/eduardkumskyi/clux-cli/cmd/clux@latest
```

Or download a prebuilt binary from the
[releases page](https://github.com/eduardkumskyi/clux-cli/releases).

## Usage

```
clux login --token <PAT>     # from the "Add a host" screen in the Clux dashboard
clux doctor                  # sanity-check docker, credentials, connectivity
clux host start               # register this machine and keep it online (foreground)
```

Run `clux help` for the full command list.

## How it works

`clux host start` dials out to the Clux backend over a WebSocket and keeps
it open — no inbound ports need to be exposed on your network. It reports
this machine's logical CPU count, total memory, and free disk space on
register, then again on every heartbeat, so the backend knows how much
capacity is actually available to schedule workspaces onto.

See [`internal/tunnel`](internal/tunnel) for the wire protocol.

## License

MIT
