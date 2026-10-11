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
