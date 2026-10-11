# Contributing

## Building and testing locally

This mirrors exactly what CI (`.github/workflows/ci.yml`) runs. Requires Go 1.23.

```
go build ./...
go vet ./...
go test ./...
gofmt -l .
```

`gofmt -l .` should print nothing. CI fails the build if it does (it runs
`diff <(gofmt -l .) <(echo -n)`); if it prints files, run `gofmt -w .` and
commit the result.

CI runs the build/vet/test job on `ubuntu-latest`, `macos-latest`, and
`windows-latest`. If your change touches anything platform-sensitive (paths,
process execution, signals), consider whether it behaves the same on all
three before opening a PR — most contributors will only have one OS to test
on locally, which is fine, just call it out in the PR description.

## Opening a PR

- Keep PRs small and focused on one change. Don't mix refactors with
  behavior changes, or drive-by formatting fixes into a feature PR.
- No unrelated changes — if you notice something else worth fixing while
  you're in there, open a separate PR for it.
- Make sure `go build ./...`, `go vet ./...`, `go test ./...`, and
  `gofmt -l .` all pass before pushing.
- Describe what you changed and why in the PR description; the diff already
  shows what changed.

## Code style

This repo's existing code is the style guide. Specifically:

- Comments explain non-obvious *why*, not *what*. Don't add a comment that
  just restates the line below it — see `internal/dockerhost/lifecycle.go`
  or `internal/config/config.go` for the calibration (e.g. why a package
  doc comment spells out isolation scope, or why a helper falls back to a
  relative path instead of failing).
- Packages are small and focused on one concern (`internal/config`,
  `internal/tunnel`, `internal/dockerhost`, `internal/dialproxy`,
  `internal/hostsession`, `internal/sysinfo`, `internal/apiclient`). Prefer
  adding a new small package over growing an existing one into a grab bag.
- No speculative abstraction — this codebase favors direct, readable code
  over extra layers of indirection added for flexibility nothing currently
  needs.
