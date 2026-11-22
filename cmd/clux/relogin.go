package main

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/eduardkumskyi/clux-cli/internal/tunnel"
)

// tokenRejectedNotice is what a terminal user sees before the inline
// browser login that replaces a rejected token.
const tokenRejectedNotice = "This computer's connection is no longer valid (it was removed or revoked). Let's connect it again."

// tokenRejectedServiceLog is what the background service logs instead:
// it never prompts.
const tokenRejectedServiceLog = `token rejected: run "clux host start" in a terminal to connect this computer again`

// reloginOnce gives `clux host start` in a terminal one inline browser
// login when the backend rejects the stored token (the computer was removed
// on the website, or its token revoked), so no second command is needed.
// Only one login per process: a token rejected right after a fresh login
// is returned as is.
type reloginOnce struct {
	interactive bool
	login       func(context.Context) error // stores the new token in the shared config
	out         io.Writer
	used        bool
}

// do runs fn, and once more after a successful login if fn failed with a
// rejected token. Without a terminal it never prompts.
func (r *reloginOnce) do(ctx context.Context, fn func(context.Context) error) error {
	for {
		err := fn(ctx)
		if !errors.Is(err, tunnel.ErrTokenRejected) || !r.interactive || r.used || ctx.Err() != nil {
			return err
		}
		r.used = true
		fmt.Fprintln(r.out, tokenRejectedNotice)
		if lerr := r.login(ctx); lerr != nil {
			return lerr
		}
	}
}

// fatalExit turns an error retrying cannot fix into how `host start`
// exits. In the service a rejected token exits 0: launchd
// (KeepAlive.SuccessfulExit=false) and systemd (Restart=on-failure) then
// leave it stopped instead of restarting it every 10 s against the
// backend; the next `clux host start`/`clux login` in a terminal brings it
// back. Other fatal errors (CLI too old) wait for an update, then restart.
func fatalExit(ctx context.Context, err error, asService bool, logf func(string, ...any),
	wait func(context.Context) bool) error {
	logf("fatal: %v", err)
	if !asService {
		return &exitError{code: exitFatalConfig, err: err}
	}
	if errors.Is(err, tunnel.ErrTokenRejected) {
		logf("%s", tokenRejectedServiceLog)
		return nil
	}
	logf("waiting for a clux update (or a new login) before retrying")
	if wait(ctx) {
		return &exitError{code: exitRestart, err: err}
	}
	return nil
}
