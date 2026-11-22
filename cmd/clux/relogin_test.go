package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/eduardkumskyi/clux-cli/internal/tunnel"
)

// rejected is what tunnel.Dial returns for a removed/revoked computer.
var rejected = &tunnel.ErrFatal{Err: fmt.Errorf("registration rejected: %w", tunnel.ErrTokenRejected)}

func TestReloginInteractiveRejectionLogsInAndRetries(t *testing.T) {
	token := "old"
	logins := 0
	var out bytes.Buffer
	r := &reloginOnce{interactive: true, out: &out, login: func(context.Context) error {
		logins++
		token = "new"
		return nil
	}}
	var seen []string
	err := r.do(context.Background(), func(context.Context) error {
		seen = append(seen, token)
		if token == "old" {
			return rejected
		}
		return nil
	})
	if err != nil {
		t.Fatalf("want success after the re-login, got %v", err)
	}
	if logins != 1 || strings.Join(seen, ",") != "old,new" {
		t.Fatalf("logins=%d attempts=%v", logins, seen)
	}
	if !strings.Contains(out.String(), tokenRejectedNotice) {
		t.Fatalf("missing notice: %q", out.String())
	}
}

func TestReloginSecondRejectionIsReturned(t *testing.T) {
	logins, attempts := 0, 0
	r := &reloginOnce{interactive: true, out: &bytes.Buffer{}, login: func(context.Context) error {
		logins++
		return nil
	}}
	run := func(context.Context) error { attempts++; return rejected }
	err := r.do(context.Background(), run)
	if !errors.Is(err, tunnel.ErrTokenRejected) || !tunnel.IsFatal(err) {
		t.Fatalf("want the fatal rejection, got %v", err)
	}
	if logins != 1 || attempts != 2 {
		t.Fatalf("logins=%d attempts=%d, want 1 and 2", logins, attempts)
	}
	// Once per process: a later rejection (e.g. the pre-check, then the
	// agent) does not prompt again.
	if err := r.do(context.Background(), run); !errors.Is(err, tunnel.ErrTokenRejected) || logins != 1 {
		t.Fatalf("second do: err=%v logins=%d", err, logins)
	}
}

func TestReloginFailedLoginIsReturned(t *testing.T) {
	r := &reloginOnce{interactive: true, out: &bytes.Buffer{}, login: func(context.Context) error {
		return errLoginCancelled
	}}
	err := r.do(context.Background(), func(context.Context) error { return rejected })
	if !errors.Is(err, errLoginCancelled) {
		t.Fatalf("want the login error, got %v", err)
	}
}

func TestReloginNonInteractiveNeverPrompts(t *testing.T) {
	var out bytes.Buffer
	r := &reloginOnce{interactive: false, out: &out, login: func(context.Context) error {
		t.Fatal("must not log in without a terminal")
		return nil
	}}
	if err := r.do(context.Background(), func(context.Context) error { return rejected }); !errors.Is(err, tunnel.ErrTokenRejected) {
		t.Fatalf("got %v", err)
	}
	if out.Len() != 0 {
		t.Fatalf("printed %q", out.String())
	}
}

func TestReloginIgnoresOtherErrors(t *testing.T) {
	r := &reloginOnce{interactive: true, out: &bytes.Buffer{}, login: func(context.Context) error {
		t.Fatal("only a rejected token triggers a login")
		return nil
	}}
	outdated := &tunnel.ErrFatal{Err: errors.New("clux too old")}
	if err := r.do(context.Background(), func(context.Context) error { return outdated }); err != outdated {
		t.Fatalf("got %v", err)
	}
}

func TestFatalExitServiceTokenRejectedExitsCleanly(t *testing.T) {
	var logged []string
	logf := func(f string, a ...any) { logged = append(logged, fmt.Sprintf(f, a...)) }
	err := fatalExit(context.Background(), rejected, true, logf, func(context.Context) bool {
		t.Fatal("a rejected token must not wait-and-restart")
		return false
	})
	if err != nil {
		t.Fatalf("service must exit 0 (no launchd/systemd restart loop), got %v", err)
	}
	if !strings.Contains(strings.Join(logged, "\n"), tokenRejectedServiceLog) {
		t.Fatalf("log lacks the hint: %v", logged)
	}
	if !tokenRejectedEvent("2026-11-22T10:00:00 " + logged[len(logged)-1]) {
		t.Fatal("`clux host status` must recognize the logged line")
	}
}

func TestFatalExitTerminalTokenRejectedIsExitFatalConfig(t *testing.T) {
	err := fatalExit(context.Background(), rejected, false, func(string, ...any) {}, nil)
	var ee *exitError
	if !errors.As(err, &ee) || ee.code != exitFatalConfig {
		t.Fatalf("want exit %d, got %v", exitFatalConfig, err)
	}
}

func TestFatalExitServiceOutdatedWaitsThenRestarts(t *testing.T) {
	outdated := &tunnel.ErrFatal{Err: errors.New("clux too old")}
	err := fatalExit(context.Background(), outdated, true, func(string, ...any) {}, func(context.Context) bool { return true })
	var ee *exitError
	if !errors.As(err, &ee) || ee.code != exitRestart {
		t.Fatalf("want exit %d after an update, got %v", exitRestart, err)
	}
}

func TestTokenRejectedEvent(t *testing.T) {
	for line, want := range map[string]bool{
		"x fatal: registration rejected: invalid or revoked token (run `clux login` to connect this computer again)": true,
		"x fatal: backend revoked this host's token (run `clux host start` in a terminal ...)":                       true,
		"x " + tokenRejectedServiceLog:                        true,
		"x fatal: registration rejected: clux 0.1 is too old": false,
		`x registered as host "mac" (id=3)`:                   false,
	} {
		if got := tokenRejectedEvent(line); got != want {
			t.Errorf("%q: got %v", line, got)
		}
	}
}
