package main

import (
	"errors"
	"testing"

	"github.com/eduardkumskyi/clux-cli/internal/supervisor"
)

func TestSupervisorsSummary(t *testing.T) {
	ok := func(sb string) slotStatus {
		return slotStatus{resp: supervisor.Response{Version: "0.4.0", Sandbox: sb}}
	}
	down := slotStatus{err: errors.New("down")}

	if v, sb, err := supervisorsSummary([]slotStatus{ok("active"), ok("active")}); err != nil || v != "0.4.0" || sb != "active" {
		t.Fatalf("all active: %q %q %v", v, sb, err)
	}
	// One slot without Seatbelt: the host as a whole can't promise it.
	if _, sb, _ := supervisorsSummary([]slotStatus{ok("active"), ok("unavailable")}); sb != "unavailable" {
		t.Fatalf("mixed sandbox reported %q", sb)
	}
	// A slot down is not "native unavailable" while others answer.
	if _, sb, err := supervisorsSummary([]slotStatus{down, ok("active")}); err != nil || sb != "active" {
		t.Fatalf("one down: %q %v", sb, err)
	}
	if _, sb, err := supervisorsSummary([]slotStatus{down, down}); err == nil || sb != "unavailable" {
		t.Fatalf("all down: %q %v", sb, err)
	}
	if _, _, err := supervisorsSummary(nil); err == nil {
		t.Fatal("no slots must be an error")
	}
}
