package native

import (
	"strings"
	"testing"
)

func TestClaimSlotRules(t *testing.T) {
	for _, c := range []struct {
		name     string
		st       SlotState
		id       string
		resident []string
		ok       bool
	}{
		{"free", SlotState{Slot: 1, Known: true, Clean: true}, "7", nil, true},
		{"held by me", SlotState{Slot: 1, Known: true, ClaimedBy: "7"}, "7", nil, true},
		{"held by another", SlotState{Slot: 1, Known: true, ClaimedBy: "8"}, "7", nil, false},
		{"released but never wiped", SlotState{Slot: 1, Known: true}, "7", nil, false},
		{"being wiped", SlotState{Slot: 1, Known: true, Clean: true, Busy: true}, "7", nil, false},
		// No record (installed before the keeper): only the workspace whose
		// files are the slot's only resident ones may continue there.
		{"unknown, my files", SlotState{Slot: 1}, "7", []string{"7"}, true},
		{"unknown, empty", SlotState{Slot: 1}, "7", nil, false},
		{"unknown, other files", SlotState{Slot: 1}, "7", []string{"8"}, false},
		{"unknown, mine and others", SlotState{Slot: 1}, "7", []string{"7", "8"}, false},
	} {
		got, err := claimSlot(c.st, c.id, c.resident)
		if (err == nil) != c.ok {
			t.Errorf("%s: err=%v, want ok=%v", c.name, err, c.ok)
			continue
		}
		if c.ok && (got.ClaimedBy != c.id || got.Clean || !got.Known) {
			t.Errorf("%s: claimed state %+v", c.name, got)
		}
	}
}

func TestWipeAllowed(t *testing.T) {
	if err := wipeAllowed(SlotState{Slot: 1, ClaimedBy: "8"}, "7"); err == nil || !strings.Contains(err.Error(), "held by workspace 8") {
		t.Errorf("wipe of another workspace's slot: %v", err)
	}
	if err := wipeAllowed(SlotState{Slot: 1, ClaimedBy: "8"}, ""); err == nil {
		t.Error("anonymous wipe of a held slot allowed")
	}
	if err := wipeAllowed(SlotState{Slot: 1, Busy: true}, ""); err == nil {
		t.Error("concurrent wipe allowed")
	}
	for _, st := range []SlotState{{Slot: 1, ClaimedBy: "7"}, {Slot: 1}, {Slot: 1, Known: true, Clean: true}} {
		if err := wipeAllowed(st, "7"); err != nil {
			t.Errorf("%+v: %v", st, err)
		}
	}
	if !(SlotState{Known: true, Clean: true}).Free() || (SlotState{Clean: true}).Free() || (SlotState{Known: true, Clean: true, ClaimedBy: "1"}).Free() {
		t.Error("Free()")
	}
}
