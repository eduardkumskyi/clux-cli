package native

import (
	"strings"
	"testing"
)

func TestCheckUpdateTarget(t *testing.T) {
	for _, tc := range []struct {
		installed, target string
		downgrade         bool
		upToDate          bool
		err               string
	}{
		{"v0.7.0", "v0.8.0", false, false, ""},
		{"v0.7.0", "v0.7.1-rc.1", false, false, ""},
		{"v0.7.0", "v0.7.0", false, true, ""},
		// Never downgrade unless explicitly asked.
		{"v0.8.0", "v0.7.0", false, false, "refusing to downgrade"},
		{"v0.8.0", "v0.7.0", true, false, ""},
		// The target must be a release tag, also when forced.
		{"v0.7.0", "0.8.0", false, false, "not a release tag"},
		{"v0.7.0", "latest", true, false, "not a release tag"},
		{"v0.7.0", "v0.8.0/../../x", true, false, "not a release tag"},
		{"v0.7.0", "", false, false, "not a release tag"},
	} {
		upToDate, err := checkUpdateTarget(tc.installed, tc.target, tc.downgrade)
		if tc.err == "" && err != nil || tc.err != "" && (err == nil || !strings.Contains(err.Error(), tc.err)) {
			t.Errorf("%s -> %q (downgrade=%v): err %v, want %q", tc.installed, tc.target, tc.downgrade, err, tc.err)
		}
		if upToDate != tc.upToDate {
			t.Errorf("%s -> %q: upToDate %v", tc.installed, tc.target, upToDate)
		}
	}
}

func TestCanSelfUpdate(t *testing.T) {
	if CanSelfUpdate("v0.6.0") || CanSelfUpdate("v0.5.2") {
		t.Fatal("daemons from before the self-update need one sudo clux native install")
	}
	if !CanSelfUpdate(FirstSelfUpdatingVersion) || !CanSelfUpdate("v1.0.0") {
		t.Fatal("daemons from the self-update on update themselves")
	}
}
