package dockerhost

import (
	"fmt"
	"testing"
)

// TestIsMissingContainerErrorMatching and TestIsMissingVolumeErrorMatching
// cover the "no such container"/"no such volume" tolerance that makes
// Stop/Delete idempotent (ByocWorkspaceProvider.stop/replace/delete_storage
// may be called on a workspace whose container or volume is already gone).
// These test the string-matching helpers directly against realistic
// docker CLI error text, rather than shelling out to a real or faked
// `docker` binary: this dev sandbox's own `docker volume rm` is
// unconditionally blocked by a data-loss-prevention hook (see MEMORY.md:
// project_data_loss_fix.md) even for an already-nonexistent volume, and a
// faked docker binary on PATH isn't portable across the CI matrix's
// windows-latest runner (no /bin/sh, no docker daemon). The real
// docker run/stop/rm/port/network paths were exercised live against a
// real Docker daemon with a throwaway mock backend server during manual
// verification instead (see the task's verification notes).
func TestIsMissingContainerErrorMatching(t *testing.T) {
	cases := []struct {
		msg  string
		want bool
	}{
		{"docker stop failed: Error: No such container: abc123", true},
		{"docker rm failed: Error response from daemon: No such container: clux-ws-1", true},
		{"docker stop failed: no such container: clux-ws-1", true},
		{"docker stop failed: permission denied", false},
		{"docker run failed: Conflict. The container name is already in use", false},
	}
	for _, c := range cases {
		if got := isMissingContainer(fmt.Errorf(c.msg)); got != c.want {
			t.Errorf("isMissingContainer(%q) = %v, want %v", c.msg, got, c.want)
		}
	}
}

func TestIsMissingVolumeErrorMatching(t *testing.T) {
	cases := []struct {
		msg  string
		want bool
	}{
		{"docker volume rm failed: Error: No such volume: clux-ws-1-data", true},
		{"docker volume rm failed: get clux-ws-1-data: no such volume", true},
		{"docker volume rm failed: volume is in use by container abc123", false},
	}
	for _, c := range cases {
		if got := isMissingVolume(fmt.Errorf(c.msg)); got != c.want {
			t.Errorf("isMissingVolume(%q) = %v, want %v", c.msg, got, c.want)
		}
	}
}

func TestFormatFloat(t *testing.T) {
	cases := map[float64]string{
		0.5:  "0.5",
		1:    "1",
		2.25: "2.25",
	}
	for in, want := range cases {
		if got := formatFloat(in); got != want {
			t.Errorf("formatFloat(%v) = %q, want %q", in, got, want)
		}
	}
}
