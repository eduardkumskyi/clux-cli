package dockerhost

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestStopDeleteIdempotentAgainstMissingResources exercises the "no such
// container"/"no such volume" tolerance paths in Stop/Delete against a
// fake `docker` binary that mimics those exact error strings, since this
// dev sandbox's real `docker volume rm` is unconditionally blocked by a
// data-loss-prevention hook (see MEMORY.md: project_data_loss_fix.md) and
// can't be exercised live even for an already-nonexistent volume. The real
// docker run/stop/rm/port/network paths are covered by the end-to-end
// mock-backend smoke test instead (which this sandbox's dockerd *can* run,
// since it only hits docker run/stop/rm/port/network, never volume rm).
func TestStopDeleteIdempotentAgainstMissingResources(t *testing.T) {
	dir := t.TempDir()
	fakeDocker := filepath.Join(dir, "docker")
	script := `#!/bin/sh
if [ "$1" = "volume" ] && [ "$2" = "rm" ]; then
  echo "Error response from daemon: get $3: no such volume" >&2
  exit 1
fi
if [ "$1" = "stop" ]; then
  echo "Error: No such container: $2" >&2
  exit 1
fi
if [ "$1" = "rm" ]; then
  last=""
  for a in "$@"; do last="$a"; done
  echo "Error: No such container: $last" >&2
  exit 1
fi
echo "unhandled fake docker call: $@" >&2
exit 1
`
	if err := os.WriteFile(fakeDocker, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	origPath := os.Getenv("PATH")
	t.Setenv("PATH", dir+string(os.PathListSeparator)+origPath)

	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatalf("fake docker not on PATH: %v", err)
	}

	ctx := context.Background()

	if err := Stop(ctx, "does-not-exist"); err != nil {
		t.Fatalf("Stop on missing container should be treated as success, got: %v", err)
	}

	res, err := Delete(ctx, "does-not-exist", "does-not-exist-vol")
	if err != nil {
		t.Fatalf("Delete on missing container+volume should be treated as success, got: %v", err)
	}
	if res.FreedStorageGB != 0 {
		t.Fatalf("expected FreedStorageGB=0 when measurement is skipped, got %d", res.FreedStorageGB)
	}
}
