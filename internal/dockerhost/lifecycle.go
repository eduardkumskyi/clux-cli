// Package dockerhost implements the CLI-side half of
// ByocWorkspaceProvider's workspace.start/stop/delete commands
// (backend/apps/workspaces/services/byoc_provider.go): the generic
// container launcher that runs on the host machine contributing compute.
//
// Isolation scope, explicitly: every container is attached to a dedicated
// bridge network (sandboxNetwork) rather than Docker's default bridge, so
// sandboxes can't casually reach other containers running on this host
// through container-to-container networking on the default bridge. That is
// the ONLY isolation this package provides. It does NOT lock down egress to
// the host's LAN or the wider internet -- containers on any bridge network
// can still reach the host's LAN and the internet via the host's routing
// table and NAT, same as any other Docker container. True network egress
// lockdown would require host-level firewall rules (iptables/nftables on
// Linux, pf on macOS, Windows Firewall on Windows), which are platform-
// specific and explicitly out of scope for this pass.
package dockerhost

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// sandboxNetwork is the dedicated bridge network every BYOC workspace
// container is attached to. See the package doc comment for exactly what
// isolation this does (and does not) provide.
const sandboxNetwork = "clux-sandbox"

// startPollAttempts/startPollInterval bound how long Start waits for a
// freshly-`docker run -d`'d container to report itself Running before
// giving up. Container start is not instant (image already pulled vs. a
// cold pull, entrypoint init work), so a single immediate inspect can race
// a container that is about to come up fine.
const (
	startPollAttempts = 10
	startPollInterval = 500 * time.Millisecond
)

// StartRequest mirrors the fields ByocWorkspaceProvider._provision sends on
// a workspace.start frame.
type StartRequest struct {
	ContainerName        string
	VolumeName           string
	Image                string
	CPULimit             float64
	MemoryLimitMB        int64
	SidecarContainerPort int
	GithubCloneURL       string // empty if the backend sent null
	HMACSecret           string
}

// StartResult is the "extra" fields merged into the workspace.start result
// frame on success.
type StartResult struct {
	SidecarPort int
}

// EnsureNetwork creates the dedicated sandbox bridge network if it doesn't
// already exist. Idempotent: safe to call on every workspace.start.
func EnsureNetwork(ctx context.Context) error {
	out, err := runDocker(ctx, "network", "inspect", sandboxNetwork)
	if err == nil {
		return nil
	}
	_ = out // inspect's error output isn't useful beyond "doesn't exist"; fall through to create.

	if _, err := runDocker(ctx, "network", "create", "--driver", "bridge", sandboxNetwork); err != nil {
		// Tolerate a race against another goroutine/process creating it
		// concurrently (docker network create isn't itself atomic-safe
		// against a parallel create of the same name).
		if _, inspectErr := runDocker(ctx, "network", "inspect", sandboxNetwork); inspectErr == nil {
			return nil
		}
		return fmt.Errorf("creating network %s: %w", sandboxNetwork, err)
	}
	return nil
}

// Start runs `docker run -d` for req, polls briefly for the container to be
// Running, then reads back the host-side published port for
// SidecarContainerPort. On any failure it best-effort removes the
// container it just tried to create before returning the error.
func Start(ctx context.Context, req StartRequest) (StartResult, error) {
	if err := EnsureNetwork(ctx); err != nil {
		return StartResult{}, err
	}

	args := []string{
		"run", "-d",
		"--name", req.ContainerName,
		"--network", sandboxNetwork,
		"--cpus", formatFloat(req.CPULimit),
		"--memory", fmt.Sprintf("%dm", req.MemoryLimitMB),
		"-p", fmt.Sprintf("127.0.0.1::%d", req.SidecarContainerPort),
		"-v", fmt.Sprintf("%s:/workspace", req.VolumeName),
	}
	if req.GithubCloneURL != "" {
		args = append(args, "-e", "GITHUB_CLONE_URL="+req.GithubCloneURL)
	}
	if req.HMACSecret != "" {
		args = append(args, "-e", "HMAC_SECRET="+req.HMACSecret)
	}
	args = append(args, req.Image)

	if _, err := runDocker(ctx, args...); err != nil {
		cleanupFailedStart(req.ContainerName)
		return StartResult{}, fmt.Errorf("docker run failed: %w", err)
	}

	if err := waitRunning(ctx, req.ContainerName); err != nil {
		cleanupFailedStart(req.ContainerName)
		return StartResult{}, err
	}

	port, err := publishedPort(ctx, req.ContainerName, req.SidecarContainerPort)
	if err != nil {
		cleanupFailedStart(req.ContainerName)
		return StartResult{}, err
	}

	return StartResult{SidecarPort: port}, nil
}

// Stop stops and removes the named container. Both docker stop and docker
// rm treat "no such container" as success -- workspace.stop is idempotent
// by contract (ByocWorkspaceProvider.stop/replace may be called on a
// workspace whose container is already gone).
func Stop(ctx context.Context, containerName string) error {
	return stopAndRemove(ctx, containerName)
}

// DeleteResult is the "extra" fields merged into the workspace.delete
// result frame on success.
type DeleteResult struct {
	FreedStorageGB int
}

// Delete stops+removes the container (idempotent, same as Stop) and then
// removes the named volume (idempotent if already gone). Best-effort
// measures the volume's size before removing it so the backend can
// decrement storage_gb_reserved; a measurement failure is not fatal to the
// delete itself, it just reports 0 freed.
func Delete(ctx context.Context, containerName, volumeName string) (DeleteResult, error) {
	if err := stopAndRemove(ctx, containerName); err != nil {
		return DeleteResult{}, err
	}

	freedGB := measureVolumeGB(ctx, volumeName)

	if _, err := runDocker(ctx, "volume", "rm", volumeName); err != nil {
		if !isMissingVolume(err) {
			return DeleteResult{}, fmt.Errorf("docker volume rm failed: %w", err)
		}
	}

	return DeleteResult{FreedStorageGB: freedGB}, nil
}

// --- helpers -----------------------------------------------------------

func stopAndRemove(ctx context.Context, containerName string) error {
	if containerName == "" {
		return nil
	}
	if _, err := runDocker(ctx, "stop", containerName); err != nil && !isMissingContainer(err) {
		return fmt.Errorf("docker stop failed: %w", err)
	}
	if _, err := runDocker(ctx, "rm", "-f", containerName); err != nil && !isMissingContainer(err) {
		return fmt.Errorf("docker rm failed: %w", err)
	}
	return nil
}

func cleanupFailedStart(containerName string) {
	// Best-effort: ignore errors, this is already an error path and the
	// container may not even exist yet (e.g. docker run itself failed).
	_, _ = runDocker(context.Background(), "rm", "-f", containerName)
}

func waitRunning(ctx context.Context, containerName string) error {
	var lastErr error
	for i := 0; i < startPollAttempts; i++ {
		out, err := runDocker(ctx, "inspect", "-f", "{{.State.Running}}", containerName)
		if err != nil {
			lastErr = err
		} else if strings.TrimSpace(out) == "true" {
			return nil
		} else {
			lastErr = fmt.Errorf("container %s state: %s", containerName, strings.TrimSpace(out))
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(startPollInterval):
		}
	}
	return fmt.Errorf("container %s did not reach running state: %w", containerName, lastErr)
}

func publishedPort(ctx context.Context, containerName string, containerPort int) (int, error) {
	out, err := runDocker(ctx, "port", containerName, fmt.Sprintf("%d/tcp", containerPort))
	if err != nil {
		return 0, fmt.Errorf("docker port failed: %w", err)
	}
	// Output looks like "127.0.0.1:34567" (possibly multiple lines if
	// published on more than one address); take the first line's port.
	line := strings.TrimSpace(strings.SplitN(out, "\n", 2)[0])
	idx := strings.LastIndex(line, ":")
	if idx < 0 || idx == len(line)-1 {
		return 0, fmt.Errorf("unexpected docker port output: %q", out)
	}
	port, err := strconv.Atoi(line[idx+1:])
	if err != nil {
		return 0, fmt.Errorf("parsing published port from %q: %w", out, err)
	}
	return port, nil
}

// measureVolumeGB best-effort measures a volume's on-disk size in whole GB
// using a disposable busybox container, before the caller removes the
// volume. Returns 0 (not an error) on any failure -- this is a nice-to-
// have for storage accounting, not required for delete to succeed.
func measureVolumeGB(ctx context.Context, volumeName string) int {
	out, err := runDocker(ctx, "run", "--rm",
		"-v", volumeName+":/data:ro",
		"busybox", "du", "-sb", "/data")
	if err != nil {
		return 0
	}
	fields := strings.Fields(out)
	if len(fields) == 0 {
		return 0
	}
	bytesUsed, err := strconv.ParseInt(fields[0], 10, 64)
	if err != nil {
		return 0
	}
	const gb = 1 << 30
	return int(bytesUsed / gb)
}

func isMissingContainer(err error) bool {
	return containsAny(err.Error(), "no such container", "No such container")
}

func isMissingVolume(err error) bool {
	return containsAny(err.Error(), "no such volume", "No such volume")
}

func containsAny(s string, substrs ...string) bool {
	for _, sub := range substrs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func formatFloat(f float64) string {
	return strconv.FormatFloat(f, 'f', -1, 64)
}

func runDocker(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "docker", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = strings.TrimSpace(stdout.String())
		}
		if msg == "" {
			msg = err.Error()
		}
		return stdout.String(), fmt.Errorf("docker %s: %s", strings.Join(args, " "), msg)
	}
	return stdout.String(), nil
}
