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
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/eduardkumskyi/clux-cli/internal/redact"
)

// containerLocks serializes Start/Stop/Delete per container name. Lifecycle
// commands outlive the tunnel session that issued them (they run under the
// process context), so after a reconnect the backend can re-issue a
// workspace.start for a container whose previous start is still running.
// Without this, the second start's stopAndRemove would kill the first run's
// container and the first run's failure cleanup would then remove the
// second run's container.
var (
	containerLocksMu sync.Mutex
	containerLocks   = map[string]chan struct{}{}
)

// lockContainer takes the per-name lock (ctx-aware); call the returned
// unlock exactly once.
func lockContainer(ctx context.Context, name string) (func(), error) {
	if name == "" {
		return func() {}, nil
	}
	containerLocksMu.Lock()
	ch, ok := containerLocks[name]
	if !ok {
		ch = make(chan struct{}, 1)
		containerLocks[name] = ch
	}
	containerLocksMu.Unlock()
	select {
	case ch <- struct{}{}:
		return func() { <-ch }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

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
	// BackendURL becomes the sidecar's CLUX_BACKEND_URL (host commands);
	// "" when the backend sent none. Validated by the caller.
	BackendURL string
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
	unlock, err := lockContainer(ctx, req.ContainerName)
	if err != nil {
		return StartResult{}, err
	}
	defer unlock()

	if err := EnsureNetwork(ctx); err != nil {
		return StartResult{}, err
	}

	// Remove any stale container with this exact managed name before running a
	// fresh one. A workspace that errored or was force-stopped can leave its
	// container behind; without this, `docker run --name` fails with a name
	// conflict on every retry ("container name ... is already in use"), so the
	// workspace can never recover. stopAndRemove treats "no such container" as
	// success, so this is a no-op on a clean first start. The per-workspace
	// data volume is separate and untouched, so no user data is lost.
	_ = stopAndRemove(ctx, req.ContainerName)

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
		// The sidecar reads SIDECAR_HMAC_SECRET (sidecar.py). With only
		// HMAC_SECRET set it ran with no secret at all, which it treats as
		// "local dev, auth off": any local process could open its control
		// WebSocket on the published 127.0.0.1 port. HMAC_SECRET stays for
		// images that might still look for it.
		args = append(args, "-e", "SIDECAR_HMAC_SECRET="+req.HMACSecret, "-e", "HMAC_SECRET="+req.HMACSecret)
	}
	if req.BackendURL != "" {
		args = append(args, "-e", "CLUX_BACKEND_URL="+req.BackendURL)
	}
	args = append(args, req.Image)

	// Pull first, on our terms: `docker run`'s own implicit pull fails on a
	// stale saved login (see ensureImage), with no way to retry.
	if err := ensureImage(ctx, req.Image); err != nil {
		return StartResult{}, err
	}

	out, err := runDocker(ctx, args...)
	// `docker run -d` prints the new container's ID; cleanup targets that
	// exact container, never just the name (see containerLocks).
	containerID := strings.TrimSpace(out)
	if err != nil {
		cleanupFailedStart(containerID, req.ContainerName)
		// The full command helps diagnosis; it carries the sidecar secret
		// and maybe a clone token, so only ever log it redacted.
		log.Printf("docker %s", strings.Join(redact.Args(args), " "))
		return StartResult{}, fmt.Errorf("docker run failed: %s", dockerMessage(err))
	}

	if err := waitRunning(ctx, req.ContainerName); err != nil {
		cleanupFailedStart(containerID, req.ContainerName)
		return StartResult{}, err
	}

	port, err := publishedPort(ctx, req.ContainerName, req.SidecarContainerPort)
	if err != nil {
		cleanupFailedStart(containerID, req.ContainerName)
		return StartResult{}, err
	}

	return StartResult{SidecarPort: port}, nil
}

// Stop stops and removes the named container. Both docker stop and docker
// rm treat "no such container" as success -- workspace.stop is idempotent
// by contract (ByocWorkspaceProvider.stop/replace may be called on a
// workspace whose container is already gone).
func Stop(ctx context.Context, containerName string) error {
	unlock, err := lockContainer(ctx, containerName)
	if err != nil {
		return err
	}
	defer unlock()
	return stopAndRemove(ctx, containerName)
}

// Running reports whether the named container exists and is running.
func Running(ctx context.Context, containerName string) (bool, error) {
	if containerName == "" {
		return false, nil
	}
	out, err := runDocker(ctx, "inspect", "-f", "{{.State.Running}}", containerName)
	if err != nil {
		if isMissingContainer(err) || containsAny(err.Error(), "No such object", "no such object") {
			return false, nil
		}
		return false, err
	}
	return strings.TrimSpace(out) == "true", nil
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
	unlock, err := lockContainer(ctx, containerName)
	if err != nil {
		return DeleteResult{}, err
	}
	defer unlock()
	if err := stopAndRemove(ctx, containerName); err != nil {
		return DeleteResult{}, err
	}

	freedGB := measureVolumeGB(ctx, volumeName)

	if _, err := runDocker(ctx, "volume", "rm", volumeName); err != nil {
		if !isMissingVolume(err) {
			return DeleteResult{}, fmt.Errorf("docker volume rm failed: %s", dockerMessage(err))
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
		return fmt.Errorf("docker stop failed: %s", dockerMessage(err))
	}
	if _, err := runDocker(ctx, "rm", "-f", containerName); err != nil && !isMissingContainer(err) {
		return fmt.Errorf("docker rm failed: %s", dockerMessage(err))
	}
	return nil
}

// cleanupFailedStart removes the container this Start created. By ID when
// docker printed one; by name only when it didn't (docker run failed before
// creating anything, or after creating it without printing) -- safe because
// the caller holds this name's lock, so no other Start/Stop/Delete can own a
// container of that name right now.
func cleanupFailedStart(containerID, containerName string) {
	target := containerID
	if !looksLikeContainerID(target) {
		target = containerName
	}
	if target == "" {
		return
	}
	// Best-effort: ignore errors, this is already an error path.
	_, _ = runDocker(context.Background(), "rm", "-f", target)
}

func looksLikeContainerID(s string) bool {
	if len(s) < 12 || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
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
		return 0, fmt.Errorf("docker port failed: %s", dockerMessage(err))
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

// publicECR is the registry the sidecar image is published to.
const publicECR = "public.ecr.aws"

// ensureImage makes sure image is present locally, pulling it if not (the
// same "missing" policy as `docker run`'s implicit pull, so a cached image
// starts offline too).
//
// A saved but expired login for public.ecr.aws in the user's
// ~/.docker/config.json (or credential store) makes every pull from it
// fail, even of a public image: the registry refuses expired credentials
// instead of ignoring them. For public.ecr.aws images such a pull is
// retried anonymously, with a temporary empty Docker config, which leaves
// the user's own config untouched.
func ensureImage(ctx context.Context, image string) error {
	if image == "" {
		return nil // `docker run` reports it
	}
	if _, err := runDocker(ctx, "image", "inspect", "--format", "{{.Id}}", image); err == nil {
		return nil
	}
	_, err := runDocker(ctx, "pull", "--quiet", image)
	if err == nil {
		return nil
	}
	msg := dockerMessage(err)
	if !isRegistryAuthError(msg) {
		return fmt.Errorf("pulling image %s failed: %s", image, msg)
	}
	reg := registryOf(image)
	if reg != publicECR {
		return fmt.Errorf("pulling image %s failed: the registry refused your saved Docker login for %s "+
			"(run `docker login %s` again, or `docker logout %s`): %s", image, reg, reg, reg, msg)
	}
	if _, aerr := runDockerAnonymous(ctx, "pull", "--quiet", image); aerr != nil {
		return fmt.Errorf("pulling image %s failed: your saved Docker login for %s was refused (%s), "+
			"and pulling anonymously failed too: %s", image, publicECR, msg, dockerMessage(aerr))
	}
	log.Printf("your saved Docker login for %s has expired; pulled %s anonymously "+
		"(`docker logout %s` removes the stale login)", publicECR, image, publicECR)
	return nil
}

// isRegistryAuthError: the registry refused the credentials docker sent.
func isRegistryAuthError(msg string) bool {
	m := strings.ToLower(msg)
	return containsAny(m,
		"authorization token has expired", "token has expired", "reauthenticate",
		"pull access denied", "unauthorized", "authentication required",
		"denied: ", "403 forbidden", "no basic auth credentials", "error getting credentials")
}

// registryOf is the registry host of an image reference ("docker.io" for
// Docker Hub's short names).
func registryOf(image string) string {
	first, _, ok := strings.Cut(image, "/")
	if !ok || !(strings.ContainsAny(first, ".:") || first == "localhost") {
		return "docker.io"
	}
	return strings.ToLower(first)
}

// dockerError is a failed docker command: which one, and what it said.
// The arguments are deliberately not in the message (they can hold
// secrets, and make it unreadable); callers that want the command line log
// it themselves via redact.Args.
type dockerError struct {
	verb string
	msg  string
}

func (e *dockerError) Error() string { return "docker " + e.verb + ": " + e.msg }

// dockerMessage is what docker itself said, without the "docker <verb>:"
// prefix.
func dockerMessage(err error) string {
	var de *dockerError
	if errors.As(err, &de) {
		return de.msg
	}
	return err.Error()
}

// dockerVerb names a command for messages: "run", "network create", ...
func dockerVerb(args []string) string {
	if len(args) == 0 {
		return ""
	}
	switch args[0] {
	case "network", "volume", "image", "container", "context":
		if len(args) > 1 {
			return args[0] + " " + args[1]
		}
	}
	return args[0]
}

// runDocker and runDockerAnonymous are variables so tests can substitute a
// fake docker.
var (
	runDocker          = func(ctx context.Context, args ...string) (string, error) { return runDockerExec(ctx, nil, args...) }
	runDockerAnonymous = runDockerWithoutLogin
)

// runDockerWithoutLogin runs docker with a temporary, empty Docker config:
// no saved logins and no credential helpers. The daemon endpoint is
// carried over (DOCKER_HOST), since the active context (Docker Desktop,
// colima, ...) lives in the config being skipped.
func runDockerWithoutLogin(ctx context.Context, args ...string) (string, error) {
	var env []string
	if os.Getenv("DOCKER_HOST") == "" {
		if out, err := runDockerExec(ctx, nil, "context", "inspect", "--format", "{{.Endpoints.docker.Host}}"); err == nil {
			if host := strings.TrimSpace(out); host != "" {
				env = append(env, "DOCKER_HOST="+host)
			}
		}
	}
	dir, err := os.MkdirTemp("", "clux-docker-anon-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte("{}\n"), 0o600); err != nil {
		return "", err
	}
	return runDockerExec(ctx, append(env, "DOCKER_CONFIG="+dir), args...)
}

// runDockerExec runs docker with the process environment plus env.
func runDockerExec(ctx context.Context, env []string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "docker", args...)
	if len(env) > 0 {
		cmd.Env = append(os.Environ(), env...)
	}
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
		return stdout.String(), &dockerError{verb: dockerVerb(args), msg: redact.String(msg)}
	}
	return stdout.String(), nil
}
