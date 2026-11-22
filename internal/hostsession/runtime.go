package hostsession

import (
	"context"
	"fmt"
	"strconv"

	"github.com/eduardkumskyi/clux-cli/internal/dockerhost"
	"github.com/eduardkumskyi/clux-cli/internal/supervisor"
)

// Runtime names in the "runtime" field of workspace.start/stop/delete.
const (
	RuntimeDocker      = "docker"
	RuntimeNativeMacOS = "native_macos"
)

// Runtime runs workspaces of one kind. Each method receives the command
// frame as decoded and returns the extra fields merged into its result.
type Runtime interface {
	Start(ctx context.Context, frame map[string]any) (map[string]any, error)
	Stop(ctx context.Context, frame map[string]any) error
	Delete(ctx context.Context, frame map[string]any) (map[string]any, error)
	Status(ctx context.Context, frame map[string]any) (map[string]any, error)
}

// DockerRuntime is the Linux sidecar container on the local Docker daemon
// (internal/dockerhost). Its frames and results are exactly what they were
// before runtimes existed.
type DockerRuntime struct{}

// Start implements Runtime.
func (DockerRuntime) Start(ctx context.Context, frame map[string]any) (map[string]any, error) {
	req := dockerhost.StartRequest{
		ContainerName:        stringField(frame, "container_name"),
		VolumeName:           stringField(frame, "volume_name"),
		Image:                stringField(frame, "image"),
		CPULimit:             floatField(frame, "cpu_limit"),
		MemoryLimitMB:        intField(frame, "memory_limit_mb"),
		SidecarContainerPort: int(intField(frame, "sidecar_container_port")),
		GithubCloneURL:       stringField(frame, "github_clone_url"),
		HMACSecret:           stringField(frame, "hmac_secret"),
		BackendURL:           backendURLField(frame),
	}
	res, err := dockerhost.Start(ctx, req)
	if err != nil {
		return nil, err
	}
	return map[string]any{"sidecar_port": res.SidecarPort}, nil
}

// Stop implements Runtime.
func (DockerRuntime) Stop(ctx context.Context, frame map[string]any) error {
	return dockerhost.Stop(ctx, stringField(frame, "container_name"))
}

// Delete implements Runtime.
func (DockerRuntime) Delete(ctx context.Context, frame map[string]any) (map[string]any, error) {
	res, err := dockerhost.Delete(ctx, stringField(frame, "container_name"), stringField(frame, "volume_name"))
	if err != nil {
		return nil, err
	}
	return map[string]any{"freed_storage_gb": res.FreedStorageGB}, nil
}

// Status implements Runtime.
func (DockerRuntime) Status(ctx context.Context, frame map[string]any) (map[string]any, error) {
	running, err := dockerhost.Running(ctx, stringField(frame, "container_name"))
	if err != nil {
		return nil, err
	}
	return map[string]any{"running": running}, nil
}

// backendURLField is workspace.start's "backend_url" when it is a plain
// http(s) URL, else "" (older backends send none: the sidecar then runs
// without CLUX_BACKEND_URL and host commands are unavailable).
func backendURLField(frame map[string]any) string {
	raw := stringField(frame, "backend_url")
	if !supervisor.ValidBackendURL(raw) {
		return ""
	}
	return raw
}

// runtimeName reads a frame's "runtime" (absent = docker, which is what
// every backend that predates runtimes means).
func runtimeName(frame map[string]any) string {
	if s := stringField(frame, "runtime"); s != "" {
		return s
	}
	return RuntimeDocker
}

// workspaceIDField reads "workspace_id", which the backend sends as a JSON
// number (string ids are accepted too).
func workspaceIDField(frame map[string]any) (string, error) {
	switch v := frame["workspace_id"].(type) {
	case float64:
		if v != float64(int64(v)) || v < 0 {
			return "", fmt.Errorf("invalid workspace_id %v", v)
		}
		return strconv.FormatInt(int64(v), 10), nil
	case string:
		if v != "" {
			return v, nil
		}
	}
	return "", fmt.Errorf("workspace_id is required")
}
