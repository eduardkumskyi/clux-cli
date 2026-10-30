// Package hostsession implements tunnel.Handler for `clux host start`:
// it dispatches workspace.start/stop/delete command frames to the
// dockerhost package and dial.open/data/close frames to the dialproxy
// package, replying over the same Session the frames arrived on.
package hostsession

import (
	"context"
	"fmt"
	"log"

	"github.com/eduardkumskyi/clux-cli/internal/dialproxy"
	"github.com/eduardkumskyi/clux-cli/internal/dockerhost"
	"github.com/eduardkumskyi/clux-cli/internal/tunnel"
)

// Handler implements tunnel.Handler, bridging inbound lifecycle/dial
// frames to the docker lifecycle + dial proxy packages.
type Handler struct {
	sess  *tunnel.Session
	dials *dialproxy.Registry
	// cmdCtx scopes docker lifecycle commands to the PROCESS, not the tunnel
	// session: a network blip must not kill a `docker run`/`docker stop`
	// halfway (the backend aborts its wait on reconnect, and the next start
	// is idempotent, so letting the command finish is always the safer
	// outcome). Ctrl+C still cancels it.
	cmdCtx context.Context
	// results carries command results across sessions (may be nil: then
	// results go straight to sess).
	results *Results
}

// New builds a handler for one tunnel session. cmdCtx is the process-level
// context lifecycle commands run under (see Handler.cmdCtx).
// results (optional) is the process-wide courier that re-sends a result
// whose session died before it went out.
func New(cmdCtx context.Context, sess *tunnel.Session, results *Results) *Handler {
	return &Handler{sess: sess, dials: dialproxy.NewRegistry(), cmdCtx: cmdCtx, results: results}
}

// Close tears down every local dial stream of this session. Running
// workspace containers are NOT touched -- they keep running across
// disconnects and are reattached by the next session's dials.
func (h *Handler) Close() { h.dials.CloseAll() }

// HandleCommand implements tunnel.Handler. It is already invoked in its
// own goroutine by Session.Run's reader loop, so it may block on docker
// freely. The session ctx is deliberately ignored in favor of cmdCtx.
func (h *Handler) HandleCommand(_ context.Context, frameType string, frame map[string]any) {
	ctx := h.cmdCtx
	if ctx == nil {
		ctx = context.Background()
	}
	correlationID, _ := frame["correlation_id"].(string)
	result := map[string]any{
		"type":           "result",
		"correlation_id": correlationID,
	}

	extra, err := dispatchCommand(ctx, frameType, frame)
	if err != nil {
		// Surface the failure locally too — otherwise the only trace is the
		// result frame sent back to the backend, and the operator watching
		// `clux host start` sees nothing while the dashboard shows a generic
		// "Workspace failed to start".
		log.Printf("command %s failed: %v", frameType, err)
		result["ok"] = false
		result["error"] = err.Error()
	} else {
		log.Printf("command %s ok", frameType)
		result["ok"] = true
		for k, v := range extra {
			result[k] = v
		}
	}
	if h.results != nil {
		h.results.Deliver(result)
		return
	}
	h.sess.Send(result)
}

func dispatchCommand(ctx context.Context, frameType string, frame map[string]any) (map[string]any, error) {
	switch frameType {
	case "workspace.start":
		req := dockerhost.StartRequest{
			ContainerName:        stringField(frame, "container_name"),
			VolumeName:           stringField(frame, "volume_name"),
			Image:                stringField(frame, "image"),
			CPULimit:             floatField(frame, "cpu_limit"),
			MemoryLimitMB:        intField(frame, "memory_limit_mb"),
			SidecarContainerPort: int(intField(frame, "sidecar_container_port")),
			GithubCloneURL:       stringField(frame, "github_clone_url"),
			HMACSecret:           stringField(frame, "hmac_secret"),
		}
		res, err := dockerhost.Start(ctx, req)
		if err != nil {
			return nil, err
		}
		return map[string]any{"sidecar_port": res.SidecarPort}, nil

	case "workspace.stop":
		containerName := stringField(frame, "container_name")
		if err := dockerhost.Stop(ctx, containerName); err != nil {
			return nil, err
		}
		return nil, nil

	case "workspace.delete":
		containerName := stringField(frame, "container_name")
		volumeName := stringField(frame, "volume_name")
		res, err := dockerhost.Delete(ctx, containerName, volumeName)
		if err != nil {
			return nil, err
		}
		return map[string]any{"freed_storage_gb": res.FreedStorageGB}, nil

	default:
		return nil, fmt.Errorf("unknown command type %q", frameType)
	}
}

// HandleDialOpen implements tunnel.Handler. Already invoked in its own
// goroutine by Session.Run's reader loop.
func (h *Handler) HandleDialOpen(ctx context.Context, streamID string, port int, secret string) {
	h.dials.Open(ctx, streamID, port, secret, h.sess.Send)
}

// HandleDialData implements tunnel.Handler.
func (h *Handler) HandleDialData(streamID string, dataB64 string) {
	h.dials.Data(streamID, dataB64)
}

// HandleDialClose implements tunnel.Handler.
func (h *Handler) HandleDialClose(streamID string) {
	h.dials.Close(streamID)
}

func stringField(frame map[string]any, key string) string {
	v, _ := frame[key].(string)
	return v
}

func floatField(frame map[string]any, key string) float64 {
	v, _ := frame[key].(float64)
	return v
}

func intField(frame map[string]any, key string) int64 {
	v, _ := frame[key].(float64) // encoding/json decodes all JSON numbers into map[string]any as float64
	return int64(v)
}
