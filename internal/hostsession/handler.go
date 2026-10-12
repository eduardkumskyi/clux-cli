// Package hostsession implements tunnel.Handler for `clux host start`:
// it dispatches workspace.start/stop/delete command frames to the
// dockerhost package and dial.open/data/close frames to the dialproxy
// package, replying over the same Session the frames arrived on.
package hostsession

import (
	"context"
	"fmt"

	"github.com/eduardkumskyi/clux-cli/internal/dialproxy"
	"github.com/eduardkumskyi/clux-cli/internal/dockerhost"
	"github.com/eduardkumskyi/clux-cli/internal/tunnel"
)

// Handler implements tunnel.Handler, bridging inbound lifecycle/dial
// frames to the docker lifecycle + dial proxy packages.
type Handler struct {
	sess  *tunnel.Session
	dials *dialproxy.Registry
}

func New(sess *tunnel.Session) *Handler {
	return &Handler{sess: sess, dials: dialproxy.NewRegistry()}
}

// HandleCommand implements tunnel.Handler. It is already invoked in its
// own goroutine by Session.Run's reader loop, so it may block on docker
// freely.
func (h *Handler) HandleCommand(ctx context.Context, frameType string, frame map[string]any) {
	correlationID, _ := frame["correlation_id"].(string)
	result := map[string]any{
		"type":           "result",
		"correlation_id": correlationID,
	}

	extra, err := dispatchCommand(ctx, frameType, frame)
	if err != nil {
		result["ok"] = false
		result["error"] = err.Error()
	} else {
		result["ok"] = true
		for k, v := range extra {
			result[k] = v
		}
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
