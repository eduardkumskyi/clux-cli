// Package hostsession implements tunnel.Handler for `clux host start`:
// it dispatches workspace.start/stop/delete command frames to the runtime
// named in their "runtime" field (docker via the dockerhost package, or the
// native macOS runtime), egress.policy/decision frames to the egress proxy,
// host_exec.run frames to the host-command executor (internal/hostexec),
// and dial.open/data/close frames to the dialproxy package, replying over
// the same Session the frames arrived on.
package hostsession

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/eduardkumskyi/clux-cli/internal/dialproxy"
	"github.com/eduardkumskyi/clux-cli/internal/egress"
	"github.com/eduardkumskyi/clux-cli/internal/hostexec"
	"github.com/eduardkumskyi/clux-cli/internal/redact"
	"github.com/eduardkumskyi/clux-cli/internal/tunnel"
)

// Handler implements tunnel.Handler, bridging inbound lifecycle/dial
// frames to the workspace runtimes + dial proxy packages.
type Handler struct {
	sess  *tunnel.Session
	dials *dialproxy.Registry
	// cmdCtx scopes lifecycle commands to the PROCESS, not the tunnel
	// session: a network blip must not kill a `docker run`/`docker stop`
	// halfway (the backend aborts its wait on reconnect, and the next start
	// is idempotent, so letting the command finish is always the safer
	// outcome). Ctrl+C still cancels it.
	cmdCtx context.Context
	// results carries command results across sessions (may be nil: then
	// results go straight to sess).
	results *Results
	opts    Options
}

// Options are the process-wide pieces a handler dispatches to.
type Options struct {
	// Runtimes by name; docker is always available (added if missing).
	Runtimes map[string]Runtime
	// Egress is the native runtime's egress proxy (nil without native mode).
	Egress *egress.Proxy
	// HostExec runs owner-approved host_exec.run commands (nil: refused).
	HostExec *hostexec.Executor
}

// New builds a handler for one tunnel session. cmdCtx is the process-level
// context lifecycle commands run under (see Handler.cmdCtx).
// results (optional) is the process-wide courier that re-sends a result
// whose session died before it went out.
func New(cmdCtx context.Context, sess *tunnel.Session, results *Results, opts Options) *Handler {
	rts := map[string]Runtime{RuntimeDocker: DockerRuntime{}}
	for k, v := range opts.Runtimes {
		rts[k] = v
	}
	opts.Runtimes = rts
	return &Handler{sess: sess, dials: dialproxy.NewRegistry(), cmdCtx: cmdCtx, results: results, opts: opts}
}

// Close tears down every local dial stream of this session. Running
// workspaces are NOT touched -- they keep running across disconnects and
// are reattached by the next session's dials.
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

	extra, err := h.dispatch(ctx, frameType, frame)
	if err != nil {
		// Surface the failure locally too — otherwise the only trace is the
		// result frame sent back to the backend, and the operator watching
		// `clux host start` sees nothing while the dashboard shows a generic
		// "Workspace failed to start".
		reason := failureReason(err)
		log.Printf("command %s failed: %s", frameType, reason)
		result["ok"] = false
		result["error"] = reason
	} else {
		if !strings.HasPrefix(frameType, "egress.") {
			log.Printf("command %s ok", frameType)
		}
		result["ok"] = true
		for k, v := range extra {
			result[k] = v
		}
	}
	// Egress frames may be fire-and-forget; only answer what can be matched.
	if strings.HasPrefix(frameType, "egress.") && correlationID == "" {
		return
	}
	if h.results != nil {
		h.results.Deliver(result)
		return
	}
	h.sess.Send(result)
}

func (h *Handler) dispatch(ctx context.Context, frameType string, frame map[string]any) (map[string]any, error) {
	switch frameType {
	case "workspace.start", "workspace.stop", "workspace.delete":
		name := runtimeName(frame)
		rt, ok := h.opts.Runtimes[name]
		if !ok {
			if name == RuntimeNativeMacOS {
				return nil, errors.New("native_macos runtime is not available on this host (macOS only; set it up with `sudo clux native install`, then restart `clux host start`)")
			}
			return nil, fmt.Errorf("unsupported runtime %q", name)
		}
		switch frameType {
		case "workspace.start":
			return rt.Start(ctx, frame)
		case "workspace.stop":
			return nil, rt.Stop(ctx, frame)
		default:
			return rt.Delete(ctx, frame)
		}

	case "egress.policy":
		if h.opts.Egress == nil {
			return nil, errors.New("no egress proxy on this host (native runtime not installed)")
		}
		id, err := workspaceIDField(frame)
		if err != nil {
			return nil, err
		}
		return nil, h.opts.Egress.SetPolicy(id, egress.PolicyFromFrame(frame))

	case "egress.decision":
		if h.opts.Egress == nil {
			return nil, errors.New("no egress proxy on this host (native runtime not installed)")
		}
		id, err := workspaceIDField(frame)
		if err != nil {
			return nil, err
		}
		decision := stringField(frame, "decision")
		switch decision {
		case egress.DecisionAllowOnce, egress.DecisionAllowProject, egress.DecisionDeny:
		default:
			return nil, fmt.Errorf("unknown egress decision %q", decision)
		}
		h.opts.Egress.Decide(id, stringField(frame, "request_id"), decision, stringField(frame, "host"))
		return nil, nil

	case "host_exec.run":
		// Accepted (or refused) at once; the outcome follows later as an
		// unsolicited host_exec.result frame (internal/hostexec).
		if h.opts.HostExec == nil {
			return nil, errors.New("host commands are not available on this host")
		}
		return nil, h.opts.HostExec.Start(frame)

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

// maxReasonBytes bounds a failure reason sent to the backend (it shows it
// to the user); room for the native runtime's sidecar log tail.
const maxReasonBytes = 4096

// failureReason is what a failed command reports, to host.log and to the
// backend: the error text with secrets masked, bounded in size.
func failureReason(err error) string {
	s := redact.String(err.Error())
	if len(s) > maxReasonBytes {
		s = strings.ToValidUTF8(s[:maxReasonBytes], "") + "…"
	}
	return s
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
