package hostsession

import (
	"context"
	"errors"
	"fmt"

	"github.com/eduardkumskyi/clux-cli/internal/egress"
	"github.com/eduardkumskyi/clux-cli/internal/sidecarrt"
	"github.com/eduardkumskyi/clux-cli/internal/supervisor"
)

// SupervisorCaller is the slice of supervisor.Client the native runtime
// uses (an interface so tests can fake the agent-user daemons).
type SupervisorCaller interface {
	Call(ctx context.Context, req supervisor.Request) (supervisor.Response, error)
}

// RuntimeInstaller is the slice of sidecarrt.Installer the native runtime
// uses.
type RuntimeInstaller interface {
	Ensure(ctx context.Context, b sidecarrt.Bundle, inUse []string) (sidecarrt.Runtime, error)
}

// NativeRuntime runs each workspace as its own agent user ("slot", see
// internal/native) via that slot's supervisor (`clux native supervise
// --slot n`). The owner side does what needs the owner's rights: assigning
// slots, installing the sidecar runtime (needs the host PAT) and the
// egress proxy the workspace's traffic is forced through.
type NativeRuntime struct {
	// Supervisor returns slot n's supervisor client.
	Supervisor func(slot int) SupervisorCaller
	Slots      *SlotMap
	Installer  RuntimeInstaller
	Egress     *egress.Proxy
	ProxyPort  int
}

// Start implements Runtime. Docker-only fields (image, volume_name, cpu and
// memory limits) are ignored.
func (n *NativeRuntime) Start(ctx context.Context, frame map[string]any) (map[string]any, error) {
	id, err := n.id(frame)
	if err != nil {
		return nil, err
	}
	bundle, err := sidecarrt.BundleFromFrame(frame["sidecar_bundle"])
	if err != nil {
		return nil, err
	}
	secret := stringField(frame, "hmac_secret")
	if secret == "" {
		return nil, errors.New("hmac_secret is required")
	}
	slot, err := n.Slots.Assign(id, func(slot int) bool {
		// A slot is only handed out if its supervisor answers and no other
		// workspace's files are in it (e.g. the assignments file was lost).
		st, err := n.Supervisor(slot).Call(ctx, supervisor.Request{Op: supervisor.OpStatus})
		if err != nil {
			return false
		}
		for _, r := range st.Resident {
			if r != id {
				return false
			}
		}
		return true
	})
	if err != nil {
		return nil, err
	}
	sup := n.Supervisor(slot)
	// The policy is in place before the sidecar exists, so its very first
	// request is already checked. A start without "egress" keeps what the
	// proxy remembers for the workspace (else: empty allow list).
	pol, known := n.Egress.Policy(id)
	if v, ok := frame["egress"]; ok || !known {
		pol = egress.PolicyFromFrame(v)
	}
	if err := n.Egress.SetPolicy(id, pol); err != nil {
		return nil, err
	}
	rt, err := n.Installer.Ensure(ctx, bundle, n.runtimesInUse(ctx))
	if err != nil {
		return nil, err
	}
	resp, err := sup.Call(ctx, supervisor.Request{
		Op:             supervisor.OpStart,
		WorkspaceID:    id,
		HMACSecret:     secret,
		GithubCloneURL: stringField(frame, "github_clone_url"),
		ProxyURL:       n.Egress.URL(id, n.ProxyPort),
		Runtime: &supervisor.RuntimeSpec{
			Version: rt.Version, Dir: rt.Dir, Python: rt.Python, Sidecar: rt.Sidecar, Claude: rt.Claude,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("native slot %d: %w", slot, err)
	}
	return map[string]any{"sidecar_port": resp.SidecarPort}, nil
}

// runtimesInUse lists the runtime versions running sidecars use (kept by
// the installer's pruning).
func (n *NativeRuntime) runtimesInUse(ctx context.Context) []string {
	var inUse []string
	for slot := 1; slot <= n.Slots.Total(); slot++ {
		st, err := n.Supervisor(slot).Call(ctx, supervisor.Request{Op: supervisor.OpStatus})
		if err != nil {
			continue
		}
		for _, w := range st.Workspaces {
			if w.Running {
				inUse = append(inUse, w.RuntimeVersion)
			}
		}
	}
	return inUse
}

// Stop implements Runtime. The egress policy and the slot are kept for the
// next start; a workspace that never got a slot has nothing to stop.
func (n *NativeRuntime) Stop(ctx context.Context, frame map[string]any) error {
	id, err := n.id(frame)
	if err != nil {
		return err
	}
	slot, ok := n.Slots.Lookup(id)
	if !ok {
		return nil
	}
	_, err = n.Supervisor(slot).Call(ctx, supervisor.Request{Op: supervisor.OpStop, WorkspaceID: id})
	return err
}

// Delete implements Runtime: the slot is wiped by its supervisor, then
// freed for another workspace.
func (n *NativeRuntime) Delete(ctx context.Context, frame map[string]any) (map[string]any, error) {
	id, err := n.id(frame)
	if err != nil {
		return nil, err
	}
	var freed int64
	if slot, ok := n.Slots.Lookup(id); ok {
		resp, err := n.Supervisor(slot).Call(ctx, supervisor.Request{Op: supervisor.OpDelete, WorkspaceID: id})
		if err != nil {
			return nil, err
		}
		freed = resp.FreedBytes
		if err := n.Slots.Release(id); err != nil {
			return nil, err
		}
	}
	n.Egress.Forget(id)
	return map[string]any{"freed_storage_gb": int(freed >> 30)}, nil
}

// Status implements Runtime.
func (n *NativeRuntime) Status(ctx context.Context, frame map[string]any) (map[string]any, error) {
	id, err := n.id(frame)
	if err != nil {
		return nil, err
	}
	slot, ok := n.Slots.Lookup(id)
	if !ok {
		return map[string]any{"running": false}, nil
	}
	st, err := n.Supervisor(slot).Call(ctx, supervisor.Request{Op: supervisor.OpStatus})
	if err != nil {
		return nil, err
	}
	for _, w := range st.Workspaces {
		if w.ID == id {
			return map[string]any{"running": w.Running, "sidecar_port": w.Port}, nil
		}
	}
	return map[string]any{"running": false}, nil
}

func (n *NativeRuntime) id(frame map[string]any) (string, error) {
	id, err := workspaceIDField(frame)
	if err != nil {
		return "", err
	}
	if !egress.ValidWorkspaceID(id) {
		return "", fmt.Errorf("invalid workspace_id %q", id)
	}
	return id, nil
}
