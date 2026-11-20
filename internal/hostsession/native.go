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
// uses (an interface so tests can fake the agent-user daemon).
type SupervisorCaller interface {
	Call(ctx context.Context, req supervisor.Request) (supervisor.Response, error)
}

// RuntimeInstaller is the slice of sidecarrt.Installer the native runtime
// uses.
type RuntimeInstaller interface {
	Ensure(ctx context.Context, b sidecarrt.Bundle, inUse []string) (sidecarrt.Runtime, error)
}

// NativeRuntime runs a workspace as the agent user via the native
// supervisor (`clux native supervise`). The owner side does what needs the
// owner's rights: installing the sidecar runtime (needs the host PAT) and
// the egress proxy the workspace's traffic is forced through.
type NativeRuntime struct {
	Supervisor SupervisorCaller
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
	var inUse []string
	if st, err := n.Supervisor.Call(ctx, supervisor.Request{Op: supervisor.OpStatus}); err == nil {
		for _, w := range st.Workspaces {
			if w.Running {
				inUse = append(inUse, w.RuntimeVersion)
			}
		}
	}
	rt, err := n.Installer.Ensure(ctx, bundle, inUse)
	if err != nil {
		return nil, err
	}
	resp, err := n.Supervisor.Call(ctx, supervisor.Request{
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
		return nil, err
	}
	return map[string]any{"sidecar_port": resp.SidecarPort}, nil
}

// Stop implements Runtime. The egress policy is kept for the next start.
func (n *NativeRuntime) Stop(ctx context.Context, frame map[string]any) error {
	id, err := n.id(frame)
	if err != nil {
		return err
	}
	_, err = n.Supervisor.Call(ctx, supervisor.Request{Op: supervisor.OpStop, WorkspaceID: id})
	return err
}

// Delete implements Runtime.
func (n *NativeRuntime) Delete(ctx context.Context, frame map[string]any) (map[string]any, error) {
	id, err := n.id(frame)
	if err != nil {
		return nil, err
	}
	resp, err := n.Supervisor.Call(ctx, supervisor.Request{Op: supervisor.OpDelete, WorkspaceID: id})
	if err != nil {
		return nil, err
	}
	n.Egress.Forget(id)
	return map[string]any{"freed_storage_gb": int(resp.FreedBytes >> 30)}, nil
}

// Status implements Runtime.
func (n *NativeRuntime) Status(ctx context.Context, frame map[string]any) (map[string]any, error) {
	id, err := n.id(frame)
	if err != nil {
		return nil, err
	}
	st, err := n.Supervisor.Call(ctx, supervisor.Request{Op: supervisor.OpStatus})
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
