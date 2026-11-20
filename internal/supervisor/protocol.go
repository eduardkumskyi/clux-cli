// Package supervisor is `clux native supervise`, the agent-user daemon
// that owns native workspace processes, and the client `clux host start`
// uses to drive it.
//
// Protocol: one JSON request line, one JSON response line per connection on
// a unix socket (/private/var/run/clux-native/supervisor.sock, _clux:_cluxctl
// 0660). The socket mode keeps everyone but the owner out at the
// filesystem level; the supervisor additionally checks the peer's uid
// (LOCAL_PEERCRED) against the configured owner, so a process that merely
// has the group can't drive it either.
package supervisor

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"
)

// Ops.
const (
	OpStart  = "start"
	OpStop   = "stop"
	OpDelete = "delete"
	OpStatus = "status"
)

// Sandbox states reported in Status (and in host capabilities).
const (
	SandboxActive      = "active"
	SandboxUnavailable = "unavailable"
)

// maxLine bounds one protocol line (a start request carries a few short
// strings; status lists workspaces).
const maxLine = 1 << 20

// Request is one supervisor call.
type Request struct {
	Op             string       `json:"op"`
	WorkspaceID    string       `json:"workspace_id,omitempty"`
	HMACSecret     string       `json:"hmac_secret,omitempty"`
	GithubCloneURL string       `json:"github_clone_url,omitempty"`
	ProxyURL       string       `json:"proxy_url,omitempty"`
	Runtime        *RuntimeSpec `json:"runtime,omitempty"`
}

// RuntimeSpec points at an installed sidecar runtime (see sidecarrt).
type RuntimeSpec struct {
	Version string `json:"version"`
	Dir     string `json:"dir"`     // runtime version dir (read-only for the agent)
	Python  string `json:"python"`  // venv interpreter
	Sidecar string `json:"sidecar"` // sidecar.py
	Claude  string `json:"claude"`  // claude CLI (CLAUDE_CLI_PATH)
}

// Response is the reply to a Request.
type Response struct {
	OK          bool              `json:"ok"`
	Error       string            `json:"error,omitempty"`
	SidecarPort int               `json:"sidecar_port,omitempty"`
	FreedBytes  int64             `json:"freed_bytes,omitempty"`
	Version     string            `json:"version,omitempty"`
	Sandbox     string            `json:"sandbox,omitempty"`
	Workspaces  []WorkspaceStatus `json:"workspaces,omitempty"`
}

// WorkspaceStatus describes one workspace the supervisor knows about.
type WorkspaceStatus struct {
	ID             string `json:"id"`
	PID            int    `json:"pid"`
	Port           int    `json:"port"`
	Running        bool   `json:"running"`
	RuntimeVersion string `json:"runtime_version"`
}

// Client talks to a supervisor socket.
type Client struct {
	Socket string
}

// Call sends req and waits for the reply (bounded by ctx). A reply with
// ok=false is returned as an error carrying the supervisor's message.
func (c *Client) Call(ctx context.Context, req Request) (Response, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", c.Socket)
	if err != nil {
		return Response{}, fmt.Errorf("native supervisor not reachable (%w); is native mode installed (`sudo clux native install`)?", err)
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	} else {
		_ = conn.SetDeadline(time.Now().Add(5 * time.Minute))
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()

	b, err := json.Marshal(req)
	if err != nil {
		return Response{}, err
	}
	if _, err := conn.Write(append(b, '\n')); err != nil {
		return Response{}, fmt.Errorf("native supervisor: %w", err)
	}
	resp, err := readResponse(conn)
	if err != nil {
		if ctx.Err() != nil {
			return Response{}, ctx.Err()
		}
		return Response{}, fmt.Errorf("native supervisor: %w", err)
	}
	if !resp.OK {
		msg := resp.Error
		if msg == "" {
			msg = "request failed"
		}
		return resp, errors.New(msg)
	}
	return resp, nil
}

func readResponse(conn net.Conn) (Response, error) {
	var resp Response
	line, err := readLine(bufio.NewReaderSize(conn, 4096))
	if err != nil {
		return resp, err
	}
	err = json.Unmarshal(line, &resp)
	return resp, err
}

func readLine(r *bufio.Reader) ([]byte, error) {
	var out []byte
	for {
		chunk, isPrefix, err := r.ReadLine()
		if err != nil {
			return nil, err
		}
		out = append(out, chunk...)
		if len(out) > maxLine {
			return nil, errors.New("line too long")
		}
		if !isPrefix {
			return out, nil
		}
	}
}
