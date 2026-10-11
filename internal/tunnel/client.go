// Package tunnel implements the CLI side of the register/heartbeat
// handshake against backend/apps/workspaces/host_consumer.py's HostConsumer.
// Phase 2 scope only: register + heartbeat. The multiplexed stream dispatch
// (terminal/exec/preview) lands in Phase 4 on top of the same connection.
package tunnel

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"github.com/gorilla/websocket"

	"github.com/eduardkumskyi/clux-cli/internal/sysinfo"
)

const hostWebsocketPath = "/ws/host/"

// Session wraps an open, registered connection to HostConsumer.
type Session struct {
	conn   *websocket.Conn
	HostID int64
	Name   string
}

type registerAck struct {
	Type   string `json:"type"`
	HostID int64  `json:"host_id"`
	Name   string `json:"name"`
}

type simpleAck struct {
	Type string `json:"type"`
}

// Dial opens the tunnel connection and performs the register handshake.
// On success the returned Session is ready for Heartbeat calls; the caller
// owns it and must Close it.
func Dial(ctx context.Context, backendURL, token, cliVersion string, info sysinfo.Info) (*Session, error) {
	wsURL, err := toWebsocketURL(backendURL)
	if err != nil {
		return nil, err
	}

	dialer := websocket.Dialer{HandshakeTimeout: 10 * time.Second}
	conn, _, err := dialer.DialContext(ctx, wsURL, nil)
	if err != nil {
		return nil, fmt.Errorf("connecting to %s: %w", wsURL, err)
	}

	frame := map[string]any{
		"type":             "register",
		"token":            token,
		"cpu_cores":        info.CPUCores,
		"memory_mb":        info.MemoryMB,
		"storage_gb_total": info.StorageGBTotal,
		"cli_version":      cliVersion,
	}
	if err := conn.WriteJSON(frame); err != nil {
		conn.Close()
		return nil, fmt.Errorf("sending register frame: %w", err)
	}

	var ack registerAck
	if err := conn.ReadJSON(&ack); err != nil {
		conn.Close()
		if ce, ok := err.(*websocket.CloseError); ok && ce.Code == 4001 {
			return nil, fmt.Errorf("registration rejected: invalid or revoked token")
		}
		return nil, fmt.Errorf("reading register response: %w", err)
	}
	if ack.Type != "register_ack" {
		conn.Close()
		return nil, fmt.Errorf("unexpected response from backend: %q", ack.Type)
	}

	return &Session{conn: conn, HostID: ack.HostID, Name: ack.Name}, nil
}

// Heartbeat sends one heartbeat frame and waits for its ack.
func (s *Session) Heartbeat(info sysinfo.Info, cliVersion string) error {
	frame := map[string]any{
		"type":             "heartbeat",
		"cpu_cores":        info.CPUCores,
		"memory_mb":        info.MemoryMB,
		"storage_gb_total": info.StorageGBTotal,
		"cli_version":      cliVersion,
	}
	if err := s.conn.WriteJSON(frame); err != nil {
		return fmt.Errorf("sending heartbeat: %w", err)
	}

	var ack simpleAck
	if err := s.conn.ReadJSON(&ack); err != nil {
		return fmt.Errorf("reading heartbeat response: %w", err)
	}
	if ack.Type != "heartbeat_ack" {
		return fmt.Errorf("unexpected heartbeat response: %q", ack.Type)
	}
	return nil
}

// Close performs a graceful WebSocket close handshake before dropping the
// TCP connection. Skipping the close frame still works (HostConsumer.
// disconnect fires on any transport-level close), but it makes ASGI server
// logs noisy with "connection closed without proper close handshake"
// warnings on every CLI command exit.
func (s *Session) Close() error {
	deadline := time.Now().Add(time.Second)
	_ = s.conn.WriteControl(websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), deadline)
	return s.conn.Close()
}

// toWebsocketURL turns the backend's http(s) base URL into the ws(s) URL
// for HostConsumer (apps/agent/ws_routing.py: re_path(r"ws/host/$", ...)).
func toWebsocketURL(backendURL string) (string, error) {
	u, err := url.Parse(backendURL)
	if err != nil {
		return "", fmt.Errorf("parsing backend URL %q: %w", backendURL, err)
	}
	switch u.Scheme {
	case "https":
		u.Scheme = "wss"
	case "http":
		u.Scheme = "ws"
	case "ws", "wss":
	default:
		return "", fmt.Errorf("unsupported backend URL scheme %q (expected http/https)", u.Scheme)
	}
	u.Path = hostWebsocketPath
	return u.String(), nil
}
