// Package tunnel implements the CLI side of the protocol against
// backend/apps/workspaces/host_consumer.py's HostConsumer.
//
// Two usage modes share the same Dial/register handshake:
//
//   - One-shot (login/whoami/doctor): Dial, read the register ack, Close.
//     These never call Run and never see a frame other than register_ack.
//   - Long-running (`clux host start`): Dial, then Run, which turns the
//     connection full-duplex -- a single reader goroutine dispatches
//     unsolicited workspace.*/dial.* frames from the backend to a Handler,
//     while a single writer goroutine (fed by a buffered channel) serializes
//     all outbound frames, since gorilla/websocket forbids concurrent
//     writers on one *websocket.Conn. Heartbeats, lifecycle command
//     results, and dial frames all funnel through that one channel via
//     Session.Send.
package tunnel

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/gorilla/websocket"

	"github.com/eduardkumskyi/clux-cli/internal/sysinfo"
)

const hostWebsocketPath = "/ws/host/"

// outboxBuffer is the depth of the writer goroutine's input channel. Sized
// generously since dial pumps (one per open stream) and lifecycle command
// handlers (one per in-flight command) can all be producing frames
// concurrently; this just has to absorb bursts, not provide unbounded
// backpressure relief.
const outboxBuffer = 256

// Session wraps an open, registered connection to HostConsumer.
type Session struct {
	conn   *websocket.Conn
	HostID int64
	Name   string

	// outbox serializes every outbound frame through the single writer
	// goroutine started by Run. Only populated/used once Run is called;
	// one-shot callers (login/whoami/doctor) never touch it.
	outbox chan any
}

type registerAck struct {
	Type   string `json:"type"`
	HostID int64  `json:"host_id"`
	Name   string `json:"name"`
}

// Dial opens the tunnel connection and performs the register handshake.
// On success the returned Session is ready for one-shot use (Close it when
// done) or for Run (to enter the long-running full-duplex loop).
func Dial(ctx context.Context, backendURL, token, cliVersion string, info sysinfo.Info) (*Session, error) {
	wsURL, err := toWebsocketURL(backendURL)
	if err != nil {
		return nil, err
	}

	// Channels' AllowedHostsOriginValidator (enabled in prod) rejects a
	// handshake whose Origin host isn't in ALLOWED_HOSTS; a header-less dial
	// gets HTTP 403 ("bad handshake"). Send the backend's own origin, which
	// is always an allowed host.
	reqHeader, err := originHeader(backendURL)
	if err != nil {
		return nil, err
	}

	dialer := websocket.Dialer{HandshakeTimeout: 10 * time.Second}
	conn, _, err := dialer.DialContext(ctx, wsURL, reqHeader)
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

// Heartbeat sends one heartbeat frame and waits for its ack. Used only by
// one-shot callers (login/whoami/doctor never run the full-duplex loop).
func (s *Session) Heartbeat(info sysinfo.Info, cliVersion string) error {
	if err := s.conn.WriteJSON(heartbeatFrame(info, cliVersion)); err != nil {
		return fmt.Errorf("sending heartbeat: %w", err)
	}
	var ack struct {
		Type string `json:"type"`
	}
	if err := s.conn.ReadJSON(&ack); err != nil {
		return fmt.Errorf("reading heartbeat response: %w", err)
	}
	if ack.Type != "heartbeat_ack" {
		return fmt.Errorf("unexpected heartbeat response: %q", ack.Type)
	}
	return nil
}

func heartbeatFrame(info sysinfo.Info, cliVersion string) map[string]any {
	return map[string]any{
		"type":             "heartbeat",
		"cpu_cores":        info.CPUCores,
		"memory_mb":        info.MemoryMB,
		"storage_gb_total": info.StorageGBTotal,
		"cli_version":      cliVersion,
	}
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

// --- full-duplex long-running loop (`clux host start`) ---------------------

// Handler receives frames dispatched by Run's single reader goroutine. Each
// method is invoked synchronously from the reader loop, so implementations
// that do real work (docker run, a TCP dial) MUST hand off to their own
// goroutine and return promptly -- otherwise a slow workspace.start would
// stall delivery of every other frame, including heartbeat_acks and
// unrelated dial traffic, on this one connection.
type Handler interface {
	// HandleCommand processes one workspace.start/stop/delete frame and
	// must eventually call Session.Send with a matching "result" frame
	// (same correlation_id). Invoked in its own goroutine by the reader
	// loop already -- no further hand-off needed inside the method, but it
	// still must not call back into the reader synchronously.
	HandleCommand(ctx context.Context, frameType string, frame map[string]any)
	// HandleDialOpen processes one dial.open frame (new stream_id); it owns
	// registering the stream for subsequent HandleDialData/HandleDialClose
	// routing and sending dial.ready/dial.error. secret is the workspace's
	// HMAC secret (dial.open's "secret" field) to present when dialing the
	// sidecar's own WebSocket auth check.
	HandleDialOpen(ctx context.Context, streamID string, port int, secret string)
	// HandleDialData routes one dial.data frame's base64 payload to the
	// stream's pump, if registered.
	HandleDialData(streamID string, dataB64 string)
	// HandleDialClose routes a dial.close frame (backend tore down its
	// side) to the stream's pump, if registered.
	HandleDialClose(streamID string)
}

// Run enters the long-running full-duplex loop: one reader goroutine reads
// frames off the connection and dispatches them to h (each dispatch target
// is responsible for not blocking this loop -- see Handler's doc), while
// one writer goroutine drains Send's outbox channel, since gorilla/
// websocket forbids concurrent writers on a single *websocket.Conn. Run
// blocks until ctx is cancelled or the connection fails.
func (s *Session) Run(ctx context.Context, h Handler) error {
	s.outbox = make(chan any, outboxBuffer)
	defer func() { s.outbox = nil }()

	writerDone := make(chan struct{})
	writerErr := make(chan error, 1)
	go func() {
		defer close(writerDone)
		for {
			select {
			case <-ctx.Done():
				return
			case frame, ok := <-s.outbox:
				if !ok {
					return
				}
				if err := s.conn.WriteJSON(frame); err != nil {
					select {
					case writerErr <- err:
					default:
					}
					return
				}
			}
		}
	}()

	readErr := make(chan error, 1)
	go func() {
		readErr <- s.readLoop(ctx, h)
	}()

	select {
	case <-ctx.Done():
		// Unblock a reader stuck in ReadJSON so readLoop's goroutine exits
		// instead of leaking; the connection is going away regardless.
		_ = s.conn.Close()
		<-writerDone
		return nil
	case err := <-readErr:
		return err
	case err := <-writerErr:
		return err
	}
}

// Send submits one outbound frame to the writer goroutine. Safe to call
// concurrently from any number of goroutines (command handlers, dial
// pumps, the heartbeat ticker) once Run has started.
func (s *Session) Send(frame any) {
	outbox := s.outbox
	if outbox == nil {
		return
	}
	defer func() { recover() }() // outbox may have been closed/niled by Run returning concurrently; dropping the frame is fine, the connection is gone anyway.
	outbox <- frame
}

// SendHeartbeat is a convenience wrapper for the caller's ticker.
func (s *Session) SendHeartbeat(info sysinfo.Info, cliVersion string) {
	s.Send(heartbeatFrame(info, cliVersion))
}

func (s *Session) readLoop(ctx context.Context, h Handler) error {
	for {
		var raw map[string]any
		if err := s.conn.ReadJSON(&raw); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("reading frame: %w", err)
		}

		frameType, _ := raw["type"].(string)
		switch frameType {
		case "heartbeat_ack", "register_ack":
			// No-op: heartbeats don't block waiting for their ack anymore,
			// and register_ack was already consumed by Dial.
		case "workspace.start", "workspace.stop", "workspace.delete":
			go h.HandleCommand(ctx, frameType, raw)
		case "dial.open":
			streamID, _ := raw["stream_id"].(string)
			port, _ := raw["port"].(float64)
			secret, _ := raw["secret"].(string)
			go h.HandleDialOpen(ctx, streamID, int(port), secret)
		case "dial.data":
			streamID, _ := raw["stream_id"].(string)
			data, _ := raw["data"].(string)
			h.HandleDialData(streamID, data)
		case "dial.close":
			streamID, _ := raw["stream_id"].(string)
			h.HandleDialClose(streamID)
		default:
			// Unknown frame type: ignore, forward-compatible with backend
			// additions this CLI build doesn't know about yet.
		}
	}
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

// originHeader returns the Origin request header the backend's origin
// validator expects: the http(s) origin (scheme://host) of backendURL. The
// backend host is always in ALLOWED_HOSTS, so this passes validation.
func originHeader(backendURL string) (http.Header, error) {
	u, err := url.Parse(backendURL)
	if err != nil {
		return nil, fmt.Errorf("parsing backend URL %q: %w", backendURL, err)
	}
	switch u.Scheme {
	case "ws":
		u.Scheme = "http"
	case "wss":
		u.Scheme = "https"
	}
	return http.Header{"Origin": {u.Scheme + "://" + u.Host}}, nil
}
