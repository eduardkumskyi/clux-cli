// Package dialproxy implements the CLI side of dial.open/data/close stream
// multiplexing: proxying WebSocket messages between the backend (over the
// tunnel connection, as base64 dial.data frames) and a real WebSocket
// connection to the sidecar's Docker-published port on this host (see
// backend/apps/workspaces/services/byoc_transport.py's
// TunnelSidecarTransport for the backend side).
//
// This dials the sidecar's actual WebSocket protocol server (ws://127.0.0.1
// :<port>), not a raw TCP byte pipe -- the sidecar expects a real WS
// handshake (including the X-Sidecar-Secret auth header) and WS-framed
// messages, the same as it would get from the direct AWS/SidecarClient
// path. One dial.data frame carries exactly one complete WS message
// (base64 of its full payload), never an arbitrary byte chunk: the
// backend's TunnelSidecarTransport.recv() returns one dial.data's payload
// per call expecting a complete JSON message, so splitting a message
// across frames would break json.loads() on the far end.
//
// Each open stream gets its own goroutine reading messages from the local
// WS connection and forwarding them as dial.data frames; inbound dial.data/
// dial.close frames for that stream_id are routed to it through a small
// buffered channel rather than a direct function call, so the tunnel's
// single reader loop never blocks on a slow/stuck local connection.
package dialproxy

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// dialTimeout bounds how long the local WebSocket handshake is allowed to
// take before it's reported back as a dial.error.
const dialTimeout = 5 * time.Second

// localWriteTimeout bounds one write to the local sidecar socket; a peer
// that stops reading must not wedge its stream's writer forever.
const localWriteTimeout = 10 * time.Second

// Registry tracks open streams by stream_id so inbound dial.data/dial.close
// frames (routed by the tunnel's reader loop) can reach the right stream's
// pump. Safe for concurrent use.
type Registry struct {
	mu      sync.Mutex
	streams map[string]*stream
}

func NewRegistry() *Registry {
	return &Registry{streams: make(map[string]*stream)}
}

type stream struct {
	conn *websocket.Conn
	// inbound carries whole decoded message payloads; close is signaled
	// separately via closeCh so a zero-length message (legal, if unlikely)
	// isn't mistaken for a close.
	inbound chan []byte
	closeCh chan struct{}
	send    func(frame any)
}

// Open handles one dial.open frame: dials the sidecar's WebSocket port
// (presenting secret as X-Sidecar-Secret, exactly like the backend's
// direct-socket SidecarClient path does), reports dial.ready/dial.error via
// send, and if successful registers the stream and starts the read-pump
// goroutine that forwards inbound messages out as dial.data frames. send
// must be safe for concurrent use from multiple streams (tunnel.Session.Send
// already is).
func (r *Registry) Open(ctx context.Context, streamID string, port int, secret string, send func(frame any)) {
	dialCtx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()

	url := fmt.Sprintf("ws://127.0.0.1:%d", port)
	header := http.Header{"X-Sidecar-Secret": []string{secret}}
	dialer := websocket.Dialer{HandshakeTimeout: dialTimeout}
	conn, _, err := dialer.DialContext(dialCtx, url, header)
	if err != nil {
		send(map[string]any{"type": "dial.error", "stream_id": streamID, "message": err.Error()})
		return
	}

	st := &stream{conn: conn, inbound: make(chan []byte, 64), closeCh: make(chan struct{}, 1), send: send}
	r.mu.Lock()
	r.streams[streamID] = st
	r.mu.Unlock()

	send(map[string]any{"type": "dial.ready", "stream_id": streamID})

	go r.pump(ctx, streamID, st, send)
}

// Data routes one decoded dial.data frame's base64 payload (a whole WS
// message) to the stream's inbound queue, to be written as one WriteMessage
// call. Called synchronously from the tunnel's reader loop, so it must not
// block: this is a channel send, not the write itself (that happens in
// pump's writer goroutine) -- a stuck local peer blocks that goroutine, not
// this one, bounded by the channel's buffer.
func (r *Registry) Data(streamID, dataB64 string) {
	r.mu.Lock()
	st := r.streams[streamID]
	r.mu.Unlock()
	if st == nil {
		return
	}
	raw, err := base64.StdEncoding.DecodeString(dataB64)
	if err != nil {
		return
	}
	select {
	case st.inbound <- raw:
	default:
		// The local peer isn't keeping up and the queue is full. Never block
		// the tunnel's single reader (that would stall every other stream,
		// heartbeat acks and commands): drop this stream instead and tell
		// the backend, which reopens it.
		r.Close(streamID)
		if st.send != nil {
			st.send(map[string]any{"type": "dial.close", "stream_id": streamID})
		}
	}
}

// Close routes a dial.close frame (backend tore down its side) to the
// stream, tearing down the local connection. Idempotent.
func (r *Registry) Close(streamID string) {
	r.mu.Lock()
	st, ok := r.streams[streamID]
	if ok {
		delete(r.streams, streamID)
	}
	r.mu.Unlock()
	if !ok {
		return
	}
	select {
	case st.closeCh <- struct{}{}:
	default:
	}
	closeGracefully(st.conn)
}

// CloseAll tears down every open stream (session ended). Idempotent.
func (r *Registry) CloseAll() {
	r.mu.Lock()
	ids := make([]string, 0, len(r.streams))
	for id := range r.streams {
		ids = append(ids, id)
	}
	r.mu.Unlock()
	for _, id := range ids {
		r.Close(id)
	}
}

// Len is the number of open streams.
func (r *Registry) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.streams)
}

// closeGracefully sends a WS close frame before dropping the TCP
// connection. Skipping it still works, but it spams the sidecar's own
// logs with "connection closed without proper close handshake" warnings
// on every stream teardown -- same rationale as tunnel.Session.Close.
func closeGracefully(conn *websocket.Conn) {
	deadline := time.Now().Add(time.Second)
	_ = conn.WriteControl(websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), deadline)
	_ = conn.Close()
}

// pump owns the stream's lifetime: one goroutine writes inbound messages to
// the local WS conn (fed by Data) and reads whole messages from the local
// WS conn to emit outbound dial.data frames, until either side closes or
// errors.
func (r *Registry) pump(ctx context.Context, streamID string, st *stream, send func(frame any)) {
	writeDone := make(chan struct{})
	go func() {
		defer close(writeDone)
		for {
			select {
			case raw := <-st.inbound:
				_ = st.conn.SetWriteDeadline(time.Now().Add(localWriteTimeout))
				if err := st.conn.WriteMessage(websocket.TextMessage, raw); err != nil {
					return
				}
			case <-st.closeCh:
				return
			case <-ctx.Done():
				// The tunnel session ended (disconnect / reconnect). Close
				// the local socket too: otherwise the read loop below keeps
				// it open and the sidecar believes the backend is still
				// attached (it would keep streaming a chat turn into a
				// connection nobody reads, instead of parking the output
				// for the backend's reconnect to replay).
				closeGracefully(st.conn)
				return
			}
		}
	}()

	for {
		_, data, err := st.conn.ReadMessage()
		if len(data) > 0 {
			send(map[string]any{
				"type":      "dial.data",
				"stream_id": streamID,
				"data":      base64.StdEncoding.EncodeToString(data),
			})
		}
		if err != nil {
			break
		}
	}

	r.mu.Lock()
	_, stillOpen := r.streams[streamID]
	if stillOpen {
		delete(r.streams, streamID)
	}
	r.mu.Unlock()

	select {
	case st.closeCh <- struct{}{}:
	default:
	}
	closeGracefully(st.conn)
	<-writeDone

	if stillOpen {
		// Only send dial.close if we're the one discovering EOF/error --
		// if Close() already removed us from the map, the backend-driven
		// dial.close already happened and echoing one back is redundant
		// (harmless on the backend, since push_dial_close just fills the
		// stream's "in" queue again, but there's no reason to).
		send(map[string]any{"type": "dial.close", "stream_id": streamID})
	}
}
