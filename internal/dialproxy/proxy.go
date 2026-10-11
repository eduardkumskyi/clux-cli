// Package dialproxy implements the CLI side of dial.open/data/close stream
// multiplexing: proxying bytes between the backend (over the tunnel
// connection, as base64 dial.data frames) and a local TCP connection to a
// Docker-published port on this host (see backend/apps/workspaces/services/
// byoc_transport.py's TunnelSidecarTransport for the backend side).
//
// Each open stream gets its own goroutine reading from the local TCP conn
// and forwarding chunks as dial.data frames; inbound dial.data/dial.close
// frames for that stream_id are routed to it through a small buffered
// channel rather than a direct function call, so the tunnel's single
// reader loop never blocks on a slow/stuck local connection.
package dialproxy

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"sync"
	"time"
)

// readChunkSize bounds how much is read from the local connection per
// dial.data frame. Arbitrary but reasonable: big enough to not fragment
// bulk transfers into a flood of tiny frames, small enough to keep each
// frame's base64 payload a modest size over the websocket.
const readChunkSize = 32 * 1024

// dialTimeout bounds how long a local TCP dial is allowed to take before
// it's reported back as a dial.error.
const dialTimeout = 5 * time.Second

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
	conn net.Conn
	// inbound carries dial.data payloads (decoded) and a nil-slice sentinel
	// is not used; close is signaled separately via closeCh so a zero-length
	// data frame (legal, if unlikely) isn't mistaken for EOF.
	inbound chan []byte
	closeCh chan struct{}
}

// Open handles one dial.open frame: dials the local port, reports
// dial.ready/dial.error via send, and if successful registers the stream
// and starts the read-pump goroutine that forwards local bytes out as
// dial.data frames. send must be safe for concurrent use from multiple
// streams (tunnel.Session.Send already is).
func (r *Registry) Open(ctx context.Context, streamID string, port int, send func(frame any)) {
	dialCtx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()

	conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		send(map[string]any{"type": "dial.error", "stream_id": streamID, "message": err.Error()})
		return
	}

	st := &stream{conn: conn, inbound: make(chan []byte, 64), closeCh: make(chan struct{}, 1)}
	r.mu.Lock()
	r.streams[streamID] = st
	r.mu.Unlock()

	send(map[string]any{"type": "dial.ready", "stream_id": streamID})

	go r.pump(ctx, streamID, st, send)
}

// Data routes one decoded-later dial.data frame's base64 payload to the
// stream's inbound queue, writing it to the local connection. Called
// synchronously from the tunnel's reader loop, so it must not block: the
// local connection write happens in a short-lived goroutine-free fast path
// only if the stream exists, and is itself a plain conn.Write -- a stuck
// local peer could in principle block this, but that mirrors the original
// backend's own blocking write semantics and keeping a bounded inbound
// channel here would only defer the problem while still bounding memory.
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
	case <-st.closeCh:
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
	_ = st.conn.Close()
}

// pump owns the stream's lifetime: one goroutine writes inbound frames to
// the local conn (fed by Data) and reads from the local conn to emit
// outbound dial.data frames, until either side closes or errors.
func (r *Registry) pump(ctx context.Context, streamID string, st *stream, send func(frame any)) {
	writeDone := make(chan struct{})
	go func() {
		defer close(writeDone)
		for {
			select {
			case raw := <-st.inbound:
				if _, err := st.conn.Write(raw); err != nil {
					return
				}
			case <-st.closeCh:
				return
			case <-ctx.Done():
				return
			}
		}
	}()

	buf := make([]byte, readChunkSize)
	for {
		n, err := st.conn.Read(buf)
		if n > 0 {
			send(map[string]any{
				"type":      "dial.data",
				"stream_id": streamID,
				"data":      base64.StdEncoding.EncodeToString(buf[:n]),
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
	_ = st.conn.Close()
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
