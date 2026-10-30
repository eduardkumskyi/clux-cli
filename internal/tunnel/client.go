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
//
// Liveness: a laptop's network dies in ways TCP alone reports late or never
// (sleep, Wi-Fi switch, captive portal, half-open NAT entry). Run therefore
// pings the backend every PingInterval and keeps a read deadline of
// ReadTimeout that every inbound frame, ping or pong pushes forward; every
// write carries a WriteTimeout deadline. A dead connection surfaces as a Run
// error within ~ReadTimeout instead of minutes, and the caller reconnects.
package tunnel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
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

// Default liveness timings. The backend (uvicorn) pings every 20s and drops
// us after 20s without a pong; we ping a bit more often so an idle tunnel
// always carries traffic, and give the read side three missed pings of
// slack before declaring the connection dead.
const (
	DefaultPingInterval = 15 * time.Second
	DefaultReadTimeout  = 45 * time.Second
	DefaultWriteTimeout = 10 * time.Second

	dialTimeout      = 10 * time.Second
	handshakeTimeout = 10 * time.Second
	registerTimeout  = 15 * time.Second
)

// Backend close codes (see host_consumer.py).
const (
	CloseInvalidToken = 4001
	CloseCLIOutdated  = 4002
	CloseSuperseded   = 4003
	CloseStale        = 4004
)

// ErrFatal wraps errors that retrying cannot fix (revoked token, CLI too
// old). The reconnect loop stops on these instead of looping forever.
type ErrFatal struct{ Err error }

func (e *ErrFatal) Error() string { return e.Err.Error() }
func (e *ErrFatal) Unwrap() error { return e.Err }

// IsFatal reports whether err should stop the reconnect loop.
func IsFatal(err error) bool {
	var f *ErrFatal
	return errors.As(err, &f)
}

// ErrSuperseded means another process (same token, maybe another machine)
// registered this host and the backend dropped us in its favor.
var ErrSuperseded = errors.New("another process or machine is using this host's token; it replaced this connection")

// ErrReconnectRequested is returned by Run when the caller asked for a
// proactive reconnect (sleep/wake or network change detected).
var ErrReconnectRequested = errors.New("reconnect requested")

// Session wraps an open, registered connection to HostConsumer.
type Session struct {
	conn   *websocket.Conn
	HostID int64
	Name   string

	// Liveness timings; zero values fall back to the Default* constants.
	// Exposed so tests can shrink them.
	PingInterval time.Duration
	ReadTimeout  time.Duration
	WriteTimeout time.Duration

	// outbox serializes every outbound frame through the single writer
	// goroutine started by Run. Only populated/used once Run is called;
	// one-shot callers (login/whoami/doctor) never touch it.
	outbox chan any
	// done is closed when Run returns, so Send never blocks on an outbox
	// nobody drains any more (dial pumps / command goroutines would
	// otherwise leak forever after a disconnect).
	done chan struct{}

	mu     sync.Mutex
	kickCh chan error

	// probing holds the active Probe deadline (ns) until a frame arrives,
	// so a probe timeout is reported with the probe's own window.
	probing atomic.Int64
}

type registerAck struct {
	Type       string `json:"type"`
	HostID     int64  `json:"host_id"`
	Name       string `json:"name"`
	Reason     string `json:"reason"`
	MinVersion string `json:"min_version"`
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

	netDialer := &net.Dialer{Timeout: dialTimeout, KeepAlive: 15 * time.Second}
	dialer := websocket.Dialer{
		HandshakeTimeout: handshakeTimeout,
		NetDialContext:   netDialer.DialContext,
		Proxy:            http.ProxyFromEnvironment,
	}
	dialCtx, cancel := context.WithTimeout(ctx, dialTimeout+handshakeTimeout)
	defer cancel()
	conn, _, err := dialer.DialContext(dialCtx, wsURL, reqHeader)
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
	_ = conn.SetWriteDeadline(time.Now().Add(DefaultWriteTimeout))
	if err := conn.WriteJSON(frame); err != nil {
		conn.Close()
		return nil, fmt.Errorf("sending register frame: %w", err)
	}

	// A backend that accepted the socket but is stuck must not hang the
	// register forever.
	_ = conn.SetReadDeadline(time.Now().Add(registerTimeout))
	var ack registerAck
	if err := conn.ReadJSON(&ack); err != nil {
		conn.Close()
		var ce *websocket.CloseError
		if errors.As(err, &ce) {
			switch ce.Code {
			case CloseInvalidToken:
				return nil, &ErrFatal{fmt.Errorf("registration rejected: invalid or revoked token (run `clux login --token ...` with a new token)")}
			case CloseCLIOutdated:
				return nil, &ErrFatal{fmt.Errorf("registration rejected: this clux version is too old, update it (curl -fsSL https://clux.space/install.sh | sh)")}
			}
		}
		return nil, fmt.Errorf("reading register response: %w", err)
	}
	switch ack.Type {
	case "register_ack":
	case "register_rejected":
		conn.Close()
		switch ack.Reason {
		case "cli_outdated":
			return nil, &ErrFatal{fmt.Errorf("registration rejected: clux %s is too old (backend needs >= %s); update: curl -fsSL https://clux.space/install.sh | sh", cliVersion, ack.MinVersion)}
		case "invalid_token", "revoked":
			return nil, &ErrFatal{fmt.Errorf("registration rejected: %s (run `clux login --token ...` with a new token)", ack.Reason)}
		}
		// Unknown reason: may be transient (backend-side), retry with backoff.
		return nil, fmt.Errorf("registration rejected: %s", ack.Reason)
	default:
		conn.Close()
		return nil, fmt.Errorf("unexpected response from backend: %q", ack.Type)
	}
	_ = conn.SetReadDeadline(time.Time{})
	_ = conn.SetWriteDeadline(time.Time{})

	return newSession(conn, ack.HostID, ack.Name), nil
}

func newSession(conn *websocket.Conn, hostID int64, name string) *Session {
	return &Session{
		conn:   conn,
		HostID: hostID,
		Name:   name,
		outbox: make(chan any, outboxBuffer),
		done:   make(chan struct{}),
	}
}

// LocalAddr is the local end of the tunnel's TCP connection; the network
// watcher uses its IP to tell whether an interface change killed it.
func (s *Session) LocalAddr() net.Addr { return s.conn.LocalAddr() }

// Heartbeat sends one heartbeat frame and waits for its ack. Used only by
// one-shot callers (login/whoami/doctor never run the full-duplex loop).
func (s *Session) Heartbeat(info sysinfo.Info, cliVersion string) error {
	_ = s.conn.SetWriteDeadline(time.Now().Add(DefaultWriteTimeout))
	if err := s.conn.WriteJSON(heartbeatFrame(info, cliVersion)); err != nil {
		return fmt.Errorf("sending heartbeat: %w", err)
	}
	_ = s.conn.SetReadDeadline(time.Now().Add(registerTimeout))
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

func (s *Session) pingInterval() time.Duration {
	if s.PingInterval > 0 {
		return s.PingInterval
	}
	return DefaultPingInterval
}

func (s *Session) readTimeout() time.Duration {
	if s.ReadTimeout > 0 {
		return s.ReadTimeout
	}
	return DefaultReadTimeout
}

func (s *Session) writeTimeout() time.Duration {
	if s.WriteTimeout > 0 {
		return s.WriteTimeout
	}
	return DefaultWriteTimeout
}

// extendRead pushes the read deadline forward; called on every inbound
// frame, ping and pong.
func (s *Session) extendRead() {
	s.probing.Store(0)
	_ = s.conn.SetReadDeadline(time.Now().Add(s.readTimeout()))
}

// Kick asks a running Run to return ErrReconnectRequested-wrapped reason
// right away (sleep/wake or network change). Safe from any goroutine; a
// no-op when Run isn't running or a kick is already pending.
func (s *Session) Kick(reason error) {
	s.mu.Lock()
	ch := s.kickCh
	s.mu.Unlock()
	if ch == nil {
		return
	}
	select {
	case ch <- reason:
	default:
	}
}

// Probe sends an immediate ping and shortens the read deadline to d, so a
// connection that died silently (e.g. after a network change that kept our
// local IP) is detected within d instead of the full ReadTimeout. A pong or
// any frame restores the normal deadline.
func (s *Session) Probe(d time.Duration) {
	// Deadline first: a pong racing back before it is set would otherwise be
	// overwritten by the shorter deadline and cause a false "dead" verdict.
	s.probing.Store(int64(d))
	_ = s.conn.SetReadDeadline(time.Now().Add(d))
	_ = s.conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(s.writeTimeout()))
}

// Run enters the long-running full-duplex loop: one reader goroutine reads
// frames off the connection and dispatches them to h (each dispatch target
// is responsible for not blocking this loop -- see Handler's doc), while
// one writer goroutine drains Send's outbox channel, since gorilla/
// websocket forbids concurrent writers on a single *websocket.Conn. A
// pinger goroutine keeps the connection provably alive. Run blocks until
// ctx is cancelled (returns nil), the connection fails or goes silent past
// ReadTimeout (returns the error), or Kick is called (returns an error
// wrapping ErrReconnectRequested). The connection is closed on return.
func (s *Session) Run(ctx context.Context, h Handler) error {
	kick := make(chan error, 1)
	s.mu.Lock()
	s.kickCh = kick
	s.mu.Unlock()

	runCtx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	defer func() {
		s.mu.Lock()
		s.kickCh = nil
		s.mu.Unlock()
		cancel()
		close(s.done)
		// Graceful close frame (best effort; the peer may be long gone) so a
		// live backend marks us offline at once instead of via its watchdog.
		_ = s.conn.WriteControl(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(time.Second))
		_ = s.conn.Close()
		wg.Wait()
	}()

	s.conn.SetPongHandler(func(string) error {
		s.extendRead()
		return nil
	})
	s.conn.SetPingHandler(func(data string) error {
		s.extendRead()
		err := s.conn.WriteControl(websocket.PongMessage, []byte(data), time.Now().Add(s.writeTimeout()))
		if err == websocket.ErrCloseSent {
			return nil
		}
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return nil
		}
		return err
	})
	s.extendRead()

	errCh := make(chan error, 3)
	report := func(err error) {
		select {
		case errCh <- err:
		default:
		}
	}

	wg.Add(1)
	go func() { // writer
		defer wg.Done()
		for {
			select {
			case <-runCtx.Done():
				return
			case frame := <-s.outbox:
				_ = s.conn.SetWriteDeadline(time.Now().Add(s.writeTimeout()))
				if err := s.conn.WriteJSON(frame); err != nil {
					report(fmt.Errorf("writing frame: %w", err))
					return
				}
			}
		}
	}()

	wg.Add(1)
	go func() { // pinger
		defer wg.Done()
		t := time.NewTicker(s.pingInterval())
		defer t.Stop()
		for {
			select {
			case <-runCtx.Done():
				return
			case <-t.C:
				if err := s.conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(s.writeTimeout())); err != nil {
					report(fmt.Errorf("sending ping: %w", err))
					return
				}
			}
		}
	}()

	wg.Add(1)
	go func() { // reader
		defer wg.Done()
		if err := s.readLoop(runCtx, h); err != nil {
			report(err)
		}
	}()

	select {
	case <-ctx.Done():
		return nil
	case reason := <-kick:
		return fmt.Errorf("%w: %v", ErrReconnectRequested, reason)
	case err := <-errCh:
		if ctx.Err() != nil {
			return nil
		}
		return err
	}
}

// Send submits one outbound frame to the writer goroutine. Safe to call
// concurrently from any number of goroutines (command handlers, dial
// pumps, the heartbeat ticker) once Run has started. After Run returns the
// frame is dropped instead of blocking: the connection is gone and the
// backend aborts whatever was in flight on it.
func (s *Session) Send(frame any) {
	select {
	case <-s.done:
		return
	default:
	}
	select {
	case s.outbox <- frame:
	case <-s.done:
	}
}

// TrySend is Send that reports whether the frame was queued on a live
// session (false once Run has returned).
func (s *Session) TrySend(frame any) bool {
	select {
	case <-s.done:
		return false
	default:
	}
	select {
	case s.outbox <- frame:
		return true
	case <-s.done:
		return false
	}
}

// Ended reports whether Run has returned.
func (s *Session) Ended() bool {
	select {
	case <-s.done:
		return true
	default:
		return false
	}
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
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				if p := time.Duration(s.probing.Load()); p > 0 {
					return fmt.Errorf("no answer to a liveness probe within %s after a network change", p)
				}
				return fmt.Errorf("connection silent for %s (no frames or pongs)", s.readTimeout())
			}
			var ce *websocket.CloseError
			if errors.As(err, &ce) {
				switch ce.Code {
				case CloseInvalidToken:
					return &ErrFatal{fmt.Errorf("backend revoked this host's token")}
				case CloseSuperseded:
					return ErrSuperseded
				case CloseStale:
					return fmt.Errorf("backend closed the tunnel as stale")
				case websocket.CloseServiceRestart:
					return fmt.Errorf("backend restarting")
				}
			}
			return fmt.Errorf("reading frame: %w", err)
		}
		s.extendRead()

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
