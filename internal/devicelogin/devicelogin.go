// Package devicelogin is the CLI half of browser login (like `gh auth
// login`): ask the backend for a one-time code, let the user confirm it in
// the web app while signed in, and poll until the backend hands over this
// machine's host token.
//
// Backend endpoints (all under /api/compute-hosts/, no auth on these two):
//
//	POST device-codes/       {machine_id, machine_secret, name, os, arch, cli_version}
//	                         -> 201 {device_code, user_code, verification_url, expires_in, interval}
//	POST device-codes/poll/  {device_code}
//	                         -> 200 {status: pending|approved|denied|expired, slow_down?,
//	                                 token?, host?: {id, name}, reused?}
//
// The device_code is a secret (whoever polls with it gets the token); it is
// never printed. The user_code is what the user types or sees in the URL.
package devicelogin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	codesPath = "/api/compute-hosts/device-codes/"
	pollPath  = "/api/compute-hosts/device-codes/poll/"

	// slowDownStep is how much a slow_down answer (or HTTP 429) stretches
	// the poll interval, as in RFC 8628.
	slowDownStep = 5 * time.Second
	maxInterval  = 30 * time.Second
	// Fallbacks if the backend omits them.
	defaultInterval  = 3 * time.Second
	defaultExpiresIn = 10 * time.Minute

	requestTimeout = 15 * time.Second
	maxBody        = 64 << 10
)

// Request describes this machine; Name is only the suggested host name.
type Request struct {
	MachineID string `json:"machine_id"`
	// MachineSecret proves this is the computer that owns the host with
	// this machine_id (the id alone is guessable).
	MachineSecret string `json:"machine_secret"`
	Name          string `json:"name"`
	OS            string `json:"os"`
	Arch          string `json:"arch"`
	CLIVersion    string `json:"cli_version"`
}

// Code is a started login, waiting for the user's confirmation.
type Code struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURL string `json:"verification_url"`
	ExpiresIn       int    `json:"expires_in"` // seconds
	Interval        int    `json:"interval"`   // seconds

	expiresAt time.Time
}

// Host is the computer the backend connected this machine as.
type Host struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

// Result is an approved login.
type Result struct {
	Token string
	Host  Host
	// Reused: the backend recognized this machine and handed back its
	// existing host (with its projects) under a fresh token.
	Reused bool
}

type pollResponse struct {
	Status   string `json:"status"`
	SlowDown bool   `json:"slow_down"`
	Token    string `json:"token"`
	Host     *Host  `json:"host"`
	Reused   bool   `json:"reused"`
}

var (
	// ErrDenied: the user pressed "Deny" in the browser.
	ErrDenied = errors.New("the connection was denied in the browser")
	// ErrExpired: the code timed out (10 minutes) or was already used.
	ErrExpired = errors.New("the code expired before it was confirmed; run the command again for a new one")
	// ErrUnsupported: the backend predates browser login.
	ErrUnsupported = errors.New("this Clux backend does not support browser login yet; create a host in the dashboard and run `clux login --token <token>`")
)

// Client talks to one backend.
type Client struct {
	BaseURL   string // e.g. https://api.clux.space
	UserAgent string
	HTTP      *http.Client // nil: a client with requestTimeout
	// Sleep waits between polls (nil: a real timer); tests make it instant.
	Sleep func(context.Context, time.Duration) error
	now   func() time.Time // swapped by tests
}

func (c *Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: requestTimeout}
}

func (c *Client) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

func (c *Client) wait(ctx context.Context, d time.Duration) error {
	if c.Sleep != nil {
		return c.Sleep(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Start asks the backend for a new code.
func (c *Client) Start(ctx context.Context, req Request) (*Code, error) {
	status, body, err := c.post(ctx, codesPath, req)
	if err != nil {
		return nil, err
	}
	switch {
	case status == http.StatusNotFound || status == http.StatusMethodNotAllowed:
		return nil, ErrUnsupported
	case status == http.StatusTooManyRequests:
		return nil, errors.New("too many login attempts from this network; wait a minute and try again")
	case status != http.StatusCreated && status != http.StatusOK:
		return nil, fmt.Errorf("starting login: backend answered HTTP %d%s", status, detail(body))
	}
	var code Code
	if err := json.Unmarshal(body, &code); err != nil {
		return nil, fmt.Errorf("starting login: unreadable backend answer: %w", err)
	}
	if code.DeviceCode == "" || code.UserCode == "" || code.VerificationURL == "" {
		return nil, errors.New("starting login: backend answer is missing the code or URL")
	}
	if !isWebURL(code.VerificationURL) {
		return nil, fmt.Errorf("starting login: backend sent a non-web verification URL %q", code.VerificationURL)
	}
	exp := time.Duration(code.ExpiresIn) * time.Second
	if exp <= 0 {
		exp = defaultExpiresIn
	}
	code.expiresAt = c.clock().Add(exp)
	return &code, nil
}

// Wait polls until the code is approved, denied or expired, or ctx ends
// (Ctrl+C). Network errors and backend hiccups are retried until expiry: a
// laptop on flaky Wi-Fi should not lose a login the user already confirmed.
func (c *Client) Wait(ctx context.Context, code *Code) (*Result, error) {
	interval := time.Duration(code.Interval) * time.Second
	if interval <= 0 {
		interval = defaultInterval
	}
	expiresAt := code.expiresAt
	if expiresAt.IsZero() {
		expiresAt = c.clock().Add(defaultExpiresIn)
	}
	var lastErr error
	for {
		if err := c.wait(ctx, interval); err != nil {
			return nil, err
		}
		if !c.clock().Before(expiresAt) {
			if lastErr != nil {
				return nil, fmt.Errorf("%w (last error: %v)", ErrExpired, lastErr)
			}
			return nil, ErrExpired
		}
		status, body, err := c.post(ctx, pollPath, map[string]string{"device_code": code.DeviceCode})
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			lastErr = err
			continue
		}
		switch {
		case status == http.StatusTooManyRequests:
			interval = slower(interval)
			continue
		case status >= 500:
			lastErr = fmt.Errorf("backend answered HTTP %d", status)
			continue
		case status != http.StatusOK:
			return nil, fmt.Errorf("waiting for confirmation: backend answered HTTP %d%s", status, detail(body))
		}
		var r pollResponse
		if err := json.Unmarshal(body, &r); err != nil {
			lastErr = fmt.Errorf("unreadable backend answer: %w", err)
			continue
		}
		switch r.Status {
		case "pending":
			if r.SlowDown {
				interval = slower(interval)
			}
		case "approved":
			if r.Token == "" || r.Host == nil {
				return nil, errors.New("waiting for confirmation: approved, but the backend sent no token")
			}
			return &Result{Token: r.Token, Host: *r.Host, Reused: r.Reused}, nil
		case "denied":
			return nil, ErrDenied
		case "expired":
			return nil, ErrExpired
		default:
			return nil, fmt.Errorf("waiting for confirmation: unknown status %q", r.Status)
		}
	}
}

func slower(d time.Duration) time.Duration {
	d += slowDownStep
	if d > maxInterval {
		d = maxInterval
	}
	return d
}

func (c *Client) post(ctx context.Context, path string, payload any) (int, []byte, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return 0, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.BaseURL, "/")+path, bytes.NewReader(data))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("contacting %s: %w", c.BaseURL, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return 0, nil, fmt.Errorf("reading backend answer: %w", err)
	}
	return resp.StatusCode, body, nil
}

// detail extracts a DRF-style {"detail": "..."} message, if any.
func detail(body []byte) string {
	var d struct {
		Detail string `json:"detail"`
	}
	if json.Unmarshal(body, &d) == nil && d.Detail != "" {
		return ": " + d.Detail
	}
	return ""
}

// isWebURL guards what we hand to the OS's "open" command: only http(s).
func isWebURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != ""
}
