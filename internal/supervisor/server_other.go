//go:build !darwin

package supervisor

import (
	"context"
	"errors"

	"github.com/eduardkumskyi/clux-cli/internal/native"
)

// Options configures a supervisor (macOS only).
type Options struct {
	Config       *native.Config
	Version      string
	Socket       string
	AgentHome    string
	RuntimeRoot  string
	SkipUIDCheck bool
	Logf         func(format string, args ...any)
}

// Server is a running supervisor (macOS only).
type Server struct{}

// NewServer always fails off macOS.
func NewServer(Options) (*Server, error) {
	return nil, errors.New("the native supervisor runs on macOS only")
}

// Sandbox reports the self-check result.
func (*Server) Sandbox() string { return SandboxUnavailable }

// Serve is never reached off macOS.
func (*Server) Serve(context.Context) error { return errors.New("macOS only") }
