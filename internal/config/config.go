// Package config persists the CLI's local state: the backend URL and PAT
// written by `clux login`, read back by `clux whoami`/`clux host start`.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
)

// Answers to the background-service offer in `clux host start`.
const (
	ServiceYes = "yes"
	ServiceNo  = "no"
)

// ErrNotLoggedIn: no stored token.
var ErrNotLoggedIn = errors.New("not logged in (run 'clux login' first)")

type Config struct {
	BackendURL string `json:"backend_url"`
	Token      string `json:"token"`
	HostName   string `json:"host_name,omitempty"`
	HostID     int64  `json:"host_id,omitempty"`
	// NativePromptDeclined records a "no" to the native macOS runtime offer
	// in `clux host start`, so it is not asked again.
	NativePromptDeclined bool `json:"native_prompt_declined,omitempty"`
	// Service is the answer to "keep this computer online in the
	// background?" (ServiceYes/ServiceNo); empty = not asked yet.
	Service string `json:"service,omitempty"`
}

// LoggedIn reports whether credentials are stored.
func (c *Config) LoggedIn() bool { return c != nil && c.Token != "" }

// ClearCredentials forgets the host (logout) but keeps the backend URL and
// the user's answers to the one-time questions.
func (c *Config) ClearCredentials() {
	c.Token, c.HostName, c.HostID = "", "", 0
}

// Credentials is the one live copy of a running host's backend URL and
// token. Everything in `clux host start` that talks to the backend (the
// tunnel, the native sidecar bundle download) reads it at call time, never
// a copy taken at startup, so a re-login (a rejected token replaced
// mid-run) reaches all of them at once. Safe for concurrent use.
type Credentials struct {
	mu         sync.RWMutex
	backendURL string
	token      string
}

// NewCredentials holds cfg's current backend URL and token.
func NewCredentials(cfg *Config) *Credentials {
	c := &Credentials{}
	if cfg != nil {
		c.backendURL, c.token = cfg.BackendURL, cfg.Token
	}
	return c
}

// Get returns the current backend URL and token.
func (c *Credentials) Get() (backendURL, token string) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.backendURL, c.token
}

// Set replaces them (after a login).
func (c *Credentials) Set(backendURL, token string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.backendURL, c.token = backendURL, token
}

func dir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolving home directory: %w", err)
	}
	return filepath.Join(home, ".clux"), nil
}

func path() (string, error) {
	d, err := dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "config.json"), nil
}

// DefaultStorageRoot is where a registered host's contributed disk space is
// measured from. Falling back to a relative path if the home directory
// can't be resolved is fine: sysinfo.Collect's MkdirAll will surface any
// real permissions problem at that point.
func DefaultStorageRoot() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".", ".clux", "storage")
	}
	return filepath.Join(home, ".clux", "storage")
}

// Load returns the stored config, or ErrNotLoggedIn without a token.
func Load() (*Config, error) {
	cfg, err := Read()
	if err != nil {
		return nil, err
	}
	if !cfg.LoggedIn() {
		return nil, ErrNotLoggedIn
	}
	return cfg, nil
}

// Read returns the stored config, logged in or not (an empty one if there
// is no file yet).
func Read() (*Config, error) {
	p, err := path()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return &Config{}, nil
		}
		return nil, err
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", p, err)
	}
	return &cfg, nil
}

// Save writes the config with 0600 permissions since it contains the host's
// PAT in plaintext.
func Save(cfg *Config) error {
	d, err := dir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(d, 0o700); err != nil {
		return err
	}
	p, err := path()
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	// Atomic: the service may read the file while `clux login` writes it,
	// and a crash mid-write must not leave half a config. The temp file is
	// created 0600 in the same directory (rename stays on one filesystem),
	// so an older, looser file is replaced with 0600 too.
	tmp, err := os.CreateTemp(d, ".config.json.tmp*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil && runtime.GOOS != "windows" {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), p)
}

func Remove() error {
	p, err := path()
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// Dir is the CLI's state directory (~/.clux): config, lock file, logs.
func Dir() (string, error) { return dir() }
