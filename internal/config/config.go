// Package config persists the CLI's local state: the backend URL and PAT
// written by `clux login`, read back by `clux whoami`/`clux host start`.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type Config struct {
	BackendURL string `json:"backend_url"`
	Token      string `json:"token"`
	HostName   string `json:"host_name,omitempty"`
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

func Load() (*Config, error) {
	p, err := path()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("not logged in (run 'clux login' first)")
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
	return os.WriteFile(p, data, 0o600)
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
