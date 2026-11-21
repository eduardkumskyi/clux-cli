package config

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func withHome(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("HOME-based test; Windows uses USERPROFILE")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	return home
}

func TestOldConfigStillLoads(t *testing.T) {
	home := withHome(t)
	_ = os.MkdirAll(filepath.Join(home, ".clux"), 0o700)
	old := `{"backend_url": "https://api.clux.space", "token": "pat", "host_name": "m", "native_prompt_declined": true}`
	if err := os.WriteFile(filepath.Join(home, ".clux", "config.json"), []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Token != "pat" || !cfg.NativePromptDeclined || cfg.Service != "" || cfg.HostID != 0 {
		t.Fatalf("cfg = %+v", cfg)
	}
}

func TestLogoutKeepsAnswers(t *testing.T) {
	withHome(t)
	if _, err := Load(); !errors.Is(err, ErrNotLoggedIn) {
		t.Fatalf("no file: %v", err)
	}
	cfg := &Config{BackendURL: "https://b", Token: "pat", HostName: "m", HostID: 3, Service: ServiceYes, NativePromptDeclined: true}
	if err := Save(cfg); err != nil {
		t.Fatal(err)
	}
	cfg.ClearCredentials()
	if err := Save(cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(); !errors.Is(err, ErrNotLoggedIn) {
		t.Fatalf("after logout: %v", err)
	}
	got, err := Read()
	if err != nil {
		t.Fatal(err)
	}
	if got.Service != ServiceYes || !got.NativePromptDeclined || got.BackendURL != "https://b" || got.Token != "" || got.HostID != 0 {
		t.Fatalf("after logout: %+v", got)
	}
}
