package supervisor

import (
	"runtime"
	"testing"
)

func TestValidBackendURL(t *testing.T) {
	for raw, want := range map[string]bool{
		"https://api.clux.space":          true,
		"http://localhost:8009":           true,
		"https://api.clux.space/":         true,
		"":                                false,
		"ftp://api.clux.space":            false,
		"https://user:pw@api.clux.space":  false,
		"https://api.clux.space/?x=1":     false,
		"https://api.clux.space/#frag":    false,
		"https://api.clux.space\nX=1":     false,
		"api.clux.space":                  false,
		"https://":                        false,
		"https://api.clux.space/a b":      false,
		"javascript:alert(1)":             false,
		"https://api.clux.space\x00extra": false,
	} {
		if got := ValidBackendURL(raw); got != want {
			t.Errorf("ValidBackendURL(%q) = %v, want %v", raw, got, want)
		}
	}
}

func TestSidecarEnvBackendURL(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("native macOS runtime only")
	}
	base := SidecarEnvParams{WorkspaceID: "12", WorkspaceDir: "/w/12", Port: 40000, HMACSecret: "s"}
	if _, ok := envValue(SidecarEnv(base), "CLUX_BACKEND_URL"); ok {
		t.Fatal("no backend URL: no CLUX_BACKEND_URL")
	}
	base.BackendURL = "https://api.clux.space"
	if v, _ := envValue(SidecarEnv(base), "CLUX_BACKEND_URL"); v != "https://api.clux.space" {
		t.Fatalf("CLUX_BACKEND_URL = %q", v)
	}
	base.BackendURL = "https://u:p@evil"
	if _, ok := envValue(SidecarEnv(base), "CLUX_BACKEND_URL"); ok {
		t.Fatal("an invalid URL must not reach the sidecar")
	}
}
