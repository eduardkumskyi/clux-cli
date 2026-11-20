package supervisor

import (
	"encoding/binary"
	"strings"
	"testing"
)

func TestParseProcArgs(t *testing.T) {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, 2)
	buf = append(buf, "/usr/bin/python3\x00\x00\x00\x00"...)
	buf = append(buf, "python3\x00sidecar.py\x00"...)
	buf = append(buf, "WORKSPACE_ID=12\x00WORKSPACE_DIR=/private/var/clux/workspaces/12\x00\x00"...)
	buf = append(buf, "executable_path=/usr/bin/python3\x00"...) // apple[] strings after the env
	args, env, err := parseProcArgs(buf)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(args, " ") != "python3 sidecar.py" {
		t.Fatalf("args %q", args)
	}
	if v, ok := envValue(env, "WORKSPACE_ID"); !ok || v != "12" {
		t.Fatalf("env %q", env)
	}
	if _, ok := envValue(env, "executable_path"); ok {
		t.Fatal("apple strings leaked into env")
	}
	if _, _, err := parseProcArgs([]byte{1}); err == nil {
		t.Fatal("short buffer accepted")
	}
}

func TestParseProcArgsEmptyArgument(t *testing.T) {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, 3)
	buf = append(buf, "/bin/sh\x00\x00"...)
	buf = append(buf, "sh\x00\x00-c\x00A=1\x00\x00"...)
	args, env, _ := parseProcArgs(buf)
	if len(args) != 3 || args[1] != "" || len(env) != 1 || env[0] != "A=1" {
		t.Fatalf("args %q env %q", args, env)
	}
}

func TestSidecarEnv(t *testing.T) {
	env := SidecarEnv(SidecarEnvParams{
		WorkspaceID: "12", WorkspaceDir: "/private/var/clux/workspaces/12", Port: 40000,
		HMACSecret: "s3cret", ProxyURL: "http://ws-12:pw@127.0.0.1:47821",
		Runtime:   RuntimeSpec{Python: "/rt/v1/venv/bin/python", Claude: "/rt/v1/venv/lib/x/_bundled/claude"},
		AgentUser: "_clux", CPUCount: 8, MemoryMB: 16384, GitTemplateDir: "/private/var/clux/run/git-template",
	})
	want := map[string]string{
		"WORKSPACE_ID":        "12",
		"WORKSPACE_DIR":       "/private/var/clux/workspaces/12",
		"SIDECAR_PORT":        "40000",
		"SIDECAR_HMAC_SECRET": "s3cret",
		"HOME":                "/private/var/clux/workspaces/12/.home",
		"TMPDIR":              "/private/var/clux/workspaces/12/.tmp/",
		"HTTPS_PROXY":         "http://ws-12:pw@127.0.0.1:47821",
		"https_proxy":         "http://ws-12:pw@127.0.0.1:47821",
		"ALL_PROXY":           "http://ws-12:pw@127.0.0.1:47821",
		"NO_PROXY":            "localhost,127.0.0.1,::1",
		"CLAUDE_CLI_PATH":     "/rt/v1/venv/lib/x/_bundled/claude",
		"MACHINE_CPU_COUNT":   "8",
		"USER":                "_clux",
		"DISABLE_DOCKER":      "1",
		"GIT_TEMPLATE_DIR":    "/private/var/clux/run/git-template",
	}
	for k, v := range want {
		if got, ok := envValue(env, k); !ok || got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
	if p, _ := envValue(env, "PATH"); !strings.HasPrefix(p, "/rt/v1/venv/lib/x/_bundled:/rt/v1/venv/bin:") {
		t.Errorf("PATH %q must start with the claude and venv dirs", p)
	}
	if _, ok := envValue(env, "GITHUB_CLONE_URL"); ok {
		t.Error("empty clone url must be omitted")
	}
	if _, ok := envValue(env, "HMAC_SECRET"); ok {
		t.Error("the sidecar reads SIDECAR_HMAC_SECRET, not HMAC_SECRET")
	}
}

func TestValidProxyURL(t *testing.T) {
	cases := []struct {
		url  string
		want bool
	}{
		{"http://ws-12:pw@127.0.0.1:47821", true},
		{"http://ws-13:pw@127.0.0.1:47821", false}, // another workspace's user
		{"http://ws-12@127.0.0.1:47821", false},
		{"http://ws-12:pw@127.0.0.1:8080", false},
		{"http://ws-12:pw@evil.example:47821", false},
		{"https://ws-12:pw@127.0.0.1:47821", false},
		{"::", false},
	}
	for _, c := range cases {
		if got := validProxyURL(c.url, "12", 47821); got != c.want {
			t.Errorf("validProxyURL(%q) = %v, want %v", c.url, got, c.want)
		}
	}
}
