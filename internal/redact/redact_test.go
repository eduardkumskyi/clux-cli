package redact

import (
	"strings"
	"testing"
)

func TestString(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{
			"docker run -d --name clux-ws-1 -e SIDECAR_HMAC_SECRET=s3cret -e HMAC_SECRET=s3cret img",
			"docker run -d --name clux-ws-1 -e SIDECAR_HMAC_SECRET=[REDACTED] -e HMAC_SECRET=[REDACTED] img",
		},
		{
			"HTTPS_PROXY=http://ws-abc:pw123@127.0.0.1:7777 WORKSPACE_ID=abc",
			"HTTPS_PROXY=http://ws-abc:[REDACTED]@127.0.0.1:7777 WORKSPACE_ID=abc",
		},
		{
			"cloning https://x-access-token:ghs_abc@github.com/o/r.git failed",
			"cloning https://x-access-token:[REDACTED]@github.com/o/r.git failed",
		},
		{"git clone https://ghp_abc@github.com/o/r", "git clone https://[REDACTED]@github.com/o/r"},
		{`{"token": "pat-1", "name": "mac"}`, `{"token": "[REDACTED]", "name": "mac"}`},
		{"Authorization: Bearer pat-123", "Authorization: Bearer [REDACTED]"},
		{"GH_TOKEN='a b' api_key=xyz passwd=1", "GH_TOKEN=[REDACTED] api_key=[REDACTED] passwd=[REDACTED]"},
		// Nothing secret: untouched.
		{
			"command workspace.start failed: GET https://api.clux.space/api/x.tar.gz: 401 Unauthorized",
			"command workspace.start failed: GET https://api.clux.space/api/x.tar.gz: 401 Unauthorized",
		},
		{"--memory 512m -p 127.0.0.1::9100 user@example.com", "--memory 512m -p 127.0.0.1::9100 user@example.com"},
		{"denied: Your authorization token has expired; no basic auth credentials", "denied: Your authorization token has expired; no basic auth credentials"},
	} {
		if got := String(c.in); got != c.want {
			t.Errorf("String(%q)\n got %q\nwant %q", c.in, got, c.want)
		}
	}
}

func TestArgsAndEnv(t *testing.T) {
	args := []string{"run", "-e", "SIDECAR_HMAC_SECRET=s", "--env=GH_TOKEN=t", "-eAUTH_X=y",
		"-e", "GITHUB_CLONE_URL=https://u:p@github.com/o/r", "-v", "vol:/workspace", "img"}
	got := strings.Join(Args(args), " ")
	want := "run -e SIDECAR_HMAC_SECRET=[REDACTED] --env=GH_TOKEN=[REDACTED] -eAUTH_X=[REDACTED] " +
		"-e GITHUB_CLONE_URL=https://u:[REDACTED]@github.com/o/r -v vol:/workspace img"
	if got != want {
		t.Fatalf("Args\n got %q\nwant %q", got, want)
	}
	if args[2] != "SIDECAR_HMAC_SECRET=s" {
		t.Fatal("Args modified its input")
	}
	env := EnvList([]string{"PATH=/usr/bin", "CLAUDE_CODE_OAUTH_TOKEN=x", "Credential_File=f", "HTTP_PROXY=http://ws-1:pw@127.0.0.1:1"})
	if strings.Join(env, " ") != "PATH=/usr/bin CLAUDE_CODE_OAUTH_TOKEN=[REDACTED] Credential_File=[REDACTED] HTTP_PROXY=http://ws-1:[REDACTED]@127.0.0.1:1" {
		t.Fatalf("EnvList %q", env)
	}
}
