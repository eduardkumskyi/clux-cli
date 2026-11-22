package supervisor

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
)

// parseProcArgs splits a kern.procargs2 buffer: int32 argc, the exec path,
// NUL padding, argc arguments, then the environment, all NUL-terminated.
func parseProcArgs(buf []byte) (args, env []string, err error) {
	if len(buf) < 4 {
		return nil, nil, errors.New("procargs: short buffer")
	}
	argc := int(int32(binary.LittleEndian.Uint32(buf)))
	rest := buf[4:]
	i := bytes.IndexByte(rest, 0) // exec path
	if i < 0 {
		return nil, nil, errors.New("procargs: no exec path")
	}
	rest = rest[i:]
	for len(rest) > 0 && rest[0] == 0 {
		rest = rest[1:]
	}
	var all []string
	for len(rest) > 0 {
		j := bytes.IndexByte(rest, 0)
		if j < 0 {
			j = len(rest)
		}
		s := string(rest[:j])
		if j < len(rest) {
			rest = rest[j+1:]
		} else {
			rest = nil
		}
		if s == "" && len(all) >= argc {
			break // end of environment
		}
		all = append(all, s)
	}
	if argc > len(all) {
		argc = len(all)
	}
	return all[:argc], all[argc:], nil
}

// envValue returns key's value in an environ slice.
func envValue(env []string, key string) (string, bool) {
	for _, kv := range env {
		if k, v, ok := strings.Cut(kv, "="); ok && k == key {
			return v, true
		}
	}
	return "", false
}

// SidecarEnvParams are the inputs of a native sidecar's environment.
type SidecarEnvParams struct {
	WorkspaceID    string
	WorkspaceDir   string
	Port           int
	HMACSecret     string
	GithubCloneURL string
	ProxyURL       string
	BackendURL     string
	Runtime        RuntimeSpec
	DeveloperDir   string
	CPUCount       int
	MemoryMB       int64
	AgentUser      string
	GitTemplateDir string
}

// SidecarEnv builds the sidecar's complete environment (nothing is
// inherited from the supervisor). The claude CLI is found via
// CLAUDE_CLI_PATH and, for today's sidecar (which spawns argv "claude"),
// via PATH: its directory comes first.
func SidecarEnv(p SidecarEnvParams) []string {
	home := filepath.Join(p.WorkspaceDir, ".home")
	tmp := filepath.Join(p.WorkspaceDir, ".tmp") + "/"
	path := strings.Join([]string{
		filepath.Dir(p.Runtime.Claude),
		filepath.Dir(p.Runtime.Python),
		"/usr/bin", "/bin", "/usr/sbin", "/sbin", "/opt/homebrew/bin", "/usr/local/bin",
	}, ":")
	noProxy := "localhost,127.0.0.1,::1"
	env := []string{
		"WORKSPACE_ID=" + p.WorkspaceID,
		"WORKSPACE_DIR=" + p.WorkspaceDir,
		"SIDECAR_PORT=" + strconv.Itoa(p.Port),
		"SIDECAR_HMAC_SECRET=" + p.HMACSecret,
		"HOME=" + home,
		"TMPDIR=" + tmp,
		"USER=" + p.AgentUser,
		"LOGNAME=" + p.AgentUser,
		"SHELL=/bin/zsh",
		"PATH=" + path,
		"LANG=en_US.UTF-8",
		"CLAUDE_CLI_PATH=" + p.Runtime.Claude,
		"CLUX_RUNTIME=native_macos",
		// No Docker in native mode; the CLI must not try to update itself
		// into the read-only runtime.
		"DISABLE_DOCKER=1",
		"DISABLE_AUTOUPDATER=1",
		"PYTHONUNBUFFERED=1",
		"PYTHONDONTWRITEBYTECODE=1",
		// Lowercase too: curl and git only honor lowercase http_proxy.
		"HTTP_PROXY=" + p.ProxyURL, "http_proxy=" + p.ProxyURL,
		"HTTPS_PROXY=" + p.ProxyURL, "https_proxy=" + p.ProxyURL,
		"ALL_PROXY=" + p.ProxyURL, "all_proxy=" + p.ProxyURL,
		"NO_PROXY=" + noProxy, "no_proxy=" + noProxy,
		"MACHINE_CPU_COUNT=" + strconv.Itoa(p.CPUCount),
		"MACHINE_MEMORY_MB=" + strconv.FormatInt(p.MemoryMB, 10),
	}
	if p.GitTemplateDir != "" {
		// Empty template: `git init`/clone create no sample hooks (writes to
		// .git/hooks are denied by the sandbox profile).
		env = append(env, "GIT_TEMPLATE_DIR="+p.GitTemplateDir)
	}
	if p.DeveloperDir != "" {
		env = append(env, "DEVELOPER_DIR="+p.DeveloperDir)
	}
	if p.GithubCloneURL != "" {
		env = append(env, "GITHUB_CLONE_URL="+p.GithubCloneURL)
	}
	if ValidBackendURL(p.BackendURL) {
		// Where the sidecar forwards the agent's host-command requests.
		env = append(env, "CLUX_BACKEND_URL="+p.BackendURL)
	}
	return env
}

// ValidBackendURL reports whether raw is a plain http(s) URL with a host
// and no credentials, query or fragment: fit to become the sidecar's
// CLUX_BACKEND_URL.
func ValidBackendURL(raw string) bool {
	if raw == "" || len(raw) > 2048 || strings.ContainsAny(raw, "\x00\r\n\t ") {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	return u.Scheme == "https" || u.Scheme == "http"
}

// validProxyURL checks the proxy URL the owner sent points at the
// configured loopback proxy port (pf allows nothing else anyway; this
// catches misconfiguration early) and carries this workspace's user.
func validProxyURL(raw, workspaceID string, port int) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || u.User == nil {
		return false
	}
	if _, ok := u.User.Password(); !ok || u.User.Username() != "ws-"+workspaceID {
		return false
	}
	return u.Host == "127.0.0.1:"+strconv.Itoa(port)
}
