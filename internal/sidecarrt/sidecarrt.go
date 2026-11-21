// Package sidecarrt installs the native sidecar runtime: the backend's
// sidecar bundle (workspace.start "sidecar_bundle"), a Python 3.12 venv
// with its hashed requirements lock, and the claude CLI that ships inside
// claude-agent-sdk.
//
// It runs in `clux host start`, as the owner, not in the agent-user
// supervisor: the bundle download needs the host's PAT (which must never
// reach the agent user), and the agent user has no network except the
// egress proxy. The result lives in native.RuntimeRoot (owner:_cluxslots
// 0750): readable and executable by every slot user, writable only by the
// owner, so a compromised workspace can't tamper with the code later
// workspaces run.
//
// Supply chain: the bundle is checked against the sha256 the backend sent;
// uv is a pinned release checked against a pinned sha256; uv checks the
// Python build it downloads against its own embedded hashes; packages are
// installed with --require-hashes and --only-binary :all: (wheels only, so
// no package build code runs on the owner's account at install time).
package sidecarrt

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

// Pinned uv release (>= 2 weeks old when pinned). Bump both hashes together
// from the release's .sha256 files.
const uvVersion = "0.9.26"

var uvSHA256 = map[string]string{
	"arm64": "fcf0a9ea6599c6ae28a4c854ac6da76f2c889354d7c36ce136ef071f7ab9721f", // uv-aarch64-apple-darwin.tar.gz
	"amd64": "171eb8c518313e157c5b4cec7b4f743bc6bab1bd23e09b646679a02d096a047f", // uv-x86_64-apple-darwin.tar.gz
}

var uvTriple = map[string]string{"arm64": "aarch64-apple-darwin", "amd64": "x86_64-apple-darwin"}

const (
	pythonVersion = "3.12"
	// DefaultKeep is how many installed sidecar versions are kept (plus any
	// still used by a running workspace).
	DefaultKeep = 2

	maxBundleBytes  = 256 << 20
	maxUVBytes      = 128 << 20
	maxExtractBytes = 512 << 20
	readyFile       = ".ready"
)

// skipOnDarwin are lock entries that only matter on Linux and ship no macOS
// wheel; the sidecar treats them as optional (inotify -> polling).
var skipOnDarwin = map[string]bool{"inotify-simple": true}

// Bundle is workspace.start's sidecar_bundle.
type Bundle struct {
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
	URL     string `json:"url"`
}

// BundleFromFrame reads and validates sidecar_bundle from a decoded frame.
func BundleFromFrame(v any) (Bundle, error) {
	m, _ := v.(map[string]any)
	if m == nil {
		return Bundle{}, errors.New("native workspace.start needs sidecar_bundle {version, sha256, url}")
	}
	b := Bundle{}
	b.Version, _ = m["version"].(string)
	b.SHA256, _ = m["sha256"].(string)
	b.URL, _ = m["url"].(string)
	b.SHA256 = strings.ToLower(b.SHA256)
	if !validVersion(b.Version) {
		return Bundle{}, fmt.Errorf("invalid sidecar_bundle.version %q", b.Version)
	}
	if len(b.SHA256) != 64 {
		return Bundle{}, errors.New("invalid sidecar_bundle.sha256")
	}
	if _, err := hex.DecodeString(b.SHA256); err != nil {
		return Bundle{}, errors.New("invalid sidecar_bundle.sha256")
	}
	if u, err := url.Parse(b.URL); err != nil || (u.Scheme != "https" && !isLocalHTTP(u)) {
		return Bundle{}, errors.New("sidecar_bundle.url must be https")
	}
	return b, nil
}

func validVersion(v string) bool {
	if v == "" || len(v) > 64 || v[0] == '.' {
		return false
	}
	for _, c := range v {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '.' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// isLocalHTTP allows plain http only to a local dev backend.
func isLocalHTTP(u *url.URL) bool {
	h := u.Hostname()
	return u.Scheme == "http" && (h == "localhost" || h == "127.0.0.1" || h == "::1")
}

// Runtime is an installed sidecar runtime.
type Runtime struct {
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
	Dir     string `json:"dir"`
	Python  string `json:"python"`
	Sidecar string `json:"sidecar"`
	Claude  string `json:"claude"`
}

// Installer installs runtimes under Root.
type Installer struct {
	Root string
	// BackendURL + Token authenticate the bundle download. The token is only
	// sent when the bundle URL has the backend's own origin.
	BackendURL string
	Token      string
	Keep       int
	Logf       func(format string, args ...any)

	HTTP     *http.Client
	UVURL    string // default: the pinned GitHub release asset for GOARCH
	UVSHA256 string
	// run executes a command (test seam).
	run func(ctx context.Context, env []string, name string, args ...string) ([]byte, error)

	mu sync.Mutex
}

func (i *Installer) logf(format string, args ...any) {
	if i.Logf != nil {
		i.Logf(format, args...)
	}
}

// Ensure returns the runtime for b, installing it if needed. inUse lists
// versions that must survive pruning (running workspaces).
func (i *Installer) Ensure(ctx context.Context, b Bundle, inUse []string) (Runtime, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	dir := filepath.Join(i.Root, "sidecar", b.Version)
	if rt, ok := readReady(dir); ok && rt.SHA256 == b.SHA256 {
		now := time.Now()
		_ = os.Chtimes(filepath.Join(dir, readyFile), now, now) // most recently used
		return rt, nil
	}
	i.logf("installing native sidecar runtime %s", b.Version)
	start := time.Now()
	rt, err := i.install(ctx, b, dir)
	if err != nil {
		_ = os.RemoveAll(dir)
		return Runtime{}, fmt.Errorf("installing sidecar runtime %s: %w", b.Version, err)
	}
	i.logf("native sidecar runtime %s installed in %s", b.Version, time.Since(start).Round(time.Second))
	i.prune(append(inUse, b.Version))
	return rt, nil
}

func (i *Installer) install(ctx context.Context, b Bundle, dir string) (Runtime, error) {
	if err := os.RemoveAll(dir); err != nil { // a half-done earlier attempt
		return Runtime{}, err
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return Runtime{}, err
	}
	archive, err := i.fetch(ctx, b.URL, b.SHA256, maxBundleBytes, i.sameOrigin(b.URL))
	if err != nil {
		return Runtime{}, fmt.Errorf("sidecar bundle: %w", err)
	}
	srcDir := filepath.Join(dir, "src")
	if err := extractTarGz(bytes.NewReader(archive), srcDir, nil); err != nil {
		return Runtime{}, fmt.Errorf("sidecar bundle: %w", err)
	}
	app, err := findSidecar(srcDir)
	if err != nil {
		return Runtime{}, err
	}
	lock, err := os.ReadFile(filepath.Join(app, "requirements.txt"))
	if err != nil {
		return Runtime{}, fmt.Errorf("sidecar bundle has no requirements.txt: %w", err)
	}
	reqPath := filepath.Join(dir, "requirements.macos.txt")
	if err := os.WriteFile(reqPath, FilterRequirements(lock, skipOnDarwin), 0o640); err != nil {
		return Runtime{}, err
	}

	uv, err := i.ensureUV(ctx)
	if err != nil {
		return Runtime{}, err
	}
	env := i.uvEnv()
	venv := filepath.Join(dir, "venv")
	if out, err := i.exec(ctx, env, uv, "venv", "--python", pythonVersion, venv); err != nil {
		return Runtime{}, fmt.Errorf("uv venv: %w: %s", err, tailBytes(out))
	}
	py := filepath.Join(venv, "bin", "python")
	if out, err := i.exec(ctx, env, uv, "pip", "install", "--python", py,
		"--require-hashes", "--only-binary", ":all:", "--compile-bytecode", "-r", reqPath); err != nil {
		return Runtime{}, fmt.Errorf("uv pip install: %w: %s", err, tailBytes(out))
	}
	claude, err := findClaude(venv)
	if err != nil {
		return Runtime{}, err
	}
	rt := Runtime{
		Version: b.Version, SHA256: b.SHA256, Dir: dir, Python: py,
		Sidecar: filepath.Join(app, "sidecar.py"), Claude: claude,
	}
	data, _ := json.MarshalIndent(rt, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, readyFile), data, 0o640); err != nil {
		return Runtime{}, err
	}
	return rt, nil
}

func (i *Installer) uvEnv() []string {
	return []string{
		"HOME=" + filepath.Join(i.Root, "cache", "home"),
		"PATH=/usr/bin:/bin:/usr/sbin:/sbin",
		"UV_PYTHON_INSTALL_DIR=" + filepath.Join(i.Root, "python"),
		"UV_CACHE_DIR=" + filepath.Join(i.Root, "cache", "uv"),
		"UV_PYTHON_PREFERENCE=only-managed",
		"UV_NO_CONFIG=1",
		"UV_NO_PROGRESS=1",
	}
}

func (i *Installer) exec(ctx context.Context, env []string, name string, args ...string) ([]byte, error) {
	if i.run != nil {
		return i.run(ctx, env, name, args...)
	}
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(env, proxyEnv()...)
	return cmd.CombinedOutput()
}

// proxyEnv passes the owner's own proxy settings through to uv.
func proxyEnv() []string {
	var out []string
	for _, k := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "NO_PROXY", "no_proxy", "SSL_CERT_FILE"} {
		if v, ok := os.LookupEnv(k); ok {
			out = append(out, k+"="+v)
		}
	}
	return out
}

func (i *Installer) ensureUV(ctx context.Context) (string, error) {
	bin := filepath.Join(i.Root, "uv", uvVersion, "uv")
	if st, err := os.Stat(bin); err == nil && st.Mode().IsRegular() && st.Mode()&0o100 != 0 {
		return bin, nil
	}
	u, sum := i.UVURL, i.UVSHA256
	if u == "" {
		triple, ok := uvTriple[runtime.GOARCH]
		if !ok {
			return "", fmt.Errorf("no pinned uv for %s", runtime.GOARCH)
		}
		u = fmt.Sprintf("https://github.com/astral-sh/uv/releases/download/%s/uv-%s.tar.gz", uvVersion, triple)
		sum = uvSHA256[runtime.GOARCH]
	}
	archive, err := i.fetch(ctx, u, sum, maxUVBytes, false)
	if err != nil {
		return "", fmt.Errorf("uv: %w", err)
	}
	dir := filepath.Dir(bin)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", err
	}
	// Only the uv binary is taken from the archive.
	if err := extractTarGz(bytes.NewReader(archive), dir, func(name string) (string, bool) {
		return "uv", filepath.Base(name) == "uv"
	}); err != nil {
		return "", fmt.Errorf("uv: %w", err)
	}
	if err := os.Chmod(bin, 0o750); err != nil {
		return "", fmt.Errorf("uv: %w", err)
	}
	return bin, nil
}

func (i *Installer) sameOrigin(raw string) bool {
	a, err1 := url.Parse(raw)
	b, err2 := url.Parse(i.BackendURL)
	return err1 == nil && err2 == nil && i.Token != "" &&
		strings.EqualFold(a.Scheme, b.Scheme) && strings.EqualFold(a.Host, b.Host)
}

// fetch downloads u (bounded) and checks its sha256.
func (i *Installer) fetch(ctx context.Context, u, wantSHA string, limit int64, auth bool) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	if auth {
		req.Header.Set("Authorization", "Bearer "+i.Token)
	}
	c := i.HTTP
	if c == nil {
		c = &http.Client{Timeout: 10 * time.Minute}
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", redact(u), resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("GET %s: larger than %d bytes", redact(u), limit)
	}
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); !strings.EqualFold(got, wantSHA) {
		return nil, fmt.Errorf("sha256 mismatch for %s: got %s, want %s", redact(u), got, wantSHA)
	}
	return data, nil
}

func redact(u string) string {
	p, err := url.Parse(u)
	if err != nil {
		return "<url>"
	}
	p.RawQuery = ""
	p.User = nil
	return p.String()
}

// prune keeps the Keep most recently used versions plus keep.
func (i *Installer) prune(keep []string) {
	n := i.Keep
	if n <= 0 {
		n = DefaultKeep
	}
	root := filepath.Join(i.Root, "sidecar")
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	type ver struct {
		name string
		used time.Time
	}
	var vs []ver
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		st, err := os.Stat(filepath.Join(root, e.Name(), readyFile))
		if err != nil {
			continue // not a finished install (only Ensure creates these, under i.mu)
		}
		vs = append(vs, ver{e.Name(), st.ModTime()})
	}
	sort.Slice(vs, func(a, b int) bool { return vs[a].used.After(vs[b].used) })
	pinned := map[string]bool{}
	for _, k := range keep {
		pinned[k] = true
	}
	kept := 0
	for _, v := range vs {
		if pinned[v.name] || kept < n {
			if !pinned[v.name] {
				kept++
			}
			continue
		}
		i.logf("removing old native sidecar runtime %s", v.name)
		_ = os.RemoveAll(filepath.Join(root, v.name))
	}
}

func readReady(dir string) (Runtime, bool) {
	b, err := os.ReadFile(filepath.Join(dir, readyFile))
	if err != nil {
		return Runtime{}, false
	}
	var rt Runtime
	if json.Unmarshal(b, &rt) != nil || rt.Python == "" || rt.Claude == "" {
		return Runtime{}, false
	}
	for _, p := range []string{rt.Python, rt.Sidecar, rt.Claude} {
		if _, err := os.Stat(p); err != nil {
			return Runtime{}, false
		}
	}
	return rt, true
}

// findSidecar locates the directory holding sidecar.py: the archive root or
// one directory down (a tar of the sidecar/ folder itself).
func findSidecar(src string) (string, error) {
	if _, err := os.Stat(filepath.Join(src, "sidecar.py")); err == nil {
		return src, nil
	}
	entries, _ := os.ReadDir(src)
	for _, e := range entries {
		d := filepath.Join(src, e.Name())
		if _, err := os.Stat(filepath.Join(d, "sidecar.py")); e.IsDir() && err == nil {
			return d, nil
		}
	}
	return "", errors.New("sidecar bundle has no sidecar.py")
}

func findClaude(venv string) (string, error) {
	m, _ := filepath.Glob(filepath.Join(venv, "lib", "python3*", "site-packages", "claude_agent_sdk", "_bundled", "claude"))
	for _, p := range m {
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() && st.Mode()&0o111 != 0 {
			return p, nil
		}
	}
	return "", errors.New("claude CLI not found in the venv (claude-agent-sdk ships it under _bundled/claude)")
}

// FilterRequirements drops the given packages from a `uv pip compile
// --generate-hashes` lock (a "name==version \" line plus its indented
// --hash/comment continuation lines). Everything else is kept verbatim.
func FilterRequirements(lock []byte, skip map[string]bool) []byte {
	var out bytes.Buffer
	dropping := false
	for _, line := range strings.SplitAfter(string(lock), "\n") {
		trimmed := strings.TrimSpace(line)
		indented := len(line) > 0 && (line[0] == ' ' || line[0] == '\t')
		if !indented && trimmed != "" && !strings.HasPrefix(trimmed, "#") && !strings.HasPrefix(trimmed, "-") {
			name := trimmed
			if i := strings.IndexAny(name, "=<>!~[; \\"); i >= 0 {
				name = name[:i]
			}
			name = strings.ReplaceAll(strings.ToLower(name), "_", "-")
			dropping = skip[name]
		} else if !indented {
			dropping = false
		}
		if !dropping {
			out.WriteString(line)
		}
	}
	return out.Bytes()
}

// extractTarGz unpacks regular files and directories only (no links or
// devices), refusing absolute paths and "..", within a size budget. pick,
// if set, renames/filters entries.
func extractTarGz(r io.Reader, dest string, pick func(name string) (string, bool)) error {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	var total int64
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		name := h.Name
		if pick != nil {
			var ok bool
			if name, ok = pick(name); !ok {
				continue
			}
		}
		clean := filepath.Clean(filepath.FromSlash(name))
		if filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
			return fmt.Errorf("archive entry %q escapes the destination", h.Name)
		}
		target := filepath.Join(dest, clean)
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o750); err != nil {
				return err
			}
		case tar.TypeReg:
			total += h.Size
			if total > maxExtractBytes {
				return errors.New("archive too large")
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
				return err
			}
			mode := os.FileMode(0o640)
			if h.Mode&0o111 != 0 {
				mode = 0o750
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
			if err != nil {
				return err
			}
			_, err = io.Copy(f, io.LimitReader(tr, h.Size))
			if cerr := f.Close(); err == nil {
				err = cerr
			}
			if err != nil {
				return err
			}
		case tar.TypeXGlobalHeader, tar.TypeXHeader:
		default:
			if pick != nil {
				continue
			}
			return fmt.Errorf("archive entry %q: links and special files are not allowed", h.Name)
		}
	}
}

func tailBytes(b []byte) string {
	const n = 1500
	if len(b) > n {
		b = b[len(b)-n:]
	}
	return strings.TrimSpace(string(b))
}
