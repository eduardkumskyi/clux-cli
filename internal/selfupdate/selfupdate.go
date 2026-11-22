// Package selfupdate replaces the running clux binary with a GitHub release
// (`clux update`): it resolves the release, downloads the archive for this
// GOOS/GOARCH (the names .goreleaser.yaml publishes), checks it against the
// release's checksums.txt, extracts the binary and renames it over the old
// one in the same directory, so a crash never leaves a half-written clux.
//
// checksums.txt is trusted only once its signature (checksums.txt.sig, see
// signature.go) verifies against a key embedded in this binary. Releases
// older than FirstSignedRelease have none; only a caller that allows it
// (`clux update`, never the root daemon) accepts those on the checksum
// alone.
package selfupdate

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Repo is the GitHub repository releases come from.
const Repo = "eduardkumskyi/clux-cli"

const (
	defaultAPIBase      = "https://api.github.com"
	defaultDownloadBase = "https://github.com"
	// The archives are ~10 MB; anything far bigger is not a clux release.
	maxArchiveBytes   = 200 << 20
	maxChecksumsBytes = 1 << 20
	maxSignatureBytes = 4 << 10
)

// Client talks to GitHub releases. Zero values use the real endpoints.
type Client struct {
	HTTP         *http.Client
	APIBase      string // https://api.github.com
	DownloadBase string // https://github.com
	GOOS, GOARCH string
	// Keys verify release signatures; nil = TrustedKeys().
	Keys []ed25519.PublicKey
}

func (c *Client) keys() []ed25519.PublicKey {
	if c.Keys != nil {
		return c.Keys
	}
	return TrustedKeys()
}

func (c *Client) http() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 2 * time.Minute}
}

func (c *Client) apiBase() string {
	if c.APIBase != "" {
		return strings.TrimRight(c.APIBase, "/")
	}
	return defaultAPIBase
}

func (c *Client) downloadBase() string {
	if c.DownloadBase != "" {
		return strings.TrimRight(c.DownloadBase, "/")
	}
	return defaultDownloadBase
}

// Latest is the tag of the newest release ("v0.6.0").
func (c *Client) Latest(ctx context.Context) (string, error) {
	url := fmt.Sprintf("%s/repos/%s/releases/latest", c.apiBase(), Repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := c.http().Do(req)
	if err != nil {
		return "", fmt.Errorf("looking up the latest release: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("looking up the latest release: GitHub answered %s", resp.Status)
	}
	var body struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil {
		return "", fmt.Errorf("reading the latest release: %w", err)
	}
	if _, ok := Parse(body.TagName); !ok {
		return "", fmt.Errorf("the latest release has an unexpected tag %q", body.TagName)
	}
	return body.TagName, nil
}

// AssetName is the release archive for a platform, as .goreleaser.yaml
// names it.
func AssetName(goos, goarch string) string {
	if goos == "windows" {
		return fmt.Sprintf("clux_%s_%s.zip", goos, goarch)
	}
	return fmt.Sprintf("clux_%s_%s.tar.gz", goos, goarch)
}

// BinaryName is the executable inside the archive.
func BinaryName(goos string) string {
	if goos == "windows" {
		return "clux.exe"
	}
	return "clux"
}

// Download fetches the release's archive for c.GOOS/c.GOARCH, verifies it
// and returns the clux binary inside it. checksums.txt must carry a valid
// signature over tag (signed = true); a bad signature is always an error.
// A missing one is accepted (signed = false) only with allowUnsigned, and
// only for a release older than FirstSignedRelease.
func (c *Client) Download(ctx context.Context, tag string, allowUnsigned bool) (binary []byte, signed bool, err error) {
	if !ValidTag(tag) {
		return nil, false, fmt.Errorf("%q is not a release tag (e.g. v0.7.0)", tag)
	}
	asset := AssetName(c.GOOS, c.GOARCH)
	base := fmt.Sprintf("%s/%s/releases/download/%s/", c.downloadBase(), Repo, tag)
	sums, err := c.fetch(ctx, base+"checksums.txt", maxChecksumsBytes)
	if err != nil {
		return nil, false, err
	}
	sig, err := c.fetch(ctx, base+SignatureAsset, maxSignatureBytes)
	switch {
	case err == nil:
		if err := VerifySignature(tag, sums, sig, c.keys()); err != nil {
			return nil, false, err
		}
		signed = true
	case !errors.Is(err, errNotFound):
		return nil, false, err
	case !allowUnsigned || !Older(tag, FirstSignedRelease):
		return nil, false, fmt.Errorf("release %s has no %s (%w); refusing it", tag, SignatureAsset, ErrUnsigned)
	}
	want, err := checksumFor(sums, asset)
	if err != nil {
		return nil, false, fmt.Errorf("release %s: %w", tag, err)
	}
	archive, err := c.fetch(ctx, base+asset, maxArchiveBytes)
	if err != nil {
		return nil, false, err
	}
	got := sha256.Sum256(archive)
	if hex.EncodeToString(got[:]) != want {
		return nil, false, fmt.Errorf("%s does not match checksums.txt of %s (download corrupted?); nothing was changed", asset, tag)
	}
	binary, err = extract(archive, c.GOOS)
	return binary, signed, err
}

// errNotFound: GitHub answered 404 for a release asset.
var errNotFound = errors.New("not found")

func (c *Client) fetch(ctx context.Context, url string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http().Do(req)
	if err != nil {
		return nil, fmt.Errorf("downloading %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("%s %w (no such release, or no build for this platform)", url, errNotFound)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("downloading %s: %s", url, resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("downloading %s: %w", url, err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("downloading %s: larger than %d bytes", url, limit)
	}
	return data, nil
}

// checksumFor reads "<sha256>  <file>" lines (goreleaser's format).
func checksumFor(sums []byte, asset string) (string, error) {
	sc := bufio.NewScanner(bytes.NewReader(sums))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) == 2 && strings.TrimPrefix(fields[1], "*") == asset {
			sum := strings.ToLower(fields[0])
			if len(sum) != sha256.Size*2 {
				return "", fmt.Errorf("bad checksum line for %s", asset)
			}
			return sum, nil
		}
	}
	return "", fmt.Errorf("checksums.txt has no entry for %s", asset)
}

func extract(archive []byte, goos string) ([]byte, error) {
	name := BinaryName(goos)
	if goos == "windows" {
		zr, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
		if err != nil {
			return nil, fmt.Errorf("reading the release archive: %w", err)
		}
		for _, f := range zr.File {
			if filepath.Base(f.Name) != name || f.FileInfo().IsDir() {
				continue
			}
			rc, err := f.Open()
			if err != nil {
				return nil, err
			}
			defer rc.Close()
			return readBinary(rc)
		}
		return nil, fmt.Errorf("the release archive has no %s", name)
	}
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, fmt.Errorf("reading the release archive: %w", err)
	}
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("the release archive has no %s", name)
		}
		if err != nil {
			return nil, fmt.Errorf("reading the release archive: %w", err)
		}
		if hdr.Typeflag == tar.TypeReg && filepath.Base(hdr.Name) == name {
			return readBinary(tr)
		}
	}
}

func readBinary(r io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxArchiveBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) == 0 || len(data) > maxArchiveBytes {
		return nil, errors.New("the binary in the release archive has an unexpected size")
	}
	return data, nil
}

// PermissionError: the binary's directory is not writable by this user
// (e.g. /usr/local/bin owned by root).
type PermissionError struct {
	Dir string
	Err error
}

func (e *PermissionError) Error() string {
	return fmt.Sprintf("%s is not writable by you: %v", e.Dir, e.Err)
}
func (e *PermissionError) Unwrap() error { return e.Err }

// Replace atomically puts binary at exe: written to a temp file in the same
// directory, then renamed over it, so exe is always either the old or the
// new binary. A running process keeps its old copy. On Windows the running
// .exe can't be overwritten but can be renamed, so it moves aside to
// exe+".old" first.
func Replace(exe string, binary []byte, goos string) error {
	dir := filepath.Dir(exe)
	tmp, err := os.CreateTemp(dir, ".clux-update-*")
	if err != nil {
		if errors.Is(err, fs.ErrPermission) {
			return &PermissionError{Dir: dir, Err: err}
		}
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after the rename
	if _, err := tmp.Write(binary); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o755); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if goos == "windows" {
		old := exe + ".old"
		_ = os.Remove(old)
		if err := os.Rename(exe, old); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	if err := os.Rename(tmpName, exe); err != nil {
		if errors.Is(err, fs.ErrPermission) {
			return &PermissionError{Dir: dir, Err: err}
		}
		return err
	}
	return nil
}

// --- versions ----------------------------------------------------------------

// Parse reads "v0.5.2" / "0.5.2" / "1.0.0-rc.1" (suffix ignored).
func Parse(v string) ([3]int, bool) {
	var out [3]int
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i]
	}
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return out, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return out, false
		}
		out[i] = n
	}
	return out, true
}

// Older reports whether a is an older release than b. An unparseable a (a
// dev build) counts as older; an unparseable b makes nothing older.
func Older(a, b string) bool {
	vb, ok := Parse(b)
	if !ok {
		return false
	}
	va, ok := Parse(a)
	if !ok {
		return true
	}
	for i := range va {
		if va[i] != vb[i] {
			return va[i] < vb[i]
		}
	}
	return false
}

// Tag is the release tag for a version the user typed ("0.6.0" -> "v0.6.0").
func Tag(v string) string {
	v = strings.TrimSpace(v)
	if v == "" || strings.HasPrefix(v, "v") {
		return v
	}
	return "v" + v
}
