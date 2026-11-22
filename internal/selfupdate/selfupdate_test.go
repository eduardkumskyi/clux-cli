package selfupdate

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func tarGz(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, data := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(data)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		tw.Write(data)
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

func zipped(t *testing.T, name string, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create(name)
	w.Write(data)
	zw.Close()
	return buf.Bytes()
}

func sum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// fakeGitHub serves the latest-release API and one release's assets.
func fakeGitHub(t *testing.T, tag string, assets map[string][]byte, checksums string) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/repos/"+Repo+"/releases/latest" {
			fmt.Fprintf(w, `{"tag_name": %q}`, tag)
			return
		}
		prefix := "/" + Repo + "/releases/download/" + tag + "/"
		name, ok := strings.CutPrefix(r.URL.Path, prefix)
		if !ok {
			http.NotFound(w, r)
			return
		}
		if name == "checksums.txt" {
			w.Write([]byte(checksums))
			return
		}
		data, ok := assets[name]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write(data)
	}))
	t.Cleanup(srv.Close)
	return &Client{APIBase: srv.URL, DownloadBase: srv.URL, GOOS: "darwin", GOARCH: "arm64"}
}

func TestVersions(t *testing.T) {
	for _, tc := range []struct {
		a, b  string
		older bool
	}{
		{"v0.5.2", "v0.6.0", true},
		{"0.9.0", "v0.10.0", true},
		{"v0.6.0", "0.6.0", false},
		{"v1.0.0", "v0.9.9", false},
		{"v0.6.0-rc.1", "v0.6.0", false},
		{"dev", "v0.1.0", true},
		{"v0.1.0", "garbage", false},
	} {
		if got := Older(tc.a, tc.b); got != tc.older {
			t.Errorf("Older(%q, %q) = %v", tc.a, tc.b, got)
		}
	}
	if Tag("0.6.0") != "v0.6.0" || Tag("v0.6.0") != "v0.6.0" {
		t.Fatal("Tag must add exactly one v")
	}
	if AssetName("windows", "amd64") != "clux_windows_amd64.zip" || AssetName("linux", "arm64") != "clux_linux_arm64.tar.gz" {
		t.Fatal("asset names must match .goreleaser.yaml")
	}
}

func TestLatestAndVerifiedDownload(t *testing.T) {
	binary := []byte("new clux binary")
	archive := tarGz(t, map[string][]byte{"README.md": []byte("x"), "clux": binary})
	c := fakeGitHub(t, "v0.6.0", map[string][]byte{"clux_darwin_arm64.tar.gz": archive},
		fmt.Sprintf("%s  clux_linux_amd64.tar.gz\n%s  clux_darwin_arm64.tar.gz\n", strings.Repeat("0", 64), sum(archive)))

	tag, err := c.Latest(context.Background())
	if err != nil || tag != "v0.6.0" {
		t.Fatalf("Latest = %q, %v", tag, err)
	}
	got, err := c.Download(context.Background(), tag)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, binary) {
		t.Fatalf("extracted %q", got)
	}
}

func TestDownloadRejectsAChecksumMismatch(t *testing.T) {
	archive := tarGz(t, map[string][]byte{"clux": []byte("tampered")})
	c := fakeGitHub(t, "v0.6.0", map[string][]byte{"clux_darwin_arm64.tar.gz": archive},
		strings.Repeat("a", 64)+"  clux_darwin_arm64.tar.gz\n")
	if _, err := c.Download(context.Background(), "v0.6.0"); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("want a checksum error, got %v", err)
	}
}

func TestDownloadNeedsAChecksumEntryAndTheAsset(t *testing.T) {
	archive := tarGz(t, map[string][]byte{"clux": []byte("x")})
	c := fakeGitHub(t, "v0.6.0", map[string][]byte{"clux_darwin_arm64.tar.gz": archive}, "")
	if _, err := c.Download(context.Background(), "v0.6.0"); err == nil || !strings.Contains(err.Error(), "no entry") {
		t.Fatalf("want a missing-entry error, got %v", err)
	}
	if _, err := c.Download(context.Background(), "v9.9.9"); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("want not found, got %v", err)
	}
}

func TestWindowsZipIsExtracted(t *testing.T) {
	archive := zipped(t, "clux.exe", []byte("exe"))
	c := fakeGitHub(t, "v0.6.0", map[string][]byte{"clux_windows_amd64.zip": archive}, sum(archive)+"  clux_windows_amd64.zip\n")
	c.GOOS, c.GOARCH = "windows", "amd64"
	got, err := c.Download(context.Background(), "v0.6.0")
	if err != nil || string(got) != "exe" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestReplaceSwapsTheFileAndLeavesNoTemp(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "clux")
	os.WriteFile(exe, []byte("old"), 0o755)
	if err := Replace(exe, []byte("new"), runtime.GOOS); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(exe)
	st, _ := os.Stat(exe)
	// Windows has no exec bits: only the content is meaningful there.
	if string(data) != "new" || runtime.GOOS != "windows" && st.Mode().Perm() != 0o755 {
		t.Fatalf("got %q mode %v", data, st.Mode())
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("leftovers: %v", entries)
	}
}

func TestReplaceInAReadOnlyDirIsAPermissionError(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs a non-root unix user")
	}
	dir := t.TempDir()
	exe := filepath.Join(dir, "clux")
	os.WriteFile(exe, []byte("old"), 0o755)
	os.Chmod(dir, 0o555)
	t.Cleanup(func() { os.Chmod(dir, 0o755) })
	err := Replace(exe, []byte("new"), runtime.GOOS)
	var perm *PermissionError
	if !errors.As(err, &perm) || perm.Dir != dir {
		t.Fatalf("want PermissionError for %s, got %v", dir, err)
	}
	if data, _ := os.ReadFile(exe); string(data) != "old" {
		t.Fatal("the old binary must be untouched")
	}
}
