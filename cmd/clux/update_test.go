package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/eduardkumskyi/clux-cli/internal/selfupdate"
)

// fakeRelease serves latest = tag with a clux_<GOOS>_<GOARCH>.tar.gz holding
// binary, plus its checksums.txt.
func fakeRelease(t *testing.T, tag string, binary []byte) *selfupdate.Client {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	tw.WriteHeader(&tar.Header{Name: "clux", Mode: 0o755, Size: int64(len(binary)), Typeflag: tar.TypeReg})
	tw.Write(binary)
	tw.Close()
	gz.Close()
	archive := buf.Bytes()
	digest := sha256.Sum256(archive)
	asset := selfupdate.AssetName("linux", "amd64")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		base := "/" + selfupdate.Repo + "/releases/download/" + tag + "/"
		switch r.URL.Path {
		case "/repos/" + selfupdate.Repo + "/releases/latest":
			fmt.Fprintf(w, `{"tag_name": %q}`, tag)
		case base + "checksums.txt":
			fmt.Fprintf(w, "%s  %s\n", hex.EncodeToString(digest[:]), asset)
		case base + asset:
			w.Write(archive)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return &selfupdate.Client{APIBase: srv.URL, DownloadBase: srv.URL, GOOS: "linux", GOARCH: "amd64"}
}

type fakeUpdate struct {
	u          *updater
	out        *bytes.Buffer
	exe        string
	restarted  bool
	sudoCalled bool
	refreshed  bool
}

func newFakeUpdate(t *testing.T, current, latest string) *fakeUpdate {
	t.Helper()
	f := &fakeUpdate{out: &bytes.Buffer{}}
	f.exe = filepath.Join(t.TempDir(), "clux")
	os.WriteFile(f.exe, []byte("old"), 0o755)
	f.u = &updater{
		current:       current,
		client:        fakeRelease(t, latest, []byte("new")),
		exe:           func() (string, error) { return f.exe, nil },
		temporary:     func(string) bool { return false },
		sudoReplace:   func(b []byte, exe string) error { f.sudoCalled = true; return os.WriteFile(exe, b, 0o755) },
		restart:       func(io.Writer) { f.restarted = true },
		nativeBehind:  func(string) string { return "" },
		nativeRefresh: func() error { f.refreshed = true; return nil },
		in:            strings.NewReader(""),
		out:           f.out,
	}
	return f
}

func (f *fakeUpdate) binary(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(f.exe)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestUpdateReplacesTheBinaryAndRestartsTheService(t *testing.T) {
	f := newFakeUpdate(t, "v0.5.2", "v0.6.0")
	if err := f.u.run(context.Background(), false, ""); err != nil {
		t.Fatal(err)
	}
	if f.binary(t) != "new" || !f.restarted {
		t.Fatalf("binary %q restarted %v; out:\n%s", f.binary(t), f.restarted, f.out)
	}
	if !strings.Contains(f.out.String(), "Updated clux v0.5.2 -> v0.6.0") {
		t.Fatalf("out:\n%s", f.out)
	}
}

func TestUpdateWhenCurrentChangesNothing(t *testing.T) {
	f := newFakeUpdate(t, "v0.6.0", "v0.6.0")
	if err := f.u.run(context.Background(), false, ""); err != nil {
		t.Fatal(err)
	}
	if f.binary(t) != "old" || f.restarted || !strings.Contains(f.out.String(), "up to date") {
		t.Fatalf("out:\n%s", f.out)
	}
}

func TestUpdateCheckOnlyReports(t *testing.T) {
	f := newFakeUpdate(t, "v0.5.2", "v0.6.0")
	if err := f.u.run(context.Background(), true, ""); err != nil {
		t.Fatal(err)
	}
	if f.binary(t) != "old" || f.restarted {
		t.Fatal("--check must change nothing")
	}
	if got := strings.TrimSpace(f.out.String()); got != "clux v0.6.0 is available (this is v0.5.2): run `clux update`" {
		t.Fatalf("out: %q", got)
	}
}

func TestUpdateToAGivenVersion(t *testing.T) {
	f := newFakeUpdate(t, "v0.7.0", "v0.6.0")
	// An explicit version installs even an older one (rollback).
	if err := f.u.run(context.Background(), false, "0.6.0"); err != nil {
		t.Fatal(err)
	}
	if f.binary(t) != "new" {
		t.Fatalf("out:\n%s", f.out)
	}
	if err := f.u.run(context.Background(), false, "../../evil"); err == nil {
		t.Fatal("a non-version must be refused")
	}
}

func TestUpdateInAReadOnlyDir(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs a non-root unix user")
	}
	f := newFakeUpdate(t, "v0.5.2", "v0.6.0")
	dir := filepath.Dir(f.exe)
	os.Chmod(dir, 0o555)
	t.Cleanup(func() { os.Chmod(dir, 0o755) })

	// Not a terminal: a clear message, nothing changed.
	err := f.u.run(context.Background(), false, "")
	if err == nil || !strings.Contains(err.Error(), "is not writable by you") || !strings.Contains(err.Error(), "in a terminal") {
		t.Fatalf("got %v", err)
	}
	if f.binary(t) != "old" || f.sudoCalled {
		t.Fatal("nothing may change without a terminal")
	}

	// A terminal: sudo replaces it (the fake "sudo" is this user, so it
	// opens the directory up first).
	f.u.interactive = true
	f.u.sudoReplace = func(b []byte, exe string) error {
		f.sudoCalled = true
		os.Chmod(dir, 0o755)
		return os.WriteFile(exe, b, 0o755)
	}
	if err := f.u.run(context.Background(), false, ""); err != nil {
		t.Fatal(err)
	}
	if !f.sudoCalled || f.binary(t) != "new" || !strings.Contains(f.out.String(), "needs admin rights") {
		t.Fatalf("out:\n%s", f.out)
	}
}

func TestUpdateRefusesHomebrewAndTemporaryBuilds(t *testing.T) {
	f := newFakeUpdate(t, "v0.5.2", "v0.6.0")
	f.u.exe = func() (string, error) { return "/opt/homebrew/Cellar/clux/0.5.2/bin/clux", nil }
	if err := f.u.run(context.Background(), false, ""); err == nil || !strings.Contains(err.Error(), "brew upgrade clux") {
		t.Fatalf("got %v", err)
	}
	f = newFakeUpdate(t, "v0.5.2", "v0.6.0")
	f.u.temporary = func(string) bool { return true }
	if err := f.u.run(context.Background(), false, ""); err == nil || !strings.Contains(err.Error(), "temporary build") {
		t.Fatalf("got %v", err)
	}
}

func TestUpdateOffersTheNativeRefresh(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the offer is skipped under sudo")
	}
	f := newFakeUpdate(t, "v0.5.2", "v0.6.0")
	f.u.nativeBehind = func(than string) string {
		if than != "v0.6.0" {
			t.Errorf("compared against %q, want the new version", than)
		}
		return "The native macOS runtime still runs clux v0.5.2 (its own copy); refresh it with: sudo clux native install"
	}
	// Not a terminal: just the command.
	if err := f.u.run(context.Background(), false, ""); err != nil {
		t.Fatal(err)
	}
	if f.refreshed || !strings.Contains(f.out.String(), "sudo clux native install") {
		t.Fatalf("out:\n%s", f.out)
	}

	f2 := newFakeUpdate(t, "v0.5.2", "v0.6.0")
	f2.u.nativeBehind = f.u.nativeBehind
	f2.u.interactive = true
	f2.u.in = strings.NewReader("y\n")
	if err := f2.u.run(context.Background(), false, ""); err != nil {
		t.Fatal(err)
	}
	if !f2.refreshed {
		t.Fatalf("a yes must run the refresh; out:\n%s", f2.out)
	}
}

func TestUpdateNotice(t *testing.T) {
	if updateNotice("v0.6.0", "0.6.0") != "" || updateNotice("v0.6.0", "") != "" {
		t.Fatal("no notice when current or unknown")
	}
	if got := updateNotice("v0.5.2", "0.6.0"); got != "clux v0.6.0 is available (this is v0.5.2): run `clux update`" {
		t.Fatalf("got %q", got)
	}
}
