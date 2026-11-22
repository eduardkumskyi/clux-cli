package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/eduardkumskyi/clux-cli/internal/native"
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
	native     *fakeNative
	// events: the order of native updates ("native <tag>") and service
	// restarts ("restart").
	events []string
}

// fakeNative is the native runtime's copy of clux.
type fakeNative struct {
	f         *fakeUpdate
	installed string
	result    native.UpdateResult
	err       error
	calls     []string // "<tag> explicit=<bool>"
	waited    string
}

func (n *fakeNative) Installed() string { return n.installed }

func (n *fakeNative) Update(_ context.Context, tag string, allowDowngrade bool) (native.UpdateResult, error) {
	n.calls = append(n.calls, fmt.Sprintf("%s explicit=%v", tag, allowDowngrade))
	n.f.events = append(n.f.events, "native "+tag)
	if n.err != nil {
		return native.UpdateResult{}, n.err
	}
	r := n.result
	r.From, r.To = n.installed, tag
	return r, nil
}

func (n *fakeNative) WaitForDaemon(_ context.Context, tag string) error {
	n.waited = tag
	return nil
}

func newFakeUpdate(t *testing.T, current, latest string) *fakeUpdate {
	t.Helper()
	f := &fakeUpdate{out: &bytes.Buffer{}}
	f.native = &fakeNative{f: f}
	f.exe = filepath.Join(t.TempDir(), "clux")
	os.WriteFile(f.exe, []byte("old"), 0o755)
	f.u = &updater{
		current:       current,
		client:        fakeRelease(t, latest, []byte("new")),
		exe:           func() (string, error) { return f.exe, nil },
		temporary:     func(string) bool { return false },
		sudoReplace:   func(b []byte, exe string) error { f.sudoCalled = true; return os.WriteFile(exe, b, 0o755) },
		restart:       func(io.Writer) { f.restarted = true; f.events = append(f.events, "restart") },
		native:        f.native,
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

// Daemons from before the self-update: replaced once as part of the same
// update on a terminal (no question; sudo asks for the password), only
// noticed elsewhere; the root daemon is not asked.
func TestUpdateBootstrapsOldNativeDaemonsOnce(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the offer is skipped under sudo")
	}
	f := newFakeUpdate(t, "v0.5.2", "v0.6.0")
	f.native.installed = "v0.5.2"
	// Not a terminal: just the command.
	if err := f.u.run(context.Background(), false, ""); err != nil {
		t.Fatal(err)
	}
	if f.refreshed || len(f.native.calls) != 0 {
		t.Fatalf("refreshed %v calls %v", f.refreshed, f.native.calls)
	}
	if want := nativeBootstrapNotice("v0.5.2"); strings.Count(f.out.String(), want) != 1 || !strings.Contains(want, "Run `clux update` once in a terminal") {
		t.Fatalf("want the bootstrap notice exactly once; out:\n%s", f.out)
	}

	f2 := newFakeUpdate(t, "v0.5.2", "v0.6.0")
	f2.native.installed = "v0.5.2"
	f2.u.interactive = true
	if err := f2.u.run(context.Background(), false, ""); err != nil {
		t.Fatal(err)
	}
	if !f2.refreshed || strings.Contains(f2.out.String(), "[Y/n]") {
		t.Fatalf("a terminal update must replace the old daemon without asking; out:\n%s", f2.out)
	}
}

// Self-updating daemons: asked to follow the CLI, no sudo, before the
// background service restarts.
func TestUpdateMovesTheNativeDaemons(t *testing.T) {
	f := newFakeUpdate(t, "v0.8.0", "v0.8.0")
	f.native.installed = "v0.7.0"
	f.native.result = native.UpdateResult{Deferred: []int{2}, DaemonRestarting: true}
	if err := f.u.run(context.Background(), false, ""); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(f.native.calls, []string{"v0.8.0 explicit=false"}) || f.native.waited != "v0.8.0" || f.refreshed {
		t.Fatalf("calls %v waited %q refreshed %v", f.native.calls, f.native.waited, f.refreshed)
	}
	out := f.out.String()
	if !strings.Contains(out, "Native macOS runtime updated to clux v0.8.0; slot(s) 2 switch over when their running workspace stops") ||
		strings.Contains(out, "sudo") {
		t.Fatalf("out:\n%s", out)
	}

	// After replacing the CLI: the daemons first, then the service.
	f = newFakeUpdate(t, "v0.8.0", "v0.6.0")
	f.native.installed = "v0.7.0"
	if err := f.u.run(context.Background(), false, "v0.6.0"); err != nil {
		t.Fatal(err)
	}
	// An explicit --version may move the daemons back.
	if !reflect.DeepEqual(f.native.calls, []string{"v0.6.0 explicit=true"}) || !reflect.DeepEqual(f.events, []string{"native v0.6.0", "restart"}) {
		t.Fatalf("calls %v events %v", f.native.calls, f.events)
	}
	if !strings.Contains(f.out.String(), "predates signed releases") {
		t.Fatalf("an unsigned legacy release needs a warning; out:\n%s", f.out)
	}

	// A failure is reported, not fatal.
	f = newFakeUpdate(t, "v0.8.0", "v0.8.0")
	f.native.installed = "v0.7.0"
	f.native.err = errors.New("release v0.8.0 has no checksums.txt.sig")
	if err := f.u.run(context.Background(), false, ""); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(f.out.String(), "Native runtime update failed: release v0.8.0 has no checksums.txt.sig") {
		t.Fatalf("out:\n%s", f.out)
	}
}

func TestSyncNativeDaemonsOnlyUpgradesImplicitly(t *testing.T) {
	var said []string
	say := func(format string, args ...any) { said = append(said, fmt.Sprintf(format, args...)) }
	ctx := context.Background()
	for _, tc := range []struct {
		installed, tag string
		explicit       bool
		want           nativeSync
		calls          int
	}{
		{"", "v0.8.0", false, nativeCurrent, 0},          // not installed
		{"v0.8.0", "v0.8.0", false, nativeCurrent, 0},    // current
		{"v0.9.0", "v0.8.0", false, nativeCurrent, 0},    // newer daemons: host start never downgrades
		{"v0.7.0", "0.3.0-dev", false, nativeCurrent, 0}, // a dev build is no release
		{"v0.7.0", "v0.8.0", false, nativeUpdated, 1},
		{"v0.9.0", "v0.8.0", true, nativeUpdated, 1},
		{"v0.6.0", "v0.8.0", false, nativeBootstrap, 0},
	} {
		f := &fakeUpdate{}
		n := &fakeNative{f: f, installed: tc.installed}
		if got := syncNativeDaemons(ctx, n, tc.tag, tc.explicit, say); got != tc.want || len(n.calls) != tc.calls {
			t.Errorf("%s -> %s explicit=%v: %v with %d call(s)", tc.installed, tc.tag, tc.explicit, got, len(n.calls))
		}
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
