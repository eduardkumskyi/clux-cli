//go:build darwin

package native

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/eduardkumskyi/clux-cli/internal/selfupdate"
)

// fakeSlot is what a fake supervisor answers to the status op.
type fakeSlot struct {
	version string
	busy    bool
	down    bool
}

// testUpdater is a daemonUpdater on a temp dir standing in for the
// root-owned libexec and /etc/clux, with releases from a fake GitHub.
type testUpdater struct {
	u         *daemonUpdater
	bin, conf string
	mu        sync.Mutex
	slots     map[int]*fakeSlot
	restarted []int
	releases  map[string]map[string][]byte // tag -> asset -> content
}

func newTestUpdater(t *testing.T, installed string) *testUpdater {
	t.Helper()
	old := trustedUIDs
	trustedUIDs = []int{0, os.Getuid()}
	t.Cleanup(func() { trustedUIDs = old })
	d := shortTempDir(t)
	libexec := filepath.Join(d, "libexec")
	os.Mkdir(libexec, 0o755)
	tu := &testUpdater{
		bin: filepath.Join(libexec, "clux"), conf: filepath.Join(d, "native.json"),
		slots:    map[int]*fakeSlot{1: {version: installed}, 2: {version: installed}},
		releases: map[string]map[string][]byte{},
	}
	os.WriteFile(tu.bin, []byte("old binary"), 0o755)
	cfg := Config{Version: configVersion, OwnerUID: os.Getuid(), BinaryPath: tu.bin, CLIVersion: installed,
		Slots: []Slot{{1, "_clux1", 431, 431}, {2, "_clux2", 433, 433}}}
	b, _ := json.Marshal(cfg)
	os.WriteFile(tu.conf, b, 0o644)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rest, ok := strings.CutPrefix(r.URL.Path, "/"+selfupdate.Repo+"/releases/download/")
		tag, name, _ := strings.Cut(rest, "/")
		data, found := tu.releases[tag][name]
		if !ok || !found {
			http.NotFound(w, r)
			return
		}
		w.Write(data)
	}))
	t.Cleanup(srv.Close)

	u := newDaemonUpdater(installed, func(ctx context.Context, n int) (string, bool, error) {
		tu.mu.Lock()
		defer tu.mu.Unlock()
		s := tu.slots[n]
		if s.down {
			return "", false, errors.New("not reachable")
		}
		return s.version, s.busy, nil
	}, t.Logf)
	u.client = &selfupdate.Client{DownloadBase: srv.URL, GOOS: "darwin", GOARCH: runtime.GOARCH}
	u.configPath, u.fileUID, u.fileGID = tu.conf, os.Getuid(), os.Getgid()
	u.loadConfig = func() (*Config, error) {
		b, err := os.ReadFile(tu.conf)
		if err != nil {
			return nil, err
		}
		var c Config
		return &c, json.Unmarshal(b, &c)
	}
	u.restartSupervisor = func(n int) error {
		tu.mu.Lock()
		defer tu.mu.Unlock()
		tu.restarted = append(tu.restarted, n)
		cfg, _ := u.loadConfig()
		tu.slots[n].version = cfg.CLIVersion // the new binary answers now
		return nil
	}
	tu.u = u
	return tu
}

// publish serves release tag whose binary is a script printing reports
// (what `clux native daemon-check` prints), signed with key (nil = no
// signature asset).
func (tu *testUpdater) publish(t *testing.T, tag, reports string, key ed25519.PrivateKey) {
	t.Helper()
	script := []byte("#!/bin/sh\n[ \"$1 $2\" = \"native daemon-check\" ] || exit 3\necho " + reports + "\n")
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	tw.WriteHeader(&tar.Header{Name: "clux", Mode: 0o755, Size: int64(len(script)), Typeflag: tar.TypeReg})
	tw.Write(script)
	tw.Close()
	gz.Close()
	asset := selfupdate.AssetName("darwin", runtime.GOARCH)
	digest := sha256.Sum256(buf.Bytes())
	sums := []byte(hex.EncodeToString(digest[:]) + "  " + asset + "\n")
	files := map[string][]byte{asset: buf.Bytes(), "checksums.txt": sums}
	if key != nil {
		files[selfupdate.SignatureAsset] = selfupdate.Sign(key, tag, sums)
	}
	tu.releases[tag] = files
}

func (tu *testUpdater) installed(t *testing.T) (binary, version string) {
	t.Helper()
	b, _ := os.ReadFile(tu.bin)
	cfg, err := tu.u.loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	return string(b), cfg.CLIVersion
}

func releaseKey(t *testing.T, tu *testUpdater) ed25519.PrivateKey {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	tu.u.client.Keys = []ed25519.PublicKey{pub}
	return priv
}

func TestDaemonUpdateInstallsAndDefersBusySlots(t *testing.T) {
	tu := newTestUpdater(t, "v0.7.0")
	key := releaseKey(t, tu)
	tu.publish(t, "v0.8.0", "v0.8.0", key)
	tu.slots[2].busy = true // slot 2 runs a workspace

	r := tu.u.update(context.Background(), KeeperRequest{Op: KeeperOpUpdate, Version: "v0.8.0"})
	if !r.OK || r.Update == nil {
		t.Fatalf("update: %+v", r)
	}
	want := UpdateResult{From: "v0.7.0", To: "v0.8.0", Restarted: []int{1}, Deferred: []int{2}}
	if !reflect.DeepEqual(*r.Update, want) {
		t.Fatalf("result %+v, want %+v", *r.Update, want)
	}
	bin, v := tu.installed(t)
	if !strings.Contains(bin, "echo v0.8.0") || v != "v0.8.0" {
		t.Fatalf("installed %q / %s", bin, v)
	}
	st, _ := os.Stat(tu.bin)
	if st.Mode().Perm() != 0o755 {
		t.Fatalf("mode %v", st.Mode())
	}
	if entries, _ := os.ReadDir(filepath.Dir(tu.bin)); len(entries) != 1 {
		t.Fatalf("staging leftovers: %v", entries)
	}

	// While slot 2 is busy, nothing else restarts and the daemon stays.
	if restarted, deferred, due := tu.u.reconcile(context.Background()); restarted != nil || !reflect.DeepEqual(deferred, []int{2}) || due {
		t.Fatalf("busy: restarted %v deferred %v due %v", restarted, deferred, due)
	}
	// Its workspace stops: slot 2 restarts, then the daemon itself is due.
	tu.slots[2].busy = false
	if restarted, deferred, due := tu.u.reconcile(context.Background()); !reflect.DeepEqual(restarted, []int{2}) || deferred != nil || !due {
		t.Fatalf("idle: restarted %v deferred %v due %v", restarted, deferred, due)
	}
	if !reflect.DeepEqual(tu.restarted, []int{1, 2}) {
		t.Fatalf("restarted %v", tu.restarted)
	}

	// Asking again for the installed version changes nothing.
	r = tu.u.update(context.Background(), KeeperRequest{Op: KeeperOpUpdate, Version: "v0.8.0"})
	if !r.OK || !r.Update.UpToDate {
		t.Fatalf("second update: %+v", r)
	}
}

func TestDaemonUpdateRestartsItselfAtOnceWhenIdle(t *testing.T) {
	tu := newTestUpdater(t, "v0.7.0")
	tu.publish(t, "v0.8.0", "v0.8.0", releaseKey(t, tu))
	tu.slots[2].down = true // a supervisor that doesn't answer is left to launchd
	r := tu.u.update(context.Background(), KeeperRequest{Op: KeeperOpUpdate, Version: "v0.8.0"})
	if !r.OK || !r.Update.DaemonRestarting || !reflect.DeepEqual(r.Update.Restarted, []int{1}) {
		t.Fatalf("update: %+v %+v", r, r.Update)
	}
}

func TestDaemonUpdateRefusals(t *testing.T) {
	ctx := context.Background()
	for name, tc := range map[string]struct {
		setup     func(t *testing.T, tu *testUpdater)
		version   string
		downgrade bool
		err       string
	}{
		"downgrade": {
			setup:   func(t *testing.T, tu *testUpdater) { tu.publish(t, "v0.6.9", "v0.6.9", releaseKey(t, tu)) },
			version: "v0.6.9", err: "refusing to downgrade",
		},
		"bad tag": {
			setup:   func(t *testing.T, tu *testUpdater) {},
			version: "v0.8.0/../../evil", downgrade: true, err: "not a release tag",
		},
		"unsigned": {
			setup:   func(t *testing.T, tu *testUpdater) { releaseKey(t, tu); tu.publish(t, "v0.8.0", "v0.8.0", nil) },
			version: "v0.8.0", err: "no checksums.txt.sig",
		},
		// Root never takes a pre-signing release, even explicitly.
		"unsigned legacy downgrade": {
			setup:   func(t *testing.T, tu *testUpdater) { releaseKey(t, tu); tu.publish(t, "v0.6.0", "v0.6.0", nil) },
			version: "v0.6.0", downgrade: true, err: "no checksums.txt.sig",
		},
		"foreign signature": {
			setup: func(t *testing.T, tu *testUpdater) {
				releaseKey(t, tu)
				_, other, _ := ed25519.GenerateKey(rand.Reader)
				tu.publish(t, "v0.8.0", "v0.8.0", other)
			},
			version: "v0.8.0", err: "does not verify",
		},
		"binary of another version": {
			setup:   func(t *testing.T, tu *testUpdater) { tu.publish(t, "v0.8.0", "v0.9.9", releaseKey(t, tu)) },
			version: "v0.8.0", err: "reports version",
		},
		"not published": {
			setup:   func(t *testing.T, tu *testUpdater) { releaseKey(t, tu) },
			version: "v0.8.0", err: "not found",
		},
	} {
		t.Run(name, func(t *testing.T) {
			tu := newTestUpdater(t, "v0.7.0")
			tc.setup(t, tu)
			r := tu.u.update(ctx, KeeperRequest{Op: KeeperOpUpdate, Version: tc.version, AllowDowngrade: tc.downgrade})
			if r.OK || !strings.Contains(r.Error, tc.err) {
				t.Fatalf("got %+v, want an error with %q", r, tc.err)
			}
			if bin, v := tu.installed(t); bin != "old binary" || v != "v0.7.0" {
				t.Fatalf("changed: %q %s", bin, v)
			}
			if entries, _ := os.ReadDir(filepath.Dir(tu.bin)); len(entries) != 1 {
				t.Fatalf("staging leftovers: %v", entries)
			}
			if len(tu.restarted) != 0 {
				t.Fatalf("restarted %v", tu.restarted)
			}
		})
	}
}

func TestDaemonUpdateExplicitDowngrade(t *testing.T) {
	tu := newTestUpdater(t, "v0.8.0")
	tu.publish(t, "v0.7.1", "v0.7.1", releaseKey(t, tu))
	r := tu.u.update(context.Background(), KeeperRequest{Op: KeeperOpUpdate, Version: "v0.7.1", AllowDowngrade: true})
	if !r.OK {
		t.Fatalf("explicit downgrade: %+v", r)
	}
	if _, v := tu.installed(t); v != "v0.7.1" {
		t.Fatalf("installed %s", v)
	}
}

func TestKeeperServesTheUpdateOps(t *testing.T) {
	tk := newTestKeeper(t, os.Getuid())
	ctx := context.Background()
	if _, err := tk.client.DaemonVersion(ctx); err == nil || !strings.Contains(err.Error(), "can't update itself") {
		t.Fatalf("without an updater: %v", err)
	}
	tu := newTestUpdater(t, "v0.7.0")
	tu.publish(t, "v0.8.0", "v0.8.0", releaseKey(t, tu))
	tk.k.updater = tu.u
	if v, err := tk.client.DaemonVersion(ctx); err != nil || v != "v0.7.0" {
		t.Fatalf("version: %q %v", v, err)
	}
	res, err := tk.client.Update(ctx, "v0.8.0", false)
	if err != nil || res.To != "v0.8.0" || !res.DaemonRestarting {
		t.Fatalf("update over the socket: %+v %v", res, err)
	}
	if _, err := tk.client.Update(ctx, "v0.7.5", false); err == nil || !strings.Contains(err.Error(), "refusing to downgrade") {
		t.Fatalf("downgrade over the socket: %v", err)
	}
}
