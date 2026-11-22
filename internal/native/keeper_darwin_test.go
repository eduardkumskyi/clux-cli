//go:build darwin

package native

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// shortTempDir is a resolved temp dir with a path short enough for a unix
// socket (104 bytes).
func shortTempDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp(os.TempDir(), "k")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	if d, err = filepath.EvalSymlinks(d); err != nil {
		t.Fatal(err)
	}
	os.Chmod(d, 0o755)
	return d
}

type testKeeper struct {
	k      *keeper
	client *KeeperClient
	mu     sync.Mutex
	wiped  []int
	fail   error
	block  chan struct{} // if set, a wipe waits for it
	res    map[int][]string
}

func (tk *testKeeper) wipeCount() int {
	tk.mu.Lock()
	defer tk.mu.Unlock()
	return len(tk.wiped)
}

// newTestKeeper serves a keeper (fake wipe, state files in a temp dir) on a
// socket; the test user is the owner and (for the root checks) trusted.
func newTestKeeper(t *testing.T, owner int) *testKeeper {
	t.Helper()
	old := trustedUIDs
	trustedUIDs = []int{0, os.Getuid()}
	t.Cleanup(func() { trustedUIDs = old })
	d := shortTempDir(t)
	cfg := &Config{OwnerUID: owner, CtlGID: os.Getgid(), Slots: []Slot{{1, "_clux1", 431, 431}, {2, "_clux2", 433, 433}}}
	tk := &testKeeper{res: map[int][]string{}}
	k, _ := newKeeper(cfg, t.Logf)
	k.stateDir = filepath.Join(d, "state")
	k.stateUID, k.stateGID = os.Getuid(), os.Getgid()
	os.Mkdir(k.stateDir, 0o755)
	k.resident = func(n int) []string { return tk.res[n] }
	k.prepare = func(Slot) error { return nil }
	k.wipe = func(ctx context.Context, s Slot) (int64, error) {
		if tk.block != nil {
			<-tk.block
		}
		tk.mu.Lock()
		defer tk.mu.Unlock()
		if tk.fail != nil {
			return 0, tk.fail
		}
		tk.wiped = append(tk.wiped, s.N)
		return 5 << 30, nil
	}
	tk.k = k
	sock := filepath.Join(d, "k.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go k.serve(ctx, l)
	tk.client = &KeeperClient{Socket: sock}
	return tk
}

func TestKeeperClaimWipeLifecycle(t *testing.T) {
	tk := newTestKeeper(t, os.Getuid())
	c, ctx := tk.client, context.Background()

	// Never recorded and empty: an earlier (pre-keeper) workspace may have
	// left things behind, so no claim without a wipe.
	if err := c.Claim(ctx, 1, "7"); err == nil || !strings.Contains(err.Error(), "needs a wipe") {
		t.Fatalf("claim of an unknown slot: %v", err)
	}
	if freed, err := c.Wipe(ctx, 1, ""); err != nil || freed != 5<<30 {
		t.Fatalf("wipe: %d %v", freed, err)
	}
	if st, _ := c.State(ctx, 1); !st.Free() {
		t.Fatalf("after wipe: %+v", st)
	}
	if err := c.Claim(ctx, 1, "7"); err != nil {
		t.Fatal(err)
	}
	if err := c.Claim(ctx, 1, "7"); err != nil {
		t.Fatalf("re-claim by the holder: %v", err)
	}
	if err := c.Claim(ctx, 1, "8"); err == nil {
		t.Fatal("second workspace claimed a held slot")
	}
	if _, err := c.Wipe(ctx, 1, "8"); err == nil {
		t.Fatal("a workspace wiped another workspace's slot")
	}
	if _, err := c.Wipe(ctx, 1, ""); err == nil {
		t.Fatal("anonymous wipe of a held slot")
	}
	// The record is what the supervisor checks before a start.
	st, err := readSlotStateFile(filepath.Join(tk.k.stateDir, "1.json"), 1)
	if err != nil || st.ClaimedBy != "7" || st.Clean {
		t.Fatalf("state file %+v %v", st, err)
	}

	// A failed wipe leaves the slot unclaimable.
	tk.fail = errors.New("processes keep coming back")
	if _, err := c.Wipe(ctx, 1, "7"); err == nil {
		t.Fatal("failed wipe reported success")
	}
	st, _ = c.State(ctx, 1)
	if st.Free() || st.Clean || st.ClaimedBy != "7" || !strings.Contains(st.LastError, "coming back") {
		t.Fatalf("after a failed wipe: %+v", st)
	}
	if err := c.Claim(ctx, 1, "8"); err == nil {
		t.Fatal("claimed a slot whose wipe failed")
	}
	tk.fail = nil
	if _, err := c.Wipe(ctx, 1, "7"); err != nil {
		t.Fatal(err)
	}
	if err := c.Claim(ctx, 1, "8"); err != nil {
		t.Fatalf("claim after a completed wipe: %v", err)
	}

	// Pre-keeper slot that holds exactly this workspace's files: adopted.
	tk.res[2] = []string{"9"}
	if err := c.Claim(ctx, 2, "9"); err != nil {
		t.Fatalf("adopting a pre-keeper workspace: %v", err)
	}
	for _, bad := range []KeeperRequest{{Op: "claim", Slot: 3, WorkspaceID: "1"}, {Op: "claim", Slot: 1}, {Op: "claim", Slot: 1, WorkspaceID: "../x"}, {Op: "nope", Slot: 1}} {
		if _, err := c.call(ctx, bad); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}

func TestKeeperReportsBusyDuringWipe(t *testing.T) {
	tk := newTestKeeper(t, os.Getuid())
	tk.block = make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, err := tk.client.Wipe(context.Background(), 1, "")
		done <- err
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		st, err := tk.client.State(context.Background(), 1)
		if err == nil && st.Busy {
			break
		}
		select {
		case werr := <-done:
			t.Fatalf("wipe returned before the slot showed busy: %v", werr)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("never busy: %+v %v", st, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := tk.client.Claim(context.Background(), 1, "7"); err == nil {
		// The claim waits for the wipe; it must not have succeeded before it.
		t.Fatal("claim during a wipe")
	}
	close(tk.block)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestKeeperServesOnlyTheOwner(t *testing.T) {
	tk := newTestKeeper(t, os.Getuid()+1)
	_, err := tk.client.State(context.Background(), 1)
	if err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("non-owner served: %v", err)
	}
}

// The owner's clients only talk to sockets root created: a socket bound by
// anyone else (the agent shares its supervisor's uid) is refused before a
// byte is sent.
func TestClientsRefuseNonRootListeners(t *testing.T) {
	tk := newTestKeeper(t, os.Getuid())
	trustedUIDs = []int{0} // the test user is not root
	if _, err := tk.client.State(context.Background(), 1); err == nil || !strings.Contains(err.Error(), "refusing to use it") {
		t.Fatalf("keeper client used a socket the test user bound: %v", err)
	}
	if tk.wipeCount() != 0 {
		t.Fatal("request reached the fake")
	}
	c, err := net.Dial("unix", tk.client.Socket)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := VerifyRootListener(c, tk.client.Socket); err == nil {
		t.Fatal("VerifyRootListener accepted a non-root socket")
	}
	// Directory check alone: a root-owned socket in a dir others can write
	// would be replaceable.
	if err := VerifyRootListener(c, "/private/tmp/x.sock"); err == nil || !strings.Contains(err.Error(), "root-only directory") {
		t.Fatalf("world-writable dir: %v", err)
	}
}
