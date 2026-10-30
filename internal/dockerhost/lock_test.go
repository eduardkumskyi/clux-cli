package dockerhost

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeDocker records calls and simulates a slow `docker run`.
type fakeDocker struct {
	mu      sync.Mutex
	calls   []string
	runs    int
	failRun bool
	running map[string]string // name -> container id
}

func (f *fakeDocker) run(ctx context.Context, args ...string) (string, error) {
	f.mu.Lock()
	f.calls = append(f.calls, strings.Join(args, " "))
	f.mu.Unlock()
	switch args[0] {
	case "network":
		return "", nil
	case "stop":
		return "", nil
	case "rm":
		f.mu.Lock()
		target := args[len(args)-1]
		for name, id := range f.running {
			if name == target || id == target {
				delete(f.running, name)
			}
		}
		f.mu.Unlock()
		return "", nil
	case "run":
		time.Sleep(30 * time.Millisecond)
		f.mu.Lock()
		f.runs++
		id := fmt.Sprintf("%064x", f.runs)
		name := ""
		for i, a := range args {
			if a == "--name" {
				name = args[i+1]
			}
		}
		f.running[name] = id
		fail := f.failRun
		f.mu.Unlock()
		if fail {
			return id + "\n", nil // created; the failure comes in waitRunning
		}
		return id + "\n", nil
	case "inspect":
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.failRun {
			return "false", nil
		}
		return "true", nil
	case "port":
		return "127.0.0.1:41234\n", nil
	}
	return "", nil
}

func withFake(t *testing.T, f *fakeDocker) {
	t.Helper()
	old := runDocker
	runDocker = f.run
	t.Cleanup(func() { runDocker = old })
}

func TestConcurrentStartsOnSameContainerAreSerialized(t *testing.T) {
	f := &fakeDocker{running: map[string]string{}}
	withFake(t, f)
	req := StartRequest{ContainerName: "clux-ws-14", VolumeName: "v", Image: "img", CPULimit: 1, MemoryLimitMB: 512, SidecarContainerPort: 9100}

	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := Start(context.Background(), req); err != nil {
				t.Errorf("start: %v", err)
			}
		}()
	}
	wg.Wait()

	// With the lock, each start's sequence (stop, rm, run, inspect, port)
	// must not interleave with the other's.
	var seq []string
	for _, c := range f.calls {
		if strings.HasPrefix(c, "network") {
			continue
		}
		seq = append(seq, strings.Fields(c)[0])
	}
	want := []string{"stop", "rm", "run", "inspect", "port", "stop", "rm", "run", "inspect", "port"}
	if strings.Join(seq, ",") != strings.Join(want, ",") {
		t.Fatalf("interleaved docker calls:\n got %v\nwant %v", seq, want)
	}
	if len(f.running) != 1 {
		t.Fatalf("want exactly one container left, got %v", f.running)
	}
}

func TestFailedStartRemovesOnlyItsOwnContainerByID(t *testing.T) {
	f := &fakeDocker{running: map[string]string{}, failRun: true}
	withFake(t, f)
	req := StartRequest{ContainerName: "clux-ws-14", Image: "img", SidecarContainerPort: 9100}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := Start(ctx, req); err == nil {
		t.Fatal("expected start to fail")
	}
	last := f.calls[len(f.calls)-1]
	if !strings.HasPrefix(last, "rm -f ") || strings.HasSuffix(last, "clux-ws-14") {
		t.Fatalf("cleanup must target the container ID, got %q", last)
	}
}

func TestStopWaitsForInFlightStart(t *testing.T) {
	f := &fakeDocker{running: map[string]string{}}
	withFake(t, f)
	req := StartRequest{ContainerName: "clux-ws-9", Image: "img", SidecarContainerPort: 9100}
	started := make(chan struct{})
	go func() {
		close(started)
		_, _ = Start(context.Background(), req)
	}()
	<-started
	time.Sleep(5 * time.Millisecond)
	if err := Stop(context.Background(), "clux-ws-9"); err != nil {
		t.Fatal(err)
	}
	// Stop ran after Start finished, so the container is gone.
	if len(f.running) != 0 {
		t.Fatalf("stop overtook start: %v", f.running)
	}
}

func TestLockRespectsContext(t *testing.T) {
	unlock, err := lockContainer(context.Background(), "x")
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := lockContainer(ctx, "x"); err == nil {
		t.Fatal("second lock should time out")
	}
}
