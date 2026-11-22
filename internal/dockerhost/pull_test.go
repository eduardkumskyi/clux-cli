package dockerhost

import (
	"bytes"
	"context"
	"log"
	"strings"
	"testing"
)

const (
	ecrImage   = "public.ecr.aws/t9o5o8m1/clux-sidecar:0.2.0@sha256:b0aa"
	expiredMsg = "Error response from daemon: pull access denied for public.ecr.aws/t9o5o8m1/clux-sidecar, " +
		"repository does not exist or may require 'docker login': denied: Your authorization token has expired. Reauthenticate and try again."
)

// pullFake is a docker whose image is not cached; pull fails with pullErr
// using the user's config, anonymous pulls with anonErr.
type pullFake struct {
	pullErr, anonErr string
	calls, anon      []string
	runArgs          []string
}

func (f *pullFake) install(t *testing.T) {
	t.Helper()
	oldRun, oldAnon := runDocker, runDockerAnonymous
	t.Cleanup(func() { runDocker, runDockerAnonymous = oldRun, oldAnon })
	fail := func(args []string, msg string) (string, error) {
		return "", &dockerError{verb: dockerVerb(args), msg: msg}
	}
	runDocker = func(ctx context.Context, args ...string) (string, error) {
		f.calls = append(f.calls, strings.Join(args, " "))
		switch args[0] {
		case "image":
			return fail(args, "Error: No such image: "+args[len(args)-1])
		case "pull":
			if f.pullErr != "" {
				return fail(args, f.pullErr)
			}
		case "run":
			f.runArgs = args
			return "0123456789abcdef0123\n", nil
		case "inspect":
			return "true\n", nil
		case "port":
			return "127.0.0.1:34567\n", nil
		}
		return "", nil
	}
	runDockerAnonymous = func(ctx context.Context, args ...string) (string, error) {
		f.anon = append(f.anon, strings.Join(args, " "))
		if f.anonErr != "" {
			return fail(args, f.anonErr)
		}
		return "", nil
	}
}

func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var b bytes.Buffer
	old, flags := log.Writer(), log.Flags()
	log.SetOutput(&b)
	log.SetFlags(0)
	t.Cleanup(func() { log.SetOutput(old); log.SetFlags(flags) })
	return &b
}

func startReq(image string) StartRequest {
	return StartRequest{ContainerName: "clux-ws-1", VolumeName: "v", Image: image, CPULimit: 1,
		MemoryLimitMB: 512, SidecarContainerPort: 9100, HMACSecret: "s3cret"}
}

func TestStartPullsBeforeRun(t *testing.T) {
	f := &pullFake{}
	f.install(t)
	if _, err := Start(context.Background(), startReq(ecrImage)); err != nil {
		t.Fatal(err)
	}
	pull, run := -1, -1
	for i, c := range f.calls {
		switch {
		case strings.HasPrefix(c, "pull "):
			pull = i
		case strings.HasPrefix(c, "run "):
			run = i
		}
	}
	if pull < 0 || run < pull || len(f.anon) != 0 {
		t.Fatalf("calls %q anon %q", f.calls, f.anon)
	}
}

func TestExpiredPublicECRLoginRetriesAnonymously(t *testing.T) {
	logs := captureLog(t)
	f := &pullFake{pullErr: expiredMsg}
	f.install(t)
	res, err := Start(context.Background(), startReq(ecrImage))
	if err != nil || res.SidecarPort != 34567 {
		t.Fatalf("%+v %v", res, err)
	}
	if len(f.anon) != 1 || f.anon[0] != "pull --quiet "+ecrImage || f.runArgs == nil {
		t.Fatalf("anon %q run %q", f.anon, f.runArgs)
	}
	if out := logs.String(); !strings.Contains(out, "saved Docker login for public.ecr.aws has expired; pulled") ||
		!strings.Contains(out, "docker logout public.ecr.aws") || strings.Count(out, "\n") != 1 {
		t.Fatalf("log %q", out)
	}
}

func TestAnonymousPullFailureNamesTheCause(t *testing.T) {
	f := &pullFake{pullErr: expiredMsg, anonErr: "Error response from daemon: manifest unknown"}
	f.install(t)
	_, err := Start(context.Background(), startReq(ecrImage))
	if err == nil || f.runArgs != nil {
		t.Fatalf("err %v run %q", err, f.runArgs)
	}
	for _, want := range []string{"pulling image " + ecrImage, "saved Docker login for public.ecr.aws was refused",
		"authorization token has expired", "anonymously failed too: Error response from daemon: manifest unknown"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error lacks %q: %v", want, err)
		}
	}
}

func TestAuthErrorOutsidePublicECRIsNotRetried(t *testing.T) {
	f := &pullFake{pullErr: "Error response from daemon: unauthorized: authentication required"}
	f.install(t)
	_, err := Start(context.Background(), startReq("ghcr.io/o/sidecar:1"))
	if err == nil || len(f.anon) != 0 || !strings.Contains(err.Error(), "docker login ghcr.io") {
		t.Fatalf("err %v anon %q", err, f.anon)
	}
}

func TestOtherPullErrorIsReported(t *testing.T) {
	f := &pullFake{pullErr: "Error response from daemon: Get \"https://public.ecr.aws/v2/\": dial tcp: lookup public.ecr.aws: no such host"}
	f.install(t)
	_, err := Start(context.Background(), startReq(ecrImage))
	if err == nil || len(f.anon) != 0 || !strings.Contains(err.Error(), "no such host") {
		t.Fatalf("err %v anon %q", err, f.anon)
	}
}

func TestCachedImageIsNotPulled(t *testing.T) {
	f := &pullFake{}
	f.install(t)
	inner := runDocker
	runDocker = func(ctx context.Context, args ...string) (string, error) {
		if args[0] == "image" {
			f.calls = append(f.calls, strings.Join(args, " "))
			return "sha256:abc\n", nil
		}
		return inner(ctx, args...)
	}
	if _, err := Start(context.Background(), startReq(ecrImage)); err != nil {
		t.Fatal(err)
	}
	for _, c := range f.calls {
		if strings.HasPrefix(c, "pull") {
			t.Fatalf("pulled a cached image: %q", f.calls)
		}
	}
}

// A failed `docker run` logs its command line, but never the secret.
func TestRunFailureLogsRedactedCommand(t *testing.T) {
	logs := captureLog(t)
	f := &pullFake{}
	f.install(t)
	inner := runDocker
	runDocker = func(ctx context.Context, args ...string) (string, error) {
		if args[0] == "run" {
			return "", &dockerError{verb: "run", msg: "Conflict. The container name is already in use"}
		}
		return inner(ctx, args...)
	}
	req := startReq(ecrImage)
	req.GithubCloneURL = "https://x-access-token:ghs_tok@github.com/o/r.git"
	_, err := Start(context.Background(), req)
	if err == nil || err.Error() != "docker run failed: Conflict. The container name is already in use" {
		t.Fatalf("err %v", err)
	}
	out := logs.String()
	if strings.Contains(out, "s3cret") || strings.Contains(out, "ghs_tok") {
		t.Fatalf("secret logged: %s", out)
	}
	if !strings.Contains(out, "-e SIDECAR_HMAC_SECRET=[REDACTED]") || !strings.Contains(out, "--name clux-ws-1") {
		t.Fatalf("command line not logged usefully: %s", out)
	}
}

func TestRegistryOf(t *testing.T) {
	for in, want := range map[string]string{
		ecrImage:                  "public.ecr.aws",
		"busybox":                 "docker.io",
		"library/busybox:1":       "docker.io",
		"localhost:5000/x":        "localhost:5000",
		"Public.ECR.aws/a/b:1":    "public.ecr.aws",
		"ghcr.io/o/r@sha256:abcd": "ghcr.io",
	} {
		if got := registryOf(in); got != want {
			t.Errorf("registryOf(%q) = %q, want %q", in, got, want)
		}
	}
}
