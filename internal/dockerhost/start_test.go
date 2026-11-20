package dockerhost

import (
	"context"
	"strings"
	"testing"
)

// TestStartPassesSidecarSecret fakes runDocker (a package variable, so no
// docker binary is needed on any CI OS) and checks the `docker run` line.
func TestStartPassesSidecarSecret(t *testing.T) {
	var runArgs []string
	orig := runDocker
	t.Cleanup(func() { runDocker = orig })
	runDocker = func(ctx context.Context, args ...string) (string, error) {
		switch args[0] {
		case "run":
			runArgs = args
			return "0123456789abcdef0123\n", nil
		case "inspect":
			return "true\n", nil
		case "port":
			return "127.0.0.1:34567\n", nil
		}
		return "", nil
	}
	res, err := Start(context.Background(), StartRequest{
		ContainerName: "clux-ws-1", VolumeName: "clux-ws-1-data", Image: "img",
		CPULimit: 1, MemoryLimitMB: 512, SidecarContainerPort: 9100, HMACSecret: "s3cret",
	})
	if err != nil || res.SidecarPort != 34567 {
		t.Fatalf("%+v %v", res, err)
	}
	line := strings.Join(runArgs, " ")
	if !strings.Contains(line, "-e SIDECAR_HMAC_SECRET=s3cret") {
		t.Fatalf("sidecar secret not passed: %s", line)
	}
	if !strings.HasSuffix(line, " img") {
		t.Fatalf("image must stay the last argument: %s", line)
	}
}
