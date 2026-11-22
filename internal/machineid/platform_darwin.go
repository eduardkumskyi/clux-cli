//go:build darwin

package machineid

import (
	"errors"
	"os/exec"
	"regexp"
)

var ioregUUID = regexp.MustCompile(`"IOPlatformUUID"\s*=\s*"([^"]+)"`)

// platformID is the hardware UUID (survives OS reinstalls on the same Mac).
func platformID() (string, error) {
	out, err := exec.Command("/usr/sbin/ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output()
	if err != nil {
		return "", err
	}
	return parseIoreg(out)
}

func parseIoreg(out []byte) (string, error) {
	m := ioregUUID.FindSubmatch(out)
	if m == nil {
		return "", errors.New("IOPlatformUUID not found in ioreg output")
	}
	return string(m[1]), nil
}
