//go:build darwin

package sysinfo

import (
	"os/exec"
	"strconv"
	"strings"
)

func totalMemoryMB() (int64, error) {
	out, err := exec.Command("sysctl", "-n", "hw.memsize").Output()
	if err != nil {
		return 0, err
	}
	bytes, err := strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64)
	if err != nil {
		return 0, err
	}
	return bytes / (1024 * 1024), nil
}
