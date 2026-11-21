//go:build linux

package machineid

import (
	"errors"
	"os"
	"strings"
)

var machineIDFiles = []string{"/etc/machine-id", "/var/lib/dbus/machine-id"}

// platformID is systemd's/dbus's per-install machine id.
func platformID() (string, error) {
	for _, p := range machineIDFiles {
		if b, err := os.ReadFile(p); err == nil {
			if s := strings.TrimSpace(string(b)); s != "" {
				return s, nil
			}
		}
	}
	return "", errors.New("no readable machine-id")
}
