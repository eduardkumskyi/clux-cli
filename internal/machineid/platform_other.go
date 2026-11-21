//go:build !darwin && !linux && !windows

package machineid

import "errors"

// platformID: no known source; the persisted random id is used.
func platformID() (string, error) { return "", errors.New("no platform machine id on this OS") }
