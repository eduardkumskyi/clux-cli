// Package sysinfo collects the capacity numbers a host reports to the
// backend on register/heartbeat: logical CPU cores, total physical memory,
// and free space on the configured storage root.
package sysinfo

import (
	"fmt"
	"os"
	"runtime"
)

type Info struct {
	CPUCores       float64
	MemoryMB       int64
	StorageGBTotal int64
}

// Collect gathers the current machine's capacity. storageRoot is created if
// it doesn't exist yet, since its free space is what gets reported.
func Collect(storageRoot string) (Info, error) {
	memMB, err := totalMemoryMB()
	if err != nil {
		return Info{}, fmt.Errorf("reading total memory: %w", err)
	}

	if err := os.MkdirAll(storageRoot, 0o755); err != nil {
		return Info{}, fmt.Errorf("creating storage root %s: %w", storageRoot, err)
	}
	diskGB, err := freeDiskGB(storageRoot)
	if err != nil {
		return Info{}, fmt.Errorf("reading free disk space at %s: %w", storageRoot, err)
	}

	return Info{
		CPUCores:       float64(runtime.NumCPU()),
		MemoryMB:       memMB,
		StorageGBTotal: diskGB,
	}, nil
}
