//go:build linux || darwin

package sysinfo

import "syscall"

// freeDiskGB is shared between linux and darwin: both populate
// syscall.Statfs_t with Bavail/Bsize fields (differing concrete integer
// widths per platform, but both convert cleanly through uint64).
func freeDiskGB(path string) (int64, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return 0, err
	}
	freeBytes := stat.Bavail * uint64(stat.Bsize)
	return int64(freeBytes / (1024 * 1024 * 1024)), nil
}
