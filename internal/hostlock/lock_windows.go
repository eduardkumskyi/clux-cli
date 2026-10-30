//go:build windows

package hostlock

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

// lockOffsetHigh puts the locked byte at 4 GiB, far past the PID text at
// offset 0: Windows byte-range locks are mandatory, so locking byte 0 would
// stop a second process from reading the holder's PID for its message.
const lockOffsetHigh = 1

func tryLock(f *os.File) error {
	ol := &windows.Overlapped{OffsetHigh: lockOffsetHigh}
	err := windows.LockFileEx(windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, ol)
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
		return errWouldBlock
	}
	return err
}

func unlock(f *os.File) {
	ol := &windows.Overlapped{OffsetHigh: lockOffsetHigh}
	_ = windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, ol)
}
