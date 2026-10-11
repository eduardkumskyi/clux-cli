//go:build windows

package sysinfo

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// memoryStatusEx mirrors the Win32 MEMORYSTATUSEX struct. x/sys/windows
// doesn't wrap GlobalMemoryStatusEx, so this calls kernel32 directly.
type memoryStatusEx struct {
	Length               uint32
	MemoryLoad           uint32
	TotalPhys            uint64
	AvailPhys            uint64
	TotalPageFile        uint64
	AvailPageFile        uint64
	TotalVirtual         uint64
	AvailVirtual         uint64
	AvailExtendedVirtual uint64
}

var procGlobalMemoryStatusEx = syscall.NewLazyDLL("kernel32.dll").NewProc("GlobalMemoryStatusEx")

func totalMemoryMB() (int64, error) {
	var m memoryStatusEx
	m.Length = uint32(unsafe.Sizeof(m))
	ok, _, _ := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&m)))
	if ok == 0 {
		return 0, fmt.Errorf("GlobalMemoryStatusEx failed")
	}
	return int64(m.TotalPhys / (1024 * 1024)), nil
}

func freeDiskGB(path string) (int64, error) {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	var freeBytesAvailable, totalBytes, totalFreeBytes uint64
	if err := windows.GetDiskFreeSpaceEx(pathPtr, &freeBytesAvailable, &totalBytes, &totalFreeBytes); err != nil {
		return 0, err
	}
	return int64(freeBytesAvailable / (1024 * 1024 * 1024)), nil
}
