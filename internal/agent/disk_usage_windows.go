//go:build windows

package agent

import (
	"syscall"
	"unsafe"
)

var kernel32 = syscall.NewLazyDLL("kernel32.dll")
var getDiskFreeSpaceEx = kernel32.NewProc("GetDiskFreeSpaceExW")

func diskUsage(path string) (used int64, total int64) {
	pointer, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, 0
	}
	var freeAvailable uint64
	var totalBytes uint64
	var totalFree uint64
	result, _, _ := getDiskFreeSpaceEx.Call(
		uintptr(unsafe.Pointer(pointer)),
		uintptr(unsafe.Pointer(&freeAvailable)),
		uintptr(unsafe.Pointer(&totalBytes)),
		uintptr(unsafe.Pointer(&totalFree)),
	)
	if result == 0 {
		return 0, 0
	}
	total = int64(totalBytes)
	used = nonNegativeInt64(int64(totalBytes - totalFree))
	return used, total
}
