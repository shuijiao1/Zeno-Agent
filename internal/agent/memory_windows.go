//go:build windows

package agent

import (
	"unsafe"
)

var globalMemoryStatusEx = kernel32.NewProc("GlobalMemoryStatusEx")

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

func platformMemoryTotals() (total int64, available int64) {
	status := memoryStatusEx{Length: uint32(unsafe.Sizeof(memoryStatusEx{}))}
	result, _, _ := globalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&status)))
	if result == 0 {
		return 0, 0
	}
	return int64(status.TotalPhys), int64(status.AvailPhys)
}

func platformSwapTotals() (total int64, free int64) {
	status := memoryStatusEx{Length: uint32(unsafe.Sizeof(memoryStatusEx{}))}
	result, _, _ := globalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&status)))
	if result == 0 {
		return 0, 0
	}
	// Windows reports pagefile totals including physical memory. Subtract RAM to
	// expose a swap/pagefile figure that matches Linux swap semantics in Zeno.
	return nonNegativeInt64(int64(status.TotalPageFile - status.TotalPhys)), nonNegativeInt64(int64(status.AvailPageFile - status.AvailPhys))
}
