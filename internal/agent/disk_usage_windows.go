//go:build windows

package agent

import (
	"os"
	"strings"
	"syscall"
	"unsafe"
)

var getDiskFreeSpaceEx = kernel32.NewProc("GetDiskFreeSpaceExW")
var getLogicalDrives = kernel32.NewProc("GetLogicalDrives")
var getDriveType = kernel32.NewProc("GetDriveTypeW")

const driveFixed = 3

func diskUsage(allowlist []string) (used int64, total int64) {
	if len(allowlist) == 0 {
		return fixedDiskUsage()
	}
	seen := map[string]struct{}{}
	for _, path := range normalizeAllowlist(allowlist) {
		root := windowsVolumeRoot(path)
		if _, ok := seen[root]; ok {
			continue
		}
		seen[root] = struct{}{}
		driveUsed, driveTotal := diskUsageForRoot(root)
		used += driveUsed
		total += driveTotal
	}
	return used, total
}

func fixedDiskUsage() (used int64, total int64) {
	mask, _, _ := getLogicalDrives.Call()
	for index := 0; index < 26; index++ {
		if mask&(1<<uint(index)) == 0 {
			continue
		}
		root := string(rune('A'+index)) + ":\\"
		pointer, err := syscall.UTF16PtrFromString(root)
		if err != nil {
			continue
		}
		driveType, _, _ := getDriveType.Call(uintptr(unsafe.Pointer(pointer)))
		if driveType != driveFixed {
			continue
		}
		driveUsed, driveTotal := diskUsageForRoot(root)
		used += driveUsed
		total += driveTotal
	}
	if total > 0 {
		return used, total
	}
	return diskUsageForRoot(windowsVolumeRoot(os.Getenv("SystemDrive")))
}

func windowsVolumeRoot(path string) string {
	trimmed := strings.TrimSpace(path)
	if len(trimmed) >= 2 && trimmed[1] == ':' {
		return strings.ToUpper(trimmed[:1]) + ":\\"
	}
	if systemDrive := strings.TrimSpace(os.Getenv("SystemDrive")); len(systemDrive) >= 2 && systemDrive[1] == ':' {
		return strings.ToUpper(systemDrive[:1]) + ":\\"
	}
	return "C:\\"
}

func diskUsageForRoot(root string) (used int64, total int64) {
	pointer, err := syscall.UTF16PtrFromString(root)
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
