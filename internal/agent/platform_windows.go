//go:build windows

package agent

import (
	"fmt"
	"runtime"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var getSystemTimes = kernel32.NewProc("GetSystemTimes")
var getTickCount64 = kernel32.NewProc("GetTickCount64")

type filetime struct {
	LowDateTime  uint32
	HighDateTime uint32
}

func windowsReadCPUTimes() (cpuTimes, bool) {
	var idle, kernel, user filetime
	result, _, _ := getSystemTimes.Call(
		uintptr(unsafe.Pointer(&idle)),
		uintptr(unsafe.Pointer(&kernel)),
		uintptr(unsafe.Pointer(&user)),
	)
	if result == 0 {
		return cpuTimes{}, false
	}
	idleTicks := filetimeUint64(idle)
	kernelTicks := filetimeUint64(kernel)
	userTicks := filetimeUint64(user)
	return cpuTimes{Total: kernelTicks + userTicks, Idle: idleTicks}, true
}

func filetimeUint64(value filetime) uint64 {
	return uint64(value.HighDateTime)<<32 | uint64(value.LowDateTime)
}

func windowsLoadAverages(cpuPercent float64, cpuCores int) (float64, float64, float64) {
	if cpuCores <= 0 {
		cpuCores = runtime.NumCPU()
	}
	if cpuPercent < 0 {
		cpuPercent = 0
	}
	load := cpuPercent * float64(cpuCores) / 100
	return load, load, load
}

func windowsProcessCount() int64 {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0
	}
	defer windows.CloseHandle(snapshot)
	entry := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	if err := windows.Process32First(snapshot, &entry); err != nil {
		return 0
	}
	var count int64
	for {
		count++
		if err := windows.Process32Next(snapshot, &entry); err != nil {
			break
		}
	}
	return count
}

func windowsNetworkTotals() networkTotals {
	// Keep totals empty for now rather than shelling out every 2 seconds; Windows
	// interface counters need a larger native IP Helper binding than the rest of
	// this lightweight collector.
	return networkTotals{}
}

func windowsOSRelease() (string, string) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err != nil {
		return "windows", ""
	}
	defer key.Close()
	product := registryString(key, "ProductName")
	display := registryString(key, "DisplayVersion")
	if display == "" {
		display = registryString(key, "ReleaseId")
	}
	build := registryString(key, "CurrentBuildNumber")
	ubr, _, _ := key.GetIntegerValue("UBR")
	parts := []string{}
	if product != "" {
		parts = append(parts, product)
	}
	if display != "" {
		parts = append(parts, display)
	}
	if build != "" {
		if ubr > 0 {
			parts = append(parts, fmt.Sprintf("build %s.%d", build, ubr))
		} else {
			parts = append(parts, "build "+build)
		}
	}
	return "windows", strings.Join(parts, " ")
}

func windowsKernelRelease() string {
	_, version := windowsOSRelease()
	return version
}

func windowsVirtualizationName() string {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `HARDWARE\DESCRIPTION\System\BIOS`, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer key.Close()
	manufacturer := registryString(key, "SystemManufacturer")
	product := registryString(key, "SystemProductName")
	return strings.TrimSpace(strings.Join(nonEmptyStrings(manufacturer, product), " "))
}

func windowsCPUModel() string {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `HARDWARE\DESCRIPTION\System\CentralProcessor\0`, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer key.Close()
	return registryString(key, "ProcessorNameString")
}

func windowsBootTime() int64 {
	uptime := windowsUptimeSeconds()
	if uptime <= 0 {
		return 0
	}
	return time.Now().UTC().Unix() - uptime
}

func windowsUptimeSeconds() int64 {
	milliseconds, _, _ := getTickCount64.Call()
	if milliseconds == 0 {
		return 0
	}
	return int64(milliseconds / 1000)
}

func registryString(key registry.Key, name string) string {
	value, _, err := key.GetStringValue(name)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(value)
}

func nonEmptyStrings(values ...string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			out = append(out, strings.TrimSpace(value))
		}
	}
	return out
}
