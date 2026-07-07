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
var getIfTable2Ex = iphlpapi.NewProc("GetIfTable2Ex")
var freeMibTable = iphlpapi.NewProc("FreeMibTable")

type filetime struct {
	LowDateTime  uint32
	HighDateTime uint32
}

type mibIfTable2 struct {
	NumEntries uint32
	Table      [1]windows.MibIfRow2
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
	var table *mibIfTable2
	result, _, _ := getIfTable2Ex.Call(uintptr(windows.MibIfEntryNormal), uintptr(unsafe.Pointer(&table)))
	if result != 0 || table == nil {
		return windowsNetworkTotalsLegacy()
	}
	defer freeMibTable.Call(uintptr(unsafe.Pointer(table)))

	var totals networkTotals
	rowSize := unsafe.Sizeof(windows.MibIfRow2{})
	base := uintptr(unsafe.Pointer(&table.Table[0]))
	for index := uint32(0); index < table.NumEntries; index++ {
		row := (*windows.MibIfRow2)(unsafe.Pointer(base + uintptr(index)*rowSize))
		if row.Type == windows.IF_TYPE_SOFTWARE_LOOPBACK || row.OperStatus != windows.IfOperStatusUp {
			continue
		}
		totals.InBytes += int64(row.InOctets)
		totals.OutBytes += int64(row.OutOctets)
	}
	return totals
}

func windowsNetworkTotalsLegacy() networkTotals {
	var size uint32 = 15 * 1024
	buffer := make([]byte, size)
	err := windows.GetAdaptersInfo((*windows.IpAdapterInfo)(unsafe.Pointer(&buffer[0])), &size)
	if err == windows.ERROR_BUFFER_OVERFLOW {
		buffer = make([]byte, size)
		err = windows.GetAdaptersInfo((*windows.IpAdapterInfo)(unsafe.Pointer(&buffer[0])), &size)
	}
	if err != nil {
		return networkTotals{}
	}
	var totals networkTotals
	for adapter := (*windows.IpAdapterInfo)(unsafe.Pointer(&buffer[0])); adapter != nil; adapter = adapter.Next {
		row := windows.MibIfRow{Index: adapter.Index}
		if err := windows.GetIfEntry(&row); err != nil {
			continue
		}
		if row.Type == windows.IF_TYPE_SOFTWARE_LOOPBACK || row.OperStatus != windows.IfOperStatusUp {
			continue
		}
		totals.InBytes += int64(row.InOctets)
		totals.OutBytes += int64(row.OutOctets)
	}
	return totals
}

func windowsOSRelease() (string, string) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err != nil {
		return "Windows", ""
	}
	defer key.Close()
	product := registryString(key, "ProductName")
	if product == "" {
		product = "Windows"
	}
	display := registryString(key, "DisplayVersion")
	if display == "" {
		display = registryString(key, "ReleaseId")
	}
	return product, display
}

func windowsKernelRelease() string {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer key.Close()
	build := registryString(key, "CurrentBuildNumber")
	if build == "" {
		return ""
	}
	ubr, _, _ := key.GetIntegerValue("UBR")
	if ubr > 0 {
		return fmt.Sprintf("build %s.%d", build, ubr)
	}
	return "build " + build
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
