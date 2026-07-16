//go:build windows

package agent

import (
	"fmt"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var getSystemTimes = kernel32.NewProc("GetSystemTimes")
var getTickCount64 = kernel32.NewProc("GetTickCount64")
var getIfTable2Ex = iphlpapi.NewProc("GetIfTable2Ex")
var freeMibTable = iphlpapi.NewProc("FreeMibTable")

const (
	windowsIfHardwareInterface = 1 << 0
	windowsIfFilterInterface   = 1 << 1
	windowsIfEndPointInterface = 1 << 7
	windowsAFInet              = 2
	windowsAFInet6             = 23
	windowsTCPTableBasicAll    = 2
	windowsUDPTableBasic       = 0
)

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
	// Windows does not expose Unix-style 1/5/15 minute runnable-queue load
	// averages. Reporting instantaneous CPU as load looked precise but had a
	// different meaning, so leave these fields unset and rely on CPUPercent.
	return 0, 0, 0
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

func windowsConnectionCounts() (tcp int64, udp int64, err error) {
	tcp4, err := windowsIPTableCount(getExtendedTcpTable, windowsAFInet, windowsTCPTableBasicAll)
	if err != nil {
		return 0, 0, fmt.Errorf("GetExtendedTcpTable(AF_INET): %w", err)
	}
	tcp6, err := windowsIPTableCount(getExtendedTcpTable, windowsAFInet6, windowsTCPTableBasicAll)
	if err != nil && !windowsIPFamilyUnavailable(err) {
		return 0, 0, fmt.Errorf("GetExtendedTcpTable(AF_INET6): %w", err)
	}
	udp4, err := windowsIPTableCount(getExtendedUdpTable, windowsAFInet, windowsUDPTableBasic)
	if err != nil {
		return 0, 0, fmt.Errorf("GetExtendedUdpTable(AF_INET): %w", err)
	}
	udp6, err := windowsIPTableCount(getExtendedUdpTable, windowsAFInet6, windowsUDPTableBasic)
	if err != nil && !windowsIPFamilyUnavailable(err) {
		return 0, 0, fmt.Errorf("GetExtendedUdpTable(AF_INET6): %w", err)
	}
	return tcp4 + tcp6, udp4 + udp6, nil
}

func windowsIPTableCount(proc *syscall.LazyProc, addressFamily, tableClass uintptr) (int64, error) {
	if err := proc.Find(); err != nil {
		return 0, err
	}
	return windowsIPTableCountWithQuery(func(buffer []byte, size *uint32) uint32 {
		var pointer uintptr
		if len(buffer) > 0 {
			pointer = uintptr(unsafe.Pointer(&buffer[0]))
		}
		result, _, _ := proc.Call(pointer, uintptr(unsafe.Pointer(size)), 0, addressFamily, tableClass, 0)
		return uint32(result)
	})
}

func windowsNetworkTotals(allowlist map[string]struct{}) (networkTotals, error) {
	var table *mibIfTable2
	result, _, _ := getIfTable2Ex.Call(uintptr(windows.MibIfEntryNormal), uintptr(unsafe.Pointer(&table)))
	if result != 0 || table == nil {
		totals, legacyErr := windowsNetworkTotalsLegacy(allowlist)
		if legacyErr != nil {
			return networkTotals{}, fmt.Errorf("GetIfTable2Ex returned %d; legacy fallback: %w", result, legacyErr)
		}
		return totals, nil
	}
	defer freeMibTable.Call(uintptr(unsafe.Pointer(table)))

	var totals networkTotals
	rowSize := unsafe.Sizeof(windows.MibIfRow2{})
	base := uintptr(unsafe.Pointer(&table.Table[0]))
	for index := uint32(0); index < table.NumEntries; index++ {
		row := (*windows.MibIfRow2)(unsafe.Pointer(base + uintptr(index)*rowSize))
		if !includeWindowsNetworkRow(row, allowlist) {
			continue
		}
		if err := addNetworkCounter(&totals.InBytes, row.InOctets); err != nil {
			return networkTotals{}, err
		}
		if err := addNetworkCounter(&totals.OutBytes, row.OutOctets); err != nil {
			return networkTotals{}, err
		}
		totals.SourceNames = append(totals.SourceNames, fmt.Sprintf("if:%d", row.InterfaceIndex))
	}
	return totals, nil
}

func windowsNetworkTotalsLegacy(allowlist map[string]struct{}) (networkTotals, error) {
	var size uint32 = 15 * 1024
	buffer := make([]byte, size)
	err := windows.GetAdaptersInfo((*windows.IpAdapterInfo)(unsafe.Pointer(&buffer[0])), &size)
	if err == windows.ERROR_BUFFER_OVERFLOW {
		if size == 0 || size > windowsIPTableMaxBufferBytes {
			return networkTotals{}, fmt.Errorf("GetAdaptersInfo requested invalid buffer size %d", size)
		}
		buffer = make([]byte, size)
		err = windows.GetAdaptersInfo((*windows.IpAdapterInfo)(unsafe.Pointer(&buffer[0])), &size)
	}
	if err != nil {
		return networkTotals{}, err
	}
	var totals networkTotals
	for adapter := (*windows.IpAdapterInfo)(unsafe.Pointer(&buffer[0])); adapter != nil; adapter = adapter.Next {
		row := windows.MibIfRow{Index: adapter.Index}
		if err := windows.GetIfEntry(&row); err != nil {
			return networkTotals{}, err
		}
		if !includeWindowsLegacyNetworkRow(&row, allowlist) {
			continue
		}
		if err := addNetworkCounter(&totals.InBytes, uint64(row.InOctets)); err != nil {
			return networkTotals{}, err
		}
		if err := addNetworkCounter(&totals.OutBytes, uint64(row.OutOctets)); err != nil {
			return networkTotals{}, err
		}
		totals.SourceNames = append(totals.SourceNames, fmt.Sprintf("if:%d", row.Index))
	}
	return totals, nil
}

func addNetworkCounter(total *int64, value uint64) error {
	if value > uint64(maxInt64) || int64(value) > maxInt64-*total {
		return fmt.Errorf("network counter total overflows int64")
	}
	*total += int64(value)
	return nil
}

func includeWindowsNetworkRow(row *windows.MibIfRow2, allowlist map[string]struct{}) bool {
	alias := strings.TrimSpace(windows.UTF16ToString(row.Alias[:]))
	description := strings.TrimSpace(windows.UTF16ToString(row.Description[:]))
	if row.Type == windows.IF_TYPE_SOFTWARE_LOOPBACK || row.OperStatus != windows.IfOperStatusUp {
		return false
	}
	if len(allowlist) > 0 {
		_, aliasOK := allowlist[alias]
		_, descriptionOK := allowlist[description]
		return aliasOK || descriptionOK
	}
	if alias != "" && !includeNetworkInterface(alias, nil) {
		return false
	}
	if description != "" && !includeNetworkInterface(description, nil) {
		return false
	}
	flags := row.InterfaceAndOperStatusFlags
	if flags&windowsIfHardwareInterface == 0 {
		return false
	}
	if flags&(windowsIfFilterInterface|windowsIfEndPointInterface) != 0 {
		return false
	}
	return row.PhysicalAddressLength > 0
}

func includeWindowsLegacyNetworkRow(row *windows.MibIfRow, allowlist map[string]struct{}) bool {
	if len(allowlist) > 0 {
		name := strings.TrimSpace(windows.UTF16ToString(row.Name[:]))
		_, ok := allowlist[name]
		return ok
	}
	if row.Type == windows.IF_TYPE_SOFTWARE_LOOPBACK || row.OperStatus != windows.IfOperStatusUp {
		return false
	}
	switch row.Type {
	case windows.IF_TYPE_ETHERNET_CSMACD, windows.IF_TYPE_IEEE80211, windows.IF_TYPE_PPP:
		return true
	default:
		return false
	}
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
