//go:build darwin

package agent

import (
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

func darwinReadCPUTimes() (cpuTimes, bool) {
	output, err := darwinCommandOutput("/usr/sbin/sysctl", "-n", "kern.cp_time")
	if err != nil {
		return cpuTimes{}, false
	}
	return parseDarwinCPUTimes(output)
}

func darwinLoadAverages() (load1, load5, load15 float64) {
	output, err := darwinCommandOutput("/usr/sbin/sysctl", "-n", "vm.loadavg")
	if err != nil {
		return 0, 0, 0
	}
	return parseDarwinLoadAverages(output)
}

func darwinProcessCount() int64 {
	processes, err := unix.SysctlKinfoProcSlice("kern.proc.all")
	if err != nil {
		return 0
	}
	return int64(len(processes))
}

func darwinConnectionCounts() (tcp int64, udp int64) {
	output, err := darwinCommandOutput("/usr/sbin/netstat", "-an")
	if err != nil {
		return 0, 0
	}
	return parseDarwinConnectionCounts(output)
}

func darwinNetworkTotals(allowlist map[string]struct{}) networkTotals {
	output, err := darwinCommandOutput("/usr/sbin/netstat", "-ibn")
	if err != nil {
		return networkTotals{}
	}
	return parseDarwinNetworkTotals(output, allowlist)
}

func darwinOSRelease() (string, string) {
	output, err := darwinCommandOutput("/usr/bin/sw_vers", "-productVersion")
	if err != nil {
		return "macos", ""
	}
	return "macos", strings.TrimSpace(output)
}

func darwinKernelRelease() string {
	value, err := unix.Sysctl("kern.osrelease")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(value)
}

func darwinVirtualizationName() string {
	value, err := unix.Sysctl("hw.model")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(value)
}

func darwinCPUModel() string {
	for _, name := range []string{"machdep.cpu.brand_string", "hw.model"} {
		value, err := unix.Sysctl(name)
		if err == nil && strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func darwinBootTime() int64 {
	value, err := unix.SysctlTimeval("kern.boottime")
	if err != nil {
		return 0
	}
	return value.Sec
}

func darwinUptimeSeconds() int64 {
	boot := darwinBootTime()
	if boot <= 0 {
		return 0
	}
	return nonNegativeInt64(time.Now().UTC().Unix() - boot)
}
