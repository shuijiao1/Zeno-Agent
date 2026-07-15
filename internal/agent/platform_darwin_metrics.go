//go:build darwin

package agent

import (
	"context"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

func darwinReadCPUTimes() (cpuTimes, bool) {
	for _, name := range []string{"kern.cp_time", "kern.cp_times"} {
		output, err := darwinCommandOutput("/usr/sbin/sysctl", "-n", name)
		if err != nil {
			continue
		}
		if values, ok := parseDarwinCPUTimes(output); ok {
			return values, true
		}
	}
	return cpuTimes{}, false
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

func darwinConnectionCounts() (tcp int64, udp int64, err error) {
	parser := darwinConnectionParser{}
	err = darwinCommandScanLinesWithLimits(context.Background(), darwinMetricsCommandTimeout, darwinMetricsMaxLines, darwinMetricsMaxLineBytes, parser.consume, "/usr/sbin/netstat", "-an")
	if err != nil {
		return 0, 0, err
	}
	return parser.result()
}

func darwinNetworkTotals(allowlist map[string]struct{}) (networkTotals, error) {
	parser := newDarwinNetworkParser(allowlist)
	err := darwinCommandScanLinesWithLimits(context.Background(), darwinMetricsCommandTimeout, darwinMetricsMaxLines, darwinMetricsMaxLineBytes, parser.consume, "/usr/sbin/netstat", "-ibn")
	if err != nil {
		return networkTotals{}, err
	}
	return parser.result()
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
