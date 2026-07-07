//go:build linux

package agent

import "os"

func platformMemoryTotals() (total int64, available int64) {
	content, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, 0
	}
	stats := parseMemoryStats(string(content))
	return stats.memTotal, stats.memAvailable
}

func platformSwapTotals() (total int64, free int64) {
	content, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, 0
	}
	stats := parseMemoryStats(string(content))
	return stats.swapTotal, stats.swapFree
}
