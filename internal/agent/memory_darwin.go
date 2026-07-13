//go:build darwin

package agent

import (
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

func platformMemoryTotals() (total int64, available int64) {
	totalBytes, err := unix.SysctlUint64("hw.memsize")
	if err != nil || totalBytes == 0 {
		return 0, 0
	}
	available = darwinAvailableMemory()
	if available < 0 {
		available = 0
	}
	if available > int64(totalBytes) {
		available = int64(totalBytes)
	}
	return int64(totalBytes), available
}

func platformSwapTotals() (total int64, free int64) {
	output, err := darwinCommandOutput("/usr/sbin/sysctl", "-n", "vm.swapusage")
	if err != nil {
		return 0, 0
	}
	return parseDarwinSwapUsage(output)
}

func darwinAvailableMemory() int64 {
	pageSize, _ := unix.SysctlUint64("hw.pagesize")
	if pageSize == 0 {
		pageSize = 4096
	}
	free, freeOK := darwinPageCount("vm.page_free_count")
	inactive, inactiveOK := darwinPageCount("vm.page_inactive_count")
	speculative, speculativeOK := darwinPageCount("vm.page_speculative_count")
	if freeOK || inactiveOK || speculativeOK {
		return int64((free + inactive + speculative) * pageSize)
	}
	return darwinAvailableMemoryFromVMStat()
}

func darwinPageCount(name string) (uint64, bool) {
	value, err := unix.SysctlUint64(name)
	if err != nil {
		return 0, false
	}
	return value, true
}

func darwinAvailableMemoryFromVMStat() int64 {
	output, err := darwinCommandOutput("/usr/bin/vm_stat")
	if err != nil {
		return 0
	}
	pageSize := int64(4096)
	if match := regexp.MustCompile(`page size of (\d+) bytes`).FindStringSubmatch(output); len(match) == 2 {
		if value, err := strconv.ParseInt(match[1], 10, 64); err == nil && value > 0 {
			pageSize = value
		}
	}
	var pages int64
	for _, line := range strings.Split(output, "\n") {
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		if name != "Pages free" && name != "Pages inactive" && name != "Pages speculative" {
			continue
		}
		value = strings.Trim(strings.TrimSpace(value), ".")
		value = strings.ReplaceAll(value, ".", "")
		if count, err := strconv.ParseInt(value, 10, 64); err == nil && count > 0 {
			pages += count
		}
	}
	return pages * pageSize
}

func parseDarwinSwapUsage(output string) (total int64, free int64) {
	var parsedTotal int64
	var parsedFree int64
	for _, match := range regexp.MustCompile(`(total|free)\s*=\s*([0-9.]+)([KMGTP])`).FindAllStringSubmatch(output, -1) {
		value, err := strconv.ParseFloat(match[2], 64)
		if err != nil {
			continue
		}
		bytes := int64(value * float64(unitMultiplier(match[3])))
		switch match[1] {
		case "total":
			parsedTotal = bytes
		case "free":
			parsedFree = bytes
		}
	}
	return parsedTotal, parsedFree
}

func unitMultiplier(unit string) int64 {
	switch strings.ToUpper(unit) {
	case "K":
		return 1024
	case "M":
		return 1024 * 1024
	case "G":
		return 1024 * 1024 * 1024
	case "T":
		return 1024 * 1024 * 1024 * 1024
	case "P":
		return 1024 * 1024 * 1024 * 1024 * 1024
	default:
		return 1
	}
}
