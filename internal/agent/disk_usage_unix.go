//go:build linux

package agent

import (
	"bufio"
	"os"
	"strings"
	"syscall"
)

var defaultExcludedDiskFSTypes = map[string]struct{}{
	"autofs":      {},
	"binfmt_misc": {},
	"bpf":         {},
	"cgroup":      {},
	"cgroup2":     {},
	"configfs":    {},
	"debugfs":     {},
	"devpts":      {},
	"devtmpfs":    {},
	"fusectl":     {},
	"hugetlbfs":   {},
	"mqueue":      {},
	"nsfs":        {},
	"overlay":     {},
	"proc":        {},
	"pstore":      {},
	"ramfs":       {},
	"rpc_pipefs":  {},
	"securityfs":  {},
	"squashfs":    {},
	"sysfs":       {},
	"tmpfs":       {},
	"tracefs":     {},
}

var defaultExcludedDiskMountPrefixes = []string{
	"/dev",
	"/proc",
	"/run",
	"/sys",
	"/var/lib/docker",
	"/var/lib/containerd",
	"/var/lib/kubelet",
	"/var/lib/containers/storage",
	"/snap",
}

func diskUsage(allowlist []string) (used int64, total int64) {
	if len(allowlist) > 0 {
		return diskUsageForAllowlist(allowlist)
	}
	return diskUsageFromMountInfo("/proc/self/mountinfo")
}

func diskUsageForAllowlist(paths []string) (used int64, total int64) {
	seen := map[uint64]struct{}{}
	for _, path := range normalizeAllowlist(paths) {
		key, ok := statDeviceKey(path)
		if ok {
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
		}
		pathUsed, pathTotal := diskUsageForPath(path)
		used += pathUsed
		total += pathTotal
	}
	return used, total
}

func diskUsageFromMountInfo(path string) (used int64, total int64) {
	file, err := os.Open(path)
	if err != nil {
		return diskUsageForPath("/")
	}
	defer file.Close()

	seen := map[string]struct{}{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		mount, ok := parseMountInfoLine(scanner.Text())
		if !ok || !includeDiskMount(mount.mountPoint, mount.fsType, mount.source) {
			continue
		}
		if _, exists := seen[mount.device]; exists {
			continue
		}
		seen[mount.device] = struct{}{}
		mountUsed, mountTotal := diskUsageForPath(mount.mountPoint)
		if mountTotal <= 0 {
			continue
		}
		used += mountUsed
		total += mountTotal
	}
	if total == 0 {
		return diskUsageForPath("/")
	}
	return used, total
}

type mountInfoEntry struct {
	device     string
	mountPoint string
	fsType     string
	source     string
}

func parseMountInfoLine(line string) (mountInfoEntry, bool) {
	left, right, ok := strings.Cut(line, " - ")
	if !ok {
		return mountInfoEntry{}, false
	}
	leftFields := strings.Fields(left)
	rightFields := strings.Fields(right)
	if len(leftFields) < 5 || len(rightFields) < 2 {
		return mountInfoEntry{}, false
	}
	return mountInfoEntry{
		device:     leftFields[2],
		mountPoint: decodeMountInfoField(leftFields[4]),
		fsType:     strings.ToLower(rightFields[0]),
		source:     decodeMountInfoField(rightFields[1]),
	}, true
}

func decodeMountInfoField(value string) string {
	replacer := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`)
	return replacer.Replace(value)
}

func includeDiskMount(mountPoint, fsType, source string) bool {
	mountPoint = strings.TrimSpace(mountPoint)
	if mountPoint == "" {
		return false
	}
	if _, excluded := defaultExcludedDiskFSTypes[strings.ToLower(fsType)]; excluded {
		return false
	}
	lowerMount := strings.ToLower(mountPoint)
	for _, prefix := range defaultExcludedDiskMountPrefixes {
		if lowerMount == prefix || strings.HasPrefix(lowerMount, prefix+"/") {
			return false
		}
	}
	lowerSource := strings.ToLower(strings.TrimSpace(source))
	if lowerSource == "" || lowerSource == "none" || strings.HasPrefix(lowerSource, "overlay") {
		return false
	}
	return true
}

func diskUsageForPath(path string) (used int64, total int64) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return 0, 0
	}
	total = int64(stat.Blocks) * int64(stat.Bsize)
	free := int64(stat.Bfree) * int64(stat.Bsize)
	used = nonNegativeInt64(total - free)
	return used, total
}

func statDeviceKey(path string) (uint64, bool) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return uint64(stat.Dev), true
}
