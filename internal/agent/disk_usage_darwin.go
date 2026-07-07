//go:build darwin

package agent

import "golang.org/x/sys/unix"

func diskUsage(allowlist []string) (used int64, total int64) {
	if len(allowlist) > 0 {
		for _, path := range normalizeAllowlist(allowlist) {
			pathUsed, pathTotal := diskUsageForPath(path)
			used += pathUsed
			total += pathTotal
		}
		return used, total
	}
	for _, candidate := range []string{"/System/Volumes/Data", "/"} {
		used, total = diskUsageForPath(candidate)
		if total > 0 {
			return used, total
		}
	}
	return 0, 0
}

func diskUsageForPath(path string) (used int64, total int64) {
	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil {
		return 0, 0
	}
	total = int64(stat.Blocks) * int64(stat.Bsize)
	free := int64(stat.Bfree) * int64(stat.Bsize)
	used = nonNegativeInt64(total - free)
	return used, total
}
