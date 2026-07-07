//go:build !windows

package agent

import "syscall"

func diskUsage(path string) (used int64, total int64) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return 0, 0
	}
	total = int64(stat.Blocks) * int64(stat.Bsize)
	free := int64(stat.Bfree) * int64(stat.Bsize)
	used = nonNegativeInt64(total - free)
	return used, total
}
