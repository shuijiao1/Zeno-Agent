package agent

func windowsPagefileSwapTotals(totalPageFile, availablePageFile, totalPhys, availablePhys uint64) (total int64, free int64) {
	return uint64DifferenceAsInt64(totalPageFile, totalPhys), uint64DifferenceAsInt64(availablePageFile, availablePhys)
}

func uint64DifferenceAsInt64(left, right uint64) int64 {
	if left <= right {
		return 0
	}
	delta := left - right
	if delta > uint64(maxInt64) {
		return maxInt64
	}
	return int64(delta)
}

const maxInt64 = int64(^uint64(0) >> 1)
