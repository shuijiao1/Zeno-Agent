package agent

import (
	"encoding/binary"
	"errors"
	"fmt"
)

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

const (
	windowsErrorInsufficientBuffer = uint32(122)
	windowsErrorNotSupported       = uint32(50)
	windowsErrorInvalidParameter   = uint32(87)
	windowsIPTableMaxAttempts      = 5
	windowsIPTableMaxBufferBytes   = uint32(64 << 20)
)

type windowsIPTableAPIError struct {
	Code uint32
}

func (err windowsIPTableAPIError) Error() string {
	return fmt.Sprintf("windows IP table query returned error %d", err.Code)
}

func windowsIPFamilyUnavailable(err error) bool {
	var apiErr windowsIPTableAPIError
	return errors.As(err, &apiErr) && (apiErr.Code == windowsErrorNotSupported || apiErr.Code == windowsErrorInvalidParameter)
}

type windowsIPTableQuery func(buffer []byte, size *uint32) uint32

// windowsIPTableCountWithQuery implements the resize protocol shared by the
// GetExtendedTcpTable/GetExtendedUdpTable family. Tables can grow between the
// sizing call and the data call, so every ERROR_INSUFFICIENT_BUFFER result must
// honor the newly returned size. Attempts and allocation are both bounded.
func windowsIPTableCountWithQuery(query windowsIPTableQuery) (int64, error) {
	if query == nil {
		return 0, fmt.Errorf("windows IP table query is nil")
	}
	var buffer []byte
	var size uint32
	for attempt := 1; attempt <= windowsIPTableMaxAttempts; attempt++ {
		result := query(buffer, &size)
		if result == 0 {
			if len(buffer) < 4 || size < 4 {
				return 0, fmt.Errorf("windows IP table query returned an undersized success buffer")
			}
			return int64(binary.LittleEndian.Uint32(buffer[:4])), nil
		}
		if result != windowsErrorInsufficientBuffer {
			return 0, windowsIPTableAPIError{Code: result}
		}
		if size < 4 {
			return 0, fmt.Errorf("windows IP table query requested invalid buffer size %d", size)
		}
		if size > windowsIPTableMaxBufferBytes {
			return 0, fmt.Errorf("windows IP table query requested %d bytes, limit is %d", size, windowsIPTableMaxBufferBytes)
		}
		buffer = make([]byte, int(size))
	}
	return 0, fmt.Errorf("windows IP table kept growing after %d attempts", windowsIPTableMaxAttempts)
}
