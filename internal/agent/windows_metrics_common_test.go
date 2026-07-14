package agent

import (
	"encoding/binary"
	"strings"
	"testing"
)

func TestWindowsIPTableCountRetriesWithUpdatedBufferSize(t *testing.T) {
	calls := 0
	count, err := windowsIPTableCountWithQuery(func(buffer []byte, size *uint32) uint32 {
		calls++
		switch calls {
		case 1:
			if len(buffer) != 0 {
				t.Fatalf("sizing call buffer len = %d, want 0", len(buffer))
			}
			*size = 8
			return windowsErrorInsufficientBuffer
		case 2:
			if len(buffer) != 8 {
				t.Fatalf("first data call buffer len = %d, want 8", len(buffer))
			}
			// The table grew between calls. The next attempt must allocate this
			// newly returned size rather than retrying the stale 8-byte buffer.
			*size = 16
			return windowsErrorInsufficientBuffer
		case 3:
			if len(buffer) != 16 {
				t.Fatalf("second data call buffer len = %d, want updated size 16", len(buffer))
			}
			binary.LittleEndian.PutUint32(buffer[:4], 37)
			*size = uint32(len(buffer))
			return 0
		default:
			t.Fatalf("unexpected query call %d", calls)
			return 1
		}
	})
	if err != nil {
		t.Fatalf("windowsIPTableCountWithQuery: %v", err)
	}
	if count != 37 || calls != 3 {
		t.Fatalf("count/calls = %d/%d, want 37/3", count, calls)
	}
}

func TestWindowsIPTableCountBoundsRepeatedGrowth(t *testing.T) {
	calls := 0
	_, err := windowsIPTableCountWithQuery(func(_ []byte, size *uint32) uint32 {
		calls++
		*size = uint32(4 + calls*4)
		return windowsErrorInsufficientBuffer
	})
	if err == nil || !strings.Contains(err.Error(), "kept growing") {
		t.Fatalf("repeated growth error = %v, want bounded retry error", err)
	}
	if calls != windowsIPTableMaxAttempts {
		t.Fatalf("query calls = %d, want bounded %d", calls, windowsIPTableMaxAttempts)
	}
}

func TestWindowsIPTableCountPropagatesAPIFailure(t *testing.T) {
	if count, err := windowsIPTableCountWithQuery(func([]byte, *uint32) uint32 { return 5 }); err == nil || count != 0 {
		t.Fatalf("API failure count/error = %d/%v, want explicit error", count, err)
	}
}
