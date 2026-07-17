package agent

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestProbeSpoolPersistsCanonicalBatchAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 7, 17, 1, 2, 3, 456, time.UTC)
	rounds := []ProbeRound{{
		RoundID:       "stable-round-id",
		ConfigVersion: 7,
		TargetID:      "target-1",
		TS:            now,
		Type:          "tcping",
		Samples:       []ProbeSample{{Seq: 1, Success: true, LatencyMS: float64Pointer(12.5)}},
	}}
	spool, err := NewProbeSpool(dir, ProbeSpoolOptions{
		Now:       func() time.Time { return now },
		FreeBytes: func(string) (uint64, error) { return 1 << 40, nil },
	})
	if err != nil {
		t.Fatalf("NewProbeSpool: %v", err)
	}
	if _, err := spool.Enqueue(rounds); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	first, err := spool.Next(now)
	if err != nil || first == nil {
		t.Fatalf("Next before restart = %#v, %v", first, err)
	}

	restarted, err := NewProbeSpool(dir, ProbeSpoolOptions{
		Now:       func() time.Time { return now },
		FreeBytes: func(string) (uint64, error) { return 1 << 40, nil },
	})
	if err != nil {
		t.Fatalf("restart NewProbeSpool: %v", err)
	}
	second, err := restarted.Next(now)
	if err != nil || second == nil {
		t.Fatalf("Next after restart = %#v, %v", second, err)
	}
	if string(first.Body) != string(second.Body) {
		t.Fatalf("body changed across restart:\nfirst:  %s\nsecond: %s", first.Body, second.Body)
	}
	var request ProbeResultsRequest
	if err := json.Unmarshal(second.Body, &request); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if request.ConfigVersion != 7 || len(request.Rounds) != 1 || request.Rounds[0].RoundID != "stable-round-id" || request.Rounds[0].TS != now.Unix() {
		t.Fatalf("recovered request lost identifiers: %+v", request)
	}

	entries, err := os.ReadDir(filepath.Join(dir, "probe-spool", "pending"))
	if err != nil || len(entries) != 1 {
		t.Fatalf("pending entries = %v, %v", entries, err)
	}
	content, err := os.ReadFile(filepath.Join(dir, "probe-spool", "pending", entries[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"test-bearer-secret", "Authorization", "https://controller.invalid", "node-secret", "192.0.2.10", "admin-password"} {
		if strings.Contains(string(content), secret) {
			t.Fatalf("spool persisted forbidden value %q: %s", secret, content)
		}
	}
	if runtime.GOOS != "windows" {
		for _, check := range []struct {
			path string
			mode os.FileMode
		}{
			{dir, 0o700},
			{filepath.Join(dir, "probe-spool"), 0o700},
			{filepath.Join(dir, "probe-spool", "pending"), 0o700},
			{filepath.Join(dir, "probe-spool", "pending", entries[0].Name()), 0o600},
		} {
			info, statErr := os.Stat(check.path)
			if statErr != nil || info.Mode().Perm() != check.mode {
				t.Fatalf("%s mode = %v, %v; want %v", check.path, info.Mode().Perm(), statErr, check.mode)
			}
		}
	}
}

func TestDefaultProbeSpoolLimits(t *testing.T) {
	limits := DefaultProbeSpoolLimits()
	if limits.TTL != 72*time.Hour || limits.MaxPendingItems != 16384 || limits.MaxPendingBytes != 256<<20 ||
		limits.MaxItemBytes != 1<<20 || limits.MinFreeBytes != 512<<20 || limits.MaxQuarantineItems != 128 || limits.MaxQuarantineBytes != 16<<20 {
		t.Fatalf("unexpected default limits: %+v", limits)
	}
}

func TestProbeSpoolRejectsRelativeDataDirectory(t *testing.T) {
	if _, err := NewProbeSpool("relative-agent-data", ProbeSpoolOptions{}); err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("relative data directory error = %v", err)
	}
}

func float64Pointer(value float64) *float64 { return &value }

func TestProbeSpoolFailsClosedAtCapacityAndLowDisk(t *testing.T) {
	now := time.Date(2026, 7, 17, 2, 0, 0, 0, time.UTC)
	round := testSpoolRound(now, "round-1")
	limits := DefaultProbeSpoolLimits()
	limits.MaxPendingItems = 1

	spool, err := NewProbeSpool(t.TempDir(), ProbeSpoolOptions{
		Limits: limits, Now: func() time.Time { return now },
		FreeBytes: func(string) (uint64, error) { return 1 << 40, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := spool.Enqueue([]ProbeRound{round}); err != nil {
		t.Fatalf("first enqueue: %v", err)
	}
	if _, err := spool.Enqueue([]ProbeRound{testSpoolRound(now, "round-2")}); err == nil || !strings.Contains(err.Error(), "capacity") {
		t.Fatalf("capacity enqueue error = %v", err)
	}
	item, err := spool.Next(now)
	if err != nil || item == nil || !strings.Contains(string(item.Body), "round-1") {
		t.Fatalf("old backlog was overwritten: %#v, %v", item, err)
	}

	lowDisk, err := NewProbeSpool(t.TempDir(), ProbeSpoolOptions{
		Now:       func() time.Time { return now },
		FreeBytes: func(string) (uint64, error) { return uint64(DefaultProbeSpoolLimits().MinFreeBytes - 1), nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lowDisk.Enqueue([]ProbeRound{round}); err == nil || !strings.Contains(err.Error(), "free space") {
		t.Fatalf("low-disk enqueue error = %v", err)
	}
	if item, err := lowDisk.Next(now); err != nil || item != nil {
		t.Fatalf("low-disk enqueue left an item: %#v, %v", item, err)
	}
}

func TestProbeSpoolPropagatesENOSPCWithoutPartialItem(t *testing.T) {
	now := time.Date(2026, 7, 17, 2, 1, 0, 0, time.UTC)
	spool, err := NewProbeSpool(t.TempDir(), ProbeSpoolOptions{
		Now: func() time.Time { return now }, FreeBytes: func(string) (uint64, error) { return 1 << 40, nil },
		AtomicWrite: func(string, []byte) error { return syscall.ENOSPC },
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := spool.Enqueue([]ProbeRound{testSpoolRound(now, "enospc")}); !errors.Is(err, syscall.ENOSPC) {
		t.Fatalf("enqueue error = %v, want ENOSPC", err)
	}
	entries, err := os.ReadDir(spool.pendingDir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("partial pending files after ENOSPC = %v, %v", entries, err)
	}
}

func TestProbeSpoolExpiresBeforeCapacityCheck(t *testing.T) {
	now := time.Date(2026, 7, 17, 3, 0, 0, 0, time.UTC)
	clock := now
	limits := DefaultProbeSpoolLimits()
	limits.MaxPendingItems = 1
	spool, err := NewProbeSpool(t.TempDir(), ProbeSpoolOptions{
		Limits: limits, Now: func() time.Time { return clock }, FreeBytes: func(string) (uint64, error) { return 1 << 40, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := spool.Enqueue([]ProbeRound{testSpoolRound(now, "expired")}); err != nil {
		t.Fatal(err)
	}
	clock = now.Add(limits.TTL)
	if _, err := spool.Enqueue([]ProbeRound{testSpoolRound(clock, "replacement")}); err != nil {
		t.Fatalf("expired item was not cleaned before capacity check: %v", err)
	}
	item, err := spool.Next(clock)
	if err != nil || item == nil || strings.Contains(string(item.Body), "expired") || !strings.Contains(string(item.Body), "replacement") {
		t.Fatalf("next after TTL cleanup = %#v, %v", item, err)
	}
}

func TestProbeSpoolQuarantinesCorruptVersionChecksumAndOversizeFiles(t *testing.T) {
	now := time.Date(2026, 7, 17, 4, 0, 0, 0, time.UTC)
	limits := DefaultProbeSpoolLimits()
	limits.MaxItemBytes = 512
	limits.MaxPendingBytes = 4096
	limits.MaxQuarantineItems = 2
	limits.MaxQuarantineBytes = 1024
	spool, err := NewProbeSpool(t.TempDir(), ProbeSpoolOptions{
		Limits: limits, Now: func() time.Time { return now }, FreeBytes: func(string) (uint64, error) { return 1 << 40, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	body, err := marshalProbeResults([]ProbeRound{testSpoolRound(now, "valid")})
	if err != nil {
		t.Fatal(err)
	}
	writeEnvelope := func(name string, envelope probeSpoolEnvelope) {
		t.Helper()
		encoded, marshalErr := json.Marshal(envelope)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		if writeErr := os.WriteFile(filepath.Join(spool.pendingDir, name), encoded, 0o600); writeErr != nil {
			t.Fatal(writeErr)
		}
	}
	base := probeSpoolEnvelope{SchemaVersion: probeSpoolSchemaVersion, Created: now.UnixNano(), NextAt: now.UnixNano(), Checksum: probeSpoolChecksum(body), Batch: body}
	badVersion := base
	badVersion.SchemaVersion++
	writeEnvelope("000-version.json", badVersion)
	badChecksum := base
	badChecksum.Checksum = strings.Repeat("0", 64)
	writeEnvelope("001-checksum.json", badChecksum)
	if err := os.WriteFile(filepath.Join(spool.pendingDir, "002-oversize.json"), make([]byte, limits.MaxItemBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	writeEnvelope("999-valid.json", base)

	item, err := spool.Next(now)
	if err != nil || item == nil || !strings.Contains(string(item.Body), "valid") {
		t.Fatalf("valid item blocked by corrupt files: %#v, %v", item, err)
	}
	quarantined, err := os.ReadDir(spool.quarantineDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(quarantined) > limits.MaxQuarantineItems {
		t.Fatalf("quarantine items = %d, limit %d", len(quarantined), limits.MaxQuarantineItems)
	}
	var quarantineBytes int64
	for _, entry := range quarantined {
		info, statErr := entry.Info()
		if statErr != nil {
			t.Fatal(statErr)
		}
		quarantineBytes += info.Size()
	}
	if quarantineBytes > limits.MaxQuarantineBytes {
		t.Fatalf("quarantine bytes = %d, limit %d", quarantineBytes, limits.MaxQuarantineBytes)
	}
}

func TestProbeSpoolRemovesUnexpectedSymlinkWithoutFollowingIt(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("non-admin Windows test environments cannot reliably create symlinks")
	}
	now := time.Date(2026, 7, 17, 4, 30, 0, 0, time.UTC)
	spool, err := NewProbeSpool(t.TempDir(), ProbeSpoolOptions{
		Now: func() time.Time { return now }, FreeBytes: func(string) (uint64, error) { return 1 << 40, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "must-not-be-chmodded")
	if err := os.WriteFile(target, []byte("outside"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(spool.pendingDir, "unexpected.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if item, err := spool.Next(now); err != nil || item != nil {
		t.Fatalf("Next with symlink = %#v, %v", item, err)
	}
	if _, err := os.Lstat(link); !os.IsNotExist(err) {
		t.Fatalf("unexpected symlink remains: %v", err)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("symlink target mode = %v; want 0644", info.Mode().Perm())
	}
}

func testSpoolRound(ts time.Time, roundID string) ProbeRound {
	return ProbeRound{RoundID: roundID, ConfigVersion: 1, TargetID: "target", TS: ts, Type: "tcping", Samples: []ProbeSample{{Seq: 1, Success: false, Error: "timeout"}}}
}
