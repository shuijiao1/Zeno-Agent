package agent

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseMemoryStatsIncludesSwapTotals(t *testing.T) {
	stats := parseMemoryStats(`MemTotal:        2097152 kB
MemAvailable:    1048576 kB
SwapTotal:       524288 kB
SwapFree:        393216 kB
`)

	if stats.memTotal != 2*1024*1024*1024 || stats.memAvailable != 1024*1024*1024 {
		t.Fatalf("memory stats = %+v, want mem total/available bytes", stats)
	}
	if stats.swapTotal != 512*1024*1024 || stats.swapFree != 384*1024*1024 {
		t.Fatalf("swap stats = %+v, want swap total/free bytes", stats)
	}
}

func TestTCPConnectionCountFromFileSkipsHeader(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tcp")
	content := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1 0000000000000000 100 0 0 10 0
   1: 0100007F:1F91 0100007F:0050 01 00000000:00000000 00:00000000 00000000     0        0 2 1 0000000000000000 100 0 0 10 0
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write tcp fixture: %v", err)
	}

	if got := tcpConnectionCountFromFile(path); got != 2 {
		t.Fatalf("tcp connection count = %d, want 2 data rows", got)
	}
}

func TestTCPConnectionCountRejectsMalformedTable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tcp")
	if err := os.WriteFile(path, []byte("not a proc connection table\n"), 0o600); err != nil {
		t.Fatalf("write malformed tcp fixture: %v", err)
	}
	if count, err := tcpConnectionCountFromFileResult(path); err == nil || count != 0 {
		t.Fatalf("malformed connection table count/error = %d/%v, want explicit error", count, err)
	}
}

func TestParseDarwinConnectionCounts(t *testing.T) {
	tcp, udp := parseDarwinConnectionCounts(`Active Internet connections
Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)
tcp4       0      0  127.0.0.1.80           *.*                    LISTEN
tcp6       0      0  ::1.443                *.*                    LISTEN
udp4       0      0  *.5353                 *.*
udp6       0      0  *.5353                 *.*
`)
	if tcp != 2 || udp != 2 {
		t.Fatalf("darwin connection counts = tcp %d udp %d, want 2/2", tcp, udp)
	}
}

func TestParseDarwinConnectionCountsRejectsUnknownOutput(t *testing.T) {
	if tcp, udp, err := parseDarwinConnectionCountsResult("netstat output changed\n"); err == nil || tcp != 0 || udp != 0 {
		t.Fatalf("unknown Darwin connection output = %d/%d, %v; want explicit error", tcp, udp, err)
	}
}

func TestParseDarwinCPUAndLoadAverages(t *testing.T) {
	times, ok := parseDarwinCPUTimes("100 20 30 400 5")
	if !ok || times.Total != 555 || times.Idle != 400 {
		t.Fatalf("darwin CPU times = %+v, %v, want total=555 idle=400", times, ok)
	}
	load1, load5, load15 := parseDarwinLoadAverages("{ 1.25 0.75 0.50 }")
	if load1 != 1.25 || load5 != 0.75 || load15 != 0.50 {
		t.Fatalf("darwin load averages = %v/%v/%v", load1, load5, load15)
	}
}

func TestParseDarwinPerCPUTimes(t *testing.T) {
	times, ok := parseDarwinCPUTimes("10 1 4 85 0 20 2 8 170 0")
	if !ok || times.Total != 300 || times.Idle != 255 {
		t.Fatalf("per-CPU times = %+v ok=%v, want total=300 idle=255", times, ok)
	}
}

func TestParseDarwinCPUTimesAcceptsSysctlBraces(t *testing.T) {
	times, ok := parseDarwinCPUTimes("{ 100 20 30 400 5 }")
	if !ok || times.Total != 555 || times.Idle != 400 {
		t.Fatalf("braced CPU times = %+v ok=%v, want total=555 idle=400", times, ok)
	}
}

func TestParseDarwinNetworkTotalsUsesLinkRowsOnce(t *testing.T) {
	output := `Name  Mtu   Network       Address            Ipkts Ierrs    Ibytes    Opkts Oerrs     Obytes  Coll
lo0   16384 <Link#1>                        100     0      1000      100     0       1000     0
en0   1500  <Link#4>    aa:bb:cc:dd:ee:ff  200     0      2048      300     0       4096     0
en0   1500  192.0.2      192.0.2.5          200     -      2048      300     -       4096     -
utun1 1380  <Link#9>                         10     0       100       10     0        100     0
`
	totals := parseDarwinNetworkTotals(output, nil)
	if totals.InBytes != 2048 || totals.OutBytes != 4096 {
		t.Fatalf("darwin network totals = %+v, want en0 link totals only", totals)
	}
	allowlisted := parseDarwinNetworkTotals(output, allowlistSet([]string{"utun1"}))
	if allowlisted.InBytes != 100 || allowlisted.OutBytes != 100 {
		t.Fatalf("allowlisted darwin network totals = %+v, want utun1", allowlisted)
	}
}

func TestParseDarwinNetworkTotalsRejectsInvalidSelectedCounter(t *testing.T) {
	output := `Name  Mtu   Network       Address            Ipkts Ierrs    Ibytes    Opkts Oerrs     Obytes  Coll
en0   1500  <Link#4>    aa:bb:cc:dd:ee:ff  200     0       bad      300     0       4096     0
`
	if _, err := parseDarwinNetworkTotalsResult(output, nil); err == nil {
		t.Fatal("parseDarwinNetworkTotalsResult accepted an invalid selected counter")
	}
}

func TestParseLinuxNetworkTotalsReturnsErrorsInsteadOfZero(t *testing.T) {
	valid := `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
  eth0: 1000 1 0 0 0 0 0 0 2000 1 0 0 0 0 0 0
`
	totals, err := parseLinuxNetworkTotals(valid, nil)
	if err != nil {
		t.Fatalf("parseLinuxNetworkTotals(valid): %v", err)
	}
	if totals.InBytes != 1000 || totals.OutBytes != 2000 {
		t.Fatalf("linux network totals = %+v, want 1000/2000", totals)
	}

	invalid := `Inter-|   Receive | Transmit
  eth0: not-a-counter 1 0 0 0 0 0 0 2000 1 0 0 0 0 0 0
`
	if totals, err := parseLinuxNetworkTotals(invalid, nil); err == nil {
		t.Fatalf("parseLinuxNetworkTotals(invalid) = %+v, nil; want explicit error", totals)
	}
	if totals, err := parseLinuxNetworkTotals("eth0: 1 1 0 0 0 0 0 0 2 1 0 0 0 0 0 0\n", nil); err == nil {
		t.Fatalf("parseLinuxNetworkTotals(missing header) = %+v, nil; want explicit error", totals)
	}
}

func TestNetworkCounterSourceTracksSelectedInterfaces(t *testing.T) {
	first := networkCounterSourceID([]string{"eth1", "eth0"})
	if first == "" || first != networkCounterSourceID([]string{"eth0", "eth1"}) {
		t.Fatalf("counter source is empty or order-dependent: %q", first)
	}
	if first == networkCounterSourceID([]string{"eth0"}) {
		t.Fatal("counter source did not change when the selected interface set changed")
	}
	if networkCounterSourceID(nil) != "" {
		t.Fatal("empty selected interface set should not claim a source identity")
	}
}

func TestCollectStateKeepsValidNetworkBaselineAcrossReadFailure(t *testing.T) {
	collector := NewMetricsCollector()
	networkReads := 0
	collector.networkReader = func(map[string]struct{}) (networkTotals, error) {
		networkReads++
		switch networkReads {
		case 1:
			return networkTotals{InBytes: 1000, OutBytes: 2000}, nil
		case 2:
			return networkTotals{}, errors.New("transient counter read failure")
		case 3:
			return networkTotals{InBytes: 1100, OutBytes: 2200}, nil
		default:
			t.Fatalf("unexpected network read %d", networkReads)
			return networkTotals{}, nil
		}
	}
	connectionReads := 0
	collector.connectionReader = func() (int64, int64, error) {
		connectionReads++
		if connectionReads == 2 {
			return 0, 0, errors.New("transient table read failure")
		}
		return 12 + int64(connectionReads), 4 + int64(connectionReads), nil
	}

	start := time.Unix(1782990000, 0)
	first := collector.CollectState(start)
	failed := collector.CollectState(start.Add(time.Second))
	recovered := collector.CollectState(start.Add(2 * time.Second))

	if first.NetTotalsValid == nil || !*first.NetTotalsValid || first.NetInTotalBytes != 1000 || first.NetOutTotalBytes != 2000 {
		t.Fatalf("first network sample = %+v, want valid 1000/2000 baseline", first)
	}
	if failed.NetTotalsValid == nil || *failed.NetTotalsValid {
		t.Fatalf("failed network sample validity = %v, want false", failed.NetTotalsValid)
	}
	if failed.NetInTotalBytes != 1000 || failed.NetOutTotalBytes != 2000 || failed.NetInSpeedBps != 0 || failed.NetOutSpeedBps != 0 {
		t.Fatalf("failed network sample = %+v, want last-known totals and zero speed", failed)
	}
	if recovered.NetTotalsValid == nil || !*recovered.NetTotalsValid {
		t.Fatalf("recovered network sample validity = %v, want true", recovered.NetTotalsValid)
	}
	// The 100/200-byte deltas span two seconds. Advancing the baseline on the
	// failed middle read would incorrectly report a 100/200 B/s spike here.
	if recovered.NetInSpeedBps != 50 || recovered.NetOutSpeedBps != 100 {
		t.Fatalf("recovered speeds = %v/%v, want 50/100 B/s over full 2s interval", recovered.NetInSpeedBps, recovered.NetOutSpeedBps)
	}
	if failed.ConnectionCountsValid == nil || *failed.ConnectionCountsValid || failed.TCPConnectionCount != first.TCPConnectionCount || failed.UDPConnectionCount != first.UDPConnectionCount {
		t.Fatalf("failed connection sample = %+v, want invalid with last-known counts", failed)
	}
	if recovered.ConnectionCountsValid == nil || !*recovered.ConnectionCountsValid || recovered.TCPConnectionCount == failed.TCPConnectionCount {
		t.Fatalf("recovered connection sample = %+v, want refreshed valid counts", recovered)
	}
}

func TestCollectStateRebasesSpeedWhenCounterSourceChanges(t *testing.T) {
	collector := NewMetricsCollector()
	reads := 0
	collector.networkReader = func(map[string]struct{}) (networkTotals, error) {
		reads++
		if reads == 1 {
			return networkTotals{InBytes: 100, OutBytes: 200, SourceNames: []string{"eth0"}}, nil
		}
		return networkTotals{InBytes: 10000, OutBytes: 20000, SourceNames: []string{"eth0", "eth1"}}, nil
	}
	collector.connectionReader = func() (int64, int64, error) { return 0, 0, nil }
	start := time.Unix(1782990000, 0)
	first := collector.CollectState(start)
	changed := collector.CollectState(start.Add(time.Second))
	if first.NetCounterSource == "" || changed.NetCounterSource == "" || first.NetCounterSource == changed.NetCounterSource {
		t.Fatalf("counter source did not identify topology change: %q -> %q", first.NetCounterSource, changed.NetCounterSource)
	}
	if changed.NetInSpeedBps != 0 || changed.NetOutSpeedBps != 0 {
		t.Fatalf("source change produced a synthetic speed spike: %v/%v", changed.NetInSpeedBps, changed.NetOutSpeedBps)
	}
}

func TestIncludeNetworkInterfaceFiltersVirtualDefaults(t *testing.T) {
	for _, name := range []string{"lo", "docker0", "vethabc", "br-123", "tun0", "utun1", "tailscale0", "kube-ipvs0", "vmbr0", "tap1", "cni0", "flannel.1", "cali123", "virbr0"} {
		if includeNetworkInterface(name, nil) {
			t.Fatalf("interface %s included by default, want excluded", name)
		}
	}
	for _, name := range []string{"eth0", "ens3", "enp1s0", "wlan0"} {
		if !includeNetworkInterface(name, nil) {
			t.Fatalf("interface %s excluded by default, want included", name)
		}
	}
}

func TestNetworkInterfaceAllowlistOverridesDefaultFilter(t *testing.T) {
	allowlist := allowlistSet([]string{"tailscale0", "eth0"})
	if !includeNetworkInterface("tailscale0", allowlist) {
		t.Fatal("allowlisted tailscale0 should be included")
	}
	if includeNetworkInterface("ens3", allowlist) {
		t.Fatal("non-allowlisted ens3 should be excluded when allowlist is set")
	}
}

func TestCollectStateIncludesExtraMetrics(t *testing.T) {
	collector := NewMetricsCollector()
	sample := collector.CollectState(time.Now())

	if sample.TS <= 0 {
		t.Fatalf("state timestamp = %d, want unix timestamp", sample.TS)
	}
	if sample.Load1 < 0 || sample.Load5 < 0 || sample.Load15 < 0 {
		t.Fatalf("load averages should be non-negative: %+v", sample)
	}
	if sample.SwapUsedBytes < 0 || sample.SwapTotalBytes < 0 || sample.ProcessCount < 0 || sample.TCPConnectionCount < 0 {
		t.Fatalf("extra state metrics should be non-negative: %+v", sample)
	}
}

func TestCollectStateAssignsUniqueStateSampleIDs(t *testing.T) {
	collector := NewMetricsCollector()
	now := time.Unix(1782990000, 0)
	first := collector.CollectState(now)
	second := collector.CollectState(now)

	if first.SampleID == "" || first.IdempotencyKey != first.SampleID {
		t.Fatalf("first state id fields = sample_id %q idempotency_key %q, want matching non-empty ids", first.SampleID, first.IdempotencyKey)
	}
	if second.SampleID == "" || second.IdempotencyKey != second.SampleID {
		t.Fatalf("second state id fields = sample_id %q idempotency_key %q, want matching non-empty ids", second.SampleID, second.IdempotencyKey)
	}
	if first.SampleID == second.SampleID {
		t.Fatalf("different collected samples reused id %q", first.SampleID)
	}
}

func TestWindowsPagefileSwapTotalsSubtractsRAMWithoutUnderflow(t *testing.T) {
	total, free := windowsPagefileSwapTotals(12<<30, 7<<30, 8<<30, 5<<30)
	if total != 4<<30 || free != 2<<30 {
		t.Fatalf("windows pagefile swap = total %d free %d, want 4GiB/2GiB", total, free)
	}
	total, free = windowsPagefileSwapTotals(4<<30, 2<<30, 8<<30, 5<<30)
	if total != 0 || free != 0 {
		t.Fatalf("underflowing windows pagefile swap = total %d free %d, want zero", total, free)
	}
}

func TestWindowsLoadAveragesAreNotSyntheticCPU(t *testing.T) {
	load1, load5, load15 := windowsLoadAverages(87.5, 16)
	if load1 != 0 || load5 != 0 || load15 != 0 {
		t.Fatalf("windows load averages = %v/%v/%v, want zero because Windows has no Unix load average", load1, load5, load15)
	}
}
