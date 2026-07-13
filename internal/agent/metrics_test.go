package agent

import (
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
