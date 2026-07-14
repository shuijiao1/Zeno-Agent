//go:build darwin

package agent

import "testing"

func TestDarwinPlatformReadsRealCommandMetrics(t *testing.T) {
	if _, ok := darwinReadCPUTimes(); !ok {
		t.Fatal("darwinReadCPUTimes returned invalid data")
	}

	totals, err := darwinNetworkTotals(nil)
	if err != nil {
		t.Fatalf("darwinNetworkTotals: %v", err)
	}
	if totals.InBytes < 0 || totals.OutBytes < 0 {
		t.Fatalf("Darwin network totals are negative: %+v", totals)
	}

	tcp, udp, err := darwinConnectionCounts()
	if err != nil {
		t.Fatalf("darwinConnectionCounts: %v", err)
	}
	if tcp < 0 || udp < 0 {
		t.Fatalf("Darwin connection counts are negative: tcp=%d udp=%d", tcp, udp)
	}
}
