//go:build windows

package agent

import "testing"

func TestWindowsPlatformReadsRealNetworkAndConnectionMetrics(t *testing.T) {
	totals, err := windowsNetworkTotals(nil)
	if err != nil {
		t.Fatalf("windowsNetworkTotals: %v", err)
	}
	if totals.InBytes < 0 || totals.OutBytes < 0 {
		t.Fatalf("Windows network totals are negative: %+v", totals)
	}

	tcp, udp, err := windowsConnectionCounts()
	if err != nil {
		t.Fatalf("windowsConnectionCounts: %v", err)
	}
	if tcp < 0 || udp < 0 {
		t.Fatalf("Windows connection counts are negative: tcp=%d udp=%d", tcp, udp)
	}
}
