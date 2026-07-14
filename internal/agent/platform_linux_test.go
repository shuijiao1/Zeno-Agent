//go:build linux

package agent

import "testing"

func TestLinuxPlatformReadsRealNetworkAndConnectionMetrics(t *testing.T) {
	totals, err := readNetworkTotals(nil)
	if err != nil {
		t.Fatalf("readNetworkTotals(/proc/net/dev): %v", err)
	}
	if totals.InBytes < 0 || totals.OutBytes < 0 {
		t.Fatalf("real Linux network totals are negative: %+v", totals)
	}

	tcp, udp, err := connectionCounts()
	if err != nil {
		t.Fatalf("connectionCounts(/proc/net): %v", err)
	}
	if tcp < 0 || udp < 0 {
		t.Fatalf("real Linux connection counts are negative: tcp=%d udp=%d", tcp, udp)
	}
}
