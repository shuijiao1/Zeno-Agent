//go:build !windows

package agent

func windowsReadCPUTimes() (cpuTimes, bool)                        { return cpuTimes{}, false }
func windowsLoadAverages(float64, int) (float64, float64, float64) { return 0, 0, 0 }
func windowsProcessCount() int64                                   { return 0 }
func windowsConnectionCounts() (int64, int64, error)               { return 0, 0, nil }
func windowsNetworkTotals(map[string]struct{}) (networkTotals, error) {
	return networkTotals{}, nil
}
func windowsOSRelease() (string, string) { return "", "" }
func windowsKernelRelease() string       { return "" }
func windowsVirtualizationName() string  { return "" }
func windowsCPUModel() string            { return "" }
func windowsBootTime() int64             { return 0 }
func windowsUptimeSeconds() int64        { return 0 }
