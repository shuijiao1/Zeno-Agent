//go:build !darwin

package agent

func darwinReadCPUTimes() (cpuTimes, bool)                  { return cpuTimes{}, false }
func darwinLoadAverages() (float64, float64, float64)       { return 0, 0, 0 }
func darwinProcessCount() int64                             { return 0 }
func darwinConnectionCounts() (int64, int64)                { return 0, 0 }
func darwinNetworkTotals(map[string]struct{}) networkTotals { return networkTotals{} }
func darwinOSRelease() (string, string)                     { return "", "" }
func darwinKernelRelease() string                           { return "" }
func darwinVirtualizationName() string                      { return "" }
func darwinCPUModel() string                                { return "" }
func darwinBootTime() int64                                 { return 0 }
func darwinUptimeSeconds() int64                            { return 0 }
