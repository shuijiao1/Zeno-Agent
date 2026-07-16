package agent

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type MetricsCollector struct {
	mu                sync.Mutex
	previousCPU       cpuTimes
	hasCPU            bool
	previousNet       networkTotals
	previousNetSource string
	previousNetAt     time.Time
	hasNet            bool
	previousTCP       int64
	previousUDP       int64
	hasConnections    bool
	networkAllowlist  map[string]struct{}
	diskAllowlist     []string
	networkReader     func(map[string]struct{}) (networkTotals, error)
	connectionReader  func() (tcp int64, udp int64, err error)
}

type MetricsOptions struct {
	NetworkInterfaceAllowlist []string
	DiskMountAllowlist        []string
}

func NewMetricsCollector(options ...MetricsOptions) *MetricsCollector {
	var opts MetricsOptions
	if len(options) > 0 {
		opts = options[0]
	}
	return &MetricsCollector{
		networkAllowlist: allowlistSet(opts.NetworkInterfaceAllowlist),
		diskAllowlist:    normalizeAllowlist(opts.DiskMountAllowlist),
		networkReader:    readNetworkTotals,
		connectionReader: connectionCounts,
	}
}

func (c *MetricsCollector) CollectHost(version string) HostInfo {
	memTotal, _ := readMemoryTotals()
	_, diskTotal := diskUsage(c.diskAllowlist)
	hostname, _ := os.Hostname()
	osName, osVersion := osRelease()
	return HostInfo{
		Hostname:         hostname,
		OSName:           osName,
		OSVersion:        osVersion,
		Kernel:           kernelRelease(),
		Arch:             normalizedArch(runtime.GOARCH),
		Virtualization:   virtualizationName(),
		CPUModel:         cpuModel(),
		CPUCores:         runtime.NumCPU(),
		MemoryTotalBytes: memTotal,
		DiskTotalBytes:   diskTotal,
		BootTime:         bootTime(),
		AgentVersion:     version,
	}
}

func (c *MetricsCollector) CollectState(now time.Time) StateSample {
	c.mu.Lock()
	defer c.mu.Unlock()

	cpu := c.cpuPercent()
	memTotal, memAvailable := readMemoryTotals()
	swapTotal, swapFree := readSwapTotals()
	load1, load5, load15 := readLoadAverages(cpu, runtime.NumCPU())
	diskUsed, diskTotal := diskUsage(c.diskAllowlist)
	networkReader := c.networkReader
	if networkReader == nil {
		networkReader = readNetworkTotals
	}
	netTotals, netErr := networkReader(c.networkAllowlist)
	netCounterSource := networkCounterSourceID(netTotals.SourceNames)
	connectionReader := c.connectionReader
	if connectionReader == nil {
		connectionReader = connectionCounts
	}
	tcpConnections, udpConnections, connectionErr := connectionReader()
	var inSpeed, outSpeed float64
	if netErr == nil {
		if c.hasNet && (netCounterSource == "" || c.previousNetSource == "" || netCounterSource == c.previousNetSource) {
			elapsed := now.Sub(c.previousNetAt).Seconds()
			if elapsed > 0 {
				inSpeed = float64(nonNegativeInt64(netTotals.InBytes-c.previousNet.InBytes)) / elapsed
				outSpeed = float64(nonNegativeInt64(netTotals.OutBytes-c.previousNet.OutBytes)) / elapsed
			}
		}
		c.previousNet = netTotals
		c.previousNetSource = netCounterSource
		c.previousNetAt = now
		c.hasNet = true
	} else if c.hasNet {
		// A transient platform read failure is not a zero counter sample. Keep the
		// last valid values and, critically, do not move previousNetAt: the next
		// valid rate is calculated over the complete elapsed interval.
		netTotals = c.previousNet
		netCounterSource = c.previousNetSource
	}
	if connectionErr == nil {
		c.previousTCP = tcpConnections
		c.previousUDP = udpConnections
		c.hasConnections = true
	} else if c.hasConnections {
		tcpConnections = c.previousTCP
		udpConnections = c.previousUDP
	}
	netTotalsValid := netErr == nil
	connectionCountsValid := connectionErr == nil

	sample := StateSample{
		TS:                    now.UTC().Unix(),
		CPUPercent:            cpu,
		Load1:                 load1,
		Load5:                 load5,
		Load15:                load15,
		MemoryUsedBytes:       nonNegativeInt64(memTotal - memAvailable),
		MemoryTotalBytes:      memTotal,
		SwapUsedBytes:         nonNegativeInt64(swapTotal - swapFree),
		SwapTotalBytes:        swapTotal,
		DiskUsedBytes:         diskUsed,
		DiskTotalBytes:        diskTotal,
		NetInTotalBytes:       netTotals.InBytes,
		NetOutTotalBytes:      netTotals.OutBytes,
		NetInSpeedBps:         inSpeed,
		NetOutSpeedBps:        outSpeed,
		NetTotalsValid:        &netTotalsValid,
		NetCounterSource:      netCounterSource,
		ProcessCount:          processCount(),
		TCPConnectionCount:    tcpConnections,
		UDPConnectionCount:    udpConnections,
		ConnectionCountsValid: &connectionCountsValid,
		UptimeSeconds:         uptimeSeconds(),
	}
	return withNewStateSampleIdentifiers(sample, now)
}

func (c *MetricsCollector) cpuPercent() float64 {
	current, ok := readCPUTimes()
	if !ok {
		return 0
	}
	defer func() {
		c.previousCPU = current
		c.hasCPU = true
	}()
	if !c.hasCPU {
		return 0
	}
	totalDelta := current.Total - c.previousCPU.Total
	idleDelta := current.Idle - c.previousCPU.Idle
	if totalDelta <= 0 {
		return 0
	}
	value := (1 - float64(idleDelta)/float64(totalDelta)) * 100
	if value < 0 {
		return 0
	}
	if value > 100 {
		return 100
	}
	return value
}

type cpuTimes struct {
	Total uint64
	Idle  uint64
}

func readCPUTimes() (cpuTimes, bool) {
	if runtime.GOOS == "windows" {
		return windowsReadCPUTimes()
	}
	if runtime.GOOS == "darwin" {
		return darwinReadCPUTimes()
	}
	content, err := os.ReadFile("/proc/stat")
	if err != nil {
		return cpuTimes{}, false
	}
	scanner := bufio.NewScanner(strings.NewReader(string(content)))
	if !scanner.Scan() {
		return cpuTimes{}, false
	}
	fields := strings.Fields(scanner.Text())
	if len(fields) < 5 || fields[0] != "cpu" {
		return cpuTimes{}, false
	}
	var total uint64
	var idle uint64
	for index, field := range fields[1:] {
		value, err := strconv.ParseUint(field, 10, 64)
		if err != nil {
			return cpuTimes{}, false
		}
		total += value
		if index == 3 || index == 4 {
			idle += value
		}
	}
	return cpuTimes{Total: total, Idle: idle}, true
}

func readMemoryTotals() (total int64, available int64) {
	return platformMemoryTotals()
}

type memoryStats struct {
	memTotal     int64
	memAvailable int64
	swapTotal    int64
	swapFree     int64
}

func readSwapTotals() (total int64, free int64) {
	return platformSwapTotals()
}

func parseMemoryStats(content string) memoryStats {
	stats := memoryStats{}
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		valueKB, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			continue
		}
		switch strings.TrimSuffix(fields[0], ":") {
		case "MemTotal":
			stats.memTotal = valueKB * 1024
		case "MemAvailable":
			stats.memAvailable = valueKB * 1024
		case "SwapTotal":
			stats.swapTotal = valueKB * 1024
		case "SwapFree":
			stats.swapFree = valueKB * 1024
		}
	}
	return stats
}

func readLoadAverages(cpuPercent float64, cpuCores int) (load1, load5, load15 float64) {
	if runtime.GOOS == "windows" {
		return windowsLoadAverages(cpuPercent, cpuCores)
	}
	if runtime.GOOS == "darwin" {
		return darwinLoadAverages()
	}
	content, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0, 0, 0
	}
	fields := strings.Fields(string(content))
	if len(fields) < 3 {
		return 0, 0, 0
	}
	load1, _ = strconv.ParseFloat(fields[0], 64)
	load5, _ = strconv.ParseFloat(fields[1], 64)
	load15, _ = strconv.ParseFloat(fields[2], 64)
	return load1, load5, load15
}

func processCount() int64 {
	if runtime.GOOS == "windows" {
		return windowsProcessCount()
	}
	if runtime.GOOS == "darwin" {
		return darwinProcessCount()
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0
	}
	var count int64
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		if name == "" {
			continue
		}
		allDigits := true
		for _, r := range name {
			if r < '0' || r > '9' {
				allDigits = false
				break
			}
		}
		if allDigits {
			count++
		}
	}
	return count
}

func connectionCounts() (tcp int64, udp int64, err error) {
	if runtime.GOOS == "darwin" {
		return darwinConnectionCounts()
	}
	if runtime.GOOS == "windows" {
		return windowsConnectionCounts()
	}
	tcp4, err := tcpConnectionCountFromFileResult("/proc/net/tcp")
	if err != nil {
		return 0, 0, err
	}
	tcp6, err := optionalConnectionCountFromFile("/proc/net/tcp6")
	if err != nil {
		return 0, 0, err
	}
	udp4, err := tcpConnectionCountFromFileResult("/proc/net/udp")
	if err != nil {
		return 0, 0, err
	}
	udp6, err := optionalConnectionCountFromFile("/proc/net/udp6")
	if err != nil {
		return 0, 0, err
	}
	return tcp4 + tcp6, udp4 + udp6, nil
}

func tcpConnectionCountFromFile(path string) int64 {
	count, _ := tcpConnectionCountFromFileResult(path)
	return count
}

func tcpConnectionCountFromFileResult(path string) (int64, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	trimmed := strings.TrimSpace(string(content))
	if trimmed == "" {
		return 0, fmt.Errorf("connection table %q is empty", path)
	}
	lines := strings.Split(trimmed, "\n")
	header := strings.Fields(lines[0])
	remoteHeaderOK := len(header) >= 3 && (header[2] == "rem_address" || header[2] == "remote_address")
	if len(header) < 3 || header[0] != "sl" || header[1] != "local_address" || !remoteHeaderOK {
		return 0, fmt.Errorf("connection table %q has an invalid header", path)
	}
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) < 10 || !strings.HasSuffix(fields[0], ":") {
			return 0, fmt.Errorf("connection table %q has a malformed row", path)
		}
	}
	return int64(len(lines) - 1), nil
}

func optionalConnectionCountFromFile(path string) (int64, error) {
	count, err := tcpConnectionCountFromFileResult(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	return count, err
}

type networkTotals struct {
	InBytes     int64
	OutBytes    int64
	SourceNames []string
}

func networkCounterSourceID(names []string) string {
	if len(names) == 0 {
		return ""
	}
	stable := append([]string(nil), names...)
	sort.Strings(stable)
	sum := sha256.Sum256([]byte(runtime.GOOS + "\x00" + strings.Join(stable, "\x00")))
	return hex.EncodeToString(sum[:])
}

var defaultExcludedInterfacePrefixes = []string{
	"lo",
	"docker",
	"veth",
	"br-",
	"tun",
	"utun",
	"tailscale",
	"kube",
	"vmbr",
	"tap",
	"cni",
	"flannel",
	"cali",
	"weave",
	"virbr",
	"vnet",
	"vethernet",
	"virtualbox",
	"vmware",
	"hyper-v",
	"loopback",
	"isatap",
	"teredo",
	"npcap",
	"bluetooth",
	"zt",
}

func readNetworkTotals(allowlist map[string]struct{}) (networkTotals, error) {
	if runtime.GOOS == "windows" {
		return windowsNetworkTotals(allowlist)
	}
	if runtime.GOOS == "darwin" {
		return darwinNetworkTotals(allowlist)
	}
	content, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return networkTotals{}, err
	}
	return parseLinuxNetworkTotals(string(content), allowlist)
}

func parseLinuxNetworkTotals(content string, allowlist map[string]struct{}) (networkTotals, error) {
	scanner := bufio.NewScanner(strings.NewReader(content))
	var totals networkTotals
	foundHeader := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "Inter-|") {
			foundHeader = true
			continue
		}
		if !strings.Contains(line, ":") {
			continue
		}
		iface, rest, _ := strings.Cut(line, ":")
		iface = strings.TrimSpace(iface)
		if !includeNetworkInterface(iface, allowlist) {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) < 16 {
			return networkTotals{}, fmt.Errorf("network interface %q has %d counter fields, want at least 16", iface, len(fields))
		}
		inBytes, err := parseNetworkCounter(fields[0])
		if err != nil {
			return networkTotals{}, fmt.Errorf("network interface %q receive counter: %w", iface, err)
		}
		outBytes, err := parseNetworkCounter(fields[8])
		if err != nil {
			return networkTotals{}, fmt.Errorf("network interface %q transmit counter: %w", iface, err)
		}
		if inBytes > maxInt64-totals.InBytes || outBytes > maxInt64-totals.OutBytes {
			return networkTotals{}, fmt.Errorf("network counter total overflows int64")
		}
		totals.InBytes += inBytes
		totals.OutBytes += outBytes
		totals.SourceNames = append(totals.SourceNames, iface)
	}
	if err := scanner.Err(); err != nil {
		return networkTotals{}, err
	}
	if !foundHeader {
		return networkTotals{}, fmt.Errorf("linux network table is missing its header")
	}
	return totals, nil
}

func parseNetworkCounter(value string) (int64, error) {
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, err
	}
	if parsed > uint64(maxInt64) {
		return 0, fmt.Errorf("counter exceeds int64")
	}
	return int64(parsed), nil
}

func normalizeAllowlist(values []string) []string {
	seen := map[string]struct{}{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		result = append(result, trimmed)
	}
	return result
}

func allowlistSet(values []string) map[string]struct{} {
	list := normalizeAllowlist(values)
	if len(list) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(list))
	for _, value := range list {
		set[value] = struct{}{}
	}
	return set
}

func includeNetworkInterface(name string, allowlist map[string]struct{}) bool {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return false
	}
	if len(allowlist) > 0 {
		_, ok := allowlist[trimmed]
		return ok
	}
	lower := strings.ToLower(trimmed)
	for _, prefix := range defaultExcludedInterfacePrefixes {
		if lower == prefix || strings.HasPrefix(lower, prefix) {
			return false
		}
	}
	return true
}

func osRelease() (string, string) {
	if runtime.GOOS == "windows" {
		return windowsOSRelease()
	}
	if runtime.GOOS == "darwin" {
		return darwinOSRelease()
	}
	content, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return "linux", ""
	}
	values := parseKeyValueLines(string(content))
	id := values["ID"]
	if id == "" {
		id = "linux"
	}
	return id, values["VERSION_ID"]
}

func kernelRelease() string {
	if runtime.GOOS == "windows" {
		return windowsKernelRelease()
	}
	if runtime.GOOS == "darwin" {
		return darwinKernelRelease()
	}
	content, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(content))
}

func virtualizationName() string {
	if runtime.GOOS == "windows" {
		return windowsVirtualizationName()
	}
	if runtime.GOOS == "darwin" {
		return darwinVirtualizationName()
	}
	for _, path := range []string{"/sys/class/dmi/id/product_name", "/sys/class/dmi/id/sys_vendor"} {
		content, err := os.ReadFile(path)
		if err == nil {
			value := strings.TrimSpace(string(content))
			if value != "" {
				return value
			}
		}
	}
	return ""
}

func cpuModel() string {
	if runtime.GOOS == "windows" {
		return windowsCPUModel()
	}
	if runtime.GOOS == "darwin" {
		return darwinCPUModel()
	}
	content, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return ""
	}
	scanner := bufio.NewScanner(strings.NewReader(string(content)))
	for scanner.Scan() {
		line := scanner.Text()
		key, value, ok := strings.Cut(line, ":")
		if ok && strings.TrimSpace(key) == "model name" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func bootTime() int64 {
	if runtime.GOOS == "windows" {
		return windowsBootTime()
	}
	if runtime.GOOS == "darwin" {
		return darwinBootTime()
	}
	content, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0
	}
	scanner := bufio.NewScanner(strings.NewReader(string(content)))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 2 && fields[0] == "btime" {
			value, _ := strconv.ParseInt(fields[1], 10, 64)
			return value
		}
	}
	return 0
}

func uptimeSeconds() int64 {
	if runtime.GOOS == "windows" {
		return windowsUptimeSeconds()
	}
	if runtime.GOOS == "darwin" {
		return darwinUptimeSeconds()
	}
	content, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(content))
	if len(fields) == 0 {
		return 0
	}
	value, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0
	}
	return int64(value)
}

func normalizedArch(arch string) string {
	switch arch {
	case "amd64":
		return "x86_64"
	case "arm64":
		return "aarch64"
	default:
		return arch
	}
}

func nonNegativeInt64(value int64) int64 {
	if value < 0 {
		return 0
	}
	return value
}
