package agent

import (
	"bufio"
	"fmt"
	"strconv"
	"strings"
)

func parseDarwinCPUTimes(output string) (cpuTimes, bool) {
	fields := strings.Fields(output)
	if len(fields) < 4 {
		return cpuTimes{}, false
	}
	// kern.cp_time is one CPU_STATES vector. Some current macOS hosts expose
	// only kern.cp_times, which is the same five-value vector repeated once per
	// logical CPU. Aggregate every vector and sum its idle (index 3) value.
	perCPU := len(fields) > 5 && len(fields)%5 == 0
	var total uint64
	var idle uint64
	for index, field := range fields {
		value, err := strconv.ParseUint(field, 10, 64)
		if err != nil {
			return cpuTimes{}, false
		}
		total += value
		if perCPU && index%5 == 3 {
			idle += value
		} else if !perCPU && index == 3 {
			idle = value
		}
	}
	return cpuTimes{Total: total, Idle: idle}, total > 0
}

func parseDarwinLoadAverages(output string) (load1, load5, load15 float64) {
	values := make([]float64, 0, 3)
	for _, field := range strings.Fields(output) {
		field = strings.Trim(field, "{}")
		value, err := strconv.ParseFloat(field, 64)
		if err == nil {
			values = append(values, value)
		}
		if len(values) == 3 {
			return values[0], values[1], values[2]
		}
	}
	return 0, 0, 0
}

func parseDarwinConnectionCounts(output string) (tcp int64, udp int64) {
	tcp, udp, _ = parseDarwinConnectionCountsResult(output)
	return tcp, udp
}

func parseDarwinConnectionCountsResult(output string) (tcp int64, udp int64, err error) {
	scanner := bufio.NewScanner(strings.NewReader(output))
	foundHeader := false
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 {
			continue
		}
		if fields[0] == "Proto" {
			foundHeader = true
			continue
		}
		protocol := strings.ToLower(fields[0])
		switch {
		case strings.HasPrefix(protocol, "tcp"):
			tcp++
		case strings.HasPrefix(protocol, "udp"):
			udp++
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, 0, err
	}
	if !foundHeader {
		return 0, 0, fmt.Errorf("darwin netstat connection output is missing its header")
	}
	return tcp, udp, nil
}

func parseDarwinNetworkTotals(output string, allowlist map[string]struct{}) networkTotals {
	totals, _ := parseDarwinNetworkTotalsResult(output, allowlist)
	return totals
}

func parseDarwinNetworkTotalsResult(output string, allowlist map[string]struct{}) (networkTotals, error) {
	scanner := bufio.NewScanner(strings.NewReader(output))
	indexes := map[string]int{}
	seen := map[string]struct{}{}
	var totals networkTotals
	foundHeader := false
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 {
			continue
		}
		if fields[0] == "Name" {
			indexes = make(map[string]int, len(fields))
			for index, field := range fields {
				indexes[field] = index
			}
			foundHeader = true
			continue
		}
		nameIndex, nameOK := indexes["Name"]
		networkIndex, networkOK := indexes["Network"]
		_, inOK := indexes["Ibytes"]
		_, outOK := indexes["Obytes"]
		if !nameOK || !networkOK || !inOK || !outOK || nameIndex >= len(fields) || networkIndex >= len(fields) || len(fields) < 7 {
			continue
		}
		name := fields[nameIndex]
		if !strings.HasPrefix(fields[networkIndex], "<Link#") || !includeNetworkInterface(name, allowlist) {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		// Link-layer rows may omit the Address column. The seven counters at
		// the end are stable, so index Ibytes/Obytes from the right.
		inBytes, inErr := parseNetworkCounter(fields[len(fields)-5])
		outBytes, outErr := parseNetworkCounter(fields[len(fields)-2])
		if inErr != nil || outErr != nil {
			return networkTotals{}, fmt.Errorf("darwin network interface %q has invalid byte counters", name)
		}
		if inBytes > maxInt64-totals.InBytes || outBytes > maxInt64-totals.OutBytes {
			return networkTotals{}, fmt.Errorf("darwin network counter total overflows int64")
		}
		totals.InBytes += inBytes
		totals.OutBytes += outBytes
	}
	if err := scanner.Err(); err != nil {
		return networkTotals{}, err
	}
	if !foundHeader {
		return networkTotals{}, fmt.Errorf("darwin netstat output is missing its header")
	}
	return totals, nil
}
