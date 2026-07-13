package agent

import (
	"bufio"
	"strconv"
	"strings"
)

func parseDarwinCPUTimes(output string) (cpuTimes, bool) {
	fields := strings.Fields(output)
	if len(fields) < 4 {
		return cpuTimes{}, false
	}
	var total uint64
	var idle uint64
	for index, field := range fields {
		value, err := strconv.ParseUint(field, 10, 64)
		if err != nil {
			return cpuTimes{}, false
		}
		total += value
		if index == 3 {
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
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 {
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
	return tcp, udp
}

func parseDarwinNetworkTotals(output string, allowlist map[string]struct{}) networkTotals {
	scanner := bufio.NewScanner(strings.NewReader(output))
	indexes := map[string]int{}
	seen := map[string]struct{}{}
	var totals networkTotals
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
		inBytes, inErr := strconv.ParseInt(fields[len(fields)-5], 10, 64)
		outBytes, outErr := strconv.ParseInt(fields[len(fields)-2], 10, 64)
		if inErr == nil && inBytes > 0 {
			totals.InBytes += inBytes
		}
		if outErr == nil && outBytes > 0 {
			totals.OutBytes += outBytes
		}
	}
	return totals
}
