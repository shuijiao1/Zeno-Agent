package agent

import (
	"bufio"
	"fmt"
	"strconv"
	"strings"
)

func parseDarwinCPUTimes(output string) (cpuTimes, bool) {
	rawFields := strings.Fields(output)
	fields := make([]string, 0, len(rawFields))
	for _, field := range rawFields {
		field = strings.Trim(field, "{},")
		if field != "" {
			fields = append(fields, field)
		}
	}
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
	parser := darwinConnectionParser{}
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		parser.consume(scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return 0, 0, err
	}
	return parser.result()
}

type darwinConnectionParser struct {
	tcp         int64
	udp         int64
	foundHeader bool
}

func (p *darwinConnectionParser) consume(line string) error {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return nil
	}
	if fields[0] == "Proto" {
		p.foundHeader = true
		return nil
	}
	protocol := strings.ToLower(fields[0])
	switch {
	case strings.HasPrefix(protocol, "tcp"):
		p.tcp++
	case strings.HasPrefix(protocol, "udp"):
		p.udp++
	}
	return nil
}

func (p *darwinConnectionParser) result() (int64, int64, error) {
	if !p.foundHeader {
		return 0, 0, fmt.Errorf("darwin netstat connection output is missing its header")
	}
	return p.tcp, p.udp, nil
}

func parseDarwinNetworkTotals(output string, allowlist map[string]struct{}) networkTotals {
	totals, _ := parseDarwinNetworkTotalsResult(output, allowlist)
	return totals
}

func parseDarwinNetworkTotalsResult(output string, allowlist map[string]struct{}) (networkTotals, error) {
	parser := newDarwinNetworkParser(allowlist)
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		if err := parser.consume(scanner.Text()); err != nil {
			return networkTotals{}, err
		}
	}
	if err := scanner.Err(); err != nil {
		return networkTotals{}, err
	}
	return parser.result()
}

type darwinNetworkParser struct {
	allowlist   map[string]struct{}
	indexes     map[string]int
	seen        map[string]struct{}
	totals      networkTotals
	foundHeader bool
}

func newDarwinNetworkParser(allowlist map[string]struct{}) *darwinNetworkParser {
	return &darwinNetworkParser{allowlist: allowlist, indexes: map[string]int{}, seen: map[string]struct{}{}}
}

func (p *darwinNetworkParser) consume(line string) error {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return nil
	}
	if fields[0] == "Name" {
		p.indexes = make(map[string]int, len(fields))
		for index, field := range fields {
			p.indexes[field] = index
		}
		p.foundHeader = true
		return nil
	}
	nameIndex, nameOK := p.indexes["Name"]
	networkIndex, networkOK := p.indexes["Network"]
	_, inOK := p.indexes["Ibytes"]
	_, outOK := p.indexes["Obytes"]
	if !nameOK || !networkOK || !inOK || !outOK || nameIndex >= len(fields) || networkIndex >= len(fields) || len(fields) < 7 {
		return nil
	}
	name := fields[nameIndex]
	if !strings.HasPrefix(fields[networkIndex], "<Link#") || !includeNetworkInterface(name, p.allowlist) {
		return nil
	}
	if _, ok := p.seen[name]; ok {
		return nil
	}
	p.seen[name] = struct{}{}
	// Link-layer rows may omit the Address column. The seven counters at the
	// end are stable, so index Ibytes/Obytes from the right.
	inBytes, inErr := parseNetworkCounter(fields[len(fields)-5])
	outBytes, outErr := parseNetworkCounter(fields[len(fields)-2])
	if inErr != nil || outErr != nil {
		return fmt.Errorf("darwin network interface %q has invalid byte counters", name)
	}
	if inBytes > maxInt64-p.totals.InBytes || outBytes > maxInt64-p.totals.OutBytes {
		return fmt.Errorf("darwin network counter total overflows int64")
	}
	p.totals.InBytes += inBytes
	p.totals.OutBytes += outBytes
	p.totals.SourceNames = append(p.totals.SourceNames, name)
	return nil
}

func (p *darwinNetworkParser) result() (networkTotals, error) {
	if !p.foundHeader {
		return networkTotals{}, fmt.Errorf("darwin netstat output is missing its header")
	}
	return p.totals, nil
}
