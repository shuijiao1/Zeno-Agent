package agent

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var probeRoundSequence atomic.Uint64

const (
	drawableLatencyCap = 5 * time.Second
	pingCommandGrace   = 250 * time.Millisecond

	maxProbeTargets           = 32
	maxProbeCount             = 32
	defaultProbeTimeoutMS     = 1000
	minProbeTimeoutMS         = 100
	maxProbeTimeoutMS         = 5000
	defaultProbeIntervalSec   = 60
	minProbeIntervalSec       = 5
	maxProbeIntervalSec       = 60 * 60
	maxConcurrentProbeTargets = 16
	maxProbeSamplesPerRun     = 1024
	maxProbeTargetBudgetMS    = 60_000
	maxProbeNodeBudgetMS      = 120_000
	probeUploadTimeout        = 30 * time.Second
	maxHTTPProbeRedirects     = 10
)

var (
	errInvalidProbeTarget  = errors.New("invalid probe target")
	errUnsafeProbeTarget   = errors.New("unsafe probe target")
	errUnsafeProbeRedirect = errors.New("unsafe probe redirect")
	errProbeDNS            = errors.New("probe dns error")
)

// SanitizeProbeTargets enforces the Agent-side copy of the Controller probe
// budget before targets can drive goroutines, process execution, or outbound
// requests. The Controller should already validate these bounds; the Agent keeps
// this guard so a stale/malicious controller response cannot exhaust resources.
func SanitizeProbeTargets(targets []ProbeTarget) []ProbeTarget {
	if len(targets) == 0 {
		return nil
	}
	if len(targets) > maxProbeTargets {
		targets = targets[:maxProbeTargets]
	}
	sanitized := make([]ProbeTarget, 0, len(targets))
	for _, target := range targets {
		target.Count = normalizedProbeCount(target.Count)
		target.TimeoutMS = normalizedProbeTimeoutMS(target.TimeoutMS)
		target.IntervalSec = normalizedProbeIntervalSec(target.IntervalSec)
		if maxCount := maxProbeTargetBudgetMS / probeSampleBudgetMS(target); target.Count > maxCount {
			target.Count = maxCount
		}
		sanitized = append(sanitized, target)
	}
	return sanitized
}

// LimitProbeTargetsForRun applies the per-run sample and worst-case execution
// budgets. It is kept separate from SanitizeProbeTargets so a large valid config
// can be spread across intervals instead of creating an oversized result body or
// an excessively long probe round.
func LimitProbeTargetsForRun(targets []ProbeTarget) []ProbeTarget {
	sanitized := SanitizeProbeTargets(targets)
	if len(sanitized) == 0 {
		return nil
	}
	limited := make([]ProbeTarget, 0, len(sanitized))
	remainingSamples := maxProbeSamplesPerRun
	remainingBudgetMS := maxProbeNodeBudgetMS
	for _, target := range sanitized {
		sampleBudgetMS := probeSampleBudgetMS(target)
		if remainingSamples <= 0 || remainingBudgetMS < sampleBudgetMS {
			break
		}
		if target.Count > remainingSamples {
			target.Count = remainingSamples
		}
		if maxCount := remainingBudgetMS / sampleBudgetMS; target.Count > maxCount {
			target.Count = maxCount
		}
		if target.Count <= 0 {
			continue
		}
		limited = append(limited, target)
		remainingSamples -= target.Count
		remainingBudgetMS -= target.Count * sampleBudgetMS
	}
	return limited
}

func ProbeRunTimeout(targets []ProbeTarget) time.Duration {
	targets = LimitProbeTargetsForRun(targets)
	if len(targets) == 0 {
		return 0
	}
	var totalMS int
	for _, target := range targets {
		totalMS += normalizedProbeCount(target.Count) * probeSampleBudgetMS(target)
	}
	if totalMS <= 0 {
		return drawableLatencyCap
	}
	return time.Duration(totalMS)*time.Millisecond + time.Second
}

func ProbeUploadTimeout() time.Duration {
	return probeUploadTimeout
}

func RunTCPProbe(ctx context.Context, target ProbeTarget) []ProbeSample {
	count := normalizedProbeCount(target.Count)
	timeout := normalizedProbeTimeout(target.TimeoutMS)
	observationTimeout := latencyObservationTimeout(timeout)
	if target.Port == nil {
		return failedProbeSamples(count, "missing_port")
	}
	if !validProbePort(*target.Port) {
		return failedProbeSamples(count, "invalid_port")
	}
	addresses, err := resolveSafeProbeHost(ctx, target.Address, true)
	if err != nil {
		return failedProbeSamples(count, classifyProbeSetupError(err))
	}

	samples := make([]ProbeSample, 0, count)
	for seq := 1; seq <= count; seq++ {
		select {
		case <-ctx.Done():
			label := classifyContextError(ctx.Err())
			if label == "" {
				label = "cancelled"
			}
			for failedSeq := seq; failedSeq <= count; failedSeq++ {
				samples = append(samples, ProbeSample{Seq: failedSeq, Success: false, Error: label})
			}
			return samples
		default:
		}
		dialCtx, cancel := context.WithTimeout(ctx, observationTimeout)
		start := time.Now()
		conn, err := dialResolvedProbeAddress(dialCtx, "tcp", addresses, *target.Port, observationTimeout)
		elapsedMS := float64(time.Since(start).Microseconds()) / 1000
		cancel()
		if err != nil {
			samples = append(samples, failedMeasuredProbeSample(seq, classifyProbeError(err)))
			continue
		}
		_ = conn.Close()
		samples = append(samples, measuredProbeSample(seq, elapsedMS, timeout))
	}
	return samples
}

var pingLatencyPattern = regexp.MustCompile(`time[=<]([0-9.]+)\s*ms`)

func RunPingProbe(ctx context.Context, target ProbeTarget) []ProbeSample {
	count := normalizedProbeCount(target.Count)
	timeout := normalizedProbeTimeout(target.TimeoutMS)
	observationTimeout := latencyObservationTimeout(timeout)
	address := strings.TrimSpace(target.Address)
	if address == "" || strings.HasPrefix(address, "-") {
		return failedProbeSamples(count, "invalid_address")
	}
	addresses, err := resolveSafeProbeHost(ctx, address, true)
	if err != nil {
		return failedProbeSamples(count, classifyProbeSetupError(err))
	}

	samples := make([]ProbeSample, 0, count)
	for seq := 1; seq <= count; seq++ {
		select {
		case <-ctx.Done():
			label := classifyContextError(ctx.Err())
			if label == "" {
				label = "cancelled"
			}
			for failedSeq := seq; failedSeq <= count; failedSeq++ {
				samples = append(samples, ProbeSample{Seq: failedSeq, Success: false, Error: label})
			}
			return samples
		default:
		}

		attemptCtx, cancel := context.WithTimeout(ctx, probeAttemptBudget(target))
		start := time.Now()
		// Keep resolved addresses as netip.Addr values until command selection so
		// an IPv6 result cannot accidentally be sent to the IPv4 ping utility.
		// Rotate a dual-stack answer between samples and fall through to the other
		// family when the first utility fails quickly (for example, ping6 missing).
		orderedAddresses := rotatedProbeAddresses(addresses, seq-1)
		var output []byte
		var err error
		for _, pingAddress := range orderedAddresses {
			command, args := pingCommandForAddr(runtime.GOOS, pingAddress, observationTimeout)
			cmd := exec.CommandContext(attemptCtx, command, args...)
			output, err = cmd.CombinedOutput()
			if err == nil || attemptCtx.Err() != nil {
				break
			}
		}
		elapsedMS := float64(time.Since(start).Microseconds()) / 1000
		ctxErr := attemptCtx.Err()
		cancel()
		if err != nil {
			samples = append(samples, failedMeasuredProbeSample(seq, classifyPingError(err, string(output), ctxErr)))
			continue
		}
		latency := elapsedMS
		if parsed, ok := parsePingLatencyMS(string(output)); ok {
			latency = parsed
		}
		samples = append(samples, measuredProbeSample(seq, latency, timeout))
	}
	return samples
}

func RunHTTPProbe(ctx context.Context, target ProbeTarget) []ProbeSample {
	count := normalizedProbeCount(target.Count)
	timeout := normalizedProbeTimeout(target.TimeoutMS)
	observationTimeout := latencyObservationTimeout(timeout)
	address := strings.TrimSpace(target.Address)
	parsedURL, err := parseHTTPProbeURL(address)
	if err != nil {
		return failedProbeSamples(count, "invalid_url")
	}
	client := newHTTPProbeClient(observationTimeout)
	defer client.CloseIdleConnections()

	samples := make([]ProbeSample, 0, count)
	for seq := 1; seq <= count; seq++ {
		select {
		case <-ctx.Done():
			label := classifyContextError(ctx.Err())
			if label == "" {
				label = "cancelled"
			}
			for failedSeq := seq; failedSeq <= count; failedSeq++ {
				samples = append(samples, ProbeSample{Seq: failedSeq, Success: false, Error: label})
			}
			return samples
		default:
		}

		attemptCtx, cancel := context.WithTimeout(ctx, observationTimeout)
		request, err := http.NewRequestWithContext(attemptCtx, http.MethodGet, parsedURL.String(), nil)
		if err != nil {
			cancel()
			samples = append(samples, ProbeSample{Seq: seq, Success: false, Error: "invalid_url"})
			continue
		}
		request.Header.Set("User-Agent", "Zeno-Agent")
		start := time.Now()
		response, err := client.Do(request)
		elapsedMS := float64(time.Since(start).Microseconds()) / 1000
		ctxErr := attemptCtx.Err()
		cancel()
		if err != nil {
			samples = append(samples, failedMeasuredProbeSample(seq, classifyHTTPProbeError(err, ctxErr)))
			continue
		}
		if response.Request == nil {
			_ = response.Body.Close()
			samples = append(samples, ProbeSample{Seq: seq, Success: false, Error: "unsafe_redirect"})
			continue
		}
		if _, err := parseHTTPProbeURL(response.Request.URL.String()); err != nil {
			_ = response.Body.Close()
			samples = append(samples, ProbeSample{Seq: seq, Success: false, Error: "unsafe_redirect"})
			continue
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1024))
		_ = response.Body.Close()
		if response.StatusCode < 200 || response.StatusCode >= 400 {
			samples = append(samples, ProbeSample{Seq: seq, Success: false, Error: fmt.Sprintf("http_status_%d", response.StatusCode)})
			continue
		}
		samples = append(samples, measuredProbeSample(seq, elapsedMS, timeout))
	}
	return samples
}

func normalizedProbeTimeout(timeoutMS int) time.Duration {
	return time.Duration(normalizedProbeTimeoutMS(timeoutMS)) * time.Millisecond
}

func normalizedProbeCount(count int) int {
	if count <= 0 {
		return 1
	}
	if count > maxProbeCount {
		return maxProbeCount
	}
	return count
}

func normalizedProbeTimeoutMS(timeoutMS int) int {
	if timeoutMS <= 0 {
		return defaultProbeTimeoutMS
	}
	if timeoutMS < minProbeTimeoutMS {
		return minProbeTimeoutMS
	}
	if timeoutMS > maxProbeTimeoutMS {
		return maxProbeTimeoutMS
	}
	return timeoutMS
}

func normalizedProbeIntervalSec(intervalSec int) int {
	if intervalSec <= 0 {
		return defaultProbeIntervalSec
	}
	if intervalSec < minProbeIntervalSec {
		return minProbeIntervalSec
	}
	if intervalSec > maxProbeIntervalSec {
		return maxProbeIntervalSec
	}
	return intervalSec
}

func latencyObservationTimeout(timeout time.Duration) time.Duration {
	// timeout_ms is an execution deadline, not merely a success threshold.
	// Normalization already clamps it to the supported 100ms..5s range.
	if timeout <= 0 {
		return time.Duration(defaultProbeTimeoutMS) * time.Millisecond
	}
	if timeout > drawableLatencyCap {
		return drawableLatencyCap
	}
	return timeout
}

func probeSampleBudgetMS(target ProbeTarget) int {
	return int(probeAttemptBudget(target) / time.Millisecond)
}

func probeAttemptBudget(target ProbeTarget) time.Duration {
	budget := latencyObservationTimeout(normalizedProbeTimeout(target.TimeoutMS))
	switch strings.ToLower(strings.TrimSpace(target.Type)) {
	case "ping", "icmp":
		// The ping utility receives timeout_ms itself. A small, explicitly
		// budgeted grace lets CommandContext reap the child and collect output.
		return budget + pingCommandGrace
	default:
		return budget
	}
}

func measuredProbeSample(seq int, elapsedMS float64, timeout time.Duration) ProbeSample {
	latency := cappedDrawableLatencyMS(elapsedMS)
	if time.Duration(elapsedMS*float64(time.Millisecond)) > timeout {
		return ProbeSample{Seq: seq, Success: false, Error: "timeout"}
	}
	return ProbeSample{Seq: seq, Success: true, LatencyMS: &latency}
}

func failedMeasuredProbeSample(seq int, errText string) ProbeSample {
	return ProbeSample{Seq: seq, Success: false, Error: errText}
}

func cappedDrawableLatencyMS(elapsedMS float64) float64 {
	if elapsedMS < 0 {
		return 0
	}
	capMS := float64(drawableLatencyCap / time.Millisecond)
	if elapsedMS > capMS {
		return capMS
	}
	return elapsedMS
}

func parseHTTPProbeURL(address string) (*url.URL, error) {
	parsed, err := url.ParseRequestURI(address)
	if err != nil || parsed == nil || parsed.Host == "" || parsed.Hostname() == "" || parsed.User != nil {
		return nil, errInvalidProbeTarget
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, errInvalidProbeTarget
	}
	if parsed.Port() != "" {
		port, err := strconv.Atoi(parsed.Port())
		if err != nil || !validProbePort(port) {
			return nil, errInvalidProbeTarget
		}
	}
	if parsed.Scheme == "http" && !allowedPlainHTTPProbeURL(parsed) {
		return nil, errInvalidProbeTarget
	}
	return parsed, nil
}

func allowedPlainHTTPProbeURL(parsed *url.URL) bool {
	if parsed == nil {
		return false
	}
	host := normalizeProbeHost(parsed.Hostname())
	if strings.EqualFold(host, "localhost") {
		return true
	}
	address, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	address = address.Unmap()
	return address.IsLoopback() || parsed.Port() != ""
}

func newHTTPProbeClient(timeout time.Duration) *http.Client {
	return newHTTPProbeClientWithResolver(timeout, newSafeProbeResolver())
}

func newHTTPProbeClientWithResolver(timeout time.Duration, resolver *safeProbeResolver) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DisableKeepAlives = true
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		return dialSafeProbeNetworkAddressWithResolver(ctx, network, address, timeout, resolver)
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxHTTPProbeRedirects {
				return errUnsafeProbeRedirect
			}
			if req.Method != http.MethodGet {
				return errUnsafeProbeRedirect
			}
			if _, err := parseHTTPProbeURL(req.URL.String()); err != nil {
				return fmt.Errorf("%w: %v", errUnsafeProbeRedirect, err)
			}
			previous := via[len(via)-1].URL
			if previous.Scheme == "https" && req.URL.Scheme != "https" {
				return errUnsafeProbeRedirect
			}
			if !sameHTTPProbeOrigin(previous, req.URL) {
				req.Header = make(http.Header)
				req.Header.Set("User-Agent", "Zeno-Agent")
			}
			if _, err := resolver.resolve(req.Context(), req.URL.Hostname(), true); err != nil {
				if classifyContextError(err) != "" {
					return err
				}
				return fmt.Errorf("%w: %v", errUnsafeProbeRedirect, err)
			}
			return nil
		},
	}
}

func sameHTTPProbeOrigin(left, right *url.URL) bool {
	if left == nil || right == nil {
		return false
	}
	return strings.EqualFold(left.Scheme, right.Scheme) &&
		strings.EqualFold(left.Hostname(), right.Hostname()) &&
		effectiveHTTPProbePort(left) == effectiveHTTPProbePort(right)
}

func effectiveHTTPProbePort(value *url.URL) string {
	if value == nil {
		return ""
	}
	if port := value.Port(); port != "" {
		return port
	}
	if strings.EqualFold(value.Scheme, "http") {
		return "80"
	}
	if strings.EqualFold(value.Scheme, "https") {
		return "443"
	}
	return ""
}

func dialSafeProbeNetworkAddressWithResolver(ctx context.Context, network, address string, timeout time.Duration, resolver *safeProbeResolver) (net.Conn, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errInvalidProbeTarget, err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || !validProbePort(port) {
		return nil, errInvalidProbeTarget
	}
	addresses, err := resolver.resolve(ctx, host, true)
	if err != nil {
		return nil, err
	}
	return dialResolvedProbeAddress(ctx, network, addresses, port, timeout)
}

func dialResolvedProbeAddress(ctx context.Context, network string, addresses []netip.Addr, port int, timeout time.Duration) (net.Conn, error) {
	if !validProbePort(port) || len(addresses) == 0 {
		return nil, errInvalidProbeTarget
	}
	dialer := net.Dialer{Timeout: timeout}
	var lastErr error
	for _, address := range addresses {
		if network == "tcp4" && !address.Is4() {
			continue
		}
		if network == "tcp6" && !address.Is6() {
			continue
		}
		conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(address.String(), strconv.Itoa(port)))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, errInvalidProbeTarget
}

type probeIPLookupFunc func(context.Context, string, string) ([]netip.Addr, error)

type safeProbeResolver struct {
	lookup probeIPLookupFunc
	mu     sync.Mutex
	cache  map[string][]netip.Addr
}

func newSafeProbeResolver() *safeProbeResolver {
	return newSafeProbeResolverWithLookup(net.DefaultResolver.LookupNetIP)
}

func newSafeProbeResolverWithLookup(lookup probeIPLookupFunc) *safeProbeResolver {
	return &safeProbeResolver{lookup: lookup, cache: map[string][]netip.Addr{}}
}

func (resolver *safeProbeResolver) resolve(ctx context.Context, host string, allowExplicitLoopback bool) ([]netip.Addr, error) {
	normalizedHost := normalizeProbeHost(host)
	if normalizedHost == "" || strings.HasPrefix(normalizedHost, "-") {
		return nil, errInvalidProbeTarget
	}
	if _, err := netip.ParseAddr(normalizedHost); err == nil {
		return resolveSafeProbeHostWithLookup(ctx, normalizedHost, allowExplicitLoopback, resolver.lookup)
	}
	cacheKey := strings.ToLower(normalizedHost)
	resolver.mu.Lock()
	if cached, ok := resolver.cache[cacheKey]; ok {
		resolver.mu.Unlock()
		return cloneProbeAddresses(cached), nil
	}
	resolver.mu.Unlock()

	addresses, err := resolveSafeProbeHostWithLookup(ctx, normalizedHost, allowExplicitLoopback, resolver.lookup)
	if err != nil {
		return nil, err
	}
	addresses = cloneProbeAddresses(addresses)
	resolver.mu.Lock()
	if cached, ok := resolver.cache[cacheKey]; ok {
		resolver.mu.Unlock()
		return cloneProbeAddresses(cached), nil
	}
	resolver.cache[cacheKey] = cloneProbeAddresses(addresses)
	resolver.mu.Unlock()
	return addresses, nil
}

func cloneProbeAddresses(addresses []netip.Addr) []netip.Addr {
	cloned := make([]netip.Addr, len(addresses))
	copy(cloned, addresses)
	return cloned
}

func normalizeProbeHost(host string) string {
	return strings.TrimSpace(strings.Trim(host, "[]"))
}

func resolveSafeProbeHost(ctx context.Context, host string, allowExplicitLoopback bool) ([]netip.Addr, error) {
	return resolveSafeProbeHostWithLookup(ctx, host, allowExplicitLoopback, net.DefaultResolver.LookupNetIP)
}

func resolveSafeProbeHostWithLookup(ctx context.Context, host string, allowExplicitLoopback bool, lookup probeIPLookupFunc) ([]netip.Addr, error) {
	host = normalizeProbeHost(host)
	if host == "" || strings.HasPrefix(host, "-") {
		return nil, errInvalidProbeTarget
	}
	if address, err := netip.ParseAddr(host); err == nil {
		address = address.Unmap()
		if err := validateSafeProbeAddress(address, allowExplicitLoopback); err != nil {
			return nil, err
		}
		return []netip.Addr{address}, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	addresses, err := lookup(ctx, "ip", host)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		if classifyContextError(err) != "" {
			return nil, err
		}
		return nil, fmt.Errorf("%w: %v", errProbeDNS, err)
	}
	if len(addresses) == 0 {
		return nil, errProbeDNS
	}
	allowLocalhostLoopback := allowExplicitLoopback && strings.EqualFold(host, "localhost")
	seen := map[netip.Addr]struct{}{}
	result := make([]netip.Addr, 0, len(addresses))
	for _, address := range addresses {
		address = address.Unmap()
		if allowLocalhostLoopback && !address.IsLoopback() {
			return nil, errUnsafeProbeTarget
		}
		if err := validateSafeProbeAddress(address, allowLocalhostLoopback); err != nil {
			return nil, err
		}
		if _, ok := seen[address]; ok {
			continue
		}
		seen[address] = struct{}{}
		result = append(result, address)
	}
	return result, nil
}

func validateSafeProbeAddress(address netip.Addr, allowLoopback bool) error {
	if !address.IsValid() || address.IsUnspecified() || address.IsMulticast() || address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() {
		return errUnsafeProbeTarget
	}
	for _, prefix := range alwaysUnsafeProbeAddressPrefixes() {
		if prefix.Contains(address) {
			return errUnsafeProbeTarget
		}
	}
	if allowLoopback && address.IsLoopback() {
		return nil
	}
	if address.IsLoopback() {
		return errUnsafeProbeTarget
	}
	return nil
}

func alwaysUnsafeProbeAddressPrefixes() []netip.Prefix {
	return []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/8"),
		netip.MustParsePrefix("169.254.0.0/16"),
		netip.MustParsePrefix("100.100.100.200/32"),
		netip.MustParsePrefix("fd00:ec2::254/128"),
		netip.MustParsePrefix("::/128"),
		netip.MustParsePrefix("fe80::/10"),
	}
}

func validProbePort(port int) bool {
	return port > 0 && port <= 65535
}

func classifyProbeSetupError(err error) string {
	if label := classifyContextError(err); label != "" {
		return label
	}
	switch {
	case errors.Is(err, errUnsafeProbeTarget):
		return "unsafe_target"
	case errors.Is(err, errProbeDNS):
		return "dns_error"
	default:
		return "invalid_address"
	}
}

func pingTimeoutSeconds(timeout time.Duration) int {
	seconds := int((timeout + time.Second - 1) / time.Second)
	if seconds < 1 {
		return 1
	}
	return seconds
}

func pingTimeoutMilliseconds(timeout time.Duration) int {
	milliseconds := int((timeout + time.Millisecond - 1) / time.Millisecond)
	if milliseconds < 1 {
		return 1
	}
	return milliseconds
}

func pingCommand(goos, address string, timeout time.Duration) (string, []string) {
	if parsed, err := netip.ParseAddr(normalizeProbeHost(address)); err == nil {
		return pingCommandForAddr(goos, parsed.Unmap(), timeout)
	}
	return pingCommandForAddress(goos, address, false, timeout)
}

func pingCommandForAddr(goos string, address netip.Addr, timeout time.Duration) (string, []string) {
	addressText := address.String()
	return pingCommandForAddress(goos, addressText, address.Is6(), timeout)
}

func pingCommandForAddress(goos, address string, ipv6 bool, timeout time.Duration) (string, []string) {
	switch goos {
	case "windows":
		args := []string{"-n", "1", "-w", strconv.Itoa(pingTimeoutMilliseconds(timeout))}
		if ipv6 {
			args = append([]string{"-6"}, args...)
		}
		return "ping", append(args, address)
	case "darwin":
		if ipv6 {
			// Darwin ping6 has no per-reply timeout flag: -W selects a legacy
			// node-information query, and -X is not supported. The attempt
			// context above is the hard timeout for this command.
			return "ping6", []string{"-n", "-c", "1", address}
		}
		return "ping", []string{"-n", "-c", "1", "-W", strconv.Itoa(pingTimeoutMilliseconds(timeout)), address}
	default:
		command := "ping"
		if ipv6 {
			command = "ping6"
		}
		return command, []string{"-n", "-c", "1", "-W", strconv.Itoa(pingTimeoutSeconds(timeout)), address}
	}
}

func rotatedProbeAddresses(addresses []netip.Addr, offset int) []netip.Addr {
	if len(addresses) <= 1 {
		return addresses
	}
	start := offset % len(addresses)
	if start < 0 {
		start += len(addresses)
	}
	rotated := make([]netip.Addr, 0, len(addresses))
	rotated = append(rotated, addresses[start:]...)
	rotated = append(rotated, addresses[:start]...)
	return rotated
}

func parsePingLatencyMS(output string) (float64, bool) {
	matches := pingLatencyPattern.FindStringSubmatch(output)
	if len(matches) != 2 {
		return 0, false
	}
	value, err := strconv.ParseFloat(matches[1], 64)
	if err != nil || value < 0 {
		return 0, false
	}
	return value, true
}

func classifyPingError(err error, output string, ctxErr error) string {
	if label := classifyContextError(ctxErr); label != "" {
		return label
	}
	if label := classifyContextError(err); label != "" {
		return label
	}
	message := strings.ToLower(output + " " + err.Error())
	if strings.Contains(message, "executable file not found") || strings.Contains(message, "no such file") {
		return "ping_unavailable"
	}
	if strings.Contains(message, "name or service not known") || strings.Contains(message, "temporary failure") || strings.Contains(message, "unknown host") || strings.Contains(message, "no such host") {
		return "dns_error"
	}
	if strings.Contains(message, "operation not permitted") || strings.Contains(message, "permission denied") {
		return "permission_denied"
	}
	if strings.Contains(message, "100% packet loss") || strings.Contains(message, "0 received") || strings.Contains(message, "timeout") {
		return "timeout"
	}
	return "ping_error"
}

func classifyHTTPProbeError(err error, ctxErr error) string {
	if label := classifyContextError(ctxErr); label != "" {
		return label
	}
	if label := classifyContextError(err); label != "" {
		return label
	}
	if errors.Is(err, errUnsafeProbeRedirect) {
		return "unsafe_redirect"
	}
	if errors.Is(err, errUnsafeProbeTarget) {
		return "unsafe_target"
	}
	if errors.Is(err, errInvalidProbeTarget) {
		return "invalid_url"
	}
	if errors.Is(err, errProbeDNS) {
		return "dns_error"
	}
	message := strings.ToLower(err.Error())
	if strings.Contains(message, "no such host") {
		return "dns_error"
	}
	if strings.Contains(message, "certificate") || strings.Contains(message, "tls") {
		return "tls_error"
	}
	if strings.Contains(message, "timeout") || strings.Contains(message, "deadline") || strings.Contains(message, "i/o timeout") {
		return "timeout"
	}
	return "http_error"
}

func failedProbeSamples(count int, errText string) []ProbeSample {
	count = normalizedProbeCount(count)
	samples := make([]ProbeSample, 0, count)
	for seq := 1; seq <= count; seq++ {
		samples = append(samples, ProbeSample{Seq: seq, Success: false, Error: errText})
	}
	return samples
}

func classifyProbeError(err error) string {
	if err == nil {
		return ""
	}
	if label := classifyContextError(err); label != "" {
		return label
	}
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return "timeout"
	}
	message := strings.ToLower(err.Error())
	if strings.Contains(message, "timeout") || strings.Contains(message, "deadline") || strings.Contains(message, "i/o timeout") {
		return "timeout"
	}
	if strings.Contains(message, "no such host") {
		return "dns_error"
	}
	return "connect_error"
}

func classifyContextError(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, context.Canceled) {
		return "cancelled"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	return ""
}

func ProbeTargets(ctx context.Context, targets []ProbeTarget, ts time.Time) []ProbeRound {
	targets = LimitProbeTargetsForRun(targets)
	rounds := make([]ProbeRound, len(targets))
	var wg sync.WaitGroup
	concurrency := maxConcurrentProbeTargets
	if concurrency > len(targets) {
		concurrency = len(targets)
	}
	if concurrency < 1 {
		return rounds
	}
	semaphore := make(chan struct{}, concurrency)
	for index, target := range targets {
		index, target := index, target
		wg.Add(1)
		go func() {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			var samples []ProbeSample
			switch target.Type {
			case "tcping", "tcp":
				samples = RunTCPProbe(ctx, target)
			case "ping", "icmp":
				samples = RunPingProbe(ctx, target)
			case "http_get", "http", "https":
				samples = RunHTTPProbe(ctx, target)
			default:
				samples = failedProbeSamples(target.Count, fmt.Sprintf("unsupported_%s", target.Type))
			}
			rounds[index] = ProbeRound{RoundID: newProbeRoundID(ts, target.ID, index), TargetID: target.ID, TS: ts, Type: target.Type, Samples: samples}
		}()
	}
	wg.Wait()
	return rounds
}

func newProbeRoundID(ts time.Time, targetID string, index int) string {
	var randomBytes [16]byte
	if _, err := rand.Read(randomBytes[:]); err == nil {
		return hex.EncodeToString(randomBytes[:])
	}
	fallback := fmt.Sprintf("%d:%s:%d:%d", ts.UnixNano(), targetID, index, probeRoundSequence.Add(1))
	digest := sha256.Sum256([]byte(fallback))
	return hex.EncodeToString(digest[:16])
}

func parseKeyValueLines(content string) map[string]string {
	values := map[string]string{}
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		values[key] = strings.Trim(strings.TrimSpace(value), `"`)
	}
	return values
}
