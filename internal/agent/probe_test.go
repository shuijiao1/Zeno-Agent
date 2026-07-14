package agent

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
)

func TestPingCommandUsesPlatformTimeoutUnits(t *testing.T) {
	tests := []struct {
		goos string
		want []string
	}{
		{goos: "linux", want: []string{"-n", "-c", "1", "-W", "5", "example.com"}},
		{goos: "darwin", want: []string{"-n", "-c", "1", "-W", "5000", "example.com"}},
		{goos: "windows", want: []string{"-n", "1", "-w", "5000", "example.com"}},
	}
	for _, test := range tests {
		t.Run(test.goos, func(t *testing.T) {
			command, args := pingCommand(test.goos, "example.com", 5*time.Second)
			if command != "ping" || !reflect.DeepEqual(args, test.want) {
				t.Fatalf("ping command = %q %q, want ping %q", command, args, test.want)
			}
		})
	}
}

func TestPingCommandUsesIPv6UtilityAndPlatformArguments(t *testing.T) {
	address := netip.MustParseAddr("2001:db8::10")
	tests := []struct {
		goos        string
		wantCommand string
		wantArgs    []string
	}{
		{goos: "linux", wantCommand: "ping6", wantArgs: []string{"-n", "-c", "1", "-W", "5", "2001:db8::10"}},
		{goos: "darwin", wantCommand: "ping6", wantArgs: []string{"-n", "-c", "1", "2001:db8::10"}},
		{goos: "windows", wantCommand: "ping", wantArgs: []string{"-6", "-n", "1", "-w", "5000", "2001:db8::10"}},
	}
	for _, test := range tests {
		t.Run(test.goos, func(t *testing.T) {
			command, args := pingCommandForAddr(test.goos, address, 5*time.Second)
			if command != test.wantCommand || !reflect.DeepEqual(args, test.wantArgs) {
				t.Fatalf("IPv6 ping command = %q %q, want %q %q", command, args, test.wantCommand, test.wantArgs)
			}
		})
	}
}

func TestRotatedProbeAddressesPreservesDualStackAddrValues(t *testing.T) {
	ipv4 := netip.MustParseAddr("192.0.2.10")
	ipv6 := netip.MustParseAddr("2001:db8::10")
	addresses := []netip.Addr{ipv4, ipv6}

	first := rotatedProbeAddresses(addresses, 0)
	second := rotatedProbeAddresses(addresses, 1)
	if !reflect.DeepEqual(first, []netip.Addr{ipv4, ipv6}) || !reflect.DeepEqual(second, []netip.Addr{ipv6, ipv4}) {
		t.Fatalf("rotated dual-stack addresses = %v / %v, want typed v4/v6 values preserved", first, second)
	}
}

func TestParsePingLatencyAcceptsWindowsLessThanOneMillisecond(t *testing.T) {
	latency, ok := parsePingLatencyMS("Reply from 127.0.0.1: bytes=32 time<1ms TTL=128")
	if !ok || latency != 1 {
		t.Fatalf("parsePingLatencyMS = %v, %v, want 1, true", latency, ok)
	}
}

func TestRunPingProbeMeasuresLoopbackLatency(t *testing.T) {
	samples := RunPingProbe(context.Background(), ProbeTarget{ID: "loopback", Type: "ping", Address: "127.0.0.1", Count: 1, TimeoutMS: 1000})

	if len(samples) != 1 {
		t.Fatalf("samples len = %d, want 1", len(samples))
	}
	if !samples[0].Success || samples[0].LatencyMS == nil || *samples[0].LatencyMS < 0 || samples[0].Error != "" {
		t.Fatalf("ping sample = %+v, want successful latency sample", samples[0])
	}
}

func TestProbeTargetsRunsPingTargetsInsteadOfMarkingUnsupported(t *testing.T) {
	rounds := ProbeTargets(context.Background(), []ProbeTarget{{ID: "loopback", Type: "ping", Address: "127.0.0.1", Count: 1, TimeoutMS: 1000}}, time.Unix(1782990000, 0))

	if len(rounds) != 1 {
		t.Fatalf("rounds len = %d, want 1", len(rounds))
	}
	if rounds[0].TargetID != "loopback" || rounds[0].Type != "ping" || len(rounds[0].Samples) != 1 {
		t.Fatalf("round = %+v, want one ping round", rounds[0])
	}
	if len(rounds[0].RoundID) != 32 {
		t.Fatalf("round id = %q, want 128-bit hex id", rounds[0].RoundID)
	}
	if rounds[0].Samples[0].Error == "unsupported_ping" {
		t.Fatalf("ping target should run real ping, got unsupported sample: %+v", rounds[0].Samples[0])
	}
	if !rounds[0].Samples[0].Success || rounds[0].Samples[0].LatencyMS == nil {
		t.Fatalf("ping sample = %+v, want successful latency sample", rounds[0].Samples[0])
	}
}

func TestRunHTTPProbeMeasuresSuccessfulGETLatency(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Method != http.MethodGet {
			t.Fatalf("method = %s, want GET", r.Method)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	samples := RunHTTPProbe(context.Background(), ProbeTarget{ID: "http-health", Type: "http_get", Address: server.URL, Count: 2, TimeoutMS: 1000})

	if len(samples) != 2 {
		t.Fatalf("samples len = %d, want 2", len(samples))
	}
	if requests != 2 {
		t.Fatalf("requests = %d, want 2", requests)
	}
	for _, sample := range samples {
		if !sample.Success || sample.LatencyMS == nil || *sample.LatencyMS < 0 || sample.Error != "" {
			t.Fatalf("http sample = %+v, want successful latency sample", sample)
		}
	}
}

func TestHTTPProbeClientDisablesKeepAlives(t *testing.T) {
	client := newHTTPProbeClient(time.Second)
	defer client.CloseIdleConnections()
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("HTTP probe transport type = %T, want *http.Transport", client.Transport)
	}
	if !transport.DisableKeepAlives {
		t.Fatal("HTTP probe transport keeps idle connections, want keep-alives disabled")
	}
}

func TestRunHTTPProbeMarksBadStatusAsFailedSample(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	samples := RunHTTPProbe(context.Background(), ProbeTarget{ID: "http-fail", Type: "http_get", Address: server.URL, Count: 1, TimeoutMS: 1000})

	if len(samples) != 1 {
		t.Fatalf("samples len = %d, want 1", len(samples))
	}
	if samples[0].Success || samples[0].LatencyMS != nil || samples[0].Error != "http_status_500" {
		t.Fatalf("http failure sample = %+v, want status failure without latency", samples[0])
	}
}

func TestRunHTTPProbeKeepsSlowLatencyWhileCountingAsTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(150 * time.Millisecond)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	samples := RunHTTPProbe(context.Background(), ProbeTarget{ID: "http-slow", Type: "http_get", Address: server.URL, Count: 1, TimeoutMS: minProbeTimeoutMS})

	if len(samples) != 1 {
		t.Fatalf("samples len = %d, want 1", len(samples))
	}
	if samples[0].Success || samples[0].Error != "timeout" || samples[0].LatencyMS == nil || *samples[0].LatencyMS < minProbeTimeoutMS || *samples[0].LatencyMS > 5000 {
		t.Fatalf("slow http sample = %+v, want timeout sample with drawable latency", samples[0])
	}
}

func TestProbeTargetsRunsHTTPGETTargetsInsteadOfMarkingUnsupported(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	rounds := ProbeTargets(context.Background(), []ProbeTarget{{ID: "http-health", Type: "http_get", Address: server.URL, Count: 1, TimeoutMS: 1000}}, time.Unix(1782990000, 0))

	if len(rounds) != 1 {
		t.Fatalf("rounds len = %d, want 1", len(rounds))
	}
	if rounds[0].TargetID != "http-health" || rounds[0].Type != "http_get" || len(rounds[0].Samples) != 1 {
		t.Fatalf("round = %+v, want one http_get round", rounds[0])
	}
	if rounds[0].Samples[0].Error == "unsupported_http_get" {
		t.Fatalf("http_get target should run real HTTP GET, got unsupported sample: %+v", rounds[0].Samples[0])
	}
	if !rounds[0].Samples[0].Success || rounds[0].Samples[0].LatencyMS == nil {
		t.Fatalf("http sample = %+v, want successful latency sample", rounds[0].Samples[0])
	}
}

func TestLatencyObservationTimeoutHasHardFiveSecondCap(t *testing.T) {
	if got := latencyObservationTimeout(12 * time.Second); got != 5*time.Second {
		t.Fatalf("long target observation timeout = %s, want 5s", got)
	}
	if got := latencyObservationTimeout(500 * time.Millisecond); got != 5*time.Second {
		t.Fatalf("short target observation timeout = %s, want 5s to retain slow timeout latency", got)
	}
}

func TestSanitizeProbeTargetsEnforcesControllerBudgets(t *testing.T) {
	targets := make([]ProbeTarget, maxProbeTargets+10)
	for index := range targets {
		targets[index] = ProbeTarget{ID: "target", Count: maxProbeCount + 100, TimeoutMS: maxProbeTimeoutMS + 1000, IntervalSec: 1}
	}

	sanitized := SanitizeProbeTargets(targets)
	if len(sanitized) != maxProbeTargets {
		t.Fatalf("sanitized targets len = %d, want %d", len(sanitized), maxProbeTargets)
	}
	for _, target := range sanitized {
		wantCount := maxProbeTargetBudgetMS / maxProbeTimeoutMS
		if target.Count != wantCount {
			t.Fatalf("sanitized count = %d, want per-target budget count %d", target.Count, wantCount)
		}
		if target.TimeoutMS != maxProbeTimeoutMS {
			t.Fatalf("sanitized timeout = %d, want %d", target.TimeoutMS, maxProbeTimeoutMS)
		}
		if target.IntervalSec != minProbeIntervalSec {
			t.Fatalf("sanitized interval = %d, want %d", target.IntervalSec, minProbeIntervalSec)
		}
	}
	lowTimeout := SanitizeProbeTargets([]ProbeTarget{{ID: "low-timeout", Count: 1, TimeoutMS: 1, IntervalSec: 60}})
	if len(lowTimeout) != 1 || lowTimeout[0].TimeoutMS != minProbeTimeoutMS {
		t.Fatalf("sanitized low timeout = %+v, want %dms", lowTimeout, minProbeTimeoutMS)
	}
}

func TestLimitProbeTargetsForRunEnforcesTotalSampleAndExecutionBudgets(t *testing.T) {
	targets := make([]ProbeTarget, 40)
	for index := range targets {
		targets[index] = ProbeTarget{ID: "target", Count: maxProbeCount, TimeoutMS: 1000, IntervalSec: 60}
	}

	limited := LimitProbeTargetsForRun(targets)
	var samples, budgetMS int
	for _, target := range limited {
		samples += target.Count
		budgetMS += target.Count * probeSampleBudgetMS(target)
	}
	wantSamples := maxProbeNodeBudgetMS / int(drawableLatencyCap/time.Millisecond)
	if samples != wantSamples {
		t.Fatalf("limited samples = %d, want real observation budget to allow %d", samples, wantSamples)
	}
	if budgetMS != maxProbeNodeBudgetMS {
		t.Fatalf("limited execution budget = %dms, want %dms", budgetMS, maxProbeNodeBudgetMS)
	}
	if samples > maxProbeSamplesPerRun {
		t.Fatalf("limited samples = %d, exceeds hard sample cap %d", samples, maxProbeSamplesPerRun)
	}
	if got := ProbeRunTimeout(limited); got != time.Duration(maxProbeNodeBudgetMS)*time.Millisecond+time.Second {
		t.Fatalf("probe run timeout = %s, want node observation budget + 1s", got)
	}
}

func TestProbeTargetsCapsConcurrentTargetExecution(t *testing.T) {
	var active atomic.Int64
	var maxActive atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		current := active.Add(1)
		for {
			previous := maxActive.Load()
			if current <= previous || maxActive.CompareAndSwap(previous, current) {
				break
			}
		}
		time.Sleep(25 * time.Millisecond)
		active.Add(-1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	targets := make([]ProbeTarget, maxConcurrentProbeTargets+6)
	for index := range targets {
		targets[index] = ProbeTarget{ID: "http", Type: "http_get", Address: server.URL, Count: 1, TimeoutMS: 1000, IntervalSec: 60}
	}

	rounds := ProbeTargets(context.Background(), targets, time.Now())
	if len(rounds) != len(targets) {
		t.Fatalf("rounds len = %d, want %d", len(rounds), len(targets))
	}
	if got := maxActive.Load(); got > maxConcurrentProbeTargets {
		t.Fatalf("max concurrent probes = %d, want <= %d", got, maxConcurrentProbeTargets)
	}
}

func TestProbeRejectsMetadataAndLinkLocalTargets(t *testing.T) {
	port := 80
	for _, sample := range RunTCPProbe(context.Background(), ProbeTarget{ID: "metadata", Type: "tcp", Address: "169.254.169.254", Port: &port, Count: 1, TimeoutMS: 1000}) {
		if sample.Error != "unsafe_target" {
			t.Fatalf("metadata tcp sample = %+v, want unsafe_target", sample)
		}
	}
	for _, sample := range RunPingProbe(context.Background(), ProbeTarget{ID: "metadata", Type: "ping", Address: "169.254.169.254", Count: 1, TimeoutMS: 1000}) {
		if sample.Error != "unsafe_target" {
			t.Fatalf("metadata ping sample = %+v, want unsafe_target", sample)
		}
	}
	for _, sample := range RunPingProbe(context.Background(), ProbeTarget{ID: "aliyun-metadata", Type: "ping", Address: "100.100.100.200", Count: 1, TimeoutMS: 1000}) {
		if sample.Error != "unsafe_target" {
			t.Fatalf("aliyun metadata ping sample = %+v, want unsafe_target", sample)
		}
	}
}

func TestProbeAddressPolicyAllowsPrivateAndCGNATTargets(t *testing.T) {
	for _, address := range []string{"10.0.0.1", "172.16.0.1", "192.168.1.1", "100.64.0.1", "100.127.255.254", "fc00::1"} {
		t.Run(address, func(t *testing.T) {
			addresses, err := resolveSafeProbeHost(context.Background(), address, false)
			if err != nil {
				t.Fatalf("resolveSafeProbeHost(%q) error = %v, want allowed", address, err)
			}
			if len(addresses) != 1 || addresses[0].String() != address {
				t.Fatalf("resolveSafeProbeHost(%q) = %+v, want exact address", address, addresses)
			}
		})
	}
}

func TestProbeAddressPolicyRejectsUnsafeSpecialTargets(t *testing.T) {
	for _, address := range []string{"169.254.1.1", "100.100.100.200", "fd00:ec2::254", "0.0.0.0", "224.0.0.1", "::", "ff02::1", "fe80::1"} {
		t.Run(address, func(t *testing.T) {
			_, err := resolveSafeProbeHost(context.Background(), address, true)
			if !errors.Is(err, errUnsafeProbeTarget) {
				t.Fatalf("resolveSafeProbeHost(%q) error = %v, want errUnsafeProbeTarget", address, err)
			}
		})
	}
}

func TestProbeHostnameResolveHonorsAlreadyDoneContextBeforeDNS(t *testing.T) {
	lookup := func(ctx context.Context, network, host string) ([]netip.Addr, error) {
		t.Fatalf("lookup called for already-done context: network=%q host=%q", network, host)
		return nil, nil
	}

	cancelledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := resolveSafeProbeHostWithLookup(cancelledCtx, "example.com", false, lookup)
	if !errors.Is(err, context.Canceled) || classifyProbeSetupError(err) != "cancelled" {
		t.Fatalf("cancelled hostname resolve error = %v/%q, want context.Canceled/cancelled", err, classifyProbeSetupError(err))
	}

	deadlineCtx, cancelDeadline := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancelDeadline()
	_, err = resolveSafeProbeHostWithLookup(deadlineCtx, "example.com", false, lookup)
	if !errors.Is(err, context.DeadlineExceeded) || classifyProbeSetupError(err) != "timeout" {
		t.Fatalf("deadline hostname resolve error = %v/%q, want context.DeadlineExceeded/timeout", err, classifyProbeSetupError(err))
	}
}

func TestHostnameProbeSetupReportsDoneContextInsteadOfDNSError(t *testing.T) {
	port := 443
	cancelledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	tcpSamples := RunTCPProbe(cancelledCtx, ProbeTarget{ID: "tcp", Type: "tcp", Address: "example.com", Port: &port, Count: 2, TimeoutMS: 1000})
	for _, sample := range tcpSamples {
		if sample.Error != "cancelled" {
			t.Fatalf("cancelled tcp hostname sample = %+v, want cancelled", sample)
		}
	}

	deadlineCtx, cancelDeadline := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancelDeadline()
	pingSamples := RunPingProbe(deadlineCtx, ProbeTarget{ID: "ping", Type: "ping", Address: "example.com", Count: 2, TimeoutMS: 1000})
	for _, sample := range pingSamples {
		if sample.Error != "timeout" {
			t.Fatalf("deadline ping hostname sample = %+v, want timeout", sample)
		}
	}
}

func TestProbeLoopsPreserveDeadlineClassification(t *testing.T) {
	port := 443
	deadlineCtx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()

	tests := []struct {
		name    string
		samples []ProbeSample
	}{
		{name: "tcp", samples: RunTCPProbe(deadlineCtx, ProbeTarget{ID: "tcp", Type: "tcp", Address: "127.0.0.1", Port: &port, Count: 2, TimeoutMS: 1000})},
		{name: "ping", samples: RunPingProbe(deadlineCtx, ProbeTarget{ID: "ping", Type: "ping", Address: "127.0.0.1", Count: 2, TimeoutMS: 1000})},
		{name: "http", samples: RunHTTPProbe(deadlineCtx, ProbeTarget{ID: "http", Type: "http_get", Address: "http://127.0.0.1:18980/health", Count: 2, TimeoutMS: 1000})},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, sample := range test.samples {
				if sample.Error != "timeout" {
					t.Fatalf("deadline sample = %+v, want timeout", sample)
				}
			}
		})
	}
}

func TestProbeContextErrorClassificationIsConsistent(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
		want string
	}{
		{name: "cancelled", err: context.Canceled, want: "cancelled"},
		{name: "deadline", err: context.DeadlineExceeded, want: "timeout"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := classifyProbeSetupError(test.err); got != test.want {
				t.Fatalf("setup classification = %q, want %q", got, test.want)
			}
			if got := classifyProbeError(test.err); got != test.want {
				t.Fatalf("tcp classification = %q, want %q", got, test.want)
			}
			if got := classifyPingError(test.err, "", test.err); got != test.want {
				t.Fatalf("ping classification = %q, want %q", got, test.want)
			}
			if got := classifyHTTPProbeError(test.err, test.err); got != test.want {
				t.Fatalf("http classification = %q, want %q", got, test.want)
			}
		})
	}
}

func TestProbeAddressPolicyAllowsOnlyExplicitLoopbackIP(t *testing.T) {
	if _, err := resolveSafeProbeHost(context.Background(), "127.0.0.1", true); err != nil {
		t.Fatalf("explicit loopback IP with allow flag error = %v, want allowed", err)
	}
	if _, err := resolveSafeProbeHost(context.Background(), "127.0.0.1", false); !errors.Is(err, errUnsafeProbeTarget) {
		t.Fatalf("explicit loopback IP without allow flag error = %v, want errUnsafeProbeTarget", err)
	}
}

func TestProbeHostnamePolicyAllowsPrivateAndCGNATTargets(t *testing.T) {
	lookup := func(ctx context.Context, network, host string) ([]netip.Addr, error) {
		if network != "ip" || host != "private.example" {
			t.Fatalf("lookup(%q, %q), want ip private.example", network, host)
		}
		return []netip.Addr{
			netip.MustParseAddr("10.0.0.5"),
			netip.MustParseAddr("100.64.0.5"),
			netip.MustParseAddr("10.0.0.5"),
		}, nil
	}

	addresses, err := resolveSafeProbeHostWithLookup(context.Background(), "private.example", false, lookup)
	if err != nil {
		t.Fatalf("private hostname error = %v, want allowed", err)
	}
	want := []netip.Addr{netip.MustParseAddr("10.0.0.5"), netip.MustParseAddr("100.64.0.5")}
	if !reflect.DeepEqual(addresses, want) {
		t.Fatalf("private hostname addresses = %+v, want %+v", addresses, want)
	}
}

func TestProbeHostnamePolicyRejectsLocalhostName(t *testing.T) {
	lookup := func(ctx context.Context, network, host string) ([]netip.Addr, error) {
		if host != "localhost" {
			t.Fatalf("lookup host = %q, want localhost", host)
		}
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}

	_, err := resolveSafeProbeHostWithLookup(context.Background(), "localhost", true, lookup)
	if !errors.Is(err, errUnsafeProbeTarget) {
		t.Fatalf("localhost hostname error = %v, want errUnsafeProbeTarget", err)
	}
}

func TestSafeProbeResolverPinsVerifiedHostnameAddress(t *testing.T) {
	calls := 0
	resolver := newSafeProbeResolverWithLookup(func(ctx context.Context, network, host string) ([]netip.Addr, error) {
		calls++
		if calls == 1 {
			return []netip.Addr{netip.MustParseAddr("10.0.0.10")}, nil
		}
		return []netip.Addr{netip.MustParseAddr("169.254.169.254")}, nil
	})

	first, err := resolver.resolve(context.Background(), "rebind.example", false)
	if err != nil {
		t.Fatalf("first resolve error = %v, want allowed", err)
	}
	first[0] = netip.MustParseAddr("8.8.8.8")
	second, err := resolver.resolve(context.Background(), "rebind.example", false)
	if err != nil {
		t.Fatalf("second resolve error = %v, want cached allowed address", err)
	}
	want := []netip.Addr{netip.MustParseAddr("10.0.0.10")}
	if !reflect.DeepEqual(second, want) {
		t.Fatalf("cached addresses = %+v, want %+v", second, want)
	}
	if calls != 1 {
		t.Fatalf("lookup calls = %d, want 1", calls)
	}
}

func TestHTTPProbeRejectsDNSRebindingToPrivateAddress(t *testing.T) {
	samples := RunHTTPProbe(context.Background(), ProbeTarget{ID: "localhost", Type: "http_get", Address: "http://localhost", Count: 1, TimeoutMS: 1000})
	if len(samples) != 1 || samples[0].Error != "unsafe_target" {
		t.Fatalf("localhost http sample = %+v, want unsafe_target", samples)
	}
}

func TestHTTPProbeRejectsUnsafeRedirectWithoutFollowing(t *testing.T) {
	var leakHits atomic.Int64
	leak := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leakHits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer leak.Close()
	leakURL, err := url.Parse(leak.URL)
	if err != nil {
		t.Fatalf("parse leak URL: %v", err)
	}
	_, leakPort, err := net.SplitHostPort(leakURL.Host)
	if err != nil {
		t.Fatalf("split leak host: %v", err)
	}

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://localhost:"+leakPort, http.StatusFound)
	}))
	defer redirector.Close()

	samples := RunHTTPProbe(context.Background(), ProbeTarget{ID: "redirect", Type: "http_get", Address: redirector.URL, Count: 1, TimeoutMS: 1000})
	if len(samples) != 1 || samples[0].Error != "unsafe_redirect" {
		t.Fatalf("redirect http sample = %+v, want unsafe_redirect", samples)
	}
	if leakHits.Load() != 0 {
		t.Fatalf("unsafe redirect target was requested %d time(s), want 0", leakHits.Load())
	}
}

func TestProbeTargetsHonorsCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	port := 443
	rounds := ProbeTargets(ctx, []ProbeTarget{{ID: "cancelled", Type: "tcp", Address: "198.51.100.10", Port: &port, Count: 2, TimeoutMS: 1000}}, time.Unix(1782990000, 0))
	if len(rounds) != 1 || len(rounds[0].Samples) != 2 {
		t.Fatalf("rounds = %+v, want one round with two cancelled samples", rounds)
	}
	for _, sample := range rounds[0].Samples {
		if sample.Error != "cancelled" {
			t.Fatalf("cancelled sample = %+v, want cancelled", sample)
		}
	}
}
