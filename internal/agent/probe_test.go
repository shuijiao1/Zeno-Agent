package agent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

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
		budgetMS += target.Count * target.TimeoutMS
	}
	wantSamples := maxProbeNodeBudgetMS / 1000
	if samples != wantSamples {
		t.Fatalf("limited samples = %d, want node execution budget to allow %d", samples, wantSamples)
	}
	if budgetMS != maxProbeNodeBudgetMS {
		t.Fatalf("limited execution budget = %dms, want %dms", budgetMS, maxProbeNodeBudgetMS)
	}
	if samples > maxProbeSamplesPerRun {
		t.Fatalf("limited samples = %d, exceeds hard sample cap %d", samples, maxProbeSamplesPerRun)
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
