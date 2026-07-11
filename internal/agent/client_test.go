package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestClientAddsAgentAuthHeadersAndPostsState(t *testing.T) {
	var sawPath, sawNode, sawAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawPath = r.URL.Path
		sawNode = r.Header.Get("X-Node-ID")
		sawAuth = r.Header.Get("Authorization")
		var body StateSample
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode state body: %v", err)
		}
		if body.TS != 1782990000 || body.CPUPercent != 12.5 || body.Load1 != 0.42 || body.Load5 != 0.35 || body.Load15 != 0.28 || body.SwapUsedBytes != 512 || body.SwapTotalBytes != 2048 || body.ProcessCount != 88 || body.TCPConnectionCount != 34 || body.UDPConnectionCount != 12 || body.NetOutSpeedBps != 1024 {
			t.Fatalf("state body = %+v, want exact sample with extra metrics", body)
		}
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "hytron", "secret-token")
	sample := StateSample{
		TS:                 1782990000,
		CPUPercent:         12.5,
		Load1:              0.42,
		Load5:              0.35,
		Load15:             0.28,
		SwapUsedBytes:      512,
		SwapTotalBytes:     2048,
		NetOutSpeedBps:     1024,
		ProcessCount:       88,
		TCPConnectionCount: 34,
		UDPConnectionCount: 12,
	}
	err := client.PostState(context.Background(), sample)
	if err != nil {
		t.Fatalf("post state: %v", err)
	}
	if sawPath != "/api/agent/v1/state" || sawNode != "hytron" || sawAuth != "Bearer secret-token" {
		t.Fatalf("path/node/auth = %q/%q/%q, want state/hytron/bearer", sawPath, sawNode, sawAuth)
	}
}

func TestClientFetchTargetsAndPostsProbeRounds(t *testing.T) {
	var posted bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/agent/v1/probe-targets":
			if r.Header.Get("X-Node-ID") != "hytron" || r.Header.Get("Authorization") != "Bearer token" {
				t.Fatalf("missing auth headers on target fetch")
			}
			_ = json.NewEncoder(w).Encode(ProbeTargetsResponse{Version: 7, Targets: []ProbeTarget{{ID: "google", Name: "Google", Type: "tcping", Address: "8.8.8.8", Count: 3, TimeoutMS: 1000, IntervalSec: 60}}})
		case "/api/agent/v1/probe-results":
			posted = true
			var body ProbeResultsRequest
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode probe body: %v", err)
			}
			if body.ConfigVersion != 7 || len(body.Rounds) != 1 || body.Rounds[0].RoundID != "round-1" || body.Rounds[0].TargetID != "google" || len(body.Rounds[0].Samples) != 1 {
				t.Fatalf("probe results body = %+v, want google round with sample", body)
			}
			w.WriteHeader(http.StatusAccepted)
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	client := NewClient(server.URL+"/", "hytron", "token")
	targets, err := client.FetchProbeTargets(context.Background())
	if err != nil {
		t.Fatalf("fetch probe targets: %v", err)
	}
	if len(targets) != 1 || targets[0].ID != "google" {
		t.Fatalf("targets = %+v, want google", targets)
	}
	latency := 10.5
	err = client.PostProbeResults(context.Background(), []ProbeRound{{RoundID: "round-1", ConfigVersion: 7, TargetID: "google", TS: time.Unix(1782990000, 0), Type: "tcping", Samples: []ProbeSample{{Seq: 1, Success: true, LatencyMS: &latency}}}})
	if err != nil {
		t.Fatalf("post probe results: %v", err)
	}
	if !posted {
		t.Fatalf("probe results were not posted")
	}
}

func TestClientRejectsMixedProbeConfigVersionsBeforePosting(t *testing.T) {
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	client := NewClient(server.URL, "hytron", "token")
	err := client.PostProbeResults(context.Background(), []ProbeRound{
		{RoundID: "round-legacy", ConfigVersion: 0},
		{RoundID: "round-current", ConfigVersion: 7},
	})
	if err == nil || !strings.Contains(err.Error(), "mixed probe config versions") {
		t.Fatalf("error = %v, want mixed-version rejection", err)
	}
	if called {
		t.Fatal("mixed-version probe batch reached controller")
	}
}

func TestClientErrorDoesNotExposeControllerResponseBody(t *testing.T) {
	const secret = "proxy-secret-must-not-leak"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(strings.Repeat(secret, 1024)))
	}))
	defer server.Close()

	client := NewClient(server.URL, "hytron", "token")
	err := client.PostHeartbeat(context.Background(), "online", "test", time.Now())
	if err == nil {
		t.Fatal("expected controller error")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("controller response body leaked in error: %v", err)
	}
	if !strings.Contains(err.Error(), "returned 502") {
		t.Fatalf("error = %q, want status without response body", err)
	}
}

func TestClientRejectsOversizedJSONResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"targets":[],"padding":"` + strings.Repeat("a", int(maxAgentAPIJSONBodyBytes)) + `"}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "hytron", "token")
	_, err := client.FetchProbeTargets(context.Background())
	if err == nil || !strings.Contains(err.Error(), "response exceeds") {
		t.Fatalf("error = %v, want bounded response error", err)
	}
}
