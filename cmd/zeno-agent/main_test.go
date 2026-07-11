package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shuijiao1/Zeno-Agent/internal/agent"
)

func TestDefaultReportIntervalsAreSplitByPurpose(t *testing.T) {
	if defaultStateInterval != 3*time.Second {
		t.Fatalf("default state interval = %s, want 3s", defaultStateInterval)
	}
	if defaultHeartbeatInterval != 15*time.Second {
		t.Fatalf("default heartbeat interval = %s, want 15s", defaultHeartbeatInterval)
	}
	if defaultHostInterval != 30*time.Minute {
		t.Fatalf("default host interval = %s, want 30m", defaultHostInterval)
	}
	if defaultIdentityRefreshInterval != 12*time.Hour {
		t.Fatalf("default identity refresh interval = %s, want 12h", defaultIdentityRefreshInterval)
	}
}

type staticIdentityDiscoverer struct {
	identity agent.NetworkIdentity
}

func (d staticIdentityDiscoverer) Discover(context.Context) agent.NetworkIdentity {
	return d.identity
}

func TestReportOnceAddsDiscoveredNetworkIdentityToHost(t *testing.T) {
	var hostPayload agent.HostInfo
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/agent/v1/heartbeat", "/api/agent/v1/state":
			w.WriteHeader(http.StatusAccepted)
		case "/api/agent/v1/host":
			if err := json.NewDecoder(r.Body).Decode(&hostPayload); err != nil {
				t.Fatalf("decode host: %v", err)
			}
			w.WriteHeader(http.StatusAccepted)
		case "/api/agent/v1/probe-targets":
			_ = json.NewEncoder(w).Encode(agent.ProbeTargetsResponse{})
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	client := agent.NewClient(server.URL, "hytron", "token")
	collector := agent.NewMetricsCollector()
	identity := staticIdentityDiscoverer{identity: agent.NetworkIdentity{PublicIPv4: "198.51.100.8", PublicIPv6: "2001:db8::8", CountryCode: "JP"}}
	if err := reportOnce(context.Background(), client, collector, "identity-test", true, nil, identity); err != nil {
		t.Fatalf("reportOnce: %v", err)
	}
	if hostPayload.PublicIPv4 != "198.51.100.8" || hostPayload.PublicIPv6 != "2001:db8::8" || hostPayload.CountryCode != "JP" {
		t.Fatalf("host identity = %+v, want discovered network identity", hostPayload)
	}
}

func TestReportStateOnlyPostsStateWithoutHeartbeatOrProbeFetch(t *testing.T) {
	var statePosts int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/agent/v1/state":
			statePosts++
			w.WriteHeader(http.StatusAccepted)
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	client := agent.NewClient(server.URL, "hytron", "token")
	collector := agent.NewMetricsCollector()
	if err := reportStateOnly(context.Background(), client, collector); err != nil {
		t.Fatalf("reportStateOnly: %v", err)
	}
	if statePosts != 1 {
		t.Fatalf("state posts = %d, want 1", statePosts)
	}
}

func TestReportOnceSkipsProbeResultsWhenNoTargetsAreDue(t *testing.T) {
	var probePosts [][]string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/agent/v1/heartbeat", "/api/agent/v1/state":
			w.WriteHeader(http.StatusAccepted)
		case "/api/agent/v1/probe-targets":
			_ = json.NewEncoder(w).Encode(agent.ProbeTargetsResponse{Targets: []agent.ProbeTarget{
				{ID: "fast", Type: "unsupported", Count: 1, IntervalSec: 3600},
				{ID: "slow", Type: "unsupported", Count: 1, IntervalSec: 3600},
			}})
		case "/api/agent/v1/probe-results":
			var payload struct {
				Rounds []struct {
					TargetID string `json:"target_id"`
				} `json:"rounds"`
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatalf("decode probe results: %v", err)
			}
			ids := make([]string, 0, len(payload.Rounds))
			for _, round := range payload.Rounds {
				ids = append(ids, round.TargetID)
			}
			probePosts = append(probePosts, ids)
			w.WriteHeader(http.StatusAccepted)
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	client := agent.NewClient(server.URL, "hytron", "token")
	collector := agent.NewMetricsCollector()
	scheduler := agent.NewProbeScheduler()
	if err := reportOnce(context.Background(), client, collector, "scheduler-test", false, scheduler, nil); err != nil {
		t.Fatalf("first reportOnce: %v", err)
	}
	if err := reportOnce(context.Background(), client, collector, "scheduler-test", false, scheduler, nil); err != nil {
		t.Fatalf("second reportOnce: %v", err)
	}

	if len(probePosts) != 1 {
		t.Fatalf("probe result posts = %+v, want exactly one post because second run has no due targets", probePosts)
	}
	if len(probePosts[0]) != 2 || probePosts[0][0] != "fast" || probePosts[0][1] != "slow" {
		t.Fatalf("first probe post target ids = %+v, want fast and slow", probePosts[0])
	}
}

func TestRunDueProbesDiscardsStaleGenerationBeforeUpload(t *testing.T) {
	manager := newProbeTargetManager()
	var probePosts atomic.Int64
	slowStarted := make(chan struct{})
	releaseSlowProbe := make(chan struct{})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/slow":
			select {
			case <-slowStarted:
			default:
				close(slowStarted)
			}
			<-releaseSlowProbe
			w.WriteHeader(http.StatusNoContent)
		case "/api/agent/v1/probe-results":
			probePosts.Add(1)
			w.WriteHeader(http.StatusAccepted)
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	manager.update([]agent.ProbeTarget{{ID: "old", Type: "http_get", Address: server.URL + "/slow", Count: 1, TimeoutMS: 1000, IntervalSec: 3600}}, 1)
	client := agent.NewClient(server.URL, "hytron", "token")
	errCh := make(chan error, 1)
	go func() { errCh <- runDueProbes(context.Background(), client, manager) }()

	select {
	case <-slowStarted:
	case <-time.After(time.Second):
		t.Fatal("slow probe did not start")
	}
	manager.update([]agent.ProbeTarget{{ID: "new", Type: "unsupported", Count: 1, TimeoutMS: 1000, IntervalSec: 3600}}, 2)
	close(releaseSlowProbe)

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("runDueProbes: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("runDueProbes did not return")
	}
	if got := probePosts.Load(); got != 0 {
		t.Fatalf("probe result posts = %d, want stale generation discarded before upload", got)
	}
	batch := manager.due(time.Now().UTC())
	if len(batch.targets) != 1 || batch.targets[0].ID != "new" || batch.version != 2 {
		t.Fatalf("due batch after generation update = %+v, want new version target still due", batch)
	}
}

func TestRunDueProbesPostsConfigVersionAndSkipsStaleCompletion(t *testing.T) {
	manager := newProbeTargetManager()
	manager.update([]agent.ProbeTarget{{ID: "same", Type: "unsupported", Count: 1, TimeoutMS: 1000, IntervalSec: 3600}}, 1)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/agent/v1/probe-results":
			var payload agent.ProbeResultsRequest
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatalf("decode probe results: %v", err)
			}
			if payload.ConfigVersion != 1 || len(payload.Rounds) != 1 {
				t.Fatalf("probe result payload = %+v, want config version 1", payload)
			}
			manager.update([]agent.ProbeTarget{{ID: "same", Type: "unsupported", Count: 1, TimeoutMS: 1000, IntervalSec: 3600}}, 2)
			w.WriteHeader(http.StatusAccepted)
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	client := agent.NewClient(server.URL, "hytron", "token")
	if err := runDueProbes(context.Background(), client, manager); err != nil {
		t.Fatalf("runDueProbes: %v", err)
	}
	batch := manager.due(time.Now().UTC())
	if len(batch.targets) != 1 || batch.targets[0].ID != "same" || batch.version != 2 {
		t.Fatalf("due batch after generation update during upload = %+v, want version 2 target still due", batch)
	}
}

func TestRefreshProbeTargetsRequiresRequestedConfigVersion(t *testing.T) {
	var responseVersion atomic.Int64
	responseVersion.Store(6)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/agent/v1/probe-targets" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(agent.ProbeTargetsResponse{
			Version: responseVersion.Load(),
			Targets: []agent.ProbeTarget{{ID: "new", Type: "unsupported", Count: 1, TimeoutMS: 1000, IntervalSec: 60}},
		})
	}))
	defer server.Close()

	manager := newProbeTargetManager()
	manager.update([]agent.ProbeTarget{{ID: "old", Type: "unsupported", Count: 1, TimeoutMS: 1000, IntervalSec: 60}}, 5)
	client := agent.NewClient(server.URL, "hytron", "token")

	if applied, err := refreshProbeTargets(context.Background(), client, manager, 7); err == nil || applied != 0 {
		t.Fatalf("stale refresh applied=%d err=%v, want rejected", applied, err)
	}
	staleBatch := manager.due(time.Now().UTC())
	if staleBatch.version != 5 || len(staleBatch.targets) != 1 || staleBatch.targets[0].ID != "old" {
		t.Fatalf("manager changed after stale refresh: %+v", staleBatch)
	}

	responseVersion.Store(7)
	if applied, err := refreshProbeTargets(context.Background(), client, manager, 7); err != nil || applied != 7 {
		t.Fatalf("current refresh applied=%d err=%v, want version 7", applied, err)
	}
	currentBatch := manager.due(time.Now().UTC())
	if currentBatch.version != 7 || len(currentBatch.targets) != 1 || currentBatch.targets[0].ID != "new" {
		t.Fatalf("manager after current refresh: %+v", currentBatch)
	}

	responseVersion.Store(0)
	if applied, err := refreshProbeTargets(context.Background(), client, manager, 8); err == nil || applied != 0 {
		t.Fatalf("version zero refresh applied=%d err=%v, want rejected", applied, err)
	}
}
