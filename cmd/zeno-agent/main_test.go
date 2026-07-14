package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
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

	mustUpdateProbeTargets(t, manager, []agent.ProbeTarget{{ID: "old", Type: "http_get", Address: server.URL + "/slow", Count: 1, TimeoutMS: 1000, IntervalSec: 3600}}, 1)
	client := agent.NewClient(server.URL, "hytron", "token")
	errCh := make(chan error, 1)
	go func() { errCh <- runDueProbes(context.Background(), client, manager) }()

	select {
	case <-slowStarted:
	case <-time.After(time.Second):
		t.Fatal("slow probe did not start")
	}
	mustUpdateProbeTargets(t, manager, []agent.ProbeTarget{{ID: "new", Type: "unsupported", Count: 1, TimeoutMS: 1000, IntervalSec: 3600}}, 2)
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
	mustUpdateProbeTargets(t, manager, []agent.ProbeTarget{{ID: "same", Type: "unsupported", Count: 1, TimeoutMS: 1000, IntervalSec: 3600}}, 1)

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
			mustUpdateProbeTargets(t, manager, []agent.ProbeTarget{{ID: "same", Type: "unsupported", Count: 1, TimeoutMS: 1000, IntervalSec: 3600}}, 2)
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
	mustUpdateProbeTargets(t, manager, []agent.ProbeTarget{{ID: "old", Type: "unsupported", Count: 1, TimeoutMS: 1000, IntervalSec: 60}}, 5)
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

func mustUpdateProbeTargets(t *testing.T, manager *probeTargetManager, targets []agent.ProbeTarget, version int64) {
	t.Helper()
	if err := manager.update(targets, version); err != nil {
		t.Fatalf("manager.update(version=%d): %v", version, err)
	}
}

func TestProbeTargetManagerAppliesLegacyVersionZeroMutableConfig(t *testing.T) {
	manager := newProbeTargetManager()
	now := time.Now().UTC()
	mustUpdateProbeTargets(t, manager, []agent.ProbeTarget{{ID: "old", Type: "unsupported", Count: 1, TimeoutMS: 1000, IntervalSec: 60}}, 0)

	oldBatch := manager.due(now)
	if len(oldBatch.targets) != 1 || oldBatch.targets[0].ID != "old" || oldBatch.version != 0 {
		t.Fatalf("initial legacy batch = %+v, want old version 0 target", oldBatch)
	}
	if !manager.markCompleted(oldBatch, now) {
		t.Fatal("markCompleted rejected current legacy batch")
	}
	if batch := manager.due(now.Add(time.Second)); len(batch.targets) != 0 {
		t.Fatalf("legacy target due immediately after completion = %+v, want none", batch)
	}

	mustUpdateProbeTargets(t, manager, []agent.ProbeTarget{{ID: "new", Type: "unsupported", Count: 1, TimeoutMS: 1000, IntervalSec: 60}}, 0)
	newBatch := manager.due(now.Add(2 * time.Second))
	if len(newBatch.targets) != 1 || newBatch.targets[0].ID != "new" || newBatch.version != 0 {
		t.Fatalf("mutable legacy batch after content change = %+v, want new version 0 target", newBatch)
	}
	if newBatch.generation <= oldBatch.generation {
		t.Fatalf("legacy content change generation = %d, want greater than %d", newBatch.generation, oldBatch.generation)
	}
}

func TestProbeTargetManagerRejectsRollbackZeroAndSameVersionDrift(t *testing.T) {
	manager := newProbeTargetManager()
	original := []agent.ProbeTarget{{ID: "target", Type: "unsupported", Count: 1, TimeoutMS: 1000, IntervalSec: 60}}
	mustUpdateProbeTargets(t, manager, original, 5)

	if err := manager.update([]agent.ProbeTarget{{ID: "old", Type: "unsupported", Count: 1, TimeoutMS: 1000, IntervalSec: 60}}, 4); err == nil {
		t.Fatal("manager accepted an older probe config version")
	}
	if err := manager.update(nil, 0); err == nil {
		t.Fatal("manager accepted version 0 over an initialized non-zero config")
	}
	if err := manager.update([]agent.ProbeTarget{{ID: "target", Type: "unsupported", Count: 2, TimeoutMS: 1000, IntervalSec: 60}}, 5); err == nil {
		t.Fatal("manager accepted different content with the same config version")
	}

	batch := manager.due(time.Now().UTC())
	if batch.version != 5 || len(batch.targets) != 1 || batch.targets[0].Count != 1 {
		t.Fatalf("manager changed after rejected configs: %+v", batch)
	}
	if err := manager.update(original, 5); err != nil {
		t.Fatalf("manager rejected idempotent same-version config: %v", err)
	}
}

func TestRunDueProbesRefreshesProbeConfigOnUploadConflict(t *testing.T) {
	manager := newProbeTargetManager()
	mustUpdateProbeTargets(t, manager, []agent.ProbeTarget{{ID: "old", Type: "unsupported", Count: 1, TimeoutMS: 1000, IntervalSec: 60}}, 1)
	var fetches atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/agent/v1/probe-results":
			w.WriteHeader(http.StatusConflict)
		case "/api/agent/v1/probe-targets":
			fetches.Add(1)
			_ = json.NewEncoder(w).Encode(agent.ProbeTargetsResponse{Version: 2, Targets: []agent.ProbeTarget{{ID: "new", Type: "unsupported", Count: 1, TimeoutMS: 1000, IntervalSec: 60}}})
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	client := agent.NewClient(server.URL, "hytron", "token")
	if err := runDueProbes(context.Background(), client, manager); err == nil {
		t.Fatal("runDueProbes returned nil, want upload conflict")
	}
	if fetches.Load() != 1 {
		t.Fatalf("probe config fetches after 409 = %d, want 1", fetches.Load())
	}
	batch := manager.due(time.Now().UTC())
	if batch.version != 2 || len(batch.targets) != 1 || batch.targets[0].ID != "new" {
		t.Fatalf("manager after 409 refresh = %+v, want version 2 new target", batch)
	}
}

func TestRunDueProbesMarksSchedulerCompletionAfterUpload(t *testing.T) {
	manager := newProbeTargetManager()
	mustUpdateProbeTargets(t, manager, []agent.ProbeTarget{{ID: "same", Type: "unsupported", Count: 1, TimeoutMS: 1000, IntervalSec: 5}}, 1)
	uploadDelay := 300 * time.Millisecond
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/agent/v1/probe-results" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		time.Sleep(uploadDelay)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	client := agent.NewClient(server.URL, "hytron", "token")
	before := time.Now().UTC()
	if err := runDueProbes(context.Background(), client, manager); err != nil {
		t.Fatalf("runDueProbes: %v", err)
	}
	batch := manager.due(before.Add(5*time.Second + uploadDelay/2))
	if len(batch.targets) != 0 {
		t.Fatalf("target due too early after upload-delayed completion mark: %+v", batch)
	}
}

func TestRunDueProbesSerializesConcurrentInvocations(t *testing.T) {
	manager := newProbeTargetManager()
	mustUpdateProbeTargets(t, manager, []agent.ProbeTarget{{ID: "same", Type: "unsupported", Count: 1, TimeoutMS: 1000, IntervalSec: 3600}}, 1)
	var uploads atomic.Int64
	firstUploadStarted := make(chan struct{})
	releaseFirstUpload := make(chan struct{})
	var startedOnce sync.Once
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/agent/v1/probe-results" {
			t.Errorf("unexpected path %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		uploads.Add(1)
		startedOnce.Do(func() { close(firstUploadStarted) })
		<-releaseFirstUpload
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	client := agent.NewClient(server.URL, "hytron", "token")
	errCh := make(chan error, 2)
	go func() { errCh <- runDueProbes(context.Background(), client, manager) }()
	select {
	case <-firstUploadStarted:
	case <-time.After(time.Second):
		t.Fatal("first probe upload did not start")
	}
	go func() { errCh <- runDueProbes(context.Background(), client, manager) }()
	// Give the second invocation time to contend for the run gate. It must not
	// obtain the same due batch and start a duplicate upload.
	time.Sleep(30 * time.Millisecond)
	if got := uploads.Load(); got != 1 {
		t.Fatalf("uploads while first run is blocked = %d, want exactly 1", got)
	}
	close(releaseFirstUpload)
	for range 2 {
		if err := <-errCh; err != nil {
			t.Fatalf("runDueProbes: %v", err)
		}
	}
	if got := uploads.Load(); got != 1 {
		t.Fatalf("total uploads from concurrent runs = %d, want exactly 1", got)
	}
}

func TestProbeConfigPollerRetriesWhenPresenceIsUnavailable(t *testing.T) {
	oldInterval := probeConfigPollInterval
	probeConfigPollInterval = 10 * time.Millisecond
	t.Cleanup(func() { probeConfigPollInterval = oldInterval })

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var attempts atomic.Int64
	done := make(chan struct{})
	go func() {
		runProbeConfigPoller(ctx, func(context.Context, int64) (int64, error) {
			attempt := attempts.Add(1)
			if attempt == 1 {
				return 0, context.DeadlineExceeded
			}
			cancel()
			return 2, nil
		})
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("probe config poller did not stop after context cancellation")
	}
	if attempts.Load() < 2 {
		t.Fatalf("probe config poll attempts = %d, want retry after failure", attempts.Load())
	}
}

func TestRunAgentStartsLivenessLoopsWhileInitialProbeUploadIsBlocked(t *testing.T) {
	oldProbeInterval := probeRunLoopInterval
	probeRunLoopInterval = 10 * time.Millisecond
	t.Cleanup(func() { probeRunLoopInterval = oldProbeInterval })

	var heartbeatPosts atomic.Int64
	var statePosts atomic.Int64
	probeUploadStarted := make(chan struct{})
	releaseProbeUpload := make(chan struct{})
	secondHeartbeat := make(chan struct{})
	secondState := make(chan struct{})
	presenceAttempt := make(chan struct{})
	var probeStartedOnce sync.Once
	var heartbeatOnce sync.Once
	var stateOnce sync.Once
	var presenceOnce sync.Once

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/agent/v1/heartbeat":
			if heartbeatPosts.Add(1) >= 2 {
				heartbeatOnce.Do(func() { close(secondHeartbeat) })
			}
			w.WriteHeader(http.StatusAccepted)
		case "/api/agent/v1/state":
			if statePosts.Add(1) >= 2 {
				stateOnce.Do(func() { close(secondState) })
			}
			w.WriteHeader(http.StatusAccepted)
		case "/api/agent/v1/host":
			w.WriteHeader(http.StatusAccepted)
		case "/api/agent/v1/probe-targets":
			_ = json.NewEncoder(w).Encode(agent.ProbeTargetsResponse{Version: 1, Targets: []agent.ProbeTarget{{ID: "slow-upload", Type: "unsupported", Count: 1, TimeoutMS: 1000, IntervalSec: 3600}}})
		case "/api/agent/v1/probe-results":
			probeStartedOnce.Do(func() { close(probeUploadStarted) })
			select {
			case <-r.Context().Done():
			case <-releaseProbeUpload:
			}
		case "/api/agent/v1/presence/ws":
			presenceOnce.Do(func() { close(presenceAttempt) })
			http.Error(w, "websocket unavailable in test", http.StatusServiceUnavailable)
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	defer close(releaseProbeUpload)

	ctx, cancel := context.WithCancel(context.Background())
	client := agent.NewClient(server.URL, "hytron", "token")
	cfg := config{
		StateInterval:           10 * time.Millisecond,
		HeartbeatInterval:       10 * time.Millisecond,
		HostInterval:            time.Hour,
		IdentityRefreshInterval: time.Hour,
		Version:                 "startup-test",
	}
	errCh := make(chan error, 1)
	go func() {
		errCh <- runAgent(ctx, cfg, client, agent.NewMetricsCollector(), staticIdentityDiscoverer{})
	}()

	select {
	case <-probeUploadStarted:
	case <-time.After(2 * time.Second):
		cancel()
		t.Fatal("initial probe upload did not start")
	}
	for label, signal := range map[string]<-chan struct{}{"heartbeat": secondHeartbeat, "state": secondState, "presence": presenceAttempt} {
		select {
		case <-signal:
		case <-time.After(time.Second):
			cancel()
			t.Fatalf("periodic %s did not run while probe upload was blocked", label)
		}
	}

	cancel()
	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("runAgent error = %v, want context canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("runAgent did not wait for and stop its workers promptly")
	}
}
