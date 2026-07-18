package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
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

func TestInstallCheckIsLocalOnlyAndDoesNotReport(t *testing.T) {
	const token = "install-check-secret"
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		http.Error(w, "must not be reached "+token, http.StatusInternalServerError)
	}))
	defer server.Close()

	err := run(context.Background(), config{
		ControllerURL: server.URL,
		NodeID:        "install-node",
		Token:         token,
		Version:       "install-check-test",
		InstallCheck:  true,
	})
	if err != nil {
		t.Fatalf("local install preflight failed: %v", err)
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("elevated install-check made %d network requests, want 0", got)
	}
}

func TestInstallReceiptRequiresBothAcceptedReportsAndContainsNoToken(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "receipt")
	nonce := strings.Repeat("a", 64)
	tracker := newInstallReceiptTracker(path, nonce)
	tracker.markHeartbeat()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("receipt exists before state acceptance: %v", err)
	}
	tracker.markState()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read receipt: %v", err)
	}
	want := installReceiptPrefix + nonce + "\n"
	if string(content) != want {
		t.Fatalf("receipt = %q, want %q", content, want)
	}
	if strings.Contains(string(content), "token") {
		t.Fatal("receipt contains credential-like material")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat receipt: %v", err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("receipt mode = %v, want 0600", info.Mode().Perm())
	}
}

type staticIdentityDiscoverer struct {
	identity agent.NetworkIdentity
}

func (d staticIdentityDiscoverer) Discover(context.Context) agent.NetworkIdentity {
	return d.identity
}

func TestRunDueProbesDiscardsStaleGenerationBeforeUpload(t *testing.T) {
	manager := newProbeTargetManager()
	slowStarted := make(chan struct{})
	releaseSlowProbe := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/slow" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		close(slowStarted)
		<-releaseSlowProbe
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	mustUpdateProbeTargets(t, manager, []agent.ProbeTarget{{ID: "old", Type: "http_get", Address: server.URL + "/slow", Count: 1, TimeoutMS: 1000, IntervalSec: 3600}}, 1)
	spool := newMainTestSpool(t)
	errCh := make(chan error, 1)
	go func() { errCh <- runDueProbes(context.Background(), spool, manager) }()
	select {
	case <-slowStarted:
	case <-time.After(time.Second):
		t.Fatal("slow probe did not start")
	}
	mustUpdateProbeTargets(t, manager, []agent.ProbeTarget{{ID: "new", Type: "unsupported", Count: 1, TimeoutMS: 1000, IntervalSec: 3600}}, 2)
	close(releaseSlowProbe)
	if err := <-errCh; err != nil {
		t.Fatalf("runDueProbes: %v", err)
	}
	if item, err := spool.Next(time.Now().UTC()); err != nil || item != nil {
		t.Fatalf("stale generation was persisted: %#v, %v", item, err)
	}
	batch := manager.due(time.Now().UTC())
	if len(batch.targets) != 1 || batch.targets[0].ID != "new" || batch.version != 2 {
		t.Fatalf("due batch = %+v", batch)
	}
}

func TestRunDueProbesPersistsConfigVersionBeforeCompletion(t *testing.T) {
	manager := newProbeTargetManager()
	mustUpdateProbeTargets(t, manager, []agent.ProbeTarget{{ID: "same", Type: "unsupported", Count: 1, TimeoutMS: 1000, IntervalSec: 3600}}, 1)
	spool := newMainTestSpool(t)
	if err := runDueProbes(context.Background(), spool, manager); err != nil {
		t.Fatalf("runDueProbes: %v", err)
	}
	item, err := spool.Next(time.Now().UTC())
	if err != nil || item == nil {
		t.Fatalf("persisted item = %#v, %v", item, err)
	}
	var payload agent.ProbeResultsRequest
	if err := json.Unmarshal(item.Body, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.ConfigVersion != 1 || len(payload.Rounds) != 1 {
		t.Fatalf("payload = %+v", payload)
	}
	if due := manager.due(time.Now().UTC()); len(due.targets) != 0 {
		t.Fatalf("scheduler was not marked after enqueue: %+v", due)
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
	client := agent.NewClient(server.URL, "node-a", "token")

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

func newMainTestSpool(t *testing.T) *agent.ProbeSpool {
	t.Helper()
	spool, err := agent.NewProbeSpool(t.TempDir(), agent.ProbeSpoolOptions{FreeBytes: func(string) (uint64, error) { return 1 << 40, nil }})
	if err != nil {
		t.Fatal(err)
	}
	return spool
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

func TestProbeUploaderRefreshesConfigOnlyForStaleConflict(t *testing.T) {
	manager := newProbeTargetManager()
	mustUpdateProbeTargets(t, manager, []agent.ProbeTarget{{ID: "old", Type: "unsupported", Count: 1, TimeoutMS: 1000, IntervalSec: 60}}, 1)
	var fetches atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/agent/v1/probe-results":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"error":"stale_probe_config"}`))
		case "/api/agent/v1/probe-targets":
			fetches.Add(1)
			_ = json.NewEncoder(w).Encode(agent.ProbeTargetsResponse{Version: 2, Targets: []agent.ProbeTarget{{ID: "new", Type: "unsupported", Count: 1, TimeoutMS: 1000, IntervalSec: 60}}})
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()
	client := agent.NewClient(server.URL, "node-a", "token")
	spool := newMainTestSpool(t)
	if _, err := spool.Enqueue([]agent.ProbeRound{{RoundID: "old-round", ConfigVersion: 1, TargetID: "old", TS: time.Now().UTC(), Type: "tcping", Samples: []agent.ProbeSample{{Seq: 1}}}}); err != nil {
		t.Fatal(err)
	}
	refreshed := make(chan struct{})
	uploader := agent.NewProbeUploader(spool, client, agent.ProbeUploaderOptions{OnRejected: func(ctx context.Context, err error) {
		var stale *agent.ProbeUploadStaleError
		if errors.As(err, &stale) {
			_, _ = refreshProbeTargets(ctx, client, manager, 0)
			close(refreshed)
		}
	}})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- uploader.Run(ctx) }()
	select {
	case <-refreshed:
	case <-time.After(time.Second):
		cancel()
		t.Fatal("uploader did not refresh stale config")
	}
	cancel()
	<-done
	if fetches.Load() != 1 {
		t.Fatalf("fetches = %d", fetches.Load())
	}
	batch := manager.due(time.Now().UTC())
	if batch.version != 2 || len(batch.targets) != 1 || batch.targets[0].ID != "new" {
		t.Fatalf("manager = %+v", batch)
	}
}

func TestRunDueProbesDoesNotMarkSchedulerWhenEnqueueFails(t *testing.T) {
	manager := newProbeTargetManager()
	mustUpdateProbeTargets(t, manager, []agent.ProbeTarget{{ID: "same", Type: "unsupported", Count: 1, TimeoutMS: 1000, IntervalSec: 5}}, 1)
	spool, err := agent.NewProbeSpool(t.TempDir(), agent.ProbeSpoolOptions{FreeBytes: func(string) (uint64, error) { return 1 << 40, nil }, AtomicWrite: func(string, []byte) error { return syscall.ENOSPC }})
	if err != nil {
		t.Fatal(err)
	}
	if err := runDueProbes(context.Background(), spool, manager); !errors.Is(err, syscall.ENOSPC) {
		t.Fatalf("runDueProbes error = %v", err)
	}
	if due := manager.due(time.Now().UTC()); len(due.targets) != 1 {
		t.Fatalf("enqueue failure marked scheduler complete: %+v", due)
	}
}

func TestRunDueProbesSerializesConcurrentInvocations(t *testing.T) {
	manager := newProbeTargetManager()
	var probes atomic.Int64
	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		probes.Add(1)
		once.Do(func() { close(started) })
		<-release
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	mustUpdateProbeTargets(t, manager, []agent.ProbeTarget{{ID: "same", Type: "http_get", Address: server.URL, Count: 1, TimeoutMS: 1000, IntervalSec: 3600}}, 1)
	spool := newMainTestSpool(t)
	errCh := make(chan error, 2)
	go func() { errCh <- runDueProbes(context.Background(), spool, manager) }()
	<-started
	go func() { errCh <- runDueProbes(context.Background(), spool, manager) }()
	time.Sleep(30 * time.Millisecond)
	if probes.Load() != 1 {
		t.Fatalf("concurrent probes = %d", probes.Load())
	}
	close(release)
	for range 2 {
		if err := <-errCh; err != nil {
			t.Fatal(err)
		}
	}
	if probes.Load() != 1 {
		t.Fatalf("total probes = %d", probes.Load())
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
	oldConfigPollInterval := probeConfigPollInterval
	probeRunLoopInterval = 10 * time.Millisecond
	probeConfigPollInterval = 10 * time.Millisecond
	t.Cleanup(func() {
		probeRunLoopInterval = oldProbeInterval
		probeConfigPollInterval = oldConfigPollInterval
	})

	var heartbeatPosts atomic.Int64
	var statePosts atomic.Int64
	var hostPosts atomic.Int64
	probeUploadStarted := make(chan struct{})
	releaseProbeUpload := make(chan struct{})
	secondProbeScheduled := make(chan struct{})
	secondHeartbeat := make(chan struct{})
	secondState := make(chan struct{})
	secondHost := make(chan struct{})
	presenceAttempt := make(chan struct{})
	var probeStartedOnce sync.Once
	var scheduledOnce sync.Once
	var heartbeatOnce sync.Once
	var stateOnce sync.Once
	var hostOnce sync.Once
	var presenceOnce sync.Once

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
			if hostPosts.Add(1) >= 2 {
				hostOnce.Do(func() { close(secondHost) })
			}
			w.WriteHeader(http.StatusAccepted)
		case "/api/agent/v1/probe-targets":
			select {
			case <-probeUploadStarted:
				_ = json.NewEncoder(w).Encode(agent.ProbeTargetsResponse{Version: 2, Targets: []agent.ProbeTarget{{ID: "second-probe", Type: "http_get", Address: server.URL + "/scheduled-probe", Count: 1, TimeoutMS: 1000, IntervalSec: 3600}}})
			default:
				_ = json.NewEncoder(w).Encode(agent.ProbeTargetsResponse{Version: 1, Targets: []agent.ProbeTarget{{ID: "slow-upload", Type: "unsupported", Count: 1, TimeoutMS: 1000, IntervalSec: 3600}}})
			}
		case "/scheduled-probe":
			scheduledOnce.Do(func() { close(secondProbeScheduled) })
			w.WriteHeader(http.StatusNoContent)
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
	client := agent.NewClient(server.URL, "node-a", "token")
	cfg := config{
		StateInterval:           10 * time.Millisecond,
		HeartbeatInterval:       10 * time.Millisecond,
		HostInterval:            10 * time.Millisecond,
		IdentityRefreshInterval: time.Hour,
		Version:                 "startup-test",
		DataDir:                 t.TempDir(),
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
	for label, signal := range map[string]<-chan struct{}{"heartbeat": secondHeartbeat, "state": secondState, "host": secondHost, "probe scheduler": secondProbeScheduled, "presence": presenceAttempt} {
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
