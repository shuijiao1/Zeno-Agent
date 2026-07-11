package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"

	"github.com/shuijiao1/Zeno-Agent/internal/agent"
)

const defaultVersion = "zeno-agent-dev"
const defaultStateInterval = 3 * time.Second
const defaultHeartbeatInterval = 15 * time.Second
const defaultHostInterval = 30 * time.Minute
const defaultIdentityRefreshInterval = 12 * time.Hour

// Kept as compatibility aliases for older tests/install commands.
const defaultReportInterval = defaultStateInterval
const defaultFullReportInterval = defaultHeartbeatInterval

type config struct {
	ControllerURL           string
	NodeID                  string
	Token                   string
	TokenFile               string
	StateInterval           time.Duration
	HeartbeatInterval       time.Duration
	HostInterval            time.Duration
	Once                    bool
	Version                 string
	IdentityRefreshInterval time.Duration
	NetworkInterfaces       string
	DiskMounts              string
}

func main() {
	cfg := config{}
	legacyInterval := time.Duration(0)
	flag.StringVar(&cfg.ControllerURL, "controller-url", "http://127.0.0.1:18980", "Zeno controller base URL")
	flag.StringVar(&cfg.NodeID, "node-id", "hytron", "agent node id")
	flag.StringVar(&cfg.Token, "token", "", "agent bearer token; prefer -token-file")
	flag.StringVar(&cfg.TokenFile, "token-file", "", "file containing the agent bearer token")
	flag.DurationVar(&legacyInterval, "interval", 0, "deprecated alias for -state-interval")
	flag.DurationVar(&cfg.StateInterval, "state-interval", defaultStateInterval, "state metrics report interval")
	flag.DurationVar(&cfg.HeartbeatInterval, "heartbeat-interval", defaultHeartbeatInterval, "heartbeat report interval")
	flag.DurationVar(&cfg.HostInterval, "host-interval", defaultHostInterval, "static host information report interval")
	flag.BoolVar(&cfg.Once, "once", false, "collect and report once, then exit")
	flag.StringVar(&cfg.Version, "version", defaultVersion, "agent version string reported to controller")
	flag.DurationVar(&cfg.IdentityRefreshInterval, "identity-refresh-interval", defaultIdentityRefreshInterval, "public IPv4/IPv6 and GeoIP refresh interval; best-effort and cached")
	flag.StringVar(&cfg.NetworkInterfaces, "network-interfaces", "", "comma-separated network interface allowlist; default excludes virtual/container interfaces")
	flag.StringVar(&cfg.DiskMounts, "disk-mounts", "", "comma-separated disk mount/path allowlist; default sums real filesystems")
	flag.Parse()
	if legacyInterval > 0 {
		cfg.StateInterval = legacyInterval
	}

	token, err := readToken(cfg.Token, cfg.TokenFile)
	if err != nil {
		log.Fatal(err)
	}
	cfg.Token = token
	if err := runPlatform(cfg); err != nil {
		log.Fatal(err)
	}
}

func runConsole(cfg config) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	return run(ctx, cfg)
}

func normalizeConfigIntervals(cfg *config) {
	if cfg.StateInterval <= 0 {
		cfg.StateInterval = defaultStateInterval
	}
	if cfg.HeartbeatInterval <= 0 {
		cfg.HeartbeatInterval = defaultHeartbeatInterval
	}
	if cfg.HostInterval <= 0 {
		cfg.HostInterval = defaultHostInterval
	}
	if cfg.IdentityRefreshInterval <= 0 {
		cfg.IdentityRefreshInterval = defaultIdentityRefreshInterval
	}
}

func run(ctx context.Context, cfg config) error {
	normalizeConfigIntervals(&cfg)
	client := agent.NewClient(cfg.ControllerURL, cfg.NodeID, cfg.Token)
	collector := agent.NewMetricsCollector(agent.MetricsOptions{NetworkInterfaceAllowlist: splitCommaList(cfg.NetworkInterfaces), DiskMountAllowlist: splitCommaList(cfg.DiskMounts)})
	probeManager := newProbeTargetManager()
	identityDiscoverer := agent.NewCachedNetworkIdentityDiscoverer(agent.NewNetworkIdentityDiscoverer(), cfg.IdentityRefreshInterval)

	refreshProbeConfig := func(ctx context.Context, requestedVersion int64) (int64, error) {
		return refreshProbeTargets(ctx, client, probeManager, requestedVersion)
	}

	if _, err := refreshProbeConfig(ctx, 0); err != nil {
		log.Printf("initial probe config fetch failed: %v", err)
	}
	if err := reportHeartbeat(ctx, client, cfg.Version); err != nil {
		log.Printf("initial heartbeat failed: %v", err)
	}
	if err := reportHost(ctx, client, collector, cfg.Version, identityDiscoverer); err != nil {
		log.Printf("initial host report failed: %v", err)
	}
	if err := reportState(ctx, client, collector); err != nil {
		log.Printf("initial state report failed: %v", err)
	}
	if err := runDueProbes(ctx, client, probeManager); err != nil {
		log.Printf("initial probe report failed: %v", err)
	}
	if cfg.Once {
		return nil
	}

	go client.RunPresence(ctx, refreshProbeConfig)
	go runPeriodic(ctx, cfg.StateInterval, func(ctx context.Context) error { return reportState(ctx, client, collector) }, "state report")
	go runPeriodic(ctx, cfg.HeartbeatInterval, func(ctx context.Context) error { return reportHeartbeat(ctx, client, cfg.Version) }, "heartbeat report")
	go runPeriodic(ctx, cfg.HostInterval, func(ctx context.Context) error {
		return reportHost(ctx, client, collector, cfg.Version, identityDiscoverer)
	}, "host report")
	go runPeriodicWithTimeout(ctx, time.Second, 30*time.Second, func(ctx context.Context) error { return runDueProbes(ctx, client, probeManager) }, "probe report")

	<-ctx.Done()
	return ctx.Err()
}

func runPeriodic(ctx context.Context, interval time.Duration, fn func(context.Context) error, label string) {
	runPeriodicWithTimeout(ctx, interval, perCallTimeout(interval), fn, label)
}

func runPeriodicWithTimeout(ctx context.Context, interval time.Duration, timeout time.Duration, fn func(context.Context) error, label string) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			callCtx, cancel := context.WithTimeout(ctx, timeout)
			if err := fn(callCtx); err != nil {
				log.Printf("%s failed: %v", label, err)
			}
			cancel()
		}
	}
}

func perCallTimeout(interval time.Duration) time.Duration {
	if interval <= 0 {
		return 20 * time.Second
	}
	if interval < 10*time.Second {
		return 10 * time.Second
	}
	if interval < 30*time.Second {
		return interval
	}
	return 30 * time.Second
}

type networkIdentityDiscoverer interface {
	Discover(context.Context) agent.NetworkIdentity
}

func reportHeartbeat(ctx context.Context, client *agent.Client, version string) error {
	now := time.Now().UTC()
	return client.PostHeartbeat(ctx, "online", version, now)
}

func reportHost(ctx context.Context, client *agent.Client, collector *agent.MetricsCollector, version string, identityDiscoverer networkIdentityDiscoverer) error {
	host := collector.CollectHost(version)
	if identityDiscoverer != nil {
		identity := identityDiscoverer.Discover(ctx)
		host.PublicIPv4 = identity.PublicIPv4
		host.PublicIPv6 = identity.PublicIPv6
		host.CountryCode = identity.CountryCode
	}
	return client.PostHost(ctx, host)
}

func reportState(ctx context.Context, client *agent.Client, collector *agent.MetricsCollector) error {
	now := time.Now().UTC()
	return client.PostState(ctx, collector.CollectState(now))
}

// reportOnce is retained for tests and one-off callers, but no longer drives the daemon loop.
func reportOnce(ctx context.Context, client *agent.Client, collector *agent.MetricsCollector, version string, includeHost bool, scheduler *agent.ProbeScheduler, identityDiscoverer networkIdentityDiscoverer) error {
	if err := reportHeartbeat(ctx, client, version); err != nil {
		return err
	}
	if includeHost {
		if err := reportHost(ctx, client, collector, version, identityDiscoverer); err != nil {
			return err
		}
	}
	if err := reportState(ctx, client, collector); err != nil {
		return err
	}
	targets, err := client.FetchProbeTargets(ctx)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	dueTargets := targets
	if scheduler != nil {
		dueTargets = scheduler.Due(targets, now)
	}
	dueTargets = agent.LimitProbeTargetsForRun(dueTargets)
	if len(dueTargets) > 0 {
		rounds := agent.ProbeTargets(ctx, dueTargets, now)
		if err := client.PostProbeResults(ctx, rounds); err != nil {
			return err
		}
		if scheduler != nil {
			scheduler.MarkCompleted(dueTargets, now)
		}
	}
	log.Printf("reported host/state and %d probe target(s)", len(dueTargets))
	return nil
}

func reportStateOnly(ctx context.Context, client *agent.Client, collector *agent.MetricsCollector) error {
	return reportState(ctx, client, collector)
}

type probeTargetManager struct {
	mu         sync.Mutex
	targets    []agent.ProbeTarget
	version    int64
	generation uint64
	scheduler  *agent.ProbeScheduler
}

type probeTargetBatch struct {
	targets    []agent.ProbeTarget
	version    int64
	generation uint64
}

func newProbeTargetManager() *probeTargetManager {
	return &probeTargetManager{scheduler: agent.NewProbeScheduler()}
}

func (m *probeTargetManager) update(targets []agent.ProbeTarget, version int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	sanitized := agent.SanitizeProbeTargets(targets)
	changed := version != m.version || !sameProbeTargets(m.targets, sanitized)
	m.targets = append(m.targets[:0], sanitized...)
	if changed {
		m.scheduler = agent.NewProbeScheduler()
		m.version = version
		m.generation++
	}
}

func (m *probeTargetManager) due(now time.Time) probeTargetBatch {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.targets) == 0 {
		return probeTargetBatch{version: m.version, generation: m.generation}
	}
	due := agent.LimitProbeTargetsForRun(m.scheduler.Due(m.targets, now))
	return probeTargetBatch{targets: append([]agent.ProbeTarget(nil), due...), version: m.version, generation: m.generation}
}

func (m *probeTargetManager) isCurrent(batch probeTargetBatch) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return batch.generation == m.generation && batch.version == m.version
}

func (m *probeTargetManager) markCompleted(batch probeTargetBatch, now time.Time) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if batch.generation != m.generation || batch.version != m.version {
		return false
	}
	m.scheduler.MarkCompleted(batch.targets, now)
	return true
}

func refreshProbeTargets(ctx context.Context, client *agent.Client, manager *probeTargetManager, requestedVersion int64) (int64, error) {
	response, err := client.FetchProbeConfig(ctx)
	if err != nil {
		return 0, err
	}
	if requestedVersion > 0 && response.Version < requestedVersion {
		return 0, fmt.Errorf("probe config version %d is older than requested version %d", response.Version, requestedVersion)
	}
	manager.update(response.Targets, response.Version)
	return response.Version, nil
}

func runDueProbes(ctx context.Context, client *agent.Client, manager *probeTargetManager) error {
	now := time.Now().UTC()
	batch := manager.due(now)
	if len(batch.targets) == 0 {
		return nil
	}
	rounds := agent.ProbeTargets(ctx, batch.targets, now)
	for index := range rounds {
		rounds[index].ConfigVersion = batch.version
	}
	if !manager.isCurrent(batch) {
		log.Printf("probe config changed while probes were running; discarded %d stale result round(s) for version %d", len(rounds), batch.version)
		return nil
	}
	if err := client.PostProbeResults(ctx, rounds); err != nil {
		return err
	}
	if !manager.markCompleted(batch, now) {
		log.Printf("probe config changed while probe results were uploading; skipped stale completion mark for version %d", batch.version)
	}
	return nil
}

func sameProbeTargets(left, right []agent.ProbeTarget) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if !sameProbeTarget(left[index], right[index]) {
			return false
		}
	}
	return true
}

func sameProbeTarget(left, right agent.ProbeTarget) bool {
	if left.ID != right.ID || left.Name != right.Name || left.Type != right.Type || left.Address != right.Address || left.Count != right.Count || left.TimeoutMS != right.TimeoutMS || left.IntervalSec != right.IntervalSec {
		return false
	}
	if left.Port == nil || right.Port == nil {
		return left.Port == nil && right.Port == nil
	}
	return *left.Port == *right.Port
}

func splitCommaList(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func readToken(token, tokenFile string) (string, error) {
	if tokenFile != "" {
		content, err := os.ReadFile(tokenFile)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(content)), nil
	}
	return strings.TrimSpace(token), nil
}
