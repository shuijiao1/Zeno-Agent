package main

import (
	"context"
	"flag"
	"hash/fnv"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"

	"github.com/shuijiao1/Zeno-Agent/internal/agent"
)

const defaultVersion = "zeno-agent-dev"
const defaultReportInterval = 2 * time.Second
const defaultFullReportInterval = 15 * time.Second

type config struct {
	ControllerURL           string
	NodeID                  string
	Token                   string
	TokenFile               string
	Interval                time.Duration
	Once                    bool
	Version                 string
	IdentityRefreshInterval time.Duration
}

func main() {
	cfg := config{}
	flag.StringVar(&cfg.ControllerURL, "controller-url", "http://127.0.0.1:18980", "Zeno controller base URL")
	flag.StringVar(&cfg.NodeID, "node-id", "hytron", "agent node id")
	flag.StringVar(&cfg.Token, "token", "", "agent bearer token; prefer -token-file")
	flag.StringVar(&cfg.TokenFile, "token-file", "", "file containing the agent bearer token")
	flag.DurationVar(&cfg.Interval, "interval", defaultReportInterval, "state refresh interval; host heartbeat and probe target refresh run every 15s")
	flag.BoolVar(&cfg.Once, "once", false, "collect and report once, then exit")
	flag.StringVar(&cfg.Version, "version", defaultVersion, "agent version string reported to controller")
	flag.DurationVar(&cfg.IdentityRefreshInterval, "identity-refresh-interval", 6*time.Hour, "public IPv4/IPv6 and GeoIP refresh interval; best-effort and cached")
	flag.Parse()

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

func run(ctx context.Context, cfg config) error {
	client := agent.NewClient(cfg.ControllerURL, cfg.NodeID, cfg.Token)
	collector := agent.NewMetricsCollector()
	scheduler := agent.NewProbeScheduler()
	identityDiscoverer := agent.NewCachedNetworkIdentityDiscoverer(agent.NewNetworkIdentityDiscoverer(), cfg.IdentityRefreshInterval)
	if cfg.Once {
		return reportOnce(ctx, client, collector, cfg.Version, true, scheduler, identityDiscoverer)
	}
	if cfg.Interval <= 0 {
		cfg.Interval = defaultReportInterval
	}
	if err := reportStateOnly(ctx, client, collector); err != nil {
		return err
	}

	var fullReportMu sync.Mutex
	fullReportRunning := false
	startFullReport := func() {
		fullReportMu.Lock()
		if fullReportRunning {
			fullReportMu.Unlock()
			return
		}
		fullReportRunning = true
		fullReportMu.Unlock()
		go func() {
			defer func() {
				fullReportMu.Lock()
				fullReportRunning = false
				fullReportMu.Unlock()
			}()
			if err := reportFull(ctx, client, collector, cfg.Version, true, scheduler, identityDiscoverer); err != nil && ctx.Err() == nil {
				log.Printf("full report failed: %v", err)
			}
		}()
	}
	startFullReport()
	if delay := reportJitter(cfg.NodeID, cfg.Interval); delay > 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
	}

	stateTicker := time.NewTicker(cfg.Interval)
	defer stateTicker.Stop()
	fullTicker := time.NewTicker(defaultFullReportInterval)
	defer fullTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-stateTicker.C:
			if err := reportStateOnly(ctx, client, collector); err != nil {
				log.Printf("state report failed: %v", err)
			}
		case <-fullTicker.C:
			startFullReport()
		}
	}
}

type networkIdentityDiscoverer interface {
	Discover(context.Context) agent.NetworkIdentity
}

func reportJitter(nodeID string, interval time.Duration) time.Duration {
	if interval <= 0 {
		return 0
	}
	h := fnv.New64a()
	_, _ = h.Write([]byte(strings.TrimSpace(nodeID)))
	return time.Duration(h.Sum64() % uint64(interval))
}

func reportOnce(ctx context.Context, client *agent.Client, collector *agent.MetricsCollector, version string, includeHost bool, scheduler *agent.ProbeScheduler, identityDiscoverer networkIdentityDiscoverer) error {
	now := time.Now().UTC()
	if err := client.PostHeartbeat(ctx, "online", version, now); err != nil {
		return err
	}
	if includeHost {
		host := collector.CollectHost(version)
		if identityDiscoverer != nil {
			identity := identityDiscoverer.Discover(ctx)
			host.PublicIPv4 = identity.PublicIPv4
			host.PublicIPv6 = identity.PublicIPv6
			host.CountryCode = identity.CountryCode
		}
		if err := client.PostHost(ctx, host); err != nil {
			return err
		}
	}
	if err := client.PostState(ctx, collector.CollectState(now)); err != nil {
		return err
	}
	targets, err := client.FetchProbeTargets(ctx)
	if err != nil {
		return err
	}
	dueTargets := targets
	if scheduler != nil {
		dueTargets = scheduler.Due(targets, now)
	}
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

func reportFull(ctx context.Context, client *agent.Client, collector *agent.MetricsCollector, version string, includeHost bool, scheduler *agent.ProbeScheduler, identityDiscoverer networkIdentityDiscoverer) error {
	now := time.Now().UTC()
	if err := client.PostHeartbeat(ctx, "online", version, now); err != nil {
		return err
	}
	if includeHost {
		host := collector.CollectHost(version)
		if identityDiscoverer != nil {
			identity := identityDiscoverer.Discover(ctx)
			host.PublicIPv4 = identity.PublicIPv4
			host.PublicIPv6 = identity.PublicIPv6
			host.CountryCode = identity.CountryCode
		}
		if err := client.PostHost(ctx, host); err != nil {
			return err
		}
	}
	targets, err := client.FetchProbeTargets(ctx)
	if err != nil {
		return err
	}
	dueTargets := targets
	if scheduler != nil {
		dueTargets = scheduler.Due(targets, now)
	}
	if len(dueTargets) > 0 {
		rounds := agent.ProbeTargets(ctx, dueTargets, now)
		if err := client.PostProbeResults(ctx, rounds); err != nil {
			return err
		}
		if scheduler != nil {
			scheduler.MarkCompleted(dueTargets, now)
		}
	}
	log.Printf("reported host and %d probe target(s)", len(dueTargets))
	return nil
}

func reportStateOnly(ctx context.Context, client *agent.Client, collector *agent.MetricsCollector) error {
	now := time.Now().UTC()
	return client.PostState(ctx, collector.CollectState(now))
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
