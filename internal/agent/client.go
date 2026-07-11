package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Client struct {
	baseURL string
	nodeID  string
	token   string
	http    *http.Client
}

const maxAgentAPIJSONBodyBytes int64 = 1 << 20

func NewClient(baseURL, nodeID, token string) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		nodeID:  strings.TrimSpace(nodeID),
		token:   strings.TrimSpace(token),
		http:    &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *Client) PostHeartbeat(ctx context.Context, status, version string, ts time.Time) error {
	return c.doJSON(ctx, http.MethodPost, "/api/agent/v1/heartbeat", HeartbeatRequest{TS: ts.UTC().Unix(), Status: status, AgentVersion: version}, nil)
}

func (c *Client) PostHost(ctx context.Context, host HostInfo) error {
	return c.doJSON(ctx, http.MethodPost, "/api/agent/v1/host", host, nil)
}

func (c *Client) PostState(ctx context.Context, state StateSample) error {
	return c.doJSON(ctx, http.MethodPost, "/api/agent/v1/state", state, nil)
}

func (c *Client) FetchProbeTargets(ctx context.Context) ([]ProbeTarget, error) {
	response, err := c.FetchProbeConfig(ctx)
	if err != nil {
		return nil, err
	}
	return response.Targets, nil
}

func (c *Client) FetchProbeConfig(ctx context.Context) (ProbeTargetsResponse, error) {
	var response ProbeTargetsResponse
	if err := c.doJSON(ctx, http.MethodGet, "/api/agent/v1/probe-targets", nil, &response); err != nil {
		return ProbeTargetsResponse{}, err
	}
	response.Targets = SanitizeProbeTargets(response.Targets)
	return response, nil
}

func (c *Client) PostProbeResults(ctx context.Context, rounds []ProbeRound) error {
	configVersion, err := commonProbeConfigVersion(rounds)
	if err != nil {
		return err
	}
	payload := ProbeResultsRequest{ConfigVersion: configVersion, Rounds: make([]probeRoundPayload, 0, len(rounds))}
	for _, round := range rounds {
		payload.Rounds = append(payload.Rounds, probeRoundPayload{
			RoundID:  round.RoundID,
			TargetID: round.TargetID,
			TS:       round.TS.UTC().Unix(),
			Type:     round.Type,
			Samples:  round.Samples,
		})
	}
	return c.doJSON(ctx, http.MethodPost, "/api/agent/v1/probe-results", payload, nil)
}

func commonProbeConfigVersion(rounds []ProbeRound) (int64, error) {
	if len(rounds) == 0 {
		return 0, nil
	}
	version := rounds[0].ConfigVersion
	if version < 0 {
		return 0, fmt.Errorf("invalid probe config version %d", version)
	}
	for _, round := range rounds[1:] {
		if round.ConfigVersion < 0 {
			return 0, fmt.Errorf("invalid probe config version %d", round.ConfigVersion)
		}
		if version != round.ConfigVersion {
			return 0, fmt.Errorf("mixed probe config versions %d and %d", version, round.ConfigVersion)
		}
	}
	return version, nil
}

func (c *Client) PresenceWebSocketURL() (string, error) {
	parsed, err := url.Parse(c.baseURL)
	if err != nil {
		return "", err
	}
	switch parsed.Scheme {
	case "http":
		parsed.Scheme = "ws"
	case "https":
		parsed.Scheme = "wss"
	case "ws", "wss":
	default:
		return "", fmt.Errorf("unsupported controller url scheme %q", parsed.Scheme)
	}
	parsed.Path = "/api/agent/v1/presence/ws"
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String(), nil
}

func (c *Client) setAuthHeaders(header http.Header) {
	header.Set("X-Node-ID", c.nodeID)
	header.Set("Authorization", "Bearer "+c.token)
}

func (c *Client) doJSON(ctx context.Context, method, path string, requestValue any, responseValue any) error {
	if c.baseURL == "" || c.nodeID == "" || c.token == "" {
		return fmt.Errorf("controller url, node id, and token are required")
	}
	var body io.Reader
	if requestValue != nil {
		encoded, err := json.Marshal(requestValue)
		if err != nil {
			return err
		}
		body = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return err
	}
	c.setAuthHeaders(req.Header)
	if requestValue != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// The Controller response is not trusted diagnostic text: it may be very
		// large or contain a proxy error page with credentials. Drain only a small
		// bounded prefix for connection reuse and report status/path without body.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		return fmt.Errorf("agent api %s %s returned %d", method, path, resp.StatusCode)
	}
	if responseValue == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		return nil
	}
	responseBody, err := io.ReadAll(io.LimitReader(resp.Body, maxAgentAPIJSONBodyBytes+1))
	if err != nil {
		return err
	}
	if int64(len(responseBody)) > maxAgentAPIJSONBodyBytes {
		return fmt.Errorf("agent api %s %s response exceeds %d bytes", method, path, maxAgentAPIJSONBodyBytes)
	}
	return json.Unmarshal(responseBody, responseValue)
}
