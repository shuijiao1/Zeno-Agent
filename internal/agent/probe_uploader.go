package agent

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	probeResultsPath          = "/api/agent/v1/probe-results"
	maxProbeUploadBackoff     = 5 * time.Minute
	defaultProbeUploadPolling = time.Second
)

// ProbeUploaderOptions contains injectable timing behavior. Jitter receives the
// exponential-backoff cap and must return a duration in [0, cap]. Values from a
// faulty hook are clamped to that range.
type ProbeUploaderOptions struct {
	Now          func() time.Time
	Jitter       func(time.Duration) time.Duration
	PollInterval time.Duration
	// OnRejected is called after a terminal response has been durably moved to
	// quarantine. It is intended for bounded reactions such as refreshing probe
	// config after stale_probe_config; retryable outcomes never invoke it.
	OnRejected func(context.Context, error)
}

// ProbeUploader durably uploads the oldest due probe batch. A single uploader
// serializes UploadOne calls so that one spool item cannot be sent concurrently
// by two goroutines in the same process.
type ProbeUploader struct {
	spool        *ProbeSpool
	client       *Client
	now          func() time.Time
	jitter       func(time.Duration) time.Duration
	pollInterval time.Duration
	onRejected   func(context.Context, error)
	mu           sync.Mutex
}

// ProbeUploadRetryError reports a failure that was retained in the spool with
// durable retry metadata. It deliberately does not retain the transport error
// or response body, either of which may contain untrusted or secret text.
type ProbeUploadRetryError struct {
	StatusCode int
	Attempt    uint32
	NextAt     time.Time
	Timeout    bool
}

func (e *ProbeUploadRetryError) Error() string {
	if e.StatusCode != 0 {
		return fmt.Sprintf("probe upload returned retryable status %d; retry scheduled", e.StatusCode)
	}
	if e.Timeout {
		return "probe upload timed out; retry scheduled"
	}
	return "probe upload transport failed; retry scheduled"
}

func (e *ProbeUploadRetryError) Unwrap() error {
	if e.StatusCode == 0 {
		return nil
	}
	return &AgentAPIStatusError{Method: http.MethodPost, Path: probeResultsPath, StatusCode: e.StatusCode}
}

func (e *ProbeUploadRetryError) Is(target error) bool {
	return e.Timeout && target == context.DeadlineExceeded
}

// ProbeUploadStaleError is returned for a 409 after the rejected batch has been
// quarantined. Callers can use this typed signal to refresh stale probe config.
type ProbeUploadStaleError struct {
	StatusCode int
}

func (e *ProbeUploadStaleError) Error() string {
	return "probe upload conflicts with the controller probe configuration"
}

func (e *ProbeUploadStaleError) Unwrap() error {
	status := e.StatusCode
	if status == 0 {
		status = http.StatusConflict
	}
	return &AgentAPIStatusError{Method: http.MethodPost, Path: probeResultsPath, StatusCode: status}
}

// ProbeUploadRoundConflictError is terminal: a Controller already has the same
// round ID with different content. Retrying identical bytes cannot resolve it,
// and refreshing target config is unrelated, so the exact batch is quarantined
// for finite operator diagnosis.
type ProbeUploadRoundConflictError struct{}

func (e *ProbeUploadRoundConflictError) Error() string {
	return "probe upload round ID conflicts with different controller content"
}

func (e *ProbeUploadRoundConflictError) Unwrap() error {
	return &AgentAPIStatusError{Method: http.MethodPost, Path: probeResultsPath, StatusCode: http.StatusConflict}
}

func NewProbeUploader(spool *ProbeSpool, client *Client, options ProbeUploaderOptions) *ProbeUploader {
	now := options.Now
	if now == nil {
		now = time.Now
	}
	jitter := options.Jitter
	if jitter == nil {
		jitter = randomProbeUploadJitter
	}
	pollInterval := options.PollInterval
	if pollInterval <= 0 {
		pollInterval = defaultProbeUploadPolling
	}
	return &ProbeUploader{
		spool:        spool,
		client:       client,
		now:          now,
		jitter:       jitter,
		pollInterval: pollInterval,
		onRejected:   options.OnRejected,
	}
}

// UploadOne uploads at most one due item. A nil result means either there was
// no due work or the item was accepted with a 2xx response.
func (u *ProbeUploader) UploadOne(ctx context.Context) error {
	_, err := u.uploadOne(ctx)
	return err
}

func (u *ProbeUploader) uploadOne(ctx context.Context) (bool, error) {
	if ctx == nil {
		return false, fmt.Errorf("probe upload context is required")
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}

	u.mu.Lock()
	defer u.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if u.spool == nil || u.client == nil {
		return false, fmt.Errorf("probe uploader requires a spool and client")
	}

	now := u.now().UTC()
	item, err := u.spool.Next(now)
	if err != nil {
		return false, fmt.Errorf("read probe upload spool: %w", err)
	}
	if item == nil {
		return false, nil
	}

	status, retryAfter, responseCode, transportErr := u.postBody(ctx, item.Body)
	if transportErr != nil {
		// An operator cancellation is not an upload failure and must not consume
		// an attempt. Deadline expiry is a retryable network timeout.
		if errors.Is(ctx.Err(), context.Canceled) {
			return true, context.Canceled
		}
		timedOut := errors.Is(transportErr, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded)
		return true, u.scheduleRetry(item, now, "", 0, timedOut)
	}

	if status >= http.StatusOK && status < http.StatusMultipleChoices {
		if err := u.spool.Ack(item.ID); err != nil {
			return true, fmt.Errorf("acknowledge accepted probe upload: %w", err)
		}
		return true, nil
	}

	if isRetryableProbeUploadStatus(status) {
		return true, u.scheduleRetry(item, now, retryAfter, status, false)
	}

	reason := "http-" + strconv.Itoa(status)
	if status == http.StatusConflict && (responseCode == "stale_probe_config" || responseCode == "probe_round_conflict") {
		reason += "-" + responseCode
	}
	if err := u.spool.Quarantine(item.ID, reason); err != nil {
		return true, fmt.Errorf("quarantine probe upload rejected with status %d: %w", status, err)
	}
	if status == http.StatusConflict {
		switch responseCode {
		case "stale_probe_config":
			return true, &ProbeUploadStaleError{StatusCode: status}
		case "probe_round_conflict":
			return true, &ProbeUploadRoundConflictError{}
		}
	}
	return true, &AgentAPIStatusError{Method: http.MethodPost, Path: probeResultsPath, StatusCode: status}
}

// Run drains due work and sleeps without busy-waiting when the spool is empty
// or all retained items are retry-gated. Cancellation always terminates it.
func (u *ProbeUploader) Run(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("probe upload context is required")
	}
	for {
		worked, err := u.uploadOne(ctx)
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		if err != nil {
			// HTTP outcomes and scheduled transport retries have already moved
			// or retry-gated the item. Local spool/client failures have not and
			// must stop the runner rather than spin on the same due item.
			var statusErr *AgentAPIStatusError
			var retryErr *ProbeUploadRetryError
			if !errors.As(err, &statusErr) && !errors.As(err, &retryErr) {
				return err
			}
			if retryErr == nil && u.onRejected != nil {
				u.onRejected(ctx, err)
			}
		}
		if worked {
			continue
		}

		timer := time.NewTimer(u.pollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-u.spool.notify:
			timer.Stop()
		case <-timer.C:
		}
	}
}

func (u *ProbeUploader) postBody(ctx context.Context, body []byte) (int, string, string, error) {
	client := u.client
	if client.baseURL == "" || client.nodeID == "" || client.token == "" {
		return 0, "", "", fmt.Errorf("probe uploader client is not configured")
	}
	if err := ValidateControllerURLWithOptions(client.baseURL, client.allowInsecureHTTP); err != nil {
		return 0, "", "", err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, client.baseURL+probeResultsPath, bytes.NewReader(body))
	if err != nil {
		return 0, "", "", err
	}
	client.setAuthHeaders(request.Header)
	request.Header.Set("Content-Type", "application/json")
	if client.http == nil {
		return 0, "", "", fmt.Errorf("probe uploader http client is not configured")
	}
	response, err := client.http.Do(request)
	if err != nil {
		return 0, "", "", err
	}
	defer response.Body.Close()
	retryAfter := response.Header.Get("Retry-After")
	// Only two fixed 409 protocol codes influence behavior. Parse a bounded JSON
	// prefix and never return or log arbitrary Controller response text.
	const maxResponseBytes = 4 << 10
	responseBody, readErr := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if readErr != nil {
		return 0, "", "", readErr
	}
	responseCode := ""
	if len(responseBody) <= maxResponseBytes && response.StatusCode == http.StatusConflict {
		var payload struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(responseBody, &payload) == nil {
			switch payload.Error {
			case "stale_probe_config", "probe_round_conflict":
				responseCode = payload.Error
			}
		}
	}
	return response.StatusCode, retryAfter, responseCode, nil
}

func (u *ProbeUploader) scheduleRetry(item *ProbeSpoolItem, now time.Time, retryAfter string, status int, timedOut bool) error {
	attempt := item.Attempt
	if attempt != ^uint32(0) {
		attempt++
	}
	delay, validRetryAfter := parseProbeRetryAfter(retryAfter, now)
	if !validRetryAfter {
		limit := probeUploadBackoff(attempt)
		delay = u.jitter(limit)
		if delay < 0 {
			delay = 0
		}
		if delay > limit {
			delay = limit
		}
	}
	nextAt := now.Add(delay).UTC()
	if err := u.spool.ScheduleRetry(item.ID, attempt, nextAt); err != nil {
		return fmt.Errorf("persist probe upload retry: %w", err)
	}
	return &ProbeUploadRetryError{StatusCode: status, Attempt: attempt, NextAt: nextAt, Timeout: timedOut}
}

func isRetryableProbeUploadStatus(status int) bool {
	return status == http.StatusRequestTimeout || status == http.StatusTooManyRequests ||
		status >= http.StatusInternalServerError && status <= 599
}

func probeUploadBackoff(attempt uint32) time.Duration {
	if attempt == 0 {
		attempt = 1
	}
	delay := time.Second
	for step := uint32(1); step < attempt; step++ {
		if delay >= maxProbeUploadBackoff/2 {
			return maxProbeUploadBackoff
		}
		delay *= 2
	}
	if delay > maxProbeUploadBackoff {
		return maxProbeUploadBackoff
	}
	return delay
}

func parseProbeRetryAfter(value string, now time.Time) (time.Duration, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, false
	}
	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil {
		if seconds < 0 {
			return 0, false
		}
		delay := time.Duration(seconds) * time.Second
		if seconds > int64(maxProbeUploadBackoff/time.Second) || delay > maxProbeUploadBackoff {
			return maxProbeUploadBackoff, true
		}
		return delay, true
	} else if allASCIIDigits(value) {
		// A syntactically valid but overflowing delta is certainly over the cap.
		return maxProbeUploadBackoff, true
	}
	when, err := http.ParseTime(value)
	if err != nil {
		return 0, false
	}
	delay := when.Sub(now)
	if delay < 0 {
		delay = 0
	}
	if delay > maxProbeUploadBackoff {
		delay = maxProbeUploadBackoff
	}
	return delay, true
}

func allASCIIDigits(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func randomProbeUploadJitter(limit time.Duration) time.Duration {
	if limit <= 0 {
		return 0
	}
	value, err := cryptorand.Int(cryptorand.Reader, big.NewInt(int64(limit)+1))
	if err != nil {
		// A failed random source must not collapse retries into a hot loop.
		return limit
	}
	return time.Duration(value.Int64())
}
