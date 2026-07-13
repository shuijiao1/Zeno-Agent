//go:build darwin

package agent

import (
	"context"
	"fmt"
	"io"
	"os/exec"
	"time"
)

const (
	darwinMetricsCommandTimeout = 2 * time.Second
	darwinMetricsMaxOutputBytes = 64 << 10
)

func darwinCommandOutput(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), darwinMetricsCommandTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", err
	}
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		return "", err
	}
	output, readErr := io.ReadAll(io.LimitReader(stdout, darwinMetricsMaxOutputBytes+1))
	if int64(len(output)) > darwinMetricsMaxOutputBytes {
		cancel()
		_ = cmd.Wait()
		return "", fmt.Errorf("darwin metrics command %s output exceeds %d bytes", name, darwinMetricsMaxOutputBytes)
	}
	waitErr := cmd.Wait()
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	if readErr != nil {
		return "", readErr
	}
	if waitErr != nil {
		return "", waitErr
	}
	return string(output), nil
}
