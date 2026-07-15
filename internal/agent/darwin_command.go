package agent

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"
)

const (
	darwinMetricsCommandTimeout = 2 * time.Second
	darwinMetricsMaxOutputBytes = 64 << 10
	darwinMetricsMaxLines       = 1 << 20
	darwinMetricsMaxLineBytes   = 1 << 20
)

var errDarwinMetricsCommandOutputLimit = errors.New("darwin metrics command output limit exceeded")
var errDarwinMetricsCommandLineLimit = errors.New("darwin metrics command line limit exceeded")

// darwinCommandOutputWithLimits is kept platform-neutral so the timeout and
// output-bound behavior can be exercised by real unit tests on every CI host.
// The Darwin collectors call it through darwinCommandOutput above.
func darwinCommandOutputWithLimits(parent context.Context, timeout time.Duration, maxOutputBytes int64, name string, args ...string) (string, error) {
	if parent == nil {
		parent = context.Background()
	}
	if timeout <= 0 {
		return "", fmt.Errorf("darwin metrics command %s has invalid timeout %s", name, timeout)
	}
	if maxOutputBytes < 0 {
		return "", fmt.Errorf("darwin metrics command %s has invalid output limit %d", name, maxOutputBytes)
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
	// Bound how long Wait may spend on inherited stdout descriptors after the
	// command is killed. This matters for shell commands that leave descendants
	// behind with the pipe still open.
	cmd.WaitDelay = 250 * time.Millisecond
	output := &boundedCommandOutput{maxBytes: maxOutputBytes, cancel: cancel}
	cmd.Stdout = output
	cmd.Stderr = io.Discard
	runErr := cmd.Run()
	if output.exceeded {
		return "", fmt.Errorf("darwin metrics command %s output exceeds %d bytes: %w", name, maxOutputBytes, errDarwinMetricsCommandOutputLimit)
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return "", fmt.Errorf("darwin metrics command %s did not finish within %s: %w", name, timeout, ctxErr)
	}
	if runErr != nil {
		return "", fmt.Errorf("darwin metrics command %s failed: %w", name, runErr)
	}
	return output.String(), nil
}

// darwinCommandScanLinesWithLimits streams line-oriented command output to a
// parser without imposing the small aggregate buffer used by scalar sysctl
// commands. It remains bounded by both line count and individual line size, so
// a busy host can expose a large netstat result without unbounded allocation.
func darwinCommandScanLinesWithLimits(parent context.Context, timeout time.Duration, maxLines, maxLineBytes int, visit func(string) error, name string, args ...string) error {
	if parent == nil {
		parent = context.Background()
	}
	if timeout <= 0 || maxLines <= 0 || maxLineBytes <= 0 || visit == nil {
		return fmt.Errorf("darwin metrics command %s has invalid streaming limits", name)
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
	cmd.Stderr = io.Discard
	cmd.WaitDelay = 250 * time.Millisecond
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("darwin metrics command %s stdout pipe: %w", name, err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("darwin metrics command %s failed to start: %w", name, err)
	}

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 64<<10), maxLineBytes)
	lineCount := 0
	var parseErr error
	for scanner.Scan() {
		lineCount++
		if lineCount > maxLines {
			parseErr = fmt.Errorf("darwin metrics command %s exceeds %d lines: %w", name, maxLines, errDarwinMetricsCommandLineLimit)
			cancel()
			break
		}
		if err := visit(scanner.Text()); err != nil {
			parseErr = err
			cancel()
			break
		}
	}
	if parseErr == nil {
		if err := scanner.Err(); err != nil {
			parseErr = fmt.Errorf("darwin metrics command %s output scan failed: %w", name, err)
			cancel()
		}
	}
	runErr := cmd.Wait()
	if parseErr != nil {
		return parseErr
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return fmt.Errorf("darwin metrics command %s did not finish within %s: %w", name, timeout, ctxErr)
	}
	if runErr != nil {
		return fmt.Errorf("darwin metrics command %s failed: %w", name, runErr)
	}
	return nil
}

type boundedCommandOutput struct {
	buffer   bytes.Buffer
	maxBytes int64
	exceeded bool
	cancel   context.CancelFunc
}

func (w *boundedCommandOutput) Write(payload []byte) (int, error) {
	if w.exceeded {
		return 0, errDarwinMetricsCommandOutputLimit
	}
	remaining := w.maxBytes - int64(w.buffer.Len())
	if remaining < int64(len(payload)) {
		written := 0
		if remaining > 0 {
			written, _ = w.buffer.Write(payload[:int(remaining)])
		}
		w.exceeded = true
		if w.cancel != nil {
			w.cancel()
		}
		return written, errDarwinMetricsCommandOutputLimit
	}
	return w.buffer.Write(payload)
}

func (w *boundedCommandOutput) String() string {
	return w.buffer.String()
}
