package agent

import (
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
)

var errDarwinMetricsCommandOutputLimit = errors.New("darwin metrics command output limit exceeded")

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
