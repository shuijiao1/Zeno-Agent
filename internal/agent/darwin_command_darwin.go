//go:build darwin

package agent

import "context"

func darwinCommandOutput(name string, args ...string) (string, error) {
	return darwinCommandOutputWithLimits(context.Background(), darwinMetricsCommandTimeout, darwinMetricsMaxOutputBytes, name, args...)
}
