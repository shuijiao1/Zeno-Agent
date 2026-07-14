package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

const darwinCommandHelperMarker = "zeno-darwin-command-helper"

func TestDarwinCommandOutputPropagatesTimeout(t *testing.T) {
	_, err := darwinCommandOutputWithLimits(
		context.Background(),
		150*time.Millisecond,
		1024,
		os.Args[0],
		"-test.run=^TestDarwinCommandHelperProcess$",
		"--",
		darwinCommandHelperMarker,
		"sleep",
	)
	if err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout error = %v, want wrapped context deadline exceeded", err)
	}
	if !strings.Contains(err.Error(), "did not finish within") {
		t.Fatalf("timeout error = %v, want explicit command timeout diagnostic", err)
	}
}

func TestDarwinCommandOutputPropagatesOutputLimit(t *testing.T) {
	_, err := darwinCommandOutputWithLimits(
		context.Background(),
		2*time.Second,
		darwinMetricsMaxOutputBytes,
		os.Args[0],
		"-test.run=^TestDarwinCommandHelperProcess$",
		"--",
		darwinCommandHelperMarker,
		"output",
	)
	if err == nil || !errors.Is(err, errDarwinMetricsCommandOutputLimit) {
		t.Fatalf("output-limit error = %v, want wrapped limit sentinel", err)
	}
	if !strings.Contains(err.Error(), fmt.Sprintf("exceeds %d bytes", darwinMetricsMaxOutputBytes)) {
		t.Fatalf("output-limit error = %v, want explicit byte-limit diagnostic", err)
	}
}

func TestDarwinCommandOutputReturnsBoundedSuccess(t *testing.T) {
	output, err := darwinCommandOutputWithLimits(
		context.Background(),
		2*time.Second,
		4096,
		os.Args[0],
		"-test.run=^TestDarwinCommandHelperProcess$",
		"--",
		darwinCommandHelperMarker,
		"success",
	)
	if err != nil {
		t.Fatalf("bounded command success: %v", err)
	}
	if !strings.Contains(output, "darwin-command-ok") {
		t.Fatalf("bounded command output = %q, want helper marker", output)
	}
}

func TestDarwinCommandHelperProcess(t *testing.T) {
	args := os.Args
	if len(args) < 2 || args[len(args)-2] != darwinCommandHelperMarker {
		return
	}
	switch args[len(args)-1] {
	case "sleep":
		time.Sleep(5 * time.Second)
	case "output":
		fmt.Print(strings.Repeat("x", darwinMetricsMaxOutputBytes+1))
	case "success":
		fmt.Print("darwin-command-ok")
	default:
		t.Fatalf("unknown helper mode %q", args[len(args)-1])
	}
}
