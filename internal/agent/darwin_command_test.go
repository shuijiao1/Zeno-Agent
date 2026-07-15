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

func TestDarwinCommandStreamingParserHandlesOutputLargerThanScalarBuffer(t *testing.T) {
	parser := darwinConnectionParser{}
	err := darwinCommandScanLinesWithLimits(
		context.Background(),
		2*time.Second,
		10_000,
		4096,
		parser.consume,
		os.Args[0],
		"-test.run=^TestDarwinCommandHelperProcess$",
		"--",
		darwinCommandHelperMarker,
		"netstat",
	)
	if err != nil {
		t.Fatalf("stream netstat output: %v", err)
	}
	tcp, udp, err := parser.result()
	if err != nil {
		t.Fatalf("stream parser result: %v", err)
	}
	if tcp != 3000 || udp != 2000 {
		t.Fatalf("stream counts tcp=%d udp=%d, want 3000/2000", tcp, udp)
	}
}

func TestDarwinCommandStreamingParserEnforcesLineLimit(t *testing.T) {
	err := darwinCommandScanLinesWithLimits(
		context.Background(),
		2*time.Second,
		10,
		4096,
		func(string) error { return nil },
		os.Args[0],
		"-test.run=^TestDarwinCommandHelperProcess$",
		"--",
		darwinCommandHelperMarker,
		"netstat",
	)
	if err == nil || !errors.Is(err, errDarwinMetricsCommandLineLimit) {
		t.Fatalf("line-limit error = %v, want wrapped line-limit sentinel", err)
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
	case "netstat":
		fmt.Println("Proto Recv-Q Send-Q Local Address Foreign Address State")
		for i := 0; i < 3000; i++ {
			fmt.Printf("tcp4 0 0 127.0.0.1.%d *.* LISTEN\n", i+1000)
		}
		for i := 0; i < 2000; i++ {
			fmt.Printf("udp4 0 0 127.0.0.1.%d *.*\n", i+5000)
		}
	default:
		t.Fatalf("unknown helper mode %q", args[len(args)-1])
	}
}
