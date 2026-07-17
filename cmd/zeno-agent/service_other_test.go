//go:build !windows

package main

import (
	"bufio"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

func TestUnixRunConsoleHandlesSIGTERMAsCleanShutdown(t *testing.T) {
	if os.Getenv("ZENO_SIGTERM_HELPER") == "1" {
		fmt.Println("ready")
		err := runConsole(config{
			ControllerURL:           os.Getenv("ZENO_SIGTERM_CONTROLLER"),
			NodeID:                  "signal-test",
			Token:                   "signal-token",
			DataDir:                 os.Getenv("ZENO_SIGTERM_DATA_DIR"),
			StateInterval:           time.Hour,
			HeartbeatInterval:       time.Hour,
			HostInterval:            time.Hour,
			IdentityRefreshInterval: time.Hour,
		}, os.Interrupt, syscall.SIGTERM)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		os.Exit(0)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/agent/v1/probe-targets":
			_, _ = w.Write([]byte(`{"version":0,"targets":[]}`))
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer server.Close()

	cmd := exec.Command(os.Args[0], "-test.run=^TestUnixRunConsoleHandlesSIGTERMAsCleanShutdown$")
	cmd.Env = append(os.Environ(),
		"ZENO_SIGTERM_HELPER=1",
		"ZENO_SIGTERM_CONTROLLER="+server.URL,
		"ZENO_SIGTERM_DATA_DIR="+t.TempDir(),
	)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	scanner := bufio.NewScanner(stdout)
	if !scanner.Scan() || scanner.Text() != "ready" {
		_ = cmd.Process.Kill()
		t.Fatalf("signal helper did not become ready: %v", scanner.Err())
	}
	// The helper prints before entering runConsole; give signal.NotifyContext a
	// brief deterministic window to install the SIGTERM handler.
	time.Sleep(100 * time.Millisecond)
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		_ = cmd.Process.Kill()
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("SIGTERM helper did not exit cleanly: %v", err)
		}
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("SIGTERM helper did not stop promptly")
	}
}
