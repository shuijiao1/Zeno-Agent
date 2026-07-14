package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestRunPresenceOnceTimesOutIdleConnection(t *testing.T) {
	oldReadTimeout := presenceReadTimeout
	presenceReadTimeout = 50 * time.Millisecond
	t.Cleanup(func() { presenceReadTimeout = oldReadTimeout })

	upgrader := websocket.Upgrader{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		<-r.Context().Done()
	}))
	defer server.Close()

	client := NewClient(server.URL, "hytron", "token")
	started := time.Now()
	err := client.runPresenceOnce(context.Background(), nil)
	if err == nil {
		t.Fatal("runPresenceOnce returned nil, want idle read timeout")
	}
	if !strings.Contains(err.Error(), "timeout") {
		t.Fatalf("runPresenceOnce error = %v, want timeout", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("runPresenceOnce elapsed %s, want quick timeout", elapsed)
	}
}

func TestRunPresenceOnceExtendsDeadlineOnServerPing(t *testing.T) {
	oldReadTimeout := presenceReadTimeout
	oldWriteTimeout := presenceWriteTimeout
	presenceReadTimeout = 50 * time.Millisecond
	presenceWriteTimeout = 50 * time.Millisecond
	t.Cleanup(func() {
		presenceReadTimeout = oldReadTimeout
		presenceWriteTimeout = oldWriteTimeout
	})

	upgrader := websocket.Upgrader{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		for i := 0; i < 3; i++ {
			deadline := time.Now().Add(50 * time.Millisecond)
			if err := conn.WriteControl(websocket.PingMessage, []byte("keepalive"), deadline); err != nil {
				return
			}
			time.Sleep(25 * time.Millisecond)
		}
		_ = conn.WriteControl(websocket.CloseMessage, []byte{}, time.Now().Add(50*time.Millisecond))
	}))
	defer server.Close()

	client := NewClient(server.URL, "hytron", "token")
	started := time.Now()
	err := client.runPresenceOnce(context.Background(), nil)
	if err == nil {
		t.Fatal("runPresenceOnce returned nil, want close error")
	}
	if elapsed := time.Since(started); elapsed < 70*time.Millisecond {
		t.Fatalf("runPresenceOnce elapsed %s, deadline was not extended by pings", elapsed)
	}
}

func TestRunPresenceOnceRejectsOversizedMessage(t *testing.T) {
	oldReadLimit := presenceReadLimit
	presenceReadLimit = 32
	t.Cleanup(func() { presenceReadLimit = oldReadLimit })

	upgrader := websocket.Upgrader{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"config_changed","version":123,"padding":"too-large"}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "hytron", "token")
	err := client.runPresenceOnce(context.Background(), nil)
	if err == nil {
		t.Fatal("runPresenceOnce returned nil, want read limit error")
	}
	if !strings.Contains(err.Error(), "read limit") {
		t.Fatalf("runPresenceOnce error = %v, want read limit error", err)
	}
}

func TestRunPresenceLoopResetsBackoffAfterStableConnection(t *testing.T) {
	client := NewClient("http://127.0.0.1", "hytron", "token")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	times := []time.Time{
		time.Unix(0, 0), time.Unix(0, 0),
		time.Unix(1, 0), time.Unix(1, 0),
		time.Unix(2, 0), time.Unix(12, 0),
	}
	timeIndex := 0
	waits := make([]time.Duration, 0, 3)
	client.runPresenceLoop(ctx, nil, presenceLoopOptions{
		runOnce: func(context.Context, PresenceConfigHandler) error { return context.Canceled },
		now: func() time.Time {
			value := times[timeIndex]
			timeIndex++
			return value
		},
		sleep: func(_ context.Context, delay time.Duration) bool {
			waits = append(waits, delay)
			if len(waits) == 3 {
				cancel()
				return false
			}
			return true
		},
		jitter:                   func(time.Duration) time.Duration { return 0 },
		initialBackoff:           time.Second,
		maxBackoff:               30 * time.Second,
		stableConnectionDuration: 10 * time.Second,
	})

	want := []time.Duration{time.Second, 2 * time.Second, time.Second}
	if len(waits) != len(want) {
		t.Fatalf("presence reconnect waits = %v, want %v", waits, want)
	}
	for index := range want {
		if waits[index] != want[index] {
			t.Fatalf("presence reconnect waits = %v, want %v", waits, want)
		}
	}
}

func TestRunPresenceOnceDoesNotRefreshOrACKConfigOnConnect(t *testing.T) {
	var configCalls atomic.Int64
	upgrader := websocket.Upgrader{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.WriteControl(websocket.CloseMessage, []byte{}, time.Now().Add(time.Second))
	}))
	defer server.Close()

	client := NewClient(server.URL, "hytron", "token")
	_ = client.runPresenceOnce(context.Background(), func(context.Context, int64) (int64, error) {
		configCalls.Add(1)
		return 9, nil
	})
	if calls := configCalls.Load(); calls != 0 {
		t.Fatalf("config handler calls on websocket connect = %d, want 0; ACKs must follow config_changed only", calls)
	}
}

func TestRunPresenceOnceACKsOnlySuccessfullyAppliedRequestedConfig(t *testing.T) {
	upgrader := websocket.Upgrader{}
	ackCh := make(chan map[string]any, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		if err := conn.WriteJSON(PresenceServerMessage{Type: "config_changed", Version: 0}); err != nil {
			return
		}
		_, payload, err := conn.ReadMessage()
		if err != nil {
			return
		}
		var ack map[string]any
		if json.Unmarshal(payload, &ack) == nil {
			ackCh <- ack
		}
		_ = conn.WriteControl(websocket.CloseMessage, []byte{}, time.Now().Add(time.Second))
	}))
	defer server.Close()

	client := NewClient(server.URL, "hytron", "token")
	_ = client.runPresenceOnce(context.Background(), func(_ context.Context, requested int64) (int64, error) {
		if requested != 0 {
			t.Errorf("requested version = %d, want legacy version 0", requested)
		}
		return 0, nil
	})
	select {
	case ack := <-ackCh:
		if ack["type"] != "config_applied" {
			t.Fatalf("ACK type = %v, want config_applied", ack["type"])
		}
		version, exists := ack["version"]
		if !exists || version != float64(0) {
			t.Fatalf("legacy ACK version = %v (exists=%v), want explicit 0", version, exists)
		}
	case <-time.After(time.Second):
		t.Fatal("did not receive config_applied ACK")
	}
}

func TestRunPresenceOnceStopsPromptlyWhenContextIsCancelled(t *testing.T) {
	upgrader := websocket.Upgrader{}
	connected := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		close(connected)
		_, _, _ = conn.ReadMessage()
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	client := NewClient(server.URL, "hytron", "token")
	errCh := make(chan error, 1)
	go func() { errCh <- client.runPresenceOnce(ctx, nil) }()
	select {
	case <-connected:
	case <-time.After(time.Second):
		t.Fatal("presence websocket did not connect")
	}
	cancel()
	select {
	case <-errCh:
	case <-time.After(time.Second):
		t.Fatal("presence websocket read did not unblock on context cancellation")
	}
}
