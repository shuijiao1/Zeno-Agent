package agent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
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
