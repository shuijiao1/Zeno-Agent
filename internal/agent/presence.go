package agent

import (
	"context"
	"encoding/json"
	"log"
	"math/rand"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
)

type PresenceServerMessage struct {
	Type    string `json:"type"`
	Version int64  `json:"version,omitempty"`
}

type PresenceClientMessage struct {
	Type    string `json:"type"`
	Version int64  `json:"version,omitempty"`
}

type PresenceConfigHandler func(ctx context.Context, requestedVersion int64) (appliedVersion int64, err error)

var (
	presenceReadTimeout              = 75 * time.Second
	presenceWriteTimeout             = 5 * time.Second
	presenceReadLimit                = int64(64 << 10)
	presenceInitialReconnectBackoff  = time.Second
	presenceMaxReconnectBackoff      = 30 * time.Second
	presenceStableConnectionDuration = presenceReadTimeout
)

func (c *Client) RunPresence(ctx context.Context, handleConfig PresenceConfigHandler) {
	c.runPresenceLoop(ctx, handleConfig, presenceLoopOptions{
		runOnce: c.runPresenceOnce,
		now:     time.Now,
		sleep:   sleepContext,
		jitter:  randomPresenceJitter,
	})
}

type presenceLoopOptions struct {
	runOnce                  func(context.Context, PresenceConfigHandler) error
	now                      func() time.Time
	sleep                    func(context.Context, time.Duration) bool
	jitter                   func(time.Duration) time.Duration
	initialBackoff           time.Duration
	maxBackoff               time.Duration
	stableConnectionDuration time.Duration
}

func (c *Client) runPresenceLoop(ctx context.Context, handleConfig PresenceConfigHandler, options presenceLoopOptions) {
	if options.runOnce == nil {
		options.runOnce = c.runPresenceOnce
	}
	if options.now == nil {
		options.now = time.Now
	}
	if options.sleep == nil {
		options.sleep = sleepContext
	}
	if options.jitter == nil {
		options.jitter = randomPresenceJitter
	}
	if options.initialBackoff <= 0 {
		options.initialBackoff = presenceInitialReconnectBackoff
	}
	if options.maxBackoff <= 0 {
		options.maxBackoff = presenceMaxReconnectBackoff
	}
	if options.maxBackoff < options.initialBackoff {
		options.maxBackoff = options.initialBackoff
	}
	if options.stableConnectionDuration <= 0 {
		options.stableConnectionDuration = presenceStableConnectionDuration
	}

	backoff := options.initialBackoff
	for ctx.Err() == nil {
		started := options.now()
		err := options.runOnce(ctx, handleConfig)
		connectedFor := options.now().Sub(started)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			log.Printf("presence websocket disconnected: %v", err)
		}
		if connectedFor >= options.stableConnectionDuration {
			backoff = options.initialBackoff
		}
		wait := backoff + options.jitter(backoff)
		if wait > options.maxBackoff {
			wait = options.maxBackoff
		}
		if !options.sleep(ctx, wait) {
			return
		}
		if backoff < options.maxBackoff {
			backoff *= 2
			if backoff > options.maxBackoff {
				backoff = options.maxBackoff
			}
		}
	}
}

func sleepContext(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func randomPresenceJitter(backoff time.Duration) time.Duration {
	if backoff <= 0 {
		return 0
	}
	return time.Duration(rand.Int63n(int64(backoff / 2)))
}

func (c *Client) runPresenceOnce(ctx context.Context, handleConfig PresenceConfigHandler) error {
	presenceURL, err := c.PresenceWebSocketURL()
	if err != nil {
		return err
	}
	header := http.Header{}
	c.setAuthHeaders(header)
	conn, _, err := websocket.DefaultDialer.DialContext(ctx, presenceURL, header)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetReadLimit(presenceReadLimit)
	log.Printf("presence websocket connected")
	refreshReadDeadline := func() error {
		return conn.SetReadDeadline(time.Now().Add(presenceReadTimeout))
	}
	if err := refreshReadDeadline(); err != nil {
		return err
	}
	conn.SetPingHandler(func(appData string) error {
		if err := refreshReadDeadline(); err != nil {
			return err
		}
		return conn.WriteControl(websocket.PongMessage, []byte(appData), time.Now().Add(presenceWriteTimeout))
	})
	conn.SetPongHandler(func(appData string) error {
		return refreshReadDeadline()
	})
	writeJSON := func(value any) error {
		if err := conn.SetWriteDeadline(time.Now().Add(presenceWriteTimeout)); err != nil {
			return err
		}
		return conn.WriteJSON(value)
	}
	writeMessage := func(messageType int, payload []byte) error {
		if err := conn.SetWriteDeadline(time.Now().Add(presenceWriteTimeout)); err != nil {
			return err
		}
		return conn.WriteMessage(messageType, payload)
	}
	if handleConfig != nil {
		refreshCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		appliedVersion, refreshErr := handleConfig(refreshCtx, 0)
		cancel()
		if refreshErr != nil {
			log.Printf("presence startup config refresh failed: %v", refreshErr)
		} else if appliedVersion > 0 {
			_ = writeJSON(PresenceClientMessage{Type: "config_applied", Version: appliedVersion})
		}
	}
	for {
		var message PresenceServerMessage
		if err := conn.ReadJSON(&message); err != nil {
			return err
		}
		switch message.Type {
		case "config_changed":
			if handleConfig == nil {
				continue
			}
			refreshCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
			appliedVersion, refreshErr := handleConfig(refreshCtx, message.Version)
			cancel()
			if refreshErr != nil {
				log.Printf("presence config refresh failed: %v", refreshErr)
				continue
			}
			if appliedVersion == 0 {
				continue
			}
			payload, _ := json.Marshal(PresenceClientMessage{Type: "config_applied", Version: appliedVersion})
			if err := writeMessage(websocket.TextMessage, payload); err != nil {
				return err
			}
		}
	}
}
