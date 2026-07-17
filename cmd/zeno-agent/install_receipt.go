package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
)

const installReceiptPrefix = "zeno-agent-install-receipt-v1 "

// installReceiptTracker emits no credential material. It only proves that the
// long-running service process has received successful heartbeat and state
// responses. The installer separately verifies the file and process owner.
type installReceiptTracker struct {
	mu          sync.Mutex
	path        string
	nonce       string
	heartbeatOK bool
	stateOK     bool
	written     bool
}

func newInstallReceiptTracker(path, nonce string) *installReceiptTracker {
	return &installReceiptTracker{path: path, nonce: nonce}
}

func (r *installReceiptTracker) markHeartbeat() { r.mark(true) }
func (r *installReceiptTracker) markState()     { r.mark(false) }

func (r *installReceiptTracker) mark(heartbeat bool) {
	if r == nil || r.path == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if heartbeat {
		r.heartbeatOK = true
	} else {
		r.stateOK = true
	}
	if r.written || !r.heartbeatOK || !r.stateOK {
		return
	}
	if err := writeInstallReceipt(r.path, r.nonce); err != nil {
		log.Printf("install receipt write failed: %v", err)
		return
	}
	r.written = true
}

func writeInstallReceipt(path, nonce string) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".zeno-install-receipt-*")
	if err != nil {
		return fmt.Errorf("create receipt: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod receipt: %w", err)
	}
	if _, err := fmt.Fprintln(tmp, installReceiptPrefix+nonce); err != nil {
		tmp.Close()
		return fmt.Errorf("write receipt: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync receipt: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close receipt: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("publish receipt: %w", err)
	}
	return nil
}
