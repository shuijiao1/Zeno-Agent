package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

type reopenLogWriter struct {
	path string
	mu   sync.Mutex
}

func (w *reopenLogWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	file, err := openRegularLogFile(w.path)
	if err != nil {
		return 0, err
	}
	n, writeErr := file.Write(p)
	closeErr := file.Close()
	if writeErr != nil {
		return n, writeErr
	}
	if closeErr != nil {
		return n, closeErr
	}
	return n, nil
}

func openRegularLogFile(path string) (*os.File, error) {
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("log file must be a regular file: %s", path)
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	return os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
}

func configureLogFile(path string) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}
	if !filepath.IsAbs(path) {
		return fmt.Errorf("log file path must be absolute")
	}
	file, err := openRegularLogFile(path)
	if err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	log.SetOutput(&reopenLogWriter{path: path})
	return nil
}
