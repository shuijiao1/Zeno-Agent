//go:build !linux && !darwin && !windows

package main

import (
	"os"
	"path/filepath"
)

func defaultAgentDataDir() string {
	if directory, err := os.UserConfigDir(); err == nil && directory != "" {
		return filepath.Join(directory, "zeno-agent")
	}
	return filepath.Join(os.TempDir(), "zeno-agent")
}
