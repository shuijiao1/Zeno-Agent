//go:build windows

package main

import (
	"os"
	"path/filepath"
)

func defaultAgentDataDir() string {
	if programData := os.Getenv("ProgramData"); programData != "" {
		return filepath.Join(programData, "Zeno", "agent-data")
	}
	return `C:\ProgramData\Zeno\agent-data`
}
