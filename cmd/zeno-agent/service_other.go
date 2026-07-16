//go:build !windows

package main

import (
	"os"
	"syscall"
)

func runPlatform(cfg config) error {
	return runConsole(cfg, os.Interrupt, syscall.SIGTERM)
}
