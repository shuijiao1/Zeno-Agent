//go:build !windows

package main

func runPlatform(cfg config) error {
	return runConsole(cfg)
}
