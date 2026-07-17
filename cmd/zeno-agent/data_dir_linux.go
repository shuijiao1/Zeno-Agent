//go:build linux

package main

func defaultAgentDataDir() string {
	return "/var/lib/zeno-agent"
}
