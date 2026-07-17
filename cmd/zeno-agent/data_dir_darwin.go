//go:build darwin

package main

func defaultAgentDataDir() string {
	return "/Library/Application Support/Zeno Agent/data"
}
