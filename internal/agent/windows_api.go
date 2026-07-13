//go:build windows

package agent

import "syscall"

var kernel32 = syscall.NewLazyDLL("kernel32.dll")
var iphlpapi = syscall.NewLazyDLL("iphlpapi.dll")

var getTcpTable2 = iphlpapi.NewProc("GetTcpTable2")
var getTcp6Table2 = iphlpapi.NewProc("GetTcp6Table2")
var getUdpTable = iphlpapi.NewProc("GetUdpTable")
var getUdp6Table = iphlpapi.NewProc("GetUdp6Table")
