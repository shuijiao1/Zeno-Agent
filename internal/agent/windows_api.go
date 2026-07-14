//go:build windows

package agent

import "syscall"

var kernel32 = syscall.NewLazyDLL("kernel32.dll")
var iphlpapi = syscall.NewLazyDLL("iphlpapi.dll")

var getExtendedTcpTable = iphlpapi.NewProc("GetExtendedTcpTable")
var getExtendedUdpTable = iphlpapi.NewProc("GetExtendedUdpTable")
