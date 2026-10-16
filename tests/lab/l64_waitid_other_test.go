//go:build lab && !linux

package lab

// l64WaitLeader is a no-op where waitid with WNOWAIT is not available; the harness runs on Linux.
func l64WaitLeader(pid int) {}
