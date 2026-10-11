//go:build linux

package main

import "golang.org/x/sys/unix"

// harden makes the agent process non-dumpable (spec §13 decision 43 ruling
// 21): no core file or crash report holds the session's key, and no process
// of this user can ptrace it. /proc/<pid> becomes root's.
func harden() error { return unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0) }
