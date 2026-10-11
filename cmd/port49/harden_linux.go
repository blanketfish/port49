//go:build linux

package main

import (
	"errors"

	"golang.org/x/sys/unix"
)

// harden makes the agent process non-dumpable (spec §13 decision 43 ruling
// 21): no core file or crash report holds the session's key, and no process
// of this user can ptrace it. /proc/<pid> becomes root's. RLIMIT_CORE 0
// beside it, for a core a dumpable flag does not cover.
func harden() error {
	return errors.Join(unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{}), unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0))
}
