//go:build darwin

package main

import (
	"errors"

	"golang.org/x/sys/unix"
)

// harden denies the agent process to a debugger (spec §13 decision 43 ruling
// 21): ptrace(PT_DENY_ATTACH), harden_linux.go's PR_SET_DUMPABLE on macOS,
// with no cgo; and RLIMIT_CORE 0, so a `ulimit -c unlimited` shell leaves no
// core holding the key.
func harden() error {
	return errors.Join(unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{}), unix.PtraceDenyAttach())
}
