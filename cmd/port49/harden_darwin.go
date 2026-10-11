//go:build darwin

package main

import "golang.org/x/sys/unix"

// harden denies the agent process to a debugger (spec §13 decision 43 ruling
// 21): ptrace(PT_DENY_ATTACH), harden_linux.go's PR_SET_DUMPABLE on macOS,
// with no cgo.
func harden() error { return unix.PtraceDenyAttach() }
