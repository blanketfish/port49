//go:build unix

package main

import "syscall"

// The CA files these tests write are read through the fence, which refuses a directory others can
// write. t.TempDir takes the process umask, and a developer's 002 makes it group-writable, so the
// tests run under 022 as CI does.
func init() { syscall.Umask(0o022) }
