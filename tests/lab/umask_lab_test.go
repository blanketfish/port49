//go:build lab && unix

package lab

import "syscall"

// The daemons the lab starts read their trust files through the fence, which refuses a directory
// others can write. t.TempDir takes the process umask, and a lab host's 002 makes it group-writable,
// so the tests run under 022 as CI does.
func init() { syscall.Umask(0o022) }
