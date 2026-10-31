//go:build unix

package kind

import "syscall"

// The smoke starts a host port49d on files in t.TempDir, which the fence refuses in a directory others
// can write; a host at umask 002 makes every one group-writable. The pin holds under every tag this
// package builds with (tests/lab's TestEveryLabTaggedPackagePinsUmask022).
func init() { syscall.Umask(0o022) }
