//go:build unix

package l60

import "syscall"

// L86 runs the broker and port49d on files in t.TempDir, which the fence refuses in a directory others
// can write; a host at umask 002 makes every one group-writable. The pin holds under every tag this
// package builds with (tests/lab's TestEveryLabTaggedPackagePinsUmask022).
func init() { syscall.Umask(0o022) }
