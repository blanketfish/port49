//go:build darwin

package main

import "golang.org/x/sys/unix"

// excludeFromTimeMachine sets the attribute `tmutil addexclusion` sets (no
// -p: the sticky one, which follows the directory), with no cgo.
func excludeFromTimeMachine(dir string) error {
	return unix.Setxattr(dir, "com.apple.metadata:com_apple_backup_excludeItem", backupdPlist(), 0)
}
