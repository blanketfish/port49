//go:build linux

package sdtest

import "syscall"

// accessACL is path's system.posix_acl_access xattr, and whether it has one.
func accessACL(path string) ([]byte, bool) {
	n, err := syscall.Getxattr(path, "system.posix_acl_access", nil)
	if err != nil || n <= 0 {
		return nil, false
	}
	b := make([]byte, n)
	if n, err = syscall.Getxattr(path, "system.posix_acl_access", b); err != nil {
		return nil, false
	}
	return b[:n], true
}
