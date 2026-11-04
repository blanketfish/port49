//go:build linux

package sdtest

import "syscall"

// hasACL reports whether path carries a POSIX access ACL; the ACL's content is not read.
func hasACL(path string) bool {
	n, err := syscall.Getxattr(path, "system.posix_acl_access", nil)
	return err == nil && n > 0
}
