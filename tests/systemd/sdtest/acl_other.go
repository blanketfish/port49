//go:build !linux

package sdtest

func hasACL(string) bool { return false }
