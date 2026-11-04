//go:build !linux

package sdtest

func accessACL(string) ([]byte, bool) { return nil, false }
