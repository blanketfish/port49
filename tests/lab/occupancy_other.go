//go:build !linux

package lab

func labInheritedLock(string) (func(), bool, error) { return nil, false, nil }
