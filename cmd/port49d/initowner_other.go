//go:build !linux

package main

// initOwner has nothing to ask off Linux: fence.CheckDir refuses there
// first, since port49 keeps the revocations file on Linux only.
func initOwner(string, string) error { return nil }
