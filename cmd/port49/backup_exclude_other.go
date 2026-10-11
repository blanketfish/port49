//go:build !darwin

package main

// excludeFromTimeMachine is macOS's; elsewhere the CACHEDIR.TAG is the mark.
func excludeFromTimeMachine(string) error { return nil }
