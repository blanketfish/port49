//go:build !linux && !darwin

package main

// harden is Linux's and macOS's alone (harden_linux.go, harden_darwin.go);
// elsewhere the OS's own protection of a process's memory is all there is.
func harden() error { return nil }
