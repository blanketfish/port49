//go:build !linux

package main

import "os"

// isTerminal is whether f is a character device: port49 is built and
// tested on Linux (tty_linux.go); elsewhere this is the best plain check.
func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}
