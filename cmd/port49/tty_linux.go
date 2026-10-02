package main

import (
	"os"

	"golang.org/x/sys/unix"
)

// isTerminal is whether f is a terminal: one that answers TCGETS. A mode
// check is not enough, since /dev/null is a character device too, and a
// script run with </dev/null must not be asked anything.
func isTerminal(f *os.File) bool {
	_, err := unix.IoctlGetTermios(int(f.Fd()), unix.TCGETS)
	return err == nil
}
