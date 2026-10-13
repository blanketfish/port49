package main

import (
	"os"

	"golang.org/x/sys/unix"
)

// echoOff clears the terminal's ECHO flag at once, so a prompt can be written
// with echo already off, as readpassphrase(3) does. The caller has saved the
// terminal's state and restores it. Best effort: term.ReadPassword turns echo
// off itself, so a terminal that refuses this is no worse than before.
func echoOff(fd int) {
	t, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return
	}
	t.Lflag &^= unix.ECHO
	_ = unix.IoctlSetTermios(fd, unix.TCSETSW, t)
}

// isTerminal is whether f is a terminal: one that answers TCGETS. A mode
// check is not enough, since /dev/null is a character device too, and a
// script run with </dev/null must not be asked anything.
func isTerminal(f *os.File) bool {
	_, err := unix.IoctlGetTermios(int(f.Fd()), unix.TCGETS)
	return err == nil
}
