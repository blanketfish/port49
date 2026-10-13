package main

import (
	"os"

	"golang.org/x/sys/unix"
)

// echoOff clears the terminal's ECHO flag at once, so a prompt can be written
// with echo already off, as readpassphrase(3) does (tty_linux.go's, with
// macOS's ioctl names). The caller has saved the terminal's state and restores
// it. Best effort: term.ReadPassword turns echo off itself.
func echoOff(fd int) {
	t, err := unix.IoctlGetTermios(fd, unix.TIOCGETA)
	if err != nil {
		return
	}
	t.Lflag &^= unix.ECHO
	_ = unix.IoctlSetTermios(fd, unix.TIOCSETAW, t)
}

// isTerminal is whether f is a terminal: one that answers TIOCGETA. A mode
// check is not enough, since /dev/null is a character device too.
func isTerminal(f *os.File) bool {
	_, err := unix.IoctlGetTermios(int(f.Fd()), unix.TIOCGETA)
	return err == nil
}
