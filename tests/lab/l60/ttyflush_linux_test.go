package l60

import (
	"os"

	"golang.org/x/sys/unix"
)

// flushTTYInput discards what was typed on tty and not yet read: a line Ryan
// typed while a port49 child held the terminal (an Enter at its paste prompt
// after the browser had already answered, say) would otherwise be read as the
// answer to the harness's next question. Best effort; through the raw
// connection, since Fd would put the file in blocking mode and lose
// readLine's deadline.
func flushTTYInput(tty *os.File) {
	rc, err := tty.SyscallConn()
	if err != nil {
		return
	}
	_ = rc.Control(func(fd uintptr) { _ = unix.IoctlSetInt(int(fd), unix.TCFLSH, unix.TCIFLUSH) })
}
