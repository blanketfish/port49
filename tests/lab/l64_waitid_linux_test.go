//go:build lab && linux

package lab

import (
	"errors"

	"golang.org/x/sys/unix"
)

// l64WaitLeader blocks until the process pid has exited and leaves it a zombie, unreaped: while it is, its pid
// and so its process group id cannot be handed to another process, so a kill of the group reaches the group the
// command started and no other (WNOWAIT, N2).
func l64WaitLeader(pid int) {
	var info unix.Siginfo
	for {
		err := unix.Waitid(unix.P_PID, pid, &info, unix.WEXITED|unix.WNOWAIT, nil)
		if !errors.Is(err, unix.EINTR) {
			return
		}
	}
}
