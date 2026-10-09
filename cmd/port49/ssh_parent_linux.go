package main

import (
	"errors"
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// askpassPath is the path ssh is told to run as SSH_ASKPASS. /proc/<pid>/exe
// runs the image this process is running, even if its file has since been
// deleted or replaced, and it is the same build as the `port49 ssh` that
// serves it; ssh sends the device an empty password when its askpass will not
// exec. It stays valid for a jump host's `ssh -W` for as long as this lives.
func askpassPath(string) string {
	return fmt.Sprintf("/proc/%d/exe", os.Getpid())
}

// sshParent is the process that ran this askpass, held so that a signal can
// reach only it. A pidfd names the process itself, not a pid that a later
// process could reuse; without one (an old kernel) the pid and Getppid check
// stand alone.
type sshParent struct {
	pid  int
	fd   int // a pidfd, or -1
	gone bool
}

// watchParent takes hold of the parent at the askpass's start. A parent that
// was already gone, and the askpass adopted by its grandparent, is marked so:
// the process now above this one is not ssh.
func watchParent() sshParent {
	ppid := os.Getppid()
	fd, err := unix.PidfdOpen(ppid, 0)
	switch {
	case err == nil && os.Getppid() == ppid:
		return sshParent{pid: ppid, fd: fd}
	case err == nil:
		_ = unix.Close(fd)
		return sshParent{pid: ppid, fd: -1, gone: true}
	case errors.Is(err, unix.ESRCH):
		return sshParent{pid: ppid, fd: -1, gone: true}
	}
	return sshParent{pid: ppid, fd: -1}
}

// terminate sends SIGTERM to the parent, and only to the process this started
// under: once it has exited and this has been adopted, Getppid no longer
// names it.
func (p sshParent) terminate() {
	if p.gone || p.pid <= 1 || os.Getppid() != p.pid {
		return
	}
	if p.fd >= 0 {
		_ = unix.PidfdSendSignal(p.fd, unix.SIGTERM, nil, 0)
		_ = unix.Close(p.fd)
		return
	}
	_ = syscall.Kill(p.pid, syscall.SIGTERM)
}
