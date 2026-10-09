package main

import (
	"errors"
	"os"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

// askpassPath is the path ssh is told to run as SSH_ASKPASS. /proc/<pid>/exe
// runs the image this process is running, even if its file has since been
// deleted or replaced, and it is the same build as the `port49 ssh` that
// serves it; ssh sends the device an empty password when its askpass will not
// exec. It stays valid for a jump host's `ssh -W` for as long as this lives.
//
// The pid is /proc/self's own, not os.Getpid(): under a /proc of another PID
// namespace (unshare -p without --mount-proc, a sandbox that binds the host's
// /proc) Getpid names some other process's image, which ssh would exec.
func askpassPath(string) string { return procExe(os.Readlink) }

// procExe is the path of this process's image under /proc: its number as
// /proc/self resolves to it, or self when /proc does not say a number.
func procExe(readlink func(string) (string, error)) string {
	pid := "self"
	if link, err := readlink("/proc/self"); err == nil {
		if n, err := strconv.Atoi(link); err == nil && n > 0 {
			pid = link
		}
	}
	return "/proc/" + pid + "/exe"
}

// Swapped by tests.
var (
	pidfdSend   = func(fd int, sig unix.Signal) error { return unix.PidfdSendSignal(fd, sig, nil, 0) }
	killProcess = func(pid int, sig syscall.Signal) error { return syscall.Kill(pid, sig) }
)

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
		err := pidfdSend(p.fd, unix.SIGTERM)
		_ = unix.Close(p.fd)
		// ESRCH: the parent is gone, which is what was wanted. Any other
		// refusal (a seccomp profile that allows pidfd_open but not the send)
		// must not leave ssh running to send an empty password: fall back to
		// the pid, behind the Getppid check above.
		if err == nil || errors.Is(err, unix.ESRCH) || os.Getppid() != p.pid {
			return
		}
	}
	_ = killProcess(p.pid, syscall.SIGTERM)
}
