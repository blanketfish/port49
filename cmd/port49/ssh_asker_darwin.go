package main

import (
	"errors"
	"net"

	"golang.org/x/sys/unix"
)

// askerParent is the parent pid of the process that dialled c (pre-flight N3).
// LOCAL_PEERPID names the process that dialled (the askpass, whatever it
// claims); its parent is ssh, which forks the askpass directly. Any read that
// fails is an error.
func askerParent(c net.Conn) (int, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return 0, errors.New("the askpass connection is not a Unix socket")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, err
	}
	var pid int
	var cerr error
	if err := raw.Control(func(fd uintptr) {
		pid, cerr = unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID)
	}); err != nil {
		return 0, err
	}
	if cerr != nil {
		return 0, cerr
	}
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		return 0, err
	}
	return int(kp.Eproc.Ppid), nil
}
