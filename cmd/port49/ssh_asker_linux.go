package main

import (
	"bytes"
	"errors"
	"net"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// askerParent is the parent pid of the process that dialled c (pre-flight N3).
// SO_PEERCRED names the process that dialled (the askpass, whatever it claims);
// its parent is ssh, which forks the askpass directly. Any read that fails is
// an error.
func askerParent(c net.Conn) (int, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return 0, errors.New("the askpass connection is not a Unix socket")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred *unix.Ucred
	var cerr error
	if err := raw.Control(func(fd uintptr) {
		cred, cerr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if cerr != nil {
		return 0, cerr
	}
	stat, err := os.ReadFile("/proc/" + strconv.Itoa(int(cred.Pid)) + "/stat")
	if err != nil {
		return 0, err
	}
	// "pid (comm) S ppid ...": comm may hold spaces and ')', so count from the last ')'.
	i := bytes.LastIndexByte(stat, ')')
	if i < 0 {
		return 0, errors.New("/proc/<pid>/stat is not in the form read")
	}
	f := strings.Fields(string(stat[i+1:]))
	if len(f) < 2 {
		return 0, errors.New("/proc/<pid>/stat is not in the form read")
	}
	return strconv.Atoi(f[1])
}
