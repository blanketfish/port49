//go:build linux

package admin

import (
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
)

// ownUID is port49d's own uid, which peerAllowed answers. A test swaps it,
// so that its own uid reads as another's without needing root.
var ownUID = func() uint32 { return uint32(os.Geteuid()) }

// peerAllowed answers port49d's own uid and root only (SO_PEERCRED), and
// returns the caller's uid.
func peerAllowed(c net.Conn) (uint32, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return 0, errors.New("not a Unix socket")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred *syscall.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if credErr != nil {
		return 0, credErr
	}
	return cred.Uid, uidAllowed(cred.Uid, ownUID())
}

// listenPrivate binds path as a socket that is 0600 from the instant it
// exists: the mode is set on the socket before bind, which Linux carries to
// the file bind creates. There is no window at the process umask, and no
// chmod by path that a link swapped in could redirect.
func listenPrivate(path string) (net.Listener, error) {
	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	if err := syscall.Fchmod(fd, 0o600); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	if err := syscall.Bind(fd, &syscall.SockaddrUnix{Name: path}); err != nil {
		syscall.Close(fd)
		return nil, &net.OpError{Op: "listen", Net: "unix", Err: os.NewSyscallError("bind", err)}
	}
	if err := syscall.Listen(fd, syscall.SOMAXCONN); err != nil {
		syscall.Close(fd)
		os.Remove(path)
		return nil, os.NewSyscallError("listen", err)
	}
	f := os.NewFile(uintptr(fd), path)
	ln, err := net.FileListener(f)
	f.Close()
	if err != nil {
		os.Remove(path)
		return nil, err
	}
	ul := ln.(*net.UnixListener)
	ul.SetUnlinkOnClose(true)
	// The peer check is the control; the mode is the second fence, so a
	// kernel that did not carry it is refused rather than served.
	if fi, err := os.Lstat(path); err != nil || fi.Mode()&os.ModeSocket == 0 || fi.Mode().Perm()&0o077 != 0 {
		ul.SetUnlinkOnClose(false)
		ul.Close()
		return nil, fmt.Errorf("%s was not created 0600; port49d will not serve it", path)
	}
	return ul, nil
}
