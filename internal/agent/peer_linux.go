package agent

import (
	"net"

	"golang.org/x/sys/unix"
)

// peerCredsReported is whether the platform reports a peer's credentials, so a dial that gets none is
// refused.
const peerCredsReported = true

func peerOf(c net.Conn) (peerCred, bool) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return peerCred{}, false
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return peerCred{}, false
	}
	var cred *unix.Ucred
	var gerr error
	if err := raw.Control(func(fd uintptr) { cred, gerr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }); err != nil || gerr != nil {
		return peerCred{}, false
	}
	return peerCred{pid: int(cred.Pid), uid: int(cred.Uid)}, true
}
