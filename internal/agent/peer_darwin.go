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
	var p peerCred
	var xerr, perr error
	if err := raw.Control(func(fd uintptr) {
		var x *unix.Xucred
		x, xerr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if xerr == nil {
			p.uid = int(x.Uid)
		}
		p.pid, perr = unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID)
	}); err != nil || xerr != nil || perr != nil {
		return peerCred{}, false
	}
	return p, true
}
