//go:build !linux

package admin

import (
	"errors"
	"net"
)

var errNeedsLinux = errors.New("admin_socket needs Linux: it checks the caller's uid (SO_PEERCRED)")

// ownUID is never asked here: peerAllowed refuses before it would be.
func ownUID() uint32 { return 0 }

// peerAllowed refuses everyone where the caller's uid cannot be read.
func peerAllowed(net.Conn, uint32) (uint32, error) {
	return 0, errNeedsLinux
}

// listenPrivate refuses to open a socket that would answer no one.
func listenPrivate(string) (net.Listener, error) {
	return nil, errNeedsLinux
}
