//go:build !linux && !darwin

package agent

import "net"

func peerOf(net.Conn) (peerCred, bool) { return peerCred{}, false }
