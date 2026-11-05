//go:build !linux && !darwin

package agent

import "net"

// peerCredsReported is whether the platform reports a peer's credentials, so a dial that gets none is
// refused. Here it does not, and the dial rests on the path checks alone.
const peerCredsReported = false

func peerOf(net.Conn) (peerCred, bool) { return peerCred{}, false }
