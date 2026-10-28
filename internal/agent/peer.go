package agent

import (
	"context"
	"fmt"
	"net"
)

// peerCred is who connected to the agent's socket, as the kernel reports it.
type peerCred struct {
	pid, uid int
}

type peerKey struct{}

// ConnContext is http.Server.ConnContext for the agent's socket: it records
// the connecting process's pid and uid (SO_PEERCRED on Linux, LOCAL_PEERPID
// and the peer's credentials on darwin) so the prompt log names who asked for
// a touch. Where the OS gives neither, nothing is recorded and the log omits
// the field.
func ConnContext(ctx context.Context, c net.Conn) context.Context {
	if p, ok := peerOf(c); ok {
		return context.WithValue(ctx, peerKey{}, p)
	}
	return ctx
}

// peerText is the log fields for the connecting peer, or "" when unknown.
func peerText(ctx context.Context) string {
	if p, ok := ctx.Value(peerKey{}).(peerCred); ok {
		return fmt.Sprintf(" peer_pid=%d peer_uid=%d", p.pid, p.uid)
	}
	return ""
}
