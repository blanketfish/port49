package author

import (
	"context"
	"strings"

	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/store"
)

// Lab is the authorizer used before the policy engine exists (plan 4). It
// returns fixed session attributes and denies commands by prefix, with a
// server_msg, which is exactly what lab register entries L2 and L10 need.
type Lab struct {
	SessionAttributes []string
	// CommandAttributes are returned on a PERMITTED per-command authorization,
	// the way SessionAttributes are on a session one.
	//
	// It is a second list rather than a reuse of the first because register
	// entry L18 varies one at a time: the same unrecognised attribute on a
	// session reply and on a per-command reply are different questions -- three
	// of the five platforms in this lab answer the session one by ending the
	// session, and what they do on the command path was unaskable until this
	// field existed, because Command returned a bare permit and there was no
	// reply to put an attribute in.
	//
	// Empty is the shipped shape and means a bare permit, which is what every
	// config in this repository but an L18 derivation carries.
	CommandAttributes []string
	// DenyPrefixes lists commands denied by prefix match on a token boundary:
	// the joined command line must equal the prefix, or begin with the prefix
	// followed by a space, so "show" denies "show version" but not "shower".
	DenyPrefixes []string
}

func (l *Lab) Session(_ context.Context, _ store.Context, _ []string) Decision {
	return Decision{Permit: true, Reason: decision.ContextMatched, Attributes: l.SessionAttributes}
}

func (l *Lab) Command(_ context.Context, _ store.Context, vector []string, _ []string) Decision {
	line := strings.Join(vector, " ")
	for _, p := range l.DenyPrefixes {
		// A denial carries no attributes on purpose: its payload is the
		// server_msg, and a FAIL with arguments hung off it is protocol
		// behaviour invented in order to measure protocol behaviour.
		if line == p || strings.HasPrefix(line, p+" ") {
			return Decision{Permit: false, Reason: decision.NoPermitDominatesDeny,
				ServerMsg: "port49: denied by lab_deny (" + p + "); see 'port49 explain'"}
		}
	}
	return Decision{Permit: true, Reason: decision.PermitDominates, Attributes: l.CommandAttributes}
}
