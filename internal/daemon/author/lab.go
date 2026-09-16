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
	DenyPrefixes      []string
}

func (l *Lab) Session(_ context.Context, _ store.Context, _ []string) Decision {
	return Decision{Permit: true, Reason: decision.ContextMatched, Attributes: l.SessionAttributes}
}

func (l *Lab) Command(_ context.Context, _ store.Context, vector []string, _ []string) Decision {
	line := strings.Join(vector, " ")
	for _, p := range l.DenyPrefixes {
		if strings.HasPrefix(line, p) {
			return Decision{Permit: false, Reason: decision.NoPermitDominatesDeny,
				ServerMsg: "port49: denied by lab_deny (" + p + ") — see 'port49 explain'"}
		}
	}
	return Decision{Permit: true, Reason: decision.PermitDominates}
}
