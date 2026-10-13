package agent

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/broker/api"
)

// Every request the agent sends the broker refuses a redirect: a mint's body,
// a refresh's challenge and answer, a revocation, an explain and the identity
// all carry the agent session header on a client certificate, and a 307 a
// front proxy answers must not carry them on (final review client I4).
func TestTheAgentFollowsNoRedirect(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	r.fb.mu.Lock()
	r.fb.redirect = true
	r.fb.mu.Unlock()
	calls := map[string]func() error{
		"mint": func() error {
			_, err := r.a.Mint(ctx, "leaf1", false, time.Minute, "")
			return err
		},
		"refresh": func() error {
			_, err := r.a.Refresh(ctx, "")
			return err
		},
		"revoke": func() error {
			_, err := r.a.Revoke(ctx, api.RevokeRequest{})
			return err
		},
		"explain": func() error {
			_, err := r.a.Explain(ctx, api.ExplainRequest{})
			return err
		},
		"identity": func() error {
			_, err := r.a.Identity(ctx)
			return err
		},
	}
	landed := func() int {
		r.fb.mu.Lock()
		defer r.fb.mu.Unlock()
		return len(r.fb.addrs["/landed"])
	}
	for _, name := range []string{"mint", "refresh", "revoke", "explain", "identity"} {
		before := landed()
		err := calls[name]()
		if err == nil || !strings.Contains(err.Error(), "never follows a redirect") {
			t.Errorf("%s: a 307 answered %v, want it said as a redirect not followed", name, err)
		}
		if n := landed() - before; n != 0 {
			t.Errorf("%s: the agent followed the broker's 307 (%d request(s) at /landed)", name, n)
		} else {
			t.Logf("%s: %v", name, err)
		}
	}
}
