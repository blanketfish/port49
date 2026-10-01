package broker

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/agent"
)

// A revocation ends the agent's session, end to end (spec §5.1.4; pre-flight
// I4; the vEOS lab, plan 7a): it closes the agent's held connection, the
// agent dials again for its next mint, and the listener answers that new
// connection credential_revoked rather than hanging up on it, which the
// agent would read as a broker that restarted and keep its session.
func TestARevocationEndsTheAgentsSession(t *testing.T) {
	for _, by := range []string{"principal", "cert"} {
		t.Run(by, func(t *testing.T) {
			f := newFixture(t, 8)
			addr, bl := serveThrough(t, f, DefaultListenerLimits, nil)
			f.b.Conns = bl
			log := &lockedBuffer{}
			a := agent.New(agent.Config{BrokerURL: "https://" + addr, Cert: f.alice, BrokerCA: f.ca.Pool(),
				Now: f.b.Now, Log: log})
			ctx := context.Background()
			if _, err := a.Connect(ctx); err != nil {
				t.Fatal(err)
			}
			if _, err := a.Mint(ctx, "leaf1", false, 0); err != nil {
				t.Fatalf("a mint before the revocation: %v", err)
			}
			req := RevokeRequest{Principal: "user:alice@example.com", Origin: "t"}
			if by == "cert" {
				req = RevokeRequest{Issuer: f.alice.Leaf.Issuer.String(), Serial: f.alice.Leaf.SerialNumber.Text(16),
					Origin: "t"}
			}
			rep, err := f.b.Revoke(ctx, req)
			if err != nil || rep.Connections != 1 {
				t.Fatalf("revoke: %+v %v", rep, err)
			}
			_, err = a.Mint(ctx, "leaf1", false, 0)
			if !errors.Is(err, agent.ErrSessionOver) || !strings.Contains(err.Error(), " was revoked at ") {
				t.Fatalf("the mint after the revocation: %v", err)
			}
			select {
			case <-a.Done():
			case <-time.After(5 * time.Second):
				t.Fatal("the agent's session did not end")
			}
			if !strings.Contains(log.String(), "the broker ended the session") {
				t.Fatalf("the agent's log: %q", log.String())
			}
		})
	}
}
