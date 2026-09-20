package author

import (
	"context"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/tacacs/wire"
)

// The ruled key (spec §13, decision 15): the authorization lookup is
// (nas, username), and the port the request carries is recorded, never keyed.

// TestPortMayDifferBetweenAuthenticationAndAuthorization is requirement (b),
// and it is the vEOS headline: the device says "ssh" at authentication and
// "vty4" at authorization, and the N9Kv sends an empty port on every command.
func TestPortMayDifferBetweenAuthenticationAndAuthorization(t *testing.T) {
	for _, port := range []string{"vty4", "", "0", "ssh"} {
		t.Run("port="+port, func(t *testing.T) {
			h, _, log := setup(t)
			resp := h.Handle(context.Background(), peer, req("alice", port, "service=shell", "cmd="))
			if resp.Status != wire.AuthorStatusPassAdd {
				t.Fatalf("%+v", resp)
			}
			r := lastRecord(t, log)
			if r["reason"] != "context_matched" {
				t.Fatalf("%v", r)
			}
			// Requirement (e): the port as seen on this exchange is in the record.
			if s := r["session"].(map[string]any); s["port"] != port {
				t.Fatalf("port on the record: %v, want %q", s["port"], port)
			}
		})
	}
}

// TestTwoUsersAuthorizeConcurrently is requirement (a): two operators on one
// device, reporting the same port, must each match their own context and
// neither may disturb the other.
func TestTwoUsersAuthorizeConcurrently(t *testing.T) {
	h, st, log := setup(t)
	if err := st.PutContext(context.Background(), store.ContextKey{NAS: "leaf-01", Username: "bob"},
		store.Context{CtxID: "ctx2", Username: "bob", Port: "ssh", PrivLvl: 15}, time.Hour); err != nil {
		t.Fatal(err)
	}
	// Both sessions report the same port, as the lab devices do: vEOS gave
	// both concurrent sessions `vty4`, the N9Kv gave both `0`.
	for _, tc := range []struct{ user, ctxID string }{{"alice", "ctx1"}, {"bob", "ctx2"}} {
		resp := h.Handle(context.Background(), peer, req(tc.user, "vty4", "service=shell", "cmd="))
		if resp.Status != wire.AuthorStatusPassAdd {
			t.Fatalf("%s session: %+v", tc.user, resp)
		}
		r := lastRecord(t, log)
		s := r["session"].(map[string]any)
		if r["event"] != "authorize_session" || r["reason"] != "context_matched" || s["username"] != tc.user || s["ctx_id"] != tc.ctxID {
			t.Fatalf("%s session: %v", tc.user, r)
		}
	}
	// And they keep matching as they interleave commands.
	for _, tc := range []struct{ user, ctxID string }{{"alice", "ctx1"}, {"bob", "ctx2"}, {"alice", "ctx1"}, {"bob", "ctx2"}} {
		resp := h.Handle(context.Background(), peer, req(tc.user, "vty4", "service=shell", "cmd=show", "cmd-arg=version"))
		if resp.Status != wire.AuthorStatusPassAdd {
			t.Fatalf("%s: %+v", tc.user, resp)
		}
		r := lastRecord(t, log)
		s := r["session"].(map[string]any)
		if r["reason"] != "permit_dominates" || s["username"] != tc.user || s["ctx_id"] != tc.ctxID {
			t.Fatalf("%s: %v", tc.user, r)
		}
	}
	// Both contexts survive the whole exchange.
	for _, u := range []string{"alice", "bob"} {
		if _, err := st.GetContext(context.Background(), store.ContextKey{NAS: "leaf-01", Username: u}); err != nil {
			t.Fatalf("%s's context was destroyed: %v", u, err)
		}
	}
}

// TestUnknownUserIsContextMissingAndLeavesOthersAlone: a name port49 never
// authenticated finds no context of its own, and — unlike the old key — takes
// nobody else's down with it.
func TestUnknownUserIsContextMissingAndLeavesOthersAlone(t *testing.T) {
	h, st, log := setup(t)
	resp := h.Handle(context.Background(), peer, req("mallory", "vty4", "service=shell", "cmd=show"))
	if resp.Status != wire.AuthorStatusFail || lastRecord(t, log)["reason"] != "context_missing" {
		t.Fatalf("%+v %v", resp, lastRecord(t, log))
	}
	if s := lastRecord(t, log)["session"].(map[string]any); s["username"] != "mallory" {
		t.Fatalf("the record must name the sender: %v", s)
	}
	if _, err := st.GetContext(context.Background(), store.ContextKey{NAS: "leaf-01", Username: "alice"}); err != nil {
		t.Fatalf("alice's context was destroyed by a stranger's command: %v", err)
	}
}

// TestAuthorizationSurvivesAContextReplacement is the second half of
// requirement (c): the same user's second login replaces the context, and the
// first shell's later commands still authorize — against the newer ctx_id,
// which is the accepted cost recorded in decision 15.
func TestAuthorizationSurvivesAContextReplacement(t *testing.T) {
	h, st, log := setup(t)
	if err := st.PutContext(context.Background(), store.ContextKey{NAS: "leaf-01", Username: "alice"},
		store.Context{CtxID: "ctx2", Username: "alice", Port: "ssh", PrivLvl: 15}, time.Hour); err != nil {
		t.Fatal(err)
	}
	resp := h.Handle(context.Background(), peer, req("alice", "vty4", "service=shell", "cmd=show", "cmd-arg=version"))
	if resp.Status != wire.AuthorStatusPassAdd {
		t.Fatalf("%+v", resp)
	}
	if s := lastRecord(t, log)["session"].(map[string]any); s["ctx_id"] != "ctx2" {
		t.Fatalf("%v", s)
	}
}
