package broker

import (
	"context"
	"testing"

	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/store"
)

// R26: a logout another region ingested reaches this region: the session's
// context marked and the person's unspent tokens deleted, with no logout
// record written here and no revoke record.
func TestReachLogoutReachesThisRegionsSessions(t *testing.T) {
	ctx := context.Background()
	f, iss, _ := oidcLoggedIn(t)
	before := len(eventsOf(f.records(t), decision.EventRevoke))
	key := store.SidKey(iss.URL, "s-sub-alice")
	rep, err := f.b.ReachLogout(ctx, store.Logout{Key: key, At: f.now, Origin: "backchannel_logout " + iss.URL})
	if err != nil || len(rep.Contexts) == 0 {
		t.Fatalf("%+v %v", rep, err)
	}
	if rep.By != ByLogoutSid || rep.Sid != "s-sub-alice" || rep.Sub != "" {
		t.Fatalf("a sid key was reached as %q sid %q sub %q", rep.By, rep.Sid, rep.Sub)
	}
	if contextRevokedAt(t, f, "leaf1").IsZero() {
		t.Fatal("the session's context was not marked")
	}
	if toks, _ := f.st.Candidates(ctx, store.TokenKey{NAS: "nx1", Username: "alice"}); len(toks) != 0 {
		t.Fatal("the person's unspent token on nx1 survived")
	}
	if _, err := f.st.GetLogout(ctx, key); err == nil {
		t.Fatal("ReachLogout wrote a logout record")
	}
	if n := len(eventsOf(f.records(t), decision.EventRevoke)); n != before {
		t.Fatalf("ReachLogout wrote %d revoke record(s)", n-before)
	}
}

// A followed key no human verifier here trusts, or that is no OIDC key,
// reaches nothing and says so: never "done".
func TestReachLogoutRefusesAKeyItCannotReach(t *testing.T) {
	ctx := context.Background()
	f, iss, _ := oidcLoggedIn(t)
	for _, key := range []string{"", "garbage", store.SidKey("https://other.example.com", "s-sub-alice")} {
		if _, err := f.b.ReachLogout(ctx, store.Logout{Key: key, At: f.now}); err == nil {
			t.Fatalf("%q: no error", key)
		}
	}
	if contextRevokedAt(t, f, "leaf1").IsZero() == false {
		t.Fatal("a refused key marked a context")
	}
	_ = iss
}
