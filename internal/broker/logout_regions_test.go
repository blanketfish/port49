package broker

import (
	"context"
	"errors"
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

// ownerDown fails the owner lookup a reach starts from.
type ownerDown struct{ store.Store }

func (ownerDown) OIDCOwner(context.Context, string) (store.OIDCOwner, error) {
	return store.OIDCOwner{}, store.ErrUnavailable
}

// Fail closed: a store error during the reach is returned, not swallowed as
// "done", and nothing is reported reached.
func TestReachLogoutReturnsAStoreErrorDuringTheReach(t *testing.T) {
	f, iss, _ := oidcLoggedIn(t)
	f.b.Store = ownerDown{f.st}
	rep, err := f.b.ReachLogout(context.Background(), store.Logout{
		Key: store.OIDCKey(store.OIDCSub, iss.URL, "sub-alice"), At: f.now})
	if !errors.Is(err, store.ErrUnavailable) || !errors.Is(rep.Err, store.ErrUnavailable) {
		t.Fatalf("err %v, rep.Err %v", err, rep.Err)
	}
	if len(rep.Contexts) != 0 || len(rep.Principals) != 0 {
		t.Fatalf("a failed reach reported %+v", rep)
	}
}
