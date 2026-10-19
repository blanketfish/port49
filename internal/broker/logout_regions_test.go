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

// failing fails one store call and passes the rest through.
type failing struct {
	store.Store
	contexts, receipts bool
}

func (s failing) ContextsByPrincipal(ctx context.Context, p string) ([]store.ContextRef, error) {
	if s.contexts {
		return nil, store.ErrUnavailable
	}
	return s.Store.ContextsByPrincipal(ctx, p)
}

func (s failing) DeleteReceiptsByPrincipal(ctx context.Context, p string) (int, error) {
	if s.receipts {
		return 0, store.ErrUnavailable
	}
	return s.Store.DeleteReceiptsByPrincipal(ctx, p)
}

// A step that fails does not stop the others, and what failed is reported,
// never claimed reached: with the context listing down, the person's tokens
// are still deleted, no context is claimed, and the error comes back.
func TestReachLogoutPartialFailureReachesTheRestAndClaimsNothingMore(t *testing.T) {
	ctx := context.Background()
	f, iss, _ := oidcLoggedIn(t)
	f.b.Store = failing{Store: f.st, contexts: true}
	rep, err := f.b.ReachLogout(ctx, store.Logout{Key: store.OIDCKey(store.OIDCSub, iss.URL, "sub-alice"), At: f.now})
	if !errors.Is(err, store.ErrUnavailable) || !errors.Is(rep.Err, store.ErrUnavailable) {
		t.Fatalf("err %v, rep.Err %v", err, rep.Err)
	}
	if toks, _ := f.st.Candidates(ctx, store.TokenKey{NAS: "nx1", Username: "alice"}); len(toks) != 0 {
		t.Fatal("a failed context step stopped the token deletion")
	}
	if len(rep.Principals) == 0 || rep.TokenKeys == 0 {
		t.Fatalf("the tokens that were deleted are not reported: %+v", rep)
	}
	if len(rep.Contexts) != 0 || !contextRevokedAt(t, f, "leaf1").IsZero() {
		t.Fatalf("a context is claimed reached that was not: %+v", rep.Contexts)
	}
}

// The last step failing leaves the earlier ones done and reported.
func TestReachLogoutFailingLastStepKeepsWhatWasReached(t *testing.T) {
	ctx := context.Background()
	f, iss, _ := oidcLoggedIn(t)
	f.b.Store = failing{Store: f.st, receipts: true}
	rep, err := f.b.ReachLogout(ctx, store.Logout{Key: store.OIDCKey(store.OIDCSub, iss.URL, "sub-alice"), At: f.now})
	if !errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("err %v", err)
	}
	if len(rep.Contexts) == 0 || contextRevokedAt(t, f, "leaf1").IsZero() {
		t.Fatalf("the contexts reached before the failure are lost: %+v", rep)
	}
}

// A broker with no identity verifiers reaches nothing and says so.
func TestReachLogoutWithNoIdentityIsRefused(t *testing.T) {
	f, iss, _ := oidcLoggedIn(t)
	f.b.Identity = nil
	rep, err := f.b.ReachLogout(context.Background(), store.Logout{Key: store.SidKey(iss.URL, "s-sub-alice"), At: f.now})
	if err == nil || len(rep.Contexts) != 0 || rep.TokenKeys != 0 {
		t.Fatalf("%+v %v", rep, err)
	}
	if !contextRevokedAt(t, f, "leaf1").IsZero() {
		t.Fatal("a refused reach marked a context")
	}
}
