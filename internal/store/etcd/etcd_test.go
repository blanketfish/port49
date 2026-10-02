package etcd

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"go.etcd.io/etcd/api/v3/v3rpc/rpctypes"
	clientv3 "go.etcd.io/etcd/client/v3"

	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/etcd/etcdtest"
	"github.com/rhwendt/port49/internal/store/storetest"
)

func TestMain(m *testing.M) { os.Exit(etcdtest.Main(m)) }

// onShared is a store on the shared member's client, under a prefix of its
// own, whose clock is clock.
func onShared(t *testing.T, clock func() time.Time) *Store {
	cli := etcdtest.Client(t)
	return newStore(cli, cli, Config{Prefix: etcdtest.Prefix(), Now: clock})
}

// backend runs LoginRacesARevocationByMark for 200 rounds, each a few
// round trips to the member, not memory's 10000: plan 7d R1's starting
// count, which Task 6, where SwapLogin is built, proves by a mutation.
var backend = storetest.Backend{New: func(t *testing.T, clock func() time.Time) store.Store {
	return onShared(t, clock)
}, RaceRounds: 200}

// run runs the named properties against etcd. Task 8 replaces every call
// with storetest.Run.
func run(t *testing.T, props map[string]func(*testing.T)) {
	for name, p := range props {
		t.Run(name, p)
	}
}

var t0 = time.Unix(1_000_000, 0).UTC()

func fixed(t *testing.T) func() store.Store {
	return func() store.Store { return onShared(t, func() time.Time { return t0 }) }
}

// The token family: tokens, receipts, the token index, the delete by ID
// and its race, and the marks (plan 7d Task 5).
func TestTokensOnEtcd(t *testing.T) {
	run(t, map[string]func(*testing.T){
		"TokenLifecycle":                     func(t *testing.T) { storetest.TokenLifecycle(t, backend) },
		"RedeemIsAtomic":                     func(t *testing.T) { storetest.RedeemIsAtomic(t, backend) },
		"SecretsAreNotAliased":               func(t *testing.T) { storetest.SecretsAreNotAliased(t, backend) },
		"RedeemByID":                         func(t *testing.T) { storetest.RedeemByID(t, backend) },
		"ReceiptRetainedPastItsSlidingBound": func(t *testing.T) { storetest.ReceiptRetainedPastItsSlidingBound(t, backend) },
		"FailReceiptMarksOnly":               func(t *testing.T) { storetest.FailReceiptMarksOnly(t, backend) },
		"DeleteReceiptsByPrincipal":          func(t *testing.T) { storetest.DeleteReceiptsByPrincipal(t, backend) },
		"TokenIndexExpiresWithItsLongestToken": func(t *testing.T) {
			storetest.TokenIndexExpiresWithItsLongestToken(t, backend)
		},
		"TokenIndex":                 func(t *testing.T) { storetest.TokenIndex(t, fixed(t), t0) },
		"DeleteTokenRemovesOne":      func(t *testing.T) { storetest.DeleteTokenRemovesOne(t, fixed(t), t0) },
		"DeleteTokenRacesRedeem":     func(t *testing.T) { storetest.DeleteTokenRacesRedeem(t, fixed(t), t0) },
		"RevocationMarks":            func(t *testing.T) { storetest.RevocationMarks(t, fixed(t), t0) },
		"RevocationMarkNeverExpires": func(t *testing.T) { storetest.RevocationMarkNeverExpires(t, backend) },
	})
}

// A lease etcd no longer knows (expired while port49d was paused, or
// revoked by an operator) costs the next put one retry on a fresh lease;
// the record lands, on a lease (Review Focus 2).
func TestAPutOnALostLeaseTakesAFreshOne(t *testing.T) {
	ctx := context.Background()
	s := onShared(t, func() time.Time { return t0 })
	k := store.TokenKey{NAS: "leaf-01", Username: "svc"}
	if _, err := s.PutToken(ctx, k, store.Token{ID: "a", Secret: []byte("x"), Kind: store.KindLogin,
		ExpiresAt: t0.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	resp, err := s.tok.Get(ctx, s.k.token(k, "a"))
	if err != nil || len(resp.Kvs) != 1 || resp.Kvs[0].Lease == 0 {
		t.Fatalf("the token has no lease: %v %v", resp, err)
	}
	if _, err := s.tok.Revoke(ctx, clientv3.LeaseID(resp.Kvs[0].Lease)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PutToken(ctx, k, store.Token{ID: "b", Secret: []byte("y"), Kind: store.KindLogin,
		ExpiresAt: t0.Add(time.Minute)}); err != nil {
		t.Fatalf("a put after its cached lease was revoked: %v", err)
	}
	resp, err = s.tok.Get(ctx, s.k.token(k, "b"))
	if err != nil || len(resp.Kvs) != 1 || resp.Kvs[0].Lease == 0 {
		t.Fatalf("the second token: %v %v", resp, err)
	}
}

// A record is never on a lease shorter than its life plus the grace: an
// expiry an hour out on port49d's clock is a lease of at least an hour and
// five minutes on etcd's, whatever the two clocks read.
func TestALeaseOutlivesItsRecord(t *testing.T) {
	ctx := context.Background()
	s := onShared(t, func() time.Time { return t0 })
	k := store.TokenKey{NAS: "leaf-01", Username: "svc"}
	if _, err := s.PutToken(ctx, k, store.Token{ID: "a", Secret: []byte("x"), Kind: store.KindLogin,
		ExpiresAt: t0.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	resp, _ := s.tok.Get(ctx, s.k.token(k, "a"))
	ttl, err := s.tok.TimeToLive(ctx, clientv3.LeaseID(resp.Kvs[0].Lease))
	if err != nil || time.Duration(ttl.TTL)*time.Second < time.Hour+5*time.Minute {
		t.Fatalf("lease TTL %ds: %v", ttl.TTL, err)
	}
	// A token already expired is put on the shortest lease and never read.
	if _, err := s.PutToken(ctx, k, store.Token{ID: "old", Secret: []byte("z"), Kind: store.KindLogin,
		ExpiresAt: t0}); err != nil {
		t.Fatalf("an expired put (7c M-2): %v", err)
	}
	if got, _ := s.Candidates(ctx, k); len(got) != 1 || got[0].ID != "a" {
		t.Fatalf("candidates: %v", got)
	}
}

// An outage is store.ErrUnavailable; a refusal by etcd's roles is not
// (it is a configuration error, never a reason to trip a circuit).
func TestUnavailableClassifies(t *testing.T) {
	if err := unavailable(context.DeadlineExceeded); !errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("a deadline: %v", err)
	}
	if err := unavailable(rpctypes.ErrPermissionDenied); errors.Is(err, store.ErrUnavailable) || !errors.Is(err, ErrRefused) {
		t.Fatalf("a refusal: %v", err)
	}
	if err := unavailable(context.Canceled); !errors.Is(err, context.Canceled) || errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("a caller that gave up: %v", err)
	}
	// A request etcd will not take for its size is neither an outage nor a
	// refusal: it says nothing about the store's health (pre-flight M19).
	if err := unavailable(rpctypes.ErrRequestTooLarge); !errors.Is(err, ErrTooLarge) || errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("a request too large: %v", err)
	}
}

// Every family scanned by prefix ends its scanned part with "/", so one
// key that is the start of another never lists the other's entries: the
// key schema itself, pinned apart from any lookup's filtering (pre-flight
// M24; Review Focus 3).
func TestScannedKeysEndWithASlash(t *testing.T) {
	k := newKeys("/p/")
	ref := store.ContextRef{NAS: "leaf-01", Username: "alice"}
	tk := store.TokenKey{NAS: "leaf-01", Username: "alice"}
	rk := store.ReceiptKey{NAS: "leaf-01", Username: "alice", Kind: store.KindLogin}
	for _, pair := range [][2]string{
		{k.lookups(famByPrincipal, "user:al"), k.lookup(famByPrincipal, "user:alice", ref)},
		{k.tokenIndex(famTokByPrin, "user:al"), k.tokenIndexed(famTokByPrin, "user:alice", tk)},
		{k.receiptsBy("user:al"), k.receiptBy("user:alice", rk)},
		{k.tokens(store.TokenKey{NAS: "leaf-0", Username: "alice"}), k.token(tk, "t")},
	} {
		if !strings.HasSuffix(pair[0], "/") || strings.HasPrefix(pair[1], pair[0]) {
			t.Errorf("%q scans %q", pair[0], pair[1])
		}
	}
}
