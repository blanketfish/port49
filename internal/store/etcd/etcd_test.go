package etcd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"go.etcd.io/etcd/api/v3/v3rpc/rpctypes"
	clientv3 "go.etcd.io/etcd/client/v3"

	"github.com/rhwendt/port49/internal/session"
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
// round trips to the member, not memory's 10000, its revocation staggered
// across the login (storetest.Backend.Stagger). Plan 7d R1's proof, Task
// 6: a SwapLogin that leaves the marks out of its transaction's compare,
// or reads them in Gets of their own before it, was caught in 10 runs of
// 10 each, the first catch by round 30; unstaggered, in none of 10000.
var backend = storetest.Backend{New: func(t *testing.T, clock func() time.Time) store.Store {
	return onShared(t, clock)
}, RaceRounds: 200, Stagger: true}

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
		"IndexTokenKeepsTheLongestUnderARace": func(t *testing.T) {
			storetest.IndexTokenKeepsTheLongestUnderARace(t, backend)
		},
		"FailReceiptSurvivesARacingExtend": func(t *testing.T) { storetest.FailReceiptSurvivesARacingExtend(t, backend) },
		"RedeemOrDeleteNotBoth":            func(t *testing.T) { storetest.RedeemOrDeleteNotBoth(t, backend) },
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

// The context family: every context property, the revisions, the narrow
// setters, the join with its marks, the blobs (plan 7d Task 6). The index
// properties that read lookups are Task 7's.
func TestContextsOnEtcd(t *testing.T) {
	run(t, map[string]func(*testing.T){
		"JoinRacesRevocation":           func(t *testing.T) { storetest.JoinRacesRevocation(t, fixed(t), t0) },
		"PolicyRevision":                func(t *testing.T) { storetest.PolicyRevision(t, fixed(t), t0) },
		"RevocationIsMonotonic":         func(t *testing.T) { storetest.RevocationIsMonotonic(t, fixed(t), t0) },
		"CeilingShortensOnly":           func(t *testing.T) { storetest.CeilingShortensOnly(t, fixed(t), t0) },
		"RefreshSetsTheCeiling":         func(t *testing.T) { storetest.RefreshSetsTheCeiling(t, fixed(t), t0) },
		"RefreshStopsAtGrace":           func(t *testing.T) { storetest.RefreshStopsAtGrace(t, fixed(t), t0) },
		"WritesBindToTheRevision":       func(t *testing.T) { storetest.WritesBindToTheRevision(t, fixed(t), t0) },
		"ContextExpires":                func(t *testing.T) { storetest.ContextExpires(t, backend) },
		"DeleteContextRemovesIt":        func(t *testing.T) { storetest.DeleteContextRemovesIt(t, backend) },
		"TouchExtendsWithoutClobbering": func(t *testing.T) { storetest.TouchExtendsWithoutClobbering(t, backend) },
		"AnnotateKeepsARacingRevocation": func(t *testing.T) {
			storetest.AnnotateKeepsARacingRevocation(t, backend)
		},
		"SetRevokedAtMarksOneField": func(t *testing.T) { storetest.SetRevokedAtMarksOneField(t, backend) },
		"RefreshMovesTheWindow":     func(t *testing.T) { storetest.RefreshMovesTheWindow(t, backend) },
		"RefreshWithoutCeiling":     func(t *testing.T) { storetest.RefreshWithoutCeiling(t, backend) },
		"AnnotateSetRules":          func(t *testing.T) { storetest.AnnotateSetRules(t, backend) },
		"AnnotateDoesNotEditAReadersSlice": func(t *testing.T) {
			storetest.AnnotateDoesNotEditAReadersSlice(t, backend)
		},
		"BlobBump":                       func(t *testing.T) { storetest.BlobBump(t, backend) },
		"SwapIsACompareAndSet":           func(t *testing.T) { storetest.SwapIsACompareAndSet(t, backend) },
		"EveryWriteMovesTheRevision":     func(t *testing.T) { storetest.EveryWriteMovesTheRevision(t, backend) },
		"SetPrivilegeIsRaiseOnly":        func(t *testing.T) { storetest.SetPrivilegeIsRaiseOnly(t, backend) },
		"SetContextPolicyBindsToTheRead": func(t *testing.T) { storetest.SetContextPolicyBindsToTheRead(t, backend) },
		"SelfRevocationBindsToTheRead":   func(t *testing.T) { storetest.SelfRevocationBindsToTheRead(t, backend) },
		"PurgeTakesEveryToken":           func(t *testing.T) { storetest.PurgeTakesEveryToken(t, backend) },
		"RewriteBindsToTheRevision":      func(t *testing.T) { storetest.RewriteBindsToTheRevision(t, backend) },
	})
}

// PolicyRev comes from etcd's revision counter through policy_moved: a
// policy write takes the write's own revision, and the next write that is
// not one keeps it (Ruling 5).
func TestPolicyRevIsTheLastPolicyWritesRevision(t *testing.T) {
	ctx := context.Background()
	s := onShared(t, func() time.Time { return t0 })
	k := store.ContextKey{NAS: "leaf-01", Username: "alice"}
	if err := s.PutContext(ctx, k, store.Context{CtxID: "c", Principal: "p", Username: "alice", BlobHash: "b"},
		time.Hour); err != nil {
		t.Fatal(err)
	}
	put, _ := s.GetContext(ctx, k)
	if put.PolicyRev != put.Rev {
		t.Fatalf("a whole write moves both revisions to its own: %d %d", put.Rev, put.PolicyRev)
	}
	if err := s.TouchContext(ctx, k, time.Hour); err != nil {
		t.Fatal(err)
	}
	touched, _ := s.GetContext(ctx, k)
	if touched.Rev == put.Rev || touched.PolicyRev != put.PolicyRev {
		t.Fatalf("a touch: %d/%d -> %d/%d", put.Rev, put.PolicyRev, touched.Rev, touched.PolicyRev)
	}
	if err := s.SetRevokedAt(ctx, k, t0); err != nil {
		t.Fatal(err)
	}
	revoked, _ := s.GetContext(ctx, k)
	if revoked.PolicyRev != revoked.Rev || revoked.PolicyRev == touched.PolicyRev {
		t.Fatalf("a revocation takes its own revision: %d/%d", revoked.Rev, revoked.PolicyRev)
	}
}

// A rewrite on the revision a read saw commits without reading again,
// and is still refused once the record has moved since that read
// (re-check MA3).
func TestARewriteAfterAReadComparesTheRevision(t *testing.T) {
	ctx := context.Background()
	s := onShared(t, func() time.Time { return t0 })
	k := store.ContextKey{NAS: "leaf-01", Username: "alice"}
	if err := s.PutContext(ctx, k, store.Context{CtxID: "c", Principal: "p", Username: "alice", PrivLvl: 1},
		time.Hour); err != nil {
		t.Fatal(err)
	}
	read, err := s.GetContext(ctx, k)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.TouchContext(ctx, k, time.Hour); err != nil { // the record moves after the read
		t.Fatal(err)
	}
	stale := read
	stale.PrivLvl = 15
	if err := s.RewriteContext(ctx, k, read.Rev, stale, 0, false); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("a rewrite of a version read and since moved: %v", err)
	}
	read, _ = s.GetContext(ctx, k)
	next := read
	next.PrivLvl = 7
	if err := s.RewriteContext(ctx, k, read.Rev, next, 0, false); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetContext(ctx, k); got.PrivLvl != 7 || !got.LastTouchedAt.Equal(read.LastTouchedAt) {
		t.Fatalf("a rewrite after a read: %+v", got)
	}
}

// Each sealed context write keeps at hand the revision it committed at,
// and that revision is the Rev the next read sees: the order a caller can
// place its own writes in (the crypt ledger's follow-up).
func TestAContextWriteReturnsItsRevision(t *testing.T) {
	ctx := context.Background()
	s := onShared(t, func() time.Time { return t0 })
	k := store.ContextKey{NAS: "leaf-01", Username: "alice"}
	c := store.Context{CtxID: "c", Principal: "p", Username: "alice", PrivLvl: 1}
	check := func(what string, mod int64, err error) store.Context {
		t.Helper()
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		got, err := s.GetContext(ctx, k)
		if err != nil || got.Rev != uint64(mod) || mod == 0 {
			t.Fatalf("%s committed at %d, and a read sees Rev %d (%v)", what, mod, got.Rev, err)
		}
		return got
	}
	mod, err := s.putContext(ctx, k, c, time.Hour)
	got := check("a put", mod, err)
	mod, err = s.swapLogin(ctx, k, got.Rev, c, time.Hour, store.LoginWrite{Principal: "p", Sid: "s", IndexTTL: time.Hour})
	got = check("a login", mod, err)
	got.PrivLvl = 7
	mod, err = s.rewriteContext(ctx, k, got.Rev, got, 0, true) // the cached path: GetContext just read it
	got = check("a rewrite after a read", mod, err)
	mod, err = s.rewriteContext(ctx, k, got.Rev, got, time.Hour, false) // a ttl reads again
	check("a rewrite with a ttl", mod, err)
}

// The index family: lookups, extension, the login's one step read back
// through them, active principals (plan 7d Task 7). The login's races run
// here with backend's RaceRounds and Stagger: they are what guards the
// mark compare and the index compare in the login's transaction (Task 6
// review C-1).
func TestIndexesOnEtcd(t *testing.T) {
	run(t, map[string]func(*testing.T){
		"Indexes":                         func(t *testing.T) { storetest.Indexes(t, backend) },
		"ExtendingCarriesIndexEntries":    func(t *testing.T) { storetest.ExtendingCarriesIndexEntries(t, backend) },
		"ExtendingNeverShortensOrCreates": func(t *testing.T) { storetest.ExtendingNeverShortensOrCreates(t, backend) },
		"ExtendingFollowsARotatedSid":     func(t *testing.T) { storetest.ExtendingFollowsARotatedSid(t, backend) },
		"ExtendingCarriesEveryJoinedCredential": func(t *testing.T) {
			storetest.ExtendingCarriesEveryJoinedCredential(t, backend)
		},
		"BlankKeysAreNeverIndexed": func(t *testing.T) { storetest.BlankKeysAreNeverIndexed(t, backend) },
		"UnindexRefClearsEveryKey": func(t *testing.T) { storetest.UnindexRefClearsEveryKey(t, backend) },
		"SwapLoginIsOneStep":       func(t *testing.T) { storetest.SwapLoginIsOneStep(t, backend) },
		"LoginsRaceToOneIndex":     func(t *testing.T) { storetest.LoginsRaceToOneIndex(t, backend) },
		"JoinHonoursAStandingMark": func(t *testing.T) { storetest.JoinHonoursAStandingMark(t, backend) },
		"IndexKeysAreExact":        func(t *testing.T) { storetest.IndexKeysAreExact(t, backend) },
		"LoginRacesARevocationByMark": func(t *testing.T) {
			storetest.LoginRacesARevocationByMark(t, backend)
		},
		"IndexWritesRaceAContextWrite": func(t *testing.T) { storetest.IndexWritesRaceAContextWrite(t, backend) },
	})
}

// The sweep prunes an index record's expired entries and removes the
// lookup entries no record lists; it never removes one a record lists,
// so a revocation never misses a ref the index holds (Ruling 6).
func TestTheSweepRemovesOnlyWhatNothingLists(t *testing.T) {
	ctx := context.Background()
	now := t0
	s := onShared(t, func() time.Time { return now })
	keep := store.ContextRef{NAS: "leaf-01", Username: "keep"}
	gone := store.ContextRef{NAS: "leaf-01", Username: "gone"}
	for _, r := range []store.ContextRef{keep, gone} {
		if err := s.IndexContext(ctx, "user:a", "sid-"+r.Username, "", r, time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.UnindexRef(ctx, gone); err != nil {
		t.Fatal(err)
	}
	if err := s.IndexContext(ctx, "", "short", "", keep, time.Minute); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Minute) // "short" has expired; the hour has not
	pruned, removed, err := s.Sweep(ctx)
	if err != nil || pruned != 1 || removed != 3 { // gone's principal and sid, keep's "short"
		t.Fatalf("Sweep = %d pruned, %d removed, %v", pruned, removed, err)
	}
	if refs, _ := s.ContextsByPrincipal(ctx, "user:a"); len(refs) != 1 || refs[0] != keep {
		t.Fatalf("after the sweep: %v", refs)
	}
	resp, err := s.ctx.Get(ctx, s.k.lookups(famByPrincipal, "user:a"), clientv3.WithPrefix(), clientv3.WithCountOnly())
	if err != nil || resp.Count != 1 {
		t.Fatalf("lookup entries left under user:a: %v %v", resp, err)
	}
}

// A planted index record never stops a revocation, the refresh or the
// sweep: a store writer puts a lookup entry for user:victim naming a ref
// with no context, and an x/ record for it that does not decode. The
// lookup keeps that ref unread, so the victim's live contexts are still
// marked; the walk and the sweep skip it, say its key (never its value)
// and count it; and the sweep deletes nothing it could not read (Task 7
// review I-1).
func TestAPlantedIndexRecordNeverStopsARevocation(t *testing.T) {
	ctx := context.Background()
	var mu sync.Mutex
	var logged []string
	undecodable := prometheus.NewCounter(prometheus.CounterOpts{Name: "undecodable"})
	cli := etcdtest.Client(t)
	s := newStore(cli, cli, Config{Prefix: etcdtest.Prefix(), Now: func() time.Time { return t0 },
		Logf: func(format string, args ...any) {
			mu.Lock()
			defer mu.Unlock()
			logged = append(logged, fmt.Sprintf(format, args...))
		}, IndexUndecodable: undecodable})
	victims := []store.ContextRef{{NAS: "leaf-01", Username: "alice"}, {NAS: "leaf-02", Username: "alice"}}
	for _, r := range victims {
		if err := s.PutContext(ctx, store.ContextKey{NAS: r.NAS, Username: r.Username},
			store.Context{CtxID: "c-" + r.NAS, Principal: "user:victim", Username: r.Username}, time.Hour); err != nil {
			t.Fatal(err)
		}
		if err := s.IndexContext(ctx, "user:victim", "", "", r, time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	planted := store.ContextRef{NAS: "zz", Username: "zz"}
	entry := s.k.lookup(famByPrincipal, "user:victim", planted)
	if _, err := s.ctx.Put(ctx, entry, "{}"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ctx.Put(ctx, s.k.indexed(planted), "not json"); err != nil {
		t.Fatal(err)
	}

	if refs, err := s.ContextsByPrincipal(ctx, "user:victim"); err != nil || len(refs) != 3 {
		t.Fatalf("a lookup over a planted record: %v %v, want the two victims and the planted ref", refs, err)
	}
	marked, err := session.New(s, func() time.Time { return t0 }, time.Hour, time.Hour).
		RevokeByPrincipal(ctx, "user:victim")
	if err != nil || len(marked) != 2 {
		t.Fatalf("a revocation of user:victim marked %v (%v), want both live contexts", marked, err)
	}
	for _, r := range victims {
		if c, err := s.GetContext(ctx, store.ContextKey{NAS: r.NAS, Username: r.Username}); err != nil ||
			c.RevokedAt.IsZero() {
			t.Fatalf("%v after the revocation: %+v %v", r, c, err)
		}
	}
	if ps, err := s.ActivePrincipals(ctx); err != nil || !slices.Equal(ps, []string{"user:victim"}) {
		t.Fatalf("active principals over a planted record: %v %v", ps, err)
	}
	if _, _, err := s.Sweep(ctx); err != nil {
		t.Fatalf("a sweep over a planted record: %v", err)
	}
	for _, key := range []string{entry, s.k.indexed(planted)} {
		if resp, err := s.ctx.Get(ctx, key); err != nil || len(resp.Kvs) != 1 {
			t.Fatalf("the sweep deleted %q, which it could not read: %v %v", key, resp, err)
		}
	}
	// One each: the two lookups (the test's and the revocation's), the
	// walk, and the sweep's two passes.
	if n := testutil.ToFloat64(undecodable); n != 5 {
		t.Fatalf("port49_store_index_records_undecodable_total = %v, want 5", n)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, line := range logged {
		if !strings.Contains(line, s.k.indexed(planted)) || strings.Contains(line, "not json") {
			t.Fatalf("a log line that does not name the key alone: %q", line)
		}
	}
}

// The lookups, the walk and the sweep page past etcd's 500-key page and
// batch past the 64-get transaction: 130 refs under one principal and 510
// index records in all, every one swept once it has expired (Task 7
// review m-2).
func TestTheIndexReadsPage(t *testing.T) {
	ctx := context.Background()
	var mu sync.Mutex
	now := t0
	s := onShared(t, func() time.Time { mu.Lock(); defer mu.Unlock(); return now })
	const many, all = 130, 510
	for i := range all {
		p := "user:many"
		if i >= many {
			p = fmt.Sprintf("user:%03d", i)
		}
		if err := s.IndexContext(ctx, p, "", "", store.ContextRef{NAS: "leaf", Username: fmt.Sprintf("u%03d", i)},
			time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	refs, err := s.ContextsByPrincipal(ctx, "user:many")
	if err != nil || len(refs) != many {
		t.Fatalf("ContextsByPrincipal = %d refs, %v; want %d", len(refs), err, many)
	}
	for i, r := range refs { // sorted, so each in its place: none twice, none left out
		if want := fmt.Sprintf("u%03d", i); r.Username != want {
			t.Fatalf("ref %d is %v, want %s", i, r, want)
		}
	}
	if ps, err := s.ActivePrincipals(ctx); err != nil || len(ps) != all-many+1 {
		t.Fatalf("ActivePrincipals = %d, %v; want %d", len(ps), err, all-many+1)
	}
	mu.Lock()
	now = now.Add(2 * time.Hour)
	mu.Unlock()
	if pruned, removed, err := s.Sweep(ctx); err != nil || pruned != all || removed != all {
		t.Fatalf("Sweep = %d pruned, %d removed, %v; want %d and %d", pruned, removed, err, all, all)
	}
	resp, err := s.ctx.Get(ctx, s.k.root, clientv3.WithPrefix(), clientv3.WithCountOnly())
	if err != nil || resp.Count != 0 {
		t.Fatalf("keys left after the sweep: %v %v", resp, err)
	}
}

// A context record that does not decode is unreadable, as one the sealing
// layer cannot open is: it carries its revision, the narrow setters refuse
// it, and a login replaces it. As a plain error on every read it would
// lock the user out on that device until its lease ended (Task 6 review
// M-4).
func TestAnUndecodableContextIsReplacedByALogin(t *testing.T) {
	ctx := context.Background()
	s := onShared(t, func() time.Time { return t0 })
	k := store.ContextKey{NAS: "leaf-01", Username: "alice"}
	ref := store.ContextRef{NAS: k.NAS, Username: k.Username}
	if err := s.PutContext(ctx, k, store.Context{CtxID: "old", Principal: "user:a", Username: "alice"},
		time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := s.IndexContext(ctx, "user:a", "sid-old", "", ref, time.Hour); err != nil {
		t.Fatal(err)
	}
	put, err := s.ctx.Put(ctx, s.k.context(k), "not json")
	if err != nil {
		t.Fatal(err)
	}
	var u *store.UnreadableContextError
	if _, err := s.GetContext(ctx, k); !errors.As(err, &u) || u.Rev != uint64(put.Header.Revision) {
		t.Fatalf("a read of an undecodable context: %v", err)
	}
	if err := s.TouchContext(ctx, k, time.Hour); !errors.As(err, &u) {
		t.Fatalf("a touch of an undecodable context: %v", err)
	}
	login := store.Context{CtxID: "new", Principal: "user:b", Username: "alice", PrivLvl: 1, AuthTime: t0,
		RefreshedAt: t0, Credential: store.Credential{Method: "oidc", Sid: "sid-new"}}
	res, err := store.JoinContext(ctx, s, k, login, t0, t0, time.Hour,
		store.LoginIndex{Principal: "user:b", Sid: "sid-new", TTL: time.Hour})
	if err != nil || !res.ReplacedUnreadable {
		t.Fatalf("a login over an undecodable context: %+v %v", res, err)
	}
	if got, err := s.GetContext(ctx, k); err != nil || got.CtxID != "new" {
		t.Fatalf("after the login: %+v %v", got, err)
	}
	if refs, err := s.ContextsByPrincipal(ctx, "user:a"); err != nil || len(refs) != 0 {
		t.Fatalf("the replaced context is still indexed: %v %v", refs, err)
	}
	if refs, err := s.ContextsBySid(ctx, "sid-new"); err != nil || len(refs) != 1 || refs[0] != ref {
		t.Fatalf("the login is not indexed: %v %v", refs, err)
	}
}

// A context that does not decode is deleted on the Rev its error carries,
// as any other is: nothing can use it, and the re-index may clear it so
// (Task 7 review m-4, K-1).
func TestAnUndecodableContextIsDeletedOnItsRev(t *testing.T) {
	ctx := context.Background()
	s := onShared(t, func() time.Time { return t0 })
	k := store.ContextKey{NAS: "leaf-01", Username: "alice"}
	if _, err := s.ctx.Put(ctx, s.k.context(k), "not json"); err != nil {
		t.Fatal(err)
	}
	var u *store.UnreadableContextError
	if _, err := s.GetContext(ctx, k); !errors.As(err, &u) {
		t.Fatalf("a read of an undecodable context: %v", err)
	}
	if err := s.DeleteContextIf(ctx, k, u.Rev+1); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("a delete on another Rev: %v", err)
	}
	if err := s.DeleteContextIf(ctx, k, u.Rev); err != nil {
		t.Fatalf("a delete on its Rev: %v", err)
	}
	if _, err := s.GetContext(ctx, k); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("after the delete: %v", err)
	}
}
