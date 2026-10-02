package etcd

import (
	"context"
	"encoding/json"
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
	"github.com/rhwendt/port49/internal/store/crypt"
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

// backend runs LoginRacesARevocationByMark, the token family's races and
// the login's for 200 rounds, each a few round trips to the member, not
// memory's 10000, each race's short side staggered across the login
// (storetest.Backend.Stagger): they are what guards the mark compare and
// the index compare in the login's transaction (Task 6 review C-1). Plan
// 7d R1's proof, Task 6: a SwapLogin that leaves the marks out of its
// transaction's compare, or reads them in Gets of their own before it, was
// caught in 10 runs of 10 each, the first catch by round 30; unstaggered,
// in none of 10000.
var backend = storetest.Backend{New: func(t *testing.T, clock func() time.Time) store.Store {
	return planting{onShared(t, clock)}
}, RaceRounds: 200, Stagger: true}

var t0 = time.Unix(1_000_000, 0).UTC()

// planting is a store with a way to write an idempotency record whole,
// as an older port49's or a corrupted one would sit there, which no
// store.Store method can (storetest.Planter).
type planting struct{ *Store }

func (p planting) PlantIdempotency(ctx context.Context, principal, key string, rec store.Idempotency) error {
	body, err := json.Marshal(idemRecOf(rec))
	if err != nil {
		return err
	}
	_, err = p.tok.Put(ctx, p.k.idem(principal, key), string(body))
	return err
}

// Every storetest property against etcd (plan 7d).
func TestTheEtcdStoreHoldsEveryProperty(t *testing.T) {
	t.Parallel()
	storetest.Run(t, backend)
}

// And through the sealing layer over etcd, which is what port49d runs,
// with bare etcd's rounds and stagger: the layer adds a round of its own
// work to each write, and the races must still meet their window (Task 6
// review C-1).
func TestTheSealingLayerOverEtcdHoldsEveryProperty(t *testing.T) {
	t.Parallel()
	storetest.Run(t, storetest.Backend{New: func(t *testing.T, clock func() time.Time) store.Store {
		return crypt.Wrap(onShared(t, clock), sealKeys, nil)
	}, RaceRounds: backend.RaceRounds, Stagger: backend.Stagger})
}

var sealKeys = crypt.Keys{Current: crypt.Key{ID: "k1", Bytes: [32]byte{1}}}

// With two of three members stopped, a write and a read each fail within
// their deadline as store.ErrUnavailable: never a stale answer (Ruling 4;
// spec §14, "Quorum lost").
func TestALostQuorumIsUnavailableNeverStale(t *testing.T) {
	t.Parallel()
	c := etcdtest.StartCluster(t)
	s, err := Open(Config{Endpoints: c.Endpoints, Prefix: etcdtest.Prefix(), Now: func() time.Time { return t0 }})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	k := store.ContextKey{NAS: "leaf-01", Username: "alice"}
	if err := s.PutContext(ctx, k, store.Context{CtxID: "c", Principal: "p", Username: "alice"}, time.Hour); err != nil {
		t.Fatal(err)
	}
	c.Stop(1)
	c.Stop(2)
	for name, call := range map[string]func(context.Context) error{
		"read":  func(ctx context.Context) error { _, err := s.GetContext(ctx, k); return err },
		"write": func(ctx context.Context) error { return s.SetRevokedAt(ctx, k, t0) },
	} {
		cctx, cancel := context.WithTimeout(ctx, time.Second)
		start := time.Now()
		err := call(cctx)
		cancel()
		elapsed := time.Since(start)
		if !errors.Is(err, store.ErrUnavailable) || elapsed > 3*time.Second {
			t.Fatalf("%s without quorum: %v after %v", name, err, elapsed)
		}
		t.Logf("%s without quorum: %v after %v", name, err, elapsed)
	}
}

// A store writer who adds a login witness, or names another identity, in
// the plaintext beside a sealed record changes nothing read through the
// sealing layer: the login witness, the principal and the receipt's
// presented credential are read from the seal alone. crypt_test.go pins
// that the plaintext is blank when written; this pins that it is ignored
// when read (Task 6 review M-2.2).
func TestThePlaintextBesideASealIsNeverRead(t *testing.T) {
	ctx := context.Background()
	now := t0
	inner := onShared(t, func() time.Time { return now })
	s := crypt.Wrap(inner, sealKeys, nil)
	edit := func(key string, v any, f func()) {
		t.Helper()
		resp, err := inner.tok.Get(ctx, key)
		if err != nil || len(resp.Kvs) != 1 {
			t.Fatalf("reading %s: %v %v", key, resp, err)
		}
		if err := json.Unmarshal(resp.Kvs[0].Value, v); err != nil {
			t.Fatal(err)
		}
		f()
		body, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := inner.tok.Put(ctx, key, string(body), clientv3.WithIgnoreLease()); err != nil {
			t.Fatal(err)
		}
	}

	var h, forged [32]byte
	copy(h[:], "hash")
	copy(forged[:], "forged")
	ck := store.ContextKey{NAS: "leaf-01", Username: "alice"}
	if err := s.PutContext(ctx, ck, store.Context{CtxID: "ctx1", Principal: "user:alice", Username: "alice",
		PrivLvl: 1, Logins: []string{store.LoginWitness(h)}}, time.Hour); err != nil {
		t.Fatal(err)
	}
	var cr ctxRec
	edit(inner.k.context(ck), &cr, func() {
		cr.Logins = append(cr.Logins, store.LoginWitness(forged))
		cr.Principal = "user:mallory"
		cr.PrivLvl, cr.MaxPrivilege, cr.Enable, cr.CtxID = 15, 15, "token", "ctx-m"
	})
	if cr.Logins[0] != store.LoginWitness(forged) {
		t.Fatalf("the sealed context held a plaintext witness: %v", cr.Logins)
	}
	c, err := s.GetContext(ctx, ck)
	if err != nil || c.Principal != "user:alice" || !slices.Equal(c.Logins, []string{store.LoginWitness(h)}) ||
		c.PrivLvl != 1 || c.MaxPrivilege != 0 || c.Enable != "" || c.CtxID != "ctx1" {
		t.Fatalf("a context read through the seal after a plaintext edit: %+v %v", c, err)
	}

	tk := store.TokenKey{NAS: "leaf-01", Username: "alice"}
	if _, err := s.PutToken(ctx, tk, store.Token{ID: "t1", Secret: []byte("x"), Kind: store.KindLogin,
		ExpiresAt: now.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	rk := store.ReceiptKey{NAS: "leaf-01", Username: "alice", Kind: store.KindLogin, CredentialSHA256: h}
	if err := s.RedeemAndReceipt(ctx, tk, "t1", store.ReceiptWrite{Key: rk, Principal: "user:alice", IndexTTL: time.Hour,
		Receipt: store.Receipt{CredentialSHA256: h, Status: 1, CtxID: "ctx1", FirstRedeemedAt: now,
			IdleExpiresAt: now.Add(time.Minute), RetainUntil: now.Add(time.Hour),
			Principal: "user:alice", Sid: "sid-1", CertKey: store.CertKey("ca", "0a")}}); err != nil {
		t.Fatal(err)
	}
	var rr receiptRec
	edit(inner.k.receipt(rk), &rr, func() {
		rr.Principal, rr.Sid, rr.CertKey = "user:mallory", "sid-m", store.CertKey("ca", "ff")
	})
	r, err := s.GetReceipt(ctx, rk)
	if err != nil || r.Principal != "user:alice" || r.Sid != "sid-1" || r.CertKey != store.CertKey("ca", "0a") {
		t.Fatalf("a receipt read through the seal after a plaintext edit: %+v %v", r, err)
	}
}

// An idempotency record is on a lease, reserved and completed alike: one
// written with none would sit in etcd forever, hidden by its expiry
// (Task 8 review m-2).
func TestAnIdempotencyRecordIsOnALease(t *testing.T) {
	ctx := context.Background()
	s := onShared(t, func() time.Time { return t0 })
	leased := func(what string) {
		t.Helper()
		resp, err := s.tok.Get(ctx, s.k.idem("user:alice", "k"))
		if err != nil || len(resp.Kvs) != 1 || resp.Kvs[0].Lease == 0 {
			t.Fatalf("%s: the record has no lease: %v %v", what, resp, err)
		}
	}
	if _, ok, err := s.ReserveIdempotency(ctx, "user:alice", "k", store.Idempotency{BodyHash: "h", Holder: "a",
		Pending: true, ExpiresAt: t0.Add(time.Minute)}); err != nil || !ok {
		t.Fatal(ok, err)
	}
	leased("a reservation")
	if err := s.CompleteIdempotency(ctx, "user:alice", "k", "a", store.Idempotency{BodyHash: "h", Holder: "a",
		Response: []byte("resp"), ExpiresAt: t0.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	leased("a completion")
}

// A completion and a release each write only the record they read: a
// write that lands between the read and the commit (here at the clock read
// that tells whether the record is live) makes the commit's compare fail
// and the call read again. A release that deleted without that compare
// would take the record a completion just wrote; a completion without it
// would write over a reservation another request took after the read.
func TestIdempotencyWritesCompareTheirRead(t *testing.T) {
	ctx := context.Background()
	var race func() // run once at the next clock read
	s := onShared(t, func() time.Time {
		if f := race; f != nil {
			race = nil
			f()
		}
		return t0
	})
	pending := func(holder string) store.Idempotency {
		return store.Idempotency{BodyHash: "h", Holder: holder, Pending: true, ExpiresAt: t0.Add(time.Minute)}
	}
	done := store.Idempotency{BodyHash: "h", Holder: "a", Response: []byte("resp"), ExpiresAt: t0.Add(time.Hour)}
	if _, ok, err := s.ReserveIdempotency(ctx, "user:alice", "k", pending("a")); err != nil || !ok {
		t.Fatal(ok, err)
	}
	race = func() {
		if err := s.CompleteIdempotency(ctx, "user:alice", "k", "a", done); err != nil {
			t.Error(err)
		}
	}
	if err := s.ReleaseIdempotency(ctx, "user:alice", "k", "a"); err != nil {
		t.Fatal(err)
	}
	if race != nil {
		t.Fatal("the completion did not race the release")
	}
	if cur, ok, err := s.ReserveIdempotency(ctx, "user:alice", "k", pending("b")); err != nil || ok ||
		string(cur.Response) != "resp" {
		t.Fatalf("a release that raced a completion took the completed record: %+v %v %v", cur, ok, err)
	}

	if _, ok, err := s.ReserveIdempotency(ctx, "user:alice", "k2", pending("a")); err != nil || !ok {
		t.Fatal(ok, err)
	}
	race = func() { // a hands the record over: b's reservation is now the live one
		if err := s.CompleteIdempotency(ctx, "user:alice", "k2", "a", pending("b")); err != nil {
			t.Error(err)
		}
	}
	if err := s.CompleteIdempotency(ctx, "user:alice", "k2", "a", done); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("a completion over a record taken over since its read: %v, want ErrConflict", err)
	}
	if cur, ok, err := s.ReserveIdempotency(ctx, "user:alice", "k2", pending("c")); err != nil || ok || cur.Holder != "b" {
		t.Fatalf("after the refused completion: %+v %v %v", cur, ok, err)
	}
}

// restored is the etcd store under the sealing layer, which a test moves
// to another member's: a restore whose revisions went back.
type restored struct{ *Store }

// An etcd restored under a live port49d to revisions below the ones it
// last wrote at is placed by the ledger, not refused: a login after the
// restore is admitted, and a store writer's replay of the context a later
// login replaced before the restore is denied. The restore is a member of
// its own, starting from revision one, given the snapshot's record, under
// a port49d whose last writes were at revisions above a hundred (Task 6b
// review C1; crypt's TestALoginAfterARestoreIsTheLast on memory).
func TestALoginAfterAnEtcdRestoreIsTheLast(t *testing.T) {
	ctx := context.Background()
	clock := func() time.Time { return t0 }
	prefix := etcdtest.Prefix()
	cli := etcdtest.Client(t)
	inner := &restored{newStore(cli, cli, Config{Prefix: prefix, Now: clock})}
	for i := range 100 { // the revisions the restore goes back below
		if _, err := cli.Put(ctx, fmt.Sprintf("%spad/%d", prefix, i), "x"); err != nil {
			t.Fatal(err)
		}
	}
	l := crypt.NewLedger()
	s := crypt.Wrap(inner, sealKeys, nil, crypt.WithLedger(l))
	l.Seal()
	k := store.ContextKey{NAS: "leaf-01", Username: "netops"}
	login := func(id string, priv uint8) store.Context {
		return store.Context{CtxID: id, Principal: "user:" + id + "@example.com", Username: "netops", PrivLvl: priv}
	}
	raw := func() []byte {
		t.Helper()
		resp, err := inner.ctx.Get(ctx, inner.k.context(k))
		if err != nil || len(resp.Kvs) != 1 {
			t.Fatalf("reading the context's record: %v %v", resp, err)
		}
		return resp.Kvs[0].Value
	}
	if err := s.PutContext(ctx, k, login("alice-1", 1), time.Hour); err != nil {
		t.Fatal(err)
	}
	snapshot := raw()
	alice, err := s.GetContext(ctx, k)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SwapContext(ctx, k, alice.Rev, login("bob-1", 15), time.Hour); err != nil {
		t.Fatal(err)
	}
	bobSealed := raw()
	last, err := s.GetContext(ctx, k)
	if err != nil {
		t.Fatal(err)
	}

	srv := etcdtest.Start(t, etcdtest.Options{}) // the restore
	cliB := srv.Client(t, "")
	inner.Store = newStore(cliB, cliB, Config{Prefix: prefix, Now: clock})
	put, err := cliB.Put(ctx, inner.k.context(k), string(snapshot))
	if err != nil {
		t.Fatal(err)
	}
	if uint64(put.Header.Revision) >= last.Rev {
		t.Fatalf("the restore is at revision %d, not below the last write's %d", put.Header.Revision, last.Rev)
	}
	var u *store.UnreadableContextError
	if _, err := s.GetContext(ctx, k); !errors.As(err, &u) {
		t.Fatalf("Alice's record, restored: %v", err)
	}
	if err := s.SwapContext(ctx, k, u.Rev, login("carol-1", 1), time.Hour); err != nil {
		t.Fatal(err)
	}
	if got, err := s.GetContext(ctx, k); err != nil || got.CtxID != "carol-1" {
		t.Fatalf("Carol's login after the restore: %q %v", got.CtxID, err)
	}
	if _, err := cliB.Put(ctx, inner.k.context(k), string(bobSealed)); err != nil { // Bob's, written back
		t.Fatal(err)
	}
	if got, err := s.GetContext(ctx, k); !errors.Is(err, crypt.ErrNotLastWritten) {
		t.Fatalf("Bob's record written back over Carol's: %q %v", got.CtxID, err)
	}
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

// Each sealed context write returns the revision it committed at, and
// that revision is the Rev the next read sees: the order the crypt ledger
// places its own writes in (store.RevStore). A write that loses its
// compare returns zero; one that loses only to an index write reads again
// and returns the revision of the write that landed (Task 6 review M-1).
func TestAContextWriteReturnsItsRevision(t *testing.T) {
	ctx := context.Background()
	var race func() // run once at the next clock read: between a write's read and its commit
	s := onShared(t, func() time.Time {
		if f := race; f != nil {
			race = nil
			f()
		}
		return t0
	})
	k := store.ContextKey{NAS: "leaf-01", Username: "alice"}
	c := store.Context{CtxID: "c", Principal: "p", Username: "alice", PrivLvl: 1}
	check := func(what string, mod uint64, err error) store.Context {
		t.Helper()
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		got, err := s.GetContext(ctx, k)
		if err != nil || got.Rev != mod || mod == 0 {
			t.Fatalf("%s committed at %d, and a read sees Rev %d (%v)", what, mod, got.Rev, err)
		}
		return got
	}
	mod, err := s.PutContextRev(ctx, k, c, time.Hour)
	got := check("a put", mod, err)
	mod, err = s.SwapLoginRev(ctx, k, got.Rev, c, time.Hour, store.LoginWrite{Principal: "p", Sid: "s", IndexTTL: time.Hour})
	got = check("a login", mod, err)
	got.PrivLvl = 7
	mod, err = s.RewriteContextRev(ctx, k, got.Rev, got, 0, true) // the cached path: GetContext just read it
	got = check("a rewrite after a read", mod, err)
	mod, err = s.RewriteContextRev(ctx, k, got.Rev, got, time.Hour, false) // a ttl reads again
	got = check("a rewrite with a ttl", mod, err)
	mod, err = s.SwapContextRev(ctx, k, got.Rev, c, time.Hour)
	stale := check("a swap", mod, err).Rev - 1

	if mod, err := s.SwapLoginRev(ctx, k, stale, c, time.Hour, store.LoginWrite{}); mod != 0 || !errors.Is(err, store.ErrConflict) {
		t.Fatalf("a login on a stale revision: %d %v, want 0 and ErrConflict", mod, err)
	}
	ref := store.ContextRef{NAS: k.NAS, Username: k.Username}
	raced := false
	race = func() {
		raced = true
		if err := s.IndexContext(ctx, "q", "", "", ref, time.Hour); err != nil {
			t.Error(err)
		}
	}
	mod, err = s.PutContextRev(ctx, k, c, time.Hour)
	if !raced {
		t.Fatal("the index write did not race the put")
	}
	check("a put after a racing index write", mod, err)
	if refs, err := s.ContextsByPrincipal(ctx, "q"); err != nil || len(refs) != 1 {
		t.Fatalf("the racing index write: %v %v", refs, err)
	}
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

// A planted lookup or token-index entry whose key does not parse never
// fails a lookup of its key: it names no ref, so it is said by its key
// alone, counted and skipped, and the real ref is still answered. The
// sweep deletes it, compared on its revision (final review I-1).
func TestAnUnparseableLookupEntryIsSkippedAndSwept(t *testing.T) {
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
	live := store.ContextRef{NAS: "leaf-01", Username: "alice"}
	if err := s.PutContext(ctx, store.ContextKey{NAS: live.NAS, Username: live.Username},
		store.Context{CtxID: "c-1", Principal: "user:alice", Username: "alice"}, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := s.IndexContext(ctx, "user:alice", "sid-1", "", live, time.Hour); err != nil {
		t.Fatal(err)
	}
	tk := store.TokenKey{NAS: "leaf-01", Username: "alice"}
	if err := s.IndexToken(ctx, "user:alice", "", tk, time.Hour); err != nil {
		t.Fatal(err)
	}
	planted := []string{s.k.lookups(famByPrincipal, "user:alice") + "%zz/x",
		s.k.lookups(famBySid, "sid-1") + "%zz/x"}
	for _, key := range planted {
		if _, err := s.ctx.Put(ctx, key, "{}"); err != nil {
			t.Fatal(err)
		}
	}
	tokPlanted := s.k.tokenIndex(famTokByPrin, "user:alice") + "%zz/x"
	if _, err := s.tok.Put(ctx, tokPlanted, `{"expires_at":"`+t0.Add(time.Hour).Format(time.RFC3339)+`"}`); err != nil {
		t.Fatal(err)
	}

	if refs, err := s.ContextsByPrincipal(ctx, "user:alice"); err != nil || !slices.Equal(refs, []store.ContextRef{live}) {
		t.Fatalf("a lookup by principal over an unparseable entry: %v %v", refs, err)
	}
	if refs, err := s.ContextsBySid(ctx, "sid-1"); err != nil || !slices.Equal(refs, []store.ContextRef{live}) {
		t.Fatalf("a lookup by sid over an unparseable entry: %v %v", refs, err)
	}
	if keys, err := s.TokensByPrincipal(ctx, "user:alice"); err != nil || !slices.Equal(keys, []store.TokenKey{tk}) {
		t.Fatalf("a token lookup over an unparseable entry: %v %v", keys, err)
	}
	if n := testutil.ToFloat64(undecodable); n != 3 {
		t.Fatalf("port49_store_index_records_undecodable_total = %v, want 3", n)
	}
	if _, removed, err := s.Sweep(ctx); err != nil || removed != 2 {
		t.Fatalf("a sweep over two unparseable entries removed %d: %v", removed, err)
	}
	for _, key := range planted {
		if resp, err := s.ctx.Get(ctx, key); err != nil || len(resp.Kvs) != 0 {
			t.Fatalf("the sweep left %q: %v %v", key, resp, err)
		}
	}
	if refs, err := s.ContextsByPrincipal(ctx, "user:alice"); err != nil || !slices.Equal(refs, []store.ContextRef{live}) {
		t.Fatalf("the sweep took the live entry: %v %v", refs, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(logged) == 0 {
		t.Fatal("no unparseable entry was said")
	}
	for _, line := range logged {
		if !strings.Contains(line, "%zz/x") || strings.Contains(line, "expires_at") {
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

// A garbled index record never drops a principal from the refresh: one
// left out would keep a policy that may be wider than the one in force.
// The principal is read off its lookup entry's own key, and every other
// principal is still listed (Task 7 review I-1, as refined).
func TestAGarbledIndexRecordKeepsItsPrincipalActive(t *testing.T) {
	ctx := context.Background()
	s := onShared(t, func() time.Time { return t0 })
	victim := store.ContextRef{NAS: "leaf-01", Username: "alice"}
	other := store.ContextRef{NAS: "leaf-02", Username: "bob"}
	for _, x := range []struct {
		ref       store.ContextRef
		principal string
	}{{victim, "user:victim"}, {other, "user:other"}} {
		if err := s.PutContext(ctx, store.ContextKey{NAS: x.ref.NAS, Username: x.ref.Username},
			store.Context{CtxID: "c", Principal: x.principal, Username: x.ref.Username}, time.Hour); err != nil {
			t.Fatal(err)
		}
		if err := s.IndexContext(ctx, x.principal, "sid-"+x.ref.Username, "", x.ref, time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.ctx.Put(ctx, s.k.indexed(victim), "not json"); err != nil {
		t.Fatal(err)
	}
	ps, err := s.ActivePrincipals(ctx)
	if err != nil || !slices.Equal(ps, []string{"user:other", "user:victim"}) {
		t.Fatalf("active principals with user:victim's index record garbled: %v %v", ps, err)
	}
}

// Every context is named with what its index record lists live and its
// lookup entries hold: one whose record is gone, or lists no live
// principal, lists none; one whose record was rewritten to list another
// principal lists that one; and a key whose lookup entry is deleted is not
// listed, for the re-index to compare with the context's own (re-check
// IA2, I2; Task 7b review I-2).
func TestUnindexedFindsAContextItsIndexLost(t *testing.T) {
	ctx := context.Background()
	now := t0
	s := onShared(t, func() time.Time { return now })
	kept := store.ContextRef{NAS: "leaf-01", Username: "kept"}
	lost := store.ContextRef{NAS: "leaf-01", Username: "lost"}
	stale := store.ContextRef{NAS: "rack/1%2Fleaf", Username: "stale"}
	moved := store.ContextRef{NAS: "leaf-02", Username: "moved"}
	unlooked := store.ContextRef{NAS: "leaf-02", Username: "unlooked"}
	for _, r := range []store.ContextRef{kept, lost, stale, moved, unlooked} {
		if err := s.PutContext(ctx, store.ContextKey{NAS: r.NAS, Username: r.Username},
			store.Context{CtxID: "c", Principal: "user:a", Username: r.Username}, 2*time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.IndexContext(ctx, "user:a", "sid-k", "", kept, 2*time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := s.IndexContext(ctx, "user:a", "", "", lost, 2*time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := s.IndexContext(ctx, "user:a", "sid-1", "", stale, time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ctx.Delete(ctx, s.k.indexed(lost)); err != nil { // a store write hides it
		t.Fatal(err)
	}
	if _, err := s.ctx.Put(ctx, s.k.indexed(moved), // and one rewritten to name another
		`{"principals":[{"key":"user:b","expires_at":"`+t0.Add(2*time.Hour).Format(time.RFC3339)+`"}]}`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ctx.Put(ctx, s.k.lookup(famByPrincipal, "user:b", moved), "{}"); err != nil {
		t.Fatal(err)
	}
	if err := s.IndexContext(ctx, "user:a", "sid-u", "", unlooked, 2*time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ctx.Delete(ctx, s.k.lookup(famByPrincipal, "user:a", unlooked)); err != nil { // its lookup alone
		t.Fatal(err)
	}
	now = now.Add(2 * time.Minute) // stale's entries have expired; its context has not
	got, err := s.Unindexed(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := map[store.ContextRef]store.IndexedRef{
		kept:  {ContextRef: kept, Principals: []string{"user:a"}, Sids: []string{"sid-k"}},
		lost:  {ContextRef: lost},
		stale: {ContextRef: stale},
		moved: {ContextRef: moved, Principals: []string{"user:b"}},
		// Listed, but its lookup entry deleted: hidden as if not listed.
		unlooked: {ContextRef: unlooked, Sids: []string{"sid-u"}},
	}
	if len(got) != len(want) {
		t.Fatalf("Unindexed = %+v, want %+v", got, want)
	}
	for _, r := range got {
		w := want[r.ContextRef]
		if !slices.Equal(r.Principals, w.Principals) || !slices.Equal(r.Sids, w.Sids) || !slices.Equal(r.Certs, w.Certs) {
			t.Fatalf("Unindexed names %+v, want %+v", r, w)
		}
	}
}

// A garbled index record is named as listing nothing, said by its key
// alone and counted, and never stops the scan. The re-index then writes it
// whole again from the context, and a login over one lands, so it locks
// nobody out (re-check I3; Task 7 review K-2).
func TestAGarbledIndexRecordIsWrittenWholeAgain(t *testing.T) {
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
	alice := store.ContextRef{NAS: "leaf-01", Username: "alice"}
	bob := store.ContextRef{NAS: "leaf-02", Username: "bob"}
	for _, r := range []store.ContextRef{alice, bob} {
		if err := s.PutContext(ctx, store.ContextKey{NAS: r.NAS, Username: r.Username},
			store.Context{CtxID: "c", Principal: "user:" + r.Username, Username: r.Username}, time.Hour); err != nil {
			t.Fatal(err)
		}
		if err := s.IndexContext(ctx, "user:"+r.Username, "sid-"+r.Username, "", r, time.Hour); err != nil {
			t.Fatal(err)
		}
		if _, err := s.ctx.Put(ctx, s.k.indexed(r), "not json"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.ctx.Put(ctx, s.k.family(famContext)+"no-ref", "{}"); err != nil { // a key that names no ref
		t.Fatal(err)
	}
	got, err := s.Unindexed(ctx)
	if err != nil || len(got) != 2 || got[0].ContextRef != alice || got[1].ContextRef != bob ||
		len(got[0].Principals)+len(got[1].Principals) != 0 {
		t.Fatalf("Unindexed over garbled records = %+v, %v", got, err)
	}
	if n := testutil.ToFloat64(undecodable); n != 2 {
		t.Fatalf("port49_store_index_records_undecodable_total = %v, want 2", n)
	}
	m := session.New(s, func() time.Time { return t0 }, time.Hour, time.Hour)
	c := store.Context{Principal: "user:alice", Credential: store.Credential{Sid: "sid-alice"}}
	if err := m.Reindex(ctx, alice, c); err != nil {
		t.Fatalf("a re-index over a garbled record: %v", err)
	}
	if refs, err := s.ContextsByPrincipal(ctx, "user:alice"); err != nil || len(refs) != 1 || refs[0] != alice {
		t.Fatalf("after the re-index, user:alice's lookup = %v %v", refs, err)
	}
	if refs, err := s.ContextsBySid(ctx, "sid-alice"); err != nil || len(refs) != 1 || refs[0] != alice {
		t.Fatalf("after the re-index, sid-alice's lookup = %v %v", refs, err)
	}
	k := store.ContextKey{NAS: bob.NAS, Username: bob.Username}
	live, err := s.GetContext(ctx, k)
	if err != nil {
		t.Fatal(err)
	}
	login := store.Context{CtxID: "c", Principal: "user:bob", Username: "bob", PrivLvl: 1, AuthTime: t0,
		RefreshedAt: t0, Credential: store.Credential{Method: "oidc", Sid: "sid-new"}}
	if err := s.SwapLogin(ctx, k, live.Rev, login, time.Hour, store.LoginWrite{Principal: "user:bob",
		Sid: "sid-new", IndexTTL: time.Hour}); err != nil {
		t.Fatalf("a login over a garbled record: %v", err)
	}
	if refs, err := s.ContextsBySid(ctx, "sid-new"); err != nil || len(refs) != 1 || refs[0] != bob {
		t.Fatalf("after the login, sid-new's lookup = %v %v", refs, err)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, line := range logged {
		if strings.Contains(line, "not json") {
			t.Fatalf("a log line quotes a record's value: %q", line)
		}
	}
}

// A garbled index record is written whole again only while it is as
// read: two index writes over one, racing, both land, the loser reading
// again the winner's record. Written with no compare, one would erase the
// other's keys (Task 7 review K-2).
func TestARebuiltIndexRecordComparesItsRevision(t *testing.T) {
	ctx := context.Background()
	s := onShared(t, func() time.Time { return t0 })
	ref := store.ContextRef{NAS: "leaf-01", Username: "alice"}
	for round := range 50 {
		if _, err := s.ctx.Put(ctx, s.k.indexed(ref), "not json"); err != nil {
			t.Fatal(err)
		}
		sid := fmt.Sprintf("sid-%d", round)
		var wg sync.WaitGroup
		var errs [2]error
		start := make(chan struct{})
		wg.Add(2)
		go func() { defer wg.Done(); <-start; errs[0] = s.IndexContext(ctx, "user:a", "", "", ref, time.Hour) }()
		go func() { defer wg.Done(); <-start; errs[1] = s.IndexContext(ctx, "", sid, "", ref, time.Hour) }()
		close(start)
		wg.Wait()
		if errs[0] != nil || errs[1] != nil {
			t.Fatal(errs)
		}
		p, err1 := s.ContextsByPrincipal(ctx, "user:a")
		q, err2 := s.ContextsBySid(ctx, sid)
		if err1 != nil || err2 != nil || len(p) != 1 || len(q) != 1 {
			t.Fatalf("round %d: a racing rebuild lost a key: by principal %v, by sid %v (%v %v)", round, p, q, err1, err2)
		}
	}
}
