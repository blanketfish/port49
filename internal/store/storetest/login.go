package storetest

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/store"
)

// loginOf is a login's context and the index it writes, for principal on
// ref under sid and the certificate (issuer "CN=Corp CA", serial).
func loginOf(principal, sid, serial string, now time.Time) (store.Context, store.LoginIndex) {
	c := store.Context{CtxID: "ctx_" + sid, Principal: principal, Username: "svc", PrivLvl: 1,
		AuthTime: now, RefreshedAt: now, Credential: store.Credential{Method: "cert", Issuer: "CN=Corp CA",
			Serial: serial, Sid: sid}}
	return c, store.LoginIndex{Principal: principal, Sid: sid, CertKey: store.CertKey("CN=Corp CA", serial),
		TTL: time.Hour}
}

func refsOf(t *testing.T, s store.Store, f func(context.Context, string) ([]store.ContextRef, error), key string) int {
	t.Helper()
	refs, err := f(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	return len(refs)
}

// SwapLoginIsOneStep is plan 7d's login: JoinContext writes the context
// and its index in one SwapLogin. A first login is found under its
// principal, sid and certificate; another principal's replace leaves the
// ref under the new login's keys alone; the same principal's second
// window keeps the first window's keys; and a write whose context moved
// since the read writes nothing, index included.
func SwapLoginIsOneStep(t *testing.T, b Backend) {
	now := t0
	s := b.New(t, func() time.Time { return now })
	ctx := context.Background()
	k := store.ContextKey{NAS: "leaf-01", Username: "svc"}
	const alice, bob = "spiffe://example.com/alice", "spiffe://example.com/bob"

	c, ix := loginOf(alice, "sid-a1", "0a", now)
	if _, err := store.JoinContext(ctx, s, k, c, now, now, time.Hour, ix); err != nil {
		t.Fatal(err)
	}
	for _, q := range []struct {
		f   func(context.Context, string) ([]store.ContextRef, error)
		key string
	}{{s.ContextsByPrincipal, alice}, {s.ContextsBySid, "sid-a1"}, {s.ContextsByCert, ix.CertKey}} {
		if refsOf(t, s, q.f, q.key) != 1 {
			t.Fatalf("a first login is not found under %q", q.key)
		}
	}
	c2, ix2 := loginOf(alice, "sid-a2", "0a", now)
	if out, err := store.JoinContext(ctx, s, k, c2, now, now, time.Hour, ix2); err != nil || !out.Joined {
		t.Fatalf("the second window: %+v %v", out, err)
	}
	if refsOf(t, s, s.ContextsBySid, "sid-a1") != 1 || refsOf(t, s, s.ContextsBySid, "sid-a2") != 1 {
		t.Fatal("a join must keep the first window's sid and add its own")
	}
	cb, ixb := loginOf(bob, "sid-b1", "0b", now)
	if out, err := store.JoinContext(ctx, s, k, cb, now, now, time.Hour, ixb); err != nil || out.Replaced == "" {
		t.Fatalf("bob's replace: %+v %v", out, err)
	}
	for key, f := range map[string]func(context.Context, string) ([]store.ContextRef, error){
		alice: s.ContextsByPrincipal, "sid-a1": s.ContextsBySid, "sid-a2": s.ContextsBySid, ix.CertKey: s.ContextsByCert,
	} {
		if refsOf(t, s, f, key) != 0 {
			t.Fatalf("after bob's replace, alice's %q still reaches bob's context", key)
		}
	}
	if refsOf(t, s, s.ContextsByPrincipal, bob) != 1 || refsOf(t, s, s.ContextsBySid, "sid-b1") != 1 {
		t.Fatal("bob's replace is not indexed under bob")
	}

	// A swap against a revision that moved writes nothing: not the context,
	// not the index.
	read, err := s.GetContext(ctx, k)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.TouchContext(ctx, k, time.Hour); err != nil {
		t.Fatal(err)
	}
	cc, _ := loginOf("spiffe://example.com/carol", "sid-c1", "0c", now)
	err = s.SwapLogin(ctx, k, read.Rev, cc, time.Hour, store.LoginWrite{ClearRef: true,
		Principal: "spiffe://example.com/carol", Sid: "sid-c1", IndexTTL: time.Hour})
	if !errors.Is(err, store.ErrConflict) {
		t.Fatalf("a stale SwapLogin: %v, want ErrConflict", err)
	}
	if refsOf(t, s, s.ContextsBySid, "sid-c1") != 0 || refsOf(t, s, s.ContextsByPrincipal, bob) != 1 {
		t.Fatal("a refused SwapLogin changed the index")
	}
}

// LoginsRaceToOneIndex is PR #7's third follow-up made a property: logins
// under one username on one device, racing, leave the ref indexed under
// the keys of the principal whose context stands, all of them, and under
// no other's. Each round races alice's two windows and bob's login over
// carol's context. No two logins replace the same context: each write is
// on the revision it read, so a second replace of one record is a lost
// update.
func LoginsRaceToOneIndex(t *testing.T, b Backend) {
	const rounds = 100
	k := store.ContextKey{NAS: "leaf-01", Username: "svc"}
	const alice, bob, carol = "spiffe://example.com/alice", "spiffe://example.com/bob", "spiffe://example.com/carol"
	for round := 0; round < rounds; round++ {
		s := b.New(t, func() time.Time { return t0 })
		ctx := context.Background()
		c0, ix0 := loginOf(carol, "sid-c", "0c", t0)
		if _, err := store.JoinContext(ctx, s, k, c0, t0, t0, time.Hour, ix0); err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		var wg sync.WaitGroup
		errs := make(chan error, 3)
		logins := []struct{ p, sid, serial string }{{alice, "sid-a1", "0a"}, {alice, "sid-a2", "0a"}, {bob, "sid-b", "0b"}}
		results := make([]store.JoinResult, len(logins))
		for i, l := range logins {
			c, ix := loginOf(l.p, l.sid, l.serial, t0)
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				var err error
				results[i], err = store.JoinContext(ctx, s, k, c, t0, t0, time.Hour, ix)
				errs <- err
			}()
		}
		close(start)
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatalf("round %d: %v", round, err)
			}
		}
		replaced := map[string]bool{}
		for i, res := range results {
			if res.Replaced == "" {
				continue
			}
			if replaced[res.Replaced] {
				t.Fatalf("round %d: %s replaced %s, which another login had replaced already", round,
					logins[i].sid, res.Replaced)
			}
			replaced[res.Replaced] = true
		}
		got, err := s.GetContext(ctx, k)
		if err != nil {
			t.Fatal(err)
		}
		mine := map[string][]string{alice: {"sid-a1", "sid-a2"}, bob: {"sid-b"}}
		for p, sids := range mine {
			want := 0
			if p == got.Principal {
				want = 1
			}
			if n := refsOf(t, s, s.ContextsByPrincipal, p); n != want {
				t.Fatalf("round %d: %s's context stands, and %s is indexed %d times", round, got.Principal, p, n)
			}
			for _, sid := range sids {
				// The other principal's sids: none reaches the context.
				if n := refsOf(t, s, s.ContextsBySid, sid); p != got.Principal && n != 0 {
					t.Fatalf("round %d: %s's context stands, and %s's sid %s reaches it", round, got.Principal, p, sid)
				}
			}
		}
		// The standing principal's own sids: the last writer's is indexed,
		// and when alice's windows met in one context — either returned
		// Joined — both are. A join is the only way the two meet, and
		// alice standing means nothing replaced it after.
		if got.Principal == alice {
			want := []string{got.Credential.Sid}
			if results[0].Joined || results[1].Joined {
				want = mine[alice]
			}
			for _, sid := range want {
				if n := refsOf(t, s, s.ContextsBySid, sid); n != 1 {
					t.Fatalf("round %d: alice's context stands, and its sid %s is indexed %d times", round, sid, n)
				}
			}
		}
		if refsOf(t, s, s.ContextsByPrincipal, carol) != 0 || refsOf(t, s, s.ContextsBySid, "sid-c") != 0 {
			t.Fatalf("round %d: carol's keys outlived the replace", round)
		}
	}
}

// markingStore puts a mark the first time JoinContext reads that none
// stands, so the mark lands between the login's read and its write.
type markingStore struct {
	store.Store
	mark store.Revocation
	once sync.Once
}

func (m *markingStore) GetRevocation(ctx context.Context, kind, key string) (store.Revocation, error) {
	r, err := m.Store.GetRevocation(ctx, kind, key)
	if errors.Is(err, store.ErrNotFound) && kind == m.mark.Kind && key == m.mark.Key {
		m.once.Do(func() {
			if perr := m.Store.PutRevocation(ctx, m.mark); perr != nil {
				panic(perr)
			}
		})
	}
	return r, err
}

// JoinHonoursAStandingMark is 7a's residual window closed (spec §5.1.4;
// decision 35): a login whose principal or certificate is marked writes
// its context revoked at the mark, unless its token was minted after it;
// and a mark that lands between the login's read of the marks and its
// write makes the write conflict, so it is decided again and lands
// revoked.
func JoinHonoursAStandingMark(t *testing.T, b Backend) {
	ctx := context.Background()
	k := store.ContextKey{NAS: "leaf-01", Username: "svc"}
	const alice = "spiffe://example.com/alice"
	at := t0.Add(-time.Minute)
	for _, kind := range []string{store.RevocationPrincipal, store.RevocationCert} {
		key := alice
		if kind == store.RevocationCert {
			key = store.CertKey("CN=Corp CA", "0a")
		}
		mark := store.Revocation{Kind: kind, Key: key, At: at, Origin: "storetest"}

		// Standing before the login.
		s := b.New(t, func() time.Time { return t0 })
		if err := s.PutRevocation(ctx, mark); err != nil {
			t.Fatal(err)
		}
		c, ix := loginOf(alice, "sid-a1", "0a", t0)
		out, err := store.JoinContext(ctx, s, k, c, at.Add(-time.Second), t0, time.Hour, ix)
		if err != nil || !out.Context.RevokedAt.Equal(at) {
			t.Fatalf("%s: a login under a standing mark wrote %+v %v", kind, out.Context, err)
		}
		// A token minted after the mark is a credential verified again
		// (decision 15): it is not carried.
		s = b.New(t, func() time.Time { return t0 })
		if err := s.PutRevocation(ctx, mark); err != nil {
			t.Fatal(err)
		}
		if out, err := store.JoinContext(ctx, s, k, c, at.Add(time.Second), t0, time.Hour, ix); err != nil ||
			!out.Context.RevokedAt.IsZero() {
			t.Fatalf("%s: a token minted after the mark: %+v %v", kind, out.Context, err)
		}

		// Landing between the read and the write.
		inner := b.New(t, func() time.Time { return t0 })
		s = &markingStore{Store: inner, mark: mark}
		out, err = store.JoinContext(ctx, s, k, c, at.Add(-time.Second), t0, time.Hour, ix)
		if err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		got, err := inner.GetContext(ctx, k)
		if err != nil || !got.RevokedAt.Equal(at) || !out.Context.RevokedAt.Equal(at) {
			t.Fatalf("%s: a mark landing mid-login: stored %+v (%v), reported %v", kind, got.RevokedAt, err,
				out.Context.RevokedAt)
		}
		// And the context is still indexed, so the revocation's second pass
		// would find it too.
		if refsOf(t, inner, inner.ContextsByPrincipal, alice) != 1 {
			t.Fatalf("%s: the revoked login is not indexed", kind)
		}
	}
}

// LoginRacesARevocationByMark is decision 35's one step, raced: a login
// against a revocation by mark — PutRevocation, then one pass over the
// index setting RevokedAt, as broker.Revoke does — never leaves the login's
// context unrevoked under a mark that stands, on a token minted before it.
// Either the login's write landed first, and is indexed in the same step,
// so the pass finds it; or the mark did, and the login's swap conflicts and
// is decided again against it. A backend that checks the marks outside the
// step that writes the context (or indexes it in another) fails here.
//
// The window is a few instructions wide on memory, so the property runs
// enough rounds to land in it: with the mark check in its own critical
// section it failed 20 runs of 20 at 10000 rounds, and about half at 300.
// -short runs 300, for a backend whose rounds are network round trips.
func LoginRacesARevocationByMark(t *testing.T, b Backend) {
	rounds := 10000
	if testing.Short() {
		rounds = 300
	}
	k := store.ContextKey{NAS: "leaf-01", Username: "svc"}
	const alice, carol = "spiffe://example.com/alice", "spiffe://example.com/carol"
	for _, kind := range []string{store.RevocationPrincipal, store.RevocationCert} {
		for round := 0; round < rounds; round++ {
			s := b.New(t, func() time.Time { return t0 })
			ctx := context.Background()
			if round%2 == 1 { // a replace of another principal's context
				c0, ix0 := loginOf(carol, "sid-c", "0c", t0)
				if _, err := store.JoinContext(ctx, s, k, c0, t0, t0, time.Hour, ix0); err != nil {
					t.Fatal(err)
				}
			}
			c, ix := loginOf(alice, "sid-a", "0a", t0)
			mark := store.Revocation{Kind: kind, Key: alice, At: t0, Origin: "storetest"}
			byIndex := s.ContextsByPrincipal
			if kind == store.RevocationCert {
				mark.Key, byIndex = ix.CertKey, s.ContextsByCert
			}
			start := make(chan struct{})
			errs := make(chan error, 2)
			var wg sync.WaitGroup
			wg.Add(2)
			go func() {
				defer wg.Done()
				<-start
				_, err := store.JoinContext(ctx, s, k, c, t0.Add(-time.Minute), t0, time.Hour, ix)
				errs <- err
			}()
			go func() {
				defer wg.Done()
				<-start
				if err := s.PutRevocation(ctx, mark); err != nil {
					errs <- err
					return
				}
				refs, err := byIndex(ctx, mark.Key)
				for _, r := range refs {
					if err == nil {
						err = s.SetRevokedAt(ctx, store.ContextKey{NAS: r.NAS, Username: r.Username}, mark.At)
					}
				}
				errs <- err
			}()
			close(start)
			wg.Wait()
			close(errs)
			for err := range errs {
				if err != nil {
					t.Fatalf("%s round %d: %v", kind, round, err)
				}
			}
			got, err := s.GetContext(ctx, k)
			if err != nil {
				t.Fatal(err)
			}
			if got.Principal == alice && got.RevokedAt.IsZero() {
				t.Fatalf("%s round %d: a login landed unrevoked under a standing mark", kind, round)
			}
		}
	}
}

// PurgeTakesEveryToken is a start on a store that persists (plan 7d):
// every token goes, live or expired, under every key, and the count is the
// live ones; receipts, contexts and marks stay.
func PurgeTakesEveryToken(t *testing.T, b Backend) {
	ctx := context.Background()
	s := b.New(t, func() time.Time { return t0 })
	for i, k := range []store.TokenKey{{NAS: "leaf-01", Username: "a"}, {NAS: "leaf-02", Username: "a"},
		{NAS: "leaf-03", Username: "b"}} {
		exp := t0.Add(time.Minute)
		if i == 2 {
			exp = t0 // expired already
		}
		if _, err := s.PutToken(ctx, k, store.Token{ID: fmt.Sprint("t", i), Secret: []byte("s"), Kind: store.KindLogin,
			ExpiresAt: exp}); err != nil {
			t.Fatal(err)
		}
	}
	ck := store.ContextKey{NAS: "leaf-01", Username: "a"}
	if err := s.PutContext(ctx, ck, store.Context{CtxID: "c", Principal: "p", Username: "a"}, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := s.PutRevocation(ctx, store.Revocation{Kind: store.RevocationPrincipal, Key: "p", At: t0}); err != nil {
		t.Fatal(err)
	}
	n, err := s.PurgeTokens(ctx)
	if err != nil || n != 2 {
		t.Fatalf("PurgeTokens = %d, %v; want the 2 live tokens", n, err)
	}
	for _, k := range []store.TokenKey{{NAS: "leaf-01", Username: "a"}, {NAS: "leaf-02", Username: "a"}} {
		if got, _ := s.Candidates(ctx, k); len(got) != 0 {
			t.Fatalf("a token under %v survived the purge", k)
		}
	}
	if _, err := s.GetContext(ctx, ck); err != nil {
		t.Fatalf("the purge took a context: %v", err)
	}
	if _, err := s.GetRevocation(ctx, store.RevocationPrincipal, "p"); err != nil {
		t.Fatalf("the purge took a mark: %v", err)
	}
	if n, err := s.PurgeTokens(ctx); err != nil || n != 0 {
		t.Fatalf("a second purge: %d %v", n, err)
	}
}

// SelfRevocationBindsToTheRead is 7c's self-revocation on any backend
// (decision 34): a revoking SetContextPolicy against the policy revision a
// read returned conflicts once another principal's login has replaced the
// context, and the replacing context stays unrevoked.
func SelfRevocationBindsToTheRead(t *testing.T, b Backend) {
	ctx := context.Background()
	s := b.New(t, func() time.Time { return t0 })
	k := store.ContextKey{NAS: "leaf-01", Username: "svc"}
	ca, ixa := loginOf("spiffe://example.com/alice", "sid-a", "0a", t0)
	if _, err := store.JoinContext(ctx, s, k, ca, t0, t0, time.Hour, ixa); err != nil {
		t.Fatal(err)
	}
	read, err := s.GetContext(ctx, k)
	if err != nil {
		t.Fatal(err)
	}
	cb, ixb := loginOf("spiffe://example.com/bob", "sid-b", "0b", t0)
	if _, err := store.JoinContext(ctx, s, k, cb, t0, t0, time.Hour, ixb); err != nil {
		t.Fatal(err)
	}
	err = s.SetContextPolicy(ctx, k, read.PolicyRev, store.ContextPolicy{RevokedAt: t0})
	if !errors.Is(err, store.ErrConflict) {
		t.Fatalf("alice's revoke after bob's replace: %v, want ErrConflict", err)
	}
	if got, err := s.GetContext(ctx, k); err != nil || got.Principal != "spiffe://example.com/bob" ||
		!got.RevokedAt.IsZero() {
		t.Fatalf("bob's context: %+v %v", got, err)
	}
}
