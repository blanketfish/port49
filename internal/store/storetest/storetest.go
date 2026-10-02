// Package storetest holds store.Store properties every implementation must
// have, written once and run against each: the memory store and the sealing
// layer over it today, a networked backend later. It is imported only by
// tests.
package storetest

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/store"
)

// Planter is a store a test can write an idempotency record into whole,
// bypassing the holder checks every store.Store method makes, as an older
// port49's record or a corrupted one would sit there. IdempotencyReservesOnce
// checks that such a record is nobody's on a store that is one.
type Planter interface {
	PlantIdempotency(ctx context.Context, principal, key string, rec store.Idempotency) error
}

// Peek is the live idempotency record under (principal, key), and whether
// there is one, read through ReserveIdempotency, which returns a live record
// untouched: store.Store has no plain read, since nothing but a reservation
// reads one. A probe reservation it writes when there is none is released.
func Peek(t *testing.T, s store.Store, principal, key string) (store.Idempotency, bool) {
	t.Helper()
	ctx := context.Background()
	cur, ok, err := s.ReserveIdempotency(ctx, principal, key, store.Idempotency{BodyHash: "peek", Holder: "storetest-peek",
		Pending: true, ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatalf("peeking at the idempotency record %q: %v", key, err)
	}
	if ok {
		if err := s.ReleaseIdempotency(ctx, principal, key, "storetest-peek"); err != nil {
			t.Fatal(err)
		}
		return store.Idempotency{}, false
	}
	return cur, true
}

// JoinRacesRevocation runs logins joining one live context concurrently with a
// revocation of it, many rounds over, and checks that nothing is lost: the
// revocation stands, because every token was minted before it; every login
// landed, because the kept privilege and auth_time are the highest any of them
// carried; and the ctx_id is the one the context was created with.
//
// newStore returns a fresh store per round. now is the fixed time the store's
// clock must return.
//
// joiners is MaxJoinAttempts-2, and that is not arbitrary: a swap is refused
// only when another writer's write landed, each of the other joiners and the
// revoker writes exactly once, so no join here can be refused MaxJoinAttempts
// times. A failure is therefore a lost write, never a starved loop.
func JoinRacesRevocation(t *testing.T, newStore func() store.Store, now time.Time) {
	t.Helper()
	const rounds = 200
	const joiners = store.MaxJoinAttempts - 2
	const principal = "user:alice@example.com"
	k := store.ContextKey{NAS: "leaf-01", Username: "alice"}
	mintedAt := now.Add(-time.Minute)
	for round := 0; round < rounds; round++ {
		s := newStore()
		ctx := context.Background()
		if err := s.PutContext(ctx, k, store.Context{CtxID: "ctx_first", Principal: principal, Username: "alice",
			PrivLvl: 1, AuthTime: now.Add(-time.Hour), RefreshedAt: now.Add(-time.Hour)}, time.Hour); err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		errs := make(chan error, joiners+1)
		var wg sync.WaitGroup
		for i := 1; i <= joiners; i++ {
			login := store.Context{CtxID: fmt.Sprintf("ctx_login_%d", i), Principal: principal, Username: "alice",
				PrivLvl: uint8(i), AuthTime: now.Add(time.Duration(i) * time.Second), RefreshedAt: now}
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				_, err := store.JoinContext(ctx, s, k, login, mintedAt, now, time.Hour, store.LoginIndex{})
				errs <- err
			}()
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs <- s.SetRevokedAt(ctx, k, now)
		}()
		close(start)
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatalf("round %d: %v", round, err)
			}
		}
		got, err := s.GetContext(ctx, k)
		if err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
		if !got.RevokedAt.Equal(now) {
			t.Fatalf("round %d: a join erased the revocation: %+v", round, got)
		}
		if got.PrivLvl != joiners || !got.AuthTime.Equal(now.Add(joiners*time.Second)) {
			t.Fatalf("round %d: a login was lost — privilege %d, auth_time %v, want %d and %v",
				round, got.PrivLvl, got.AuthTime, joiners, now.Add(joiners*time.Second))
		}
		if got.CtxID != "ctx_first" {
			t.Fatalf("round %d: a join replaced the ctx_id: %+v", round, got)
		}
	}
}

// PolicyRevision checks what SetContextPolicy's compare-and-set keys on
// (spec §5.1.3): policy_rev, which only a write to what the refresh decides
// moves. Accounting, touches, a refresh of the clocks and a grant of the level
// already held land between the refresher's read and its write without making
// it lose; a join, a replace, a revocation, a level that moved, a new blob
// hash and another policy write each send it back to read again, with nothing
// written. And a revocation stands: a refresh neither clears one nor moves it
// earlier.
//
// newStore returns a fresh store whose clock returns now.
func PolicyRevision(t *testing.T, newStore func() store.Store, now time.Time) {
	t.Helper()
	const principal = "user:alice@example.com"
	k := store.ContextKey{NAS: "leaf-01", Username: "alice"}
	seed := store.Context{CtxID: "ctx_first", Principal: principal, Username: "alice", PrivLvl: 1,
		MaxPrivilege: 15, Enable: "token", BlobHash: "sha256:old",
		AuthTime: now.Add(-time.Hour), RefreshedAt: now.Add(-time.Hour)}
	ctx := context.Background()
	fresh := func() store.Store {
		s := newStore()
		if err := s.PutContext(ctx, k, seed, time.Hour); err != nil {
			t.Fatal(err)
		}
		return s
	}
	read := func(s store.Store) store.Context {
		c, err := s.GetContext(ctx, k)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	refresh := store.ContextPolicy{BlobHash: "sha256:new", MaxPrivilege: 7, Enable: "none"}

	// Accounting and activity move the record's revision and not the
	// policy's: the refresh that read before them still lands.
	for _, w := range []struct {
		name  string
		write func(store.Store) error
	}{
		{"AnnotateContext", func(s store.Store) error {
			return s.AnnotateContext(ctx, k, "h", store.AccountingStateOpen)
		}},
		{"TouchContext", func(s store.Store) error { return s.TouchContext(ctx, k, time.Hour) }},
		{"RefreshContext of the clocks", func(s store.Store) error {
			return s.RefreshContext(ctx, k, store.ContextRefresh{AuthTime: now, RefreshedAt: now}, time.Hour)
		}},
		{"RefreshContext with the same blob", func(s store.Store) error {
			return s.RefreshContext(ctx, k, store.ContextRefresh{AuthTime: now, RefreshedAt: now,
				BlobHash: "sha256:old"}, time.Hour)
		}},
		{"SetPrivilege at the held level", func(s store.Store) error { return s.SetPrivilege(ctx, k, 1) }},
	} {
		s := fresh()
		before := read(s)
		if err := w.write(s); err != nil {
			t.Fatalf("%s: %v", w.name, err)
		}
		if between := read(s); between.Rev == before.Rev || between.PolicyRev != before.PolicyRev {
			t.Fatalf("%s must move Rev and not PolicyRev: %d/%d -> %d/%d",
				w.name, before.Rev, before.PolicyRev, between.Rev, between.PolicyRev)
		}
		if err := s.SetContextPolicy(ctx, k, before.PolicyRev, refresh); err != nil {
			t.Fatalf("%s between the read and the write must not make the refresh lose: %v", w.name, err)
		}
		if got := read(s); got.BlobHash != "sha256:new" || got.MaxPrivilege != 7 || got.Enable != "none" {
			t.Fatalf("%s: the refresh did not land: %+v", w.name, got)
		}
	}

	// A write to what the refresh decides sends it back to read again, and
	// the refused write leaves the record as that write left it.
	login := store.Context{CtxID: "ctx_login", Principal: principal, Username: "alice", PrivLvl: 1,
		MaxPrivilege: 15, Enable: "token", BlobHash: "sha256:old", AuthTime: now, RefreshedAt: now}
	for _, w := range []struct {
		name  string
		write func(store.Store) error
	}{
		{"JoinContext", func(s store.Store) error {
			_, err := store.JoinContext(ctx, s, k, login, now, now, time.Hour, store.LoginIndex{})
			return err
		}},
		{"PutContext", func(s store.Store) error { return s.PutContext(ctx, k, seed, time.Hour) }},
		{"SetRevokedAt", func(s store.Store) error { return s.SetRevokedAt(ctx, k, now) }},
		{"SetPrivilege raising the level", func(s store.Store) error { return s.SetPrivilege(ctx, k, 15) }},
		{"RefreshContext with a new blob", func(s store.Store) error {
			return s.RefreshContext(ctx, k, store.ContextRefresh{AuthTime: now, RefreshedAt: now,
				BlobHash: "sha256:directory"}, time.Hour)
		}},
		{"SetContextPolicy", func(s store.Store) error {
			return s.SetContextPolicy(ctx, k, read(s).PolicyRev,
				store.ContextPolicy{BlobHash: "sha256:other", MaxPrivilege: 15, Enable: "auto"})
		}},
	} {
		s := fresh()
		before := read(s)
		if err := w.write(s); err != nil {
			t.Fatalf("%s: %v", w.name, err)
		}
		after := read(s)
		if after.PolicyRev == before.PolicyRev {
			t.Fatalf("%s must move PolicyRev: %+v", w.name, after)
		}
		if err := s.SetContextPolicy(ctx, k, before.PolicyRev, refresh); !errors.Is(err, store.ErrConflict) {
			t.Fatalf("%s between the read and the write must conflict: %v", w.name, err)
		}
		if got := read(s); got.BlobHash != after.BlobHash || got.MaxPrivilege != after.MaxPrivilege ||
			got.Enable != after.Enable || got.PrivLvl != after.PrivLvl || got.Rev != after.Rev {
			t.Fatalf("%s: a refused refresh wrote: %+v, want %+v", w.name, got, after)
		}
	}

	// A write that does not revoke names a blob: one with none would leave a
	// live context pointing at nothing. It is refused, and nothing is written.
	{
		s := fresh()
		before := read(s)
		if err := s.SetContextPolicy(ctx, k, before.PolicyRev, store.ContextPolicy{MaxPrivilege: 7}); err == nil {
			t.Fatal("a non-revoking write with no blob hash must be refused")
		}
		if got := read(s); got.BlobHash != before.BlobHash || got.MaxPrivilege != before.MaxPrivilege ||
			got.Rev != before.Rev {
			t.Fatalf("a refused write wrote: %+v", got)
		}
	}

	// A revocation stands. A refresh read after it cannot clear it, and a
	// revoking refresh stamped earlier cannot move it earlier, which would let
	// a token minted between the two lift it at the next join.
	s := fresh()
	revokedAt := now.Add(-time.Minute)
	if err := s.SetRevokedAt(ctx, k, revokedAt); err != nil {
		t.Fatal(err)
	}
	if err := s.SetContextPolicy(ctx, k, read(s).PolicyRev, refresh); err != nil {
		t.Fatal(err)
	}
	if got := read(s); !got.RevokedAt.Equal(revokedAt) {
		t.Fatalf("a refresh cleared a revocation: %+v", got)
	}
	if err := s.SetContextPolicy(ctx, k, read(s).PolicyRev,
		store.ContextPolicy{RevokedAt: now.Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if got := read(s); !got.RevokedAt.Equal(revokedAt) {
		t.Fatalf("a revoking refresh moved a later revocation earlier: %+v", got)
	}
	if _, err := store.JoinContext(ctx, s, k, login, now.Add(-30*time.Minute), now, time.Hour, store.LoginIndex{}); err != nil {
		t.Fatal(err)
	}
	if got := read(s); !got.RevokedAt.Equal(revokedAt) {
		t.Fatalf("a token minted before the revocation lifted it: %+v", got)
	}
}

// RevocationIsMonotonic checks that SetRevokedAt keeps the later of the mark
// it holds and the one it is given (spec §5.6). A mark moved earlier weakens
// the revocation: a token minted between the two instants would count as
// minted after it and lift it at the next join. The refresh's revocation
// relies on this, since it writes the mark unconditionally, whatever a
// revoke-by-sid or a revoke-by-principal stamped first.
//
// newStore returns a fresh store whose clock returns now.
func RevocationIsMonotonic(t *testing.T, newStore func() store.Store, now time.Time) {
	t.Helper()
	const principal = "user:alice@example.com"
	k := store.ContextKey{NAS: "leaf-01", Username: "alice"}
	ctx := context.Background()
	s := newStore()
	if err := s.PutContext(ctx, k, store.Context{CtxID: "ctx_first", Principal: principal, Username: "alice",
		PrivLvl: 1, AuthTime: now.Add(-time.Hour), RefreshedAt: now.Add(-time.Hour)}, time.Hour); err != nil {
		t.Fatal(err)
	}
	marked := func() time.Time {
		c, err := s.GetContext(ctx, k)
		if err != nil {
			t.Fatal(err)
		}
		return c.RevokedAt
	}
	later, earlier := now.Add(-time.Minute), now.Add(-time.Hour)
	if err := s.SetRevokedAt(ctx, k, later); err != nil {
		t.Fatal(err)
	}
	if err := s.SetRevokedAt(ctx, k, earlier); err != nil {
		t.Fatal(err)
	}
	if got := marked(); !got.Equal(later) {
		t.Fatalf("an earlier mark replaced a later one: %v, want %v", got, later)
	}
	// And the weakening it would have allowed: a token minted between the
	// two does not lift the revocation.
	login := store.Context{CtxID: "ctx_login", Principal: principal, Username: "alice", PrivLvl: 1,
		AuthTime: now, RefreshedAt: now}
	if _, err := store.JoinContext(ctx, s, k, login, now.Add(-30*time.Minute), now, time.Hour, store.LoginIndex{}); err != nil {
		t.Fatal(err)
	}
	if got := marked(); !got.Equal(later) {
		t.Fatalf("a token minted before the revocation lifted it: %v", got)
	}
	if err := s.SetRevokedAt(ctx, k, now); err != nil {
		t.Fatal(err)
	}
	if got := marked(); !got.Equal(now) {
		t.Fatalf("a later mark must replace an earlier one: %v, want %v", got, now)
	}
}

// IdempotencyReservesOnce is design §17's "a retry that reaches a different
// replica MUST behave identically" made a store property (plan 7a): of many
// concurrent reservations under one key exactly one wins, and every loser
// sees the winner's pending record; a completion is a compare-and-set on the
// holder; a release takes only its own pending reservation; and a key is
// scoped to its principal.
//
// newStore returns a fresh store whose clock returns now.
func IdempotencyReservesOnce(t *testing.T, newStore func() store.Store, now time.Time) {
	t.Helper()
	const principal, key, racers = "user:alice@example.com", "01J\x00leaf-01", 32
	ctx := context.Background()
	s := newStore()
	pending := func(holder string) store.Idempotency {
		return store.Idempotency{BodyHash: "h1", Holder: holder, Pending: true, ExpiresAt: now.Add(time.Minute)}
	}
	start := make(chan struct{})
	won := make(chan string, racers)
	var wg sync.WaitGroup
	for i := 0; i < racers; i++ {
		holder := fmt.Sprintf("holder-%02d", i)
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			cur, ok, err := s.ReserveIdempotency(ctx, principal, key, pending(holder))
			switch {
			case err != nil:
				t.Error(err)
			case ok:
				won <- holder
			case !cur.Pending || cur.BodyHash != "h1" || cur.Holder == "":
				t.Errorf("a losing reservation must see the winner's pending record: %+v", cur)
			}
		}()
	}
	close(start)
	wg.Wait()
	close(won)
	var winners []string
	for h := range won {
		winners = append(winners, h)
	}
	if len(winners) != 1 {
		t.Fatalf("%d concurrent reservations of one key won: %v", len(winners), winners)
	}
	winner := winners[0]

	if err := s.ReleaseIdempotency(ctx, principal, key, "someone-else"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.ReserveIdempotency(ctx, principal, key, pending("late")); ok {
		t.Fatal("a release by another holder removed the reservation")
	}
	done := store.Idempotency{BodyHash: "h1", Holder: winner, Response: []byte(`{"login":"x"}`),
		ExpiresAt: now.Add(time.Hour)}
	if err := s.CompleteIdempotency(ctx, principal, key, "someone-else", done); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("a completion by another holder: %v, want ErrConflict", err)
	}
	if err := s.CompleteIdempotency(ctx, principal, key, winner, done); err != nil {
		t.Fatal(err)
	}
	cur, ok, err := s.ReserveIdempotency(ctx, principal, key, pending("after"))
	if err != nil || ok || cur.Pending || cur.Holder != winner || string(cur.Response) != `{"login":"x"}` {
		t.Fatalf("after completion a reservation must find the completed record: %+v %v %v", cur, ok, err)
	}
	if err := s.ReleaseIdempotency(ctx, principal, key, winner); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.ReserveIdempotency(ctx, principal, key, pending("after-release")); ok {
		t.Fatal("a release removed a completed record")
	}
	// Taking over a completed record (a replay the minter abandons) is a
	// compare-and-set on the old holder too.
	again := done
	again.Holder, again.Response = "next", []byte(`{"login":"y"}`)
	if err := s.CompleteIdempotency(ctx, principal, key, winner, again); err != nil {
		t.Fatalf("replacing a completed record by its holder: %v", err)
	}
	if err := s.CompleteIdempotency(ctx, principal, "never-reserved", "", done); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("completing a key nobody reserved: %v, want ErrConflict", err)
	}
	if _, ok, err := s.ReserveIdempotency(ctx, "user:bob@example.com", key, pending("bob")); err != nil || !ok {
		t.Fatalf("another principal under the same key is its own record: %v %v", ok, err)
	}

	// The empty holder is one anyone can name, so the store refuses it on
	// every side: no reservation or completion carries it, and no completion
	// expects it.
	if _, ok, err := s.ReserveIdempotency(ctx, principal, "anon", pending("")); err == nil || ok {
		t.Fatalf("a reservation without a holder: %v %v, want refused", ok, err)
	}
	if _, ok, err := s.ReserveIdempotency(ctx, principal, "anon", pending("anon-holder")); err != nil || !ok {
		t.Fatalf("a refused reservation wrote a record: %v %v", ok, err)
	}
	anon := done
	anon.Holder = ""
	if err := s.CompleteIdempotency(ctx, principal, "anon", "anon-holder", anon); err == nil {
		t.Fatal("a completion without a holder was written")
	}
	if err := s.CompleteIdempotency(ctx, principal, "anon", "", done); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("a completion expecting the empty holder: %v, want ErrConflict", err)
	}
	// A record with no holder at all is still nobody's: expecting the empty
	// holder does not match it. No store.Store method writes one, so it is
	// planted where the backend can (Planter).
	if p, ok := s.(Planter); ok {
		if err := p.PlantIdempotency(ctx, principal, "planted",
			store.Idempotency{BodyHash: "h1", Response: []byte("x"), ExpiresAt: now.Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
		if err := s.CompleteIdempotency(ctx, principal, "planted", "", done); !errors.Is(err, store.ErrConflict) {
			t.Fatalf("a completion expecting the empty holder of a holderless record: %v, want ErrConflict", err)
		}
	}
	if cur, ok, _ := s.ReserveIdempotency(ctx, principal, "anon", pending("late")); ok || !cur.Pending || cur.Holder != "anon-holder" {
		t.Fatalf("a refused completion changed the reservation: %+v %v", cur, ok)
	}
}

// IdempotencyLeaseExpires is the reservation's lease (plan 7a): a
// reservation a dead broker left behind expires, past it a retry reserves
// afresh, and the dead holder can no longer complete or release what is now
// someone else's.
//
// newStore returns a fresh store whose clock reads now, and a func that moves
// that clock forward; a backend whose expiry is server-side advances it by
// its own means.
func IdempotencyLeaseExpires(t *testing.T, newStore func() (store.Store, func(time.Duration)), now time.Time) {
	t.Helper()
	ctx := context.Background()
	s, advance := newStore()
	res := func(h string) store.Idempotency {
		return store.Idempotency{BodyHash: "h1", Holder: h, Pending: true, ExpiresAt: now.Add(time.Minute)}
	}
	if _, ok, err := s.ReserveIdempotency(ctx, "user:alice", "k", res("dead")); err != nil || !ok {
		t.Fatalf("first reservation: %v %v", ok, err)
	}
	advance(time.Minute)
	now = now.Add(time.Minute)
	if _, ok, err := s.ReserveIdempotency(ctx, "user:alice", "k", res("retry")); err != nil || !ok {
		t.Fatalf("a reservation past its expiry must not stand: %v %v", ok, err)
	}
	if err := s.CompleteIdempotency(ctx, "user:alice", "k", "dead",
		store.Idempotency{BodyHash: "h1", Holder: "dead", ExpiresAt: now.Add(time.Hour)}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("the dead holder completed the retry's reservation: %v", err)
	}
	if err := s.ReleaseIdempotency(ctx, "user:alice", "k", "dead"); err != nil {
		t.Fatal(err)
	}
	if cur, ok, _ := s.ReserveIdempotency(ctx, "user:alice", "k", res("third")); ok || cur.Holder != "retry" {
		t.Fatalf("the dead holder released the retry's reservation: %+v %v", cur, ok)
	}
}

// TokenIndex is what a revocation needs to find a principal's, or a
// certificate's, unspent tokens without a keyspace scan (plan 7a): keys come
// back sorted, one entry per key however often it is indexed, an empty
// principal or certificate is never an index key, and one principal's or
// certificate's keys are its own.
func TokenIndex(t *testing.T, newStore func() store.Store, now time.Time) {
	t.Helper()
	ctx := context.Background()
	s := newStore()
	const alice, bob = "user:alice@example.com", "user:bob@example.com"
	certA := store.CertKey("CN=Corp CA", "3f9a01")
	leaf2 := store.TokenKey{NAS: "leaf-02", Username: "alice"}
	leaf1 := store.TokenKey{NAS: "leaf-01", Username: "alice"}
	for _, k := range []store.TokenKey{leaf2, leaf1, leaf2} {
		if err := s.IndexToken(ctx, alice, certA, k, time.Minute); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.IndexToken(ctx, bob, "", store.TokenKey{NAS: "leaf-01", Username: "bob"}, time.Minute); err != nil {
		t.Fatal(err)
	}
	got, err := s.TokensByPrincipal(ctx, alice)
	if err != nil || len(got) != 2 || got[0] != leaf1 || got[1] != leaf2 {
		t.Fatalf("alice's keys: %v %v", got, err)
	}
	if got, err := s.TokensByCert(ctx, certA); err != nil || len(got) != 2 {
		t.Fatalf("the certificate's keys: %v %v", got, err)
	}
	if got, err := s.TokensByCert(ctx, ""); err != nil || len(got) != 0 {
		t.Fatalf("an empty certificate key indexed %v (%v): every certificate-less login would share it", got, err)
	}
	if got, _ := s.TokensByPrincipal(ctx, "user:carol@example.com"); len(got) != 0 {
		t.Fatalf("a principal with no token: %v", got)
	}

	// A certificate key with no issuer or no serial names no certificate,
	// as IndexContext reads it: indexed, every such login would share it. A
	// key that is not a CertKey at all names none either.
	for _, blank := range []string{store.CertKey("", ""), store.CertKey("CN=Corp CA", ""), store.CertKey("", "3f9a01"),
		"3f9a01"} {
		if err := s.IndexToken(ctx, bob, blank, store.TokenKey{NAS: "leaf-02", Username: "bob"}, time.Minute); err != nil {
			t.Fatal(err)
		}
		if got, err := s.TokensByCert(ctx, blank); err != nil || len(got) != 0 {
			t.Fatalf("the blank certificate key %q indexed %v (%v)", blank, got, err)
		}
	}
}

// DeleteTokenRemovesOne is DeleteToken (plan 7c): it removes the live token
// with that ID and leaves every other under the key, and every token under
// every other key; a second delete, an ID never put, and a key with nothing
// under it are ErrNotFound. A principal ending its own sessions deletes its
// own tokens this way and never another's under the same (device, username)
// (spec §5.1.4; decision 34).
//
// The token index (plan 7a) is by key, not by ID, so DeleteToken leaves it
// as it is: the remaining token's principal and certificate still lead to
// it, and the deleted token's principal may still name the key, where it
// finds nothing of its own and no error. Whether that stale entry is pruned
// is the backend's choice; that it never breaks a lookup is not.
func DeleteTokenRemovesOne(t *testing.T, newStore func() store.Store, now time.Time) {
	t.Helper()
	ctx := context.Background()
	s := newStore()
	k := store.TokenKey{NAS: "leaf-01", Username: "svc"}
	other := store.TokenKey{NAS: "leaf-02", Username: "svc"}
	cert := store.CertKey("CN=Corp CA", "3f9a01")
	put := func(k store.TokenKey, id, principal string) {
		t.Helper()
		// Index first, as the minter does (store.IndexToken).
		if err := s.IndexToken(ctx, principal, cert, k, time.Minute); err != nil {
			t.Fatal(err)
		}
		if _, err := s.PutToken(ctx, k, store.Token{ID: id, Secret: []byte("secret-" + id), Kind: store.KindLogin,
			ExpiresAt: now.Add(time.Minute), Principal: principal, Username: k.Username, MintedAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	put(k, "a", "spiffe://example.com/a")
	put(k, "b", "spiffe://example.com/b")
	put(other, "a", "spiffe://example.com/a")
	if err := s.DeleteToken(ctx, k, "a"); err != nil {
		t.Fatal(err)
	}
	got, err := s.Candidates(ctx, k)
	if err != nil || len(got) != 1 || got[0].ID != "b" || got[0].Principal != "spiffe://example.com/b" {
		t.Fatalf("left under the key: %v %v", got, err)
	}
	if got, err := s.Candidates(ctx, other); err != nil || len(got) != 1 {
		t.Fatalf("another key's token: %v %v", got, err)
	}
	for _, c := range []struct {
		k  store.TokenKey
		id string
	}{{k, "a"}, {k, "never"}, {store.TokenKey{NAS: "nowhere", Username: "svc"}, "b"}} {
		if err := s.DeleteToken(ctx, c.k, c.id); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("DeleteToken(%v, %q) = %v, want ErrNotFound", c.k, c.id, err)
		}
	}

	// The survivor is still reachable through both indexes, so a revocation
	// of b, or of the certificate, still finds it.
	if keys, err := s.TokensByPrincipal(ctx, "spiffe://example.com/b"); err != nil || !slices.Contains(keys, k) {
		t.Fatalf("b's keys after a's delete: %v %v", keys, err)
	}
	if keys, err := s.TokensByCert(ctx, cert); err != nil || !slices.Contains(keys, k) || !slices.Contains(keys, other) {
		t.Fatalf("the certificate's keys after a's delete: %v %v", keys, err)
	}
	// a's keys still include other, where a's token lives; any key they still
	// name under which a has nothing yields no token of a's and no error.
	keys, err := s.TokensByPrincipal(ctx, "spiffe://example.com/a")
	if err != nil || !slices.Contains(keys, other) {
		t.Fatalf("a's keys after its delete: %v %v", keys, err)
	}
	for _, key := range keys {
		got, err := s.Candidates(ctx, key)
		if err != nil {
			t.Fatalf("Candidates(%v) through a's index: %v", key, err)
		}
		for _, tok := range got {
			if key == k && tok.Principal == "spiffe://example.com/a" {
				t.Fatalf("a's deleted token is still under %v", key)
			}
		}
	}

	// A middle entry, then the last: each compacts the set differently, and
	// neither may disturb a survivor's secret.
	three := store.TokenKey{NAS: "leaf-03", Username: "svc"}
	for _, id := range []string{"x", "y", "z"} {
		put(three, id, "spiffe://example.com/"+id)
	}
	for _, step := range []struct {
		id   string
		want []string
	}{{"y", []string{"x", "z"}}, {"z", []string{"x"}}} {
		if err := s.DeleteToken(ctx, three, step.id); err != nil {
			t.Fatalf("DeleteToken(%q): %v", step.id, err)
		}
		SecretsIntact(t, s, three, step.want...)
	}

	// An expired token is not live, so there is nothing to delete.
	expired := store.TokenKey{NAS: "leaf-04", Username: "svc"}
	if _, err := s.PutToken(ctx, expired, store.Token{ID: "old", Secret: []byte("secret-old"), Kind: store.KindLogin,
		ExpiresAt: now, Principal: "spiffe://example.com/a", Username: expired.Username, MintedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteToken(ctx, expired, "old"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("DeleteToken on an expired token = %v, want ErrNotFound", err)
	}
}

// SecretsIntact fails t unless the live tokens under k are exactly ids, in
// any order, each with the Secret "secret-"+ID. A Secret is compared and
// never printed.
func SecretsIntact(t *testing.T, s store.Store, k store.TokenKey, ids ...string) {
	t.Helper()
	got, err := s.Candidates(context.Background(), k)
	if err != nil {
		t.Fatalf("Candidates(%v): %v", k, err)
	}
	var have []string
	for _, tok := range got {
		have = append(have, tok.ID)
		if string(tok.Secret) != "secret-"+tok.ID {
			t.Fatalf("under %v, token %q's secret was damaged", k, tok.ID)
		}
	}
	slices.Sort(have)
	want := slices.Clone(ids)
	slices.Sort(want)
	if !slices.Equal(have, want) {
		t.Fatalf("under %v: tokens %v, want %v", k, have, want)
	}
}

// DeleteTokenRacesRedeem is DeleteToken among the other writers of one key's
// token set (plan 7c). Each round puts a, b and d under one key, then runs at
// once: RedeemAndReceipt and DeleteToken of a, DeleteToken of b, and PutToken
// of c. Whatever the interleaving, exactly one of a's redeem and delete wins
// and the other is ErrNotFound; b's delete succeeds; and the set ends as
// exactly c and d with their secrets whole. So a spent token never comes
// back (a replay), a token put concurrently is never lost, and a delete never
// takes a token under another ID. A backend that rewrites the set from a stale
// read, without a compare on what it read, fails one of these.
func DeleteTokenRacesRedeem(t *testing.T, newStore func() store.Store, now time.Time) {
	t.Helper()
	const rounds = 200
	k := store.TokenKey{NAS: "leaf-01", Username: "svc"}
	tok := func(id string) store.Token {
		return store.Token{ID: id, Secret: []byte("secret-" + id), Kind: store.KindLogin,
			ExpiresAt: now.Add(time.Minute), Principal: "spiffe://example.com/" + id, Username: k.Username, MintedAt: now}
	}
	w := store.ReceiptWrite{
		Key:       store.ReceiptKey{NAS: k.NAS, Username: k.Username, Kind: store.KindLogin, CredentialSHA256: [32]byte{1}},
		Receipt:   store.Receipt{CredentialSHA256: [32]byte{1}, FirstRedeemedAt: now, IdleExpiresAt: now.Add(time.Minute), RetainUntil: now.Add(time.Hour)},
		Principal: "spiffe://example.com/a",
		IndexTTL:  time.Hour,
	}
	for round := 0; round < rounds; round++ {
		s := newStore()
		ctx := context.Background()
		for _, id := range []string{"a", "b", "d"} {
			if _, err := s.PutToken(ctx, k, tok(id)); err != nil {
				t.Fatal(err)
			}
		}
		start := make(chan struct{})
		var redeemErr, deleteAErr, deleteBErr, putErr error
		var wg sync.WaitGroup
		for _, f := range []func(){
			func() { redeemErr = s.RedeemAndReceipt(ctx, k, "a", w) },
			func() { deleteAErr = s.DeleteToken(ctx, k, "a") },
			func() { deleteBErr = s.DeleteToken(ctx, k, "b") },
			func() { _, putErr = s.PutToken(ctx, k, tok("c")) },
		} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				f()
			}()
		}
		close(start)
		wg.Wait()
		if deleteBErr != nil || putErr != nil {
			t.Fatalf("round %d: delete b %v, put c %v", round, deleteBErr, putErr)
		}
		switch {
		case redeemErr == nil && errors.Is(deleteAErr, store.ErrNotFound):
		case deleteAErr == nil && errors.Is(redeemErr, store.ErrNotFound):
		default:
			t.Fatalf("round %d: redeem a %v, delete a %v; want exactly one nil and the other ErrNotFound",
				round, redeemErr, deleteAErr)
		}
		SecretsIntact(t, s, k, "c", "d")
		if err := s.RedeemAndReceipt(ctx, k, "a", w); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("round %d: a redeemed again: %v", round, err)
		}
	}
}

// RevocationMarks is the mark a revocation leaves (spec §5.1.4; plan 7a): it
// stands until it is deleted; a second put of the same key keeps the first
// whole, so a repeat neither moves its time nor its origin; a principal's
// and a certificate's marks are kept apart; and the list is sorted. A mark
// that could match nothing — an unknown kind, an empty key, a certificate
// key with no issuer, no serial or no "|", which the token and context indexes
// never hold — is refused, so a revocation never reports a mark that
// revokes nothing; and so is a mark with no time, which a login would read
// as no mark at all (store.CheckRevocation).
func RevocationMarks(t *testing.T, newStore func() store.Store, now time.Time) {
	t.Helper()
	ctx := context.Background()
	s := newStore()
	alice := store.Revocation{Kind: store.RevocationPrincipal, Key: "user:alice@example.com", At: now,
		Origin: "admin_socket uid 0"}
	cert := store.Revocation{Kind: store.RevocationCert, Key: store.CertKey("CN=Corp CA", "3f9a01"),
		At: now.Add(time.Second), Origin: "admin_socket uid 0"}
	// bob sorts after alice within the principal kind, and is put first, so
	// the list's order within a kind is the store's, not the order of puts.
	bob := store.Revocation{Kind: store.RevocationPrincipal, Key: "user:bob@example.com", At: now,
		Origin: "admin_socket uid 0"}
	if _, err := s.GetRevocation(ctx, alice.Kind, alice.Key); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("no mark yet: %v", err)
	}
	for _, r := range []store.Revocation{bob, cert, alice} {
		if err := s.PutRevocation(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	again := alice
	again.At, again.Origin = now.Add(time.Hour), "admin_socket uid 1000"
	if err := s.PutRevocation(ctx, again); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetRevocation(ctx, alice.Kind, alice.Key)
	if err != nil || !got.At.Equal(now) || got.Origin != alice.Origin {
		t.Fatalf("a repeat revocation moved the mark: %+v %v", got, err)
	}
	if _, err := s.GetRevocation(ctx, store.RevocationCert, alice.Key); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a principal's mark answered for a certificate: %v", err)
	}
	for _, r := range []store.Revocation{
		{Kind: "", Key: "user:bob@example.com", At: now},
		{Kind: "device", Key: "user:bob@example.com", At: now},
		{Kind: store.RevocationPrincipal, Key: "", At: now},
		{Kind: store.RevocationCert, Key: "", At: now},
		{Kind: store.RevocationCert, Key: store.CertKey("", "3f9a01"), At: now},
		{Kind: store.RevocationCert, Key: store.CertKey("CN=Corp CA", ""), At: now},
		{Kind: store.RevocationCert, Key: "3f9a01", At: now},
		{Kind: store.RevocationPrincipal, Key: "user:carol@example.com"},
	} {
		if err := s.PutRevocation(ctx, r); !errors.Is(err, store.ErrIncompleteMark) {
			t.Fatalf("an incomplete mark was taken: %+v %v", r, err)
		}
	}
	list, err := s.ListRevocations(ctx)
	if err != nil || len(list) != 3 || list[0].Kind != store.RevocationCert || list[1].Key != alice.Key ||
		list[2].Key != bob.Key {
		t.Fatalf("list: %+v %v", list, err)
	}
	if err := s.DeleteRevocation(ctx, alice.Kind, alice.Key); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetRevocation(ctx, alice.Kind, alice.Key); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a lifted mark stands: %v", err)
	}
	if err := s.DeleteRevocation(ctx, alice.Kind, alice.Key); err != nil {
		t.Fatalf("lifting a mark twice: %v", err)
	}
	if got, err := s.GetRevocation(ctx, cert.Kind, cert.Key); err != nil || !got.At.Equal(cert.At) {
		t.Fatalf("lifting a principal's mark lifted the certificate's: %+v %v", got, err)
	}
}

// CeilingShortensOnly is decision 33's rule for a policy edit: a policy
// write shortens a context's ceiling, gives one to a context with none, and
// never lengthens or removes one. A context with no AuthTime to anchor a
// ceiling is given one in the distant past, as a login gives a token with
// none (authen's loginContext): it denies, loudly, rather than staying an
// unbounded session that looks like a legitimate `never`.
func CeilingShortensOnly(t *testing.T, newStore func() store.Store, now time.Time) {
	t.Helper()
	ctx := context.Background()
	k := store.ContextKey{NAS: "leaf-01", Username: "alice"}
	auth := now.Add(-time.Hour)
	for _, tc := range []struct {
		name    string
		expires time.Time // zero: no ceiling
		age     time.Duration
		want    time.Time
	}{
		{"shortened", auth.Add(8 * time.Hour), 2 * time.Hour, auth.Add(2 * time.Hour)},
		{"never lengthened", auth.Add(2 * time.Hour), 8 * time.Hour, auth.Add(2 * time.Hour)},
		{"given one", time.Time{}, 2 * time.Hour, auth.Add(2 * time.Hour)},
		{"never removed", auth.Add(2 * time.Hour), 0, auth.Add(2 * time.Hour)},
	} {
		s := newStore()
		if err := s.PutContext(ctx, k, store.Context{CtxID: "c", Principal: "user:a", Username: "alice", BlobHash: "b1",
			AuthTime: auth, SessionExpires: tc.expires, RefreshedAt: auth}, time.Hour); err != nil {
			t.Fatal(err)
		}
		c, _ := s.GetContext(ctx, k)
		if err := s.SetContextPolicy(ctx, k, c.PolicyRev, store.ContextPolicy{BlobHash: "b2", MaxSessionAge: tc.age}); err != nil {
			t.Fatal(err)
		}
		if c, _ := s.GetContext(ctx, k); !c.SessionExpires.Equal(tc.want) {
			t.Errorf("%s: session_expires %v, want %v", tc.name, c.SessionExpires, tc.want)
		}
	}
	s := newStore()
	if err := s.PutContext(ctx, k, store.Context{CtxID: "c", Principal: "user:a", Username: "alice", BlobHash: "b1",
		RefreshedAt: auth}, time.Hour); err != nil {
		t.Fatal(err)
	}
	c, _ := s.GetContext(ctx, k)
	if err := s.SetContextPolicy(ctx, k, c.PolicyRev, store.ContextPolicy{BlobHash: "b2", MaxSessionAge: 2 * time.Hour}); err != nil {
		t.Fatal(err)
	}
	if c, _ := s.GetContext(ctx, k); c.SessionExpires.IsZero() || !c.SessionExpires.Before(now) {
		t.Errorf("no auth_time: session_expires %v, want a ceiling already past", c.SessionExpires)
	}
}

// RefreshSetsTheCeiling: a refresh is a fresh authentication event, so it
// sets the ceiling it is given from the new auth_time, lengthening, or
// clearing it for never; one given none keeps the window (spec §5.6).
func RefreshSetsTheCeiling(t *testing.T, newStore func() store.Store, now time.Time) {
	t.Helper()
	ctx := context.Background()
	k := store.ContextKey{NAS: "leaf-01", Username: "alice"}
	auth := now.Add(-time.Hour)
	eight, never := 8*time.Hour, time.Duration(0)
	for _, tc := range []struct {
		name string
		age  *time.Duration
		want time.Time
	}{
		{"set", &eight, now.Add(8 * time.Hour)},
		{"never", &never, time.Time{}},
		{"window kept", nil, now.Add(2 * time.Hour)},
	} {
		s := newStore()
		if err := s.PutContext(ctx, k, store.Context{CtxID: "c", Principal: "user:a", Username: "alice", BlobHash: "b",
			AuthTime: auth, SessionExpires: auth.Add(2 * time.Hour), RefreshedAt: auth}, time.Hour); err != nil {
			t.Fatal(err)
		}
		if err := s.RefreshContext(ctx, k, store.ContextRefresh{AuthTime: now, RefreshedAt: now, SessionAge: tc.age},
			time.Hour); err != nil {
			t.Fatal(err)
		}
		if c, _ := s.GetContext(ctx, k); !c.SessionExpires.Equal(tc.want) {
			t.Errorf("%s: session_expires %v, want %v", tc.name, c.SessionExpires, tc.want)
		}
	}
}

// RefreshStopsAtGrace: a refresh whose GraceCutoff is after the context's
// ceiling writes nothing and says so (spec §5.6, teardown row 3); one inside
// the window resumes the context, and so does one of a context with no
// ceiling (`never`), which has no window to be past.
func RefreshStopsAtGrace(t *testing.T, newStore func() store.Store, now time.Time) {
	t.Helper()
	ctx := context.Background()
	k := store.ContextKey{NAS: "leaf-01", Username: "alice"}
	s := newStore()
	auth := now.Add(-3 * time.Hour)
	if err := s.PutContext(ctx, k, store.Context{CtxID: "c", Principal: "user:a", Username: "alice", BlobHash: "b",
		AuthTime: auth, SessionExpires: auth.Add(2 * time.Hour), RefreshedAt: auth}, time.Hour); err != nil {
		t.Fatal(err)
	}
	err := s.RefreshContext(ctx, k, store.ContextRefresh{AuthTime: now, RefreshedAt: now,
		GraceCutoff: now.Add(-10 * time.Minute)}, time.Hour)
	if !errors.Is(err, store.ErrPastGrace) {
		t.Fatalf("a context an hour past its ceiling with a 10m window: %v", err)
	}
	if c, _ := s.GetContext(ctx, k); !c.AuthTime.Equal(auth) {
		t.Fatal("a refused refresh wrote")
	}
	if err := s.RefreshContext(ctx, k, store.ContextRefresh{AuthTime: now, RefreshedAt: now,
		GraceCutoff: now.Add(-2 * time.Hour)}, time.Hour); err != nil {
		t.Fatalf("inside the window: %v", err)
	}

	s = newStore()
	if err := s.PutContext(ctx, k, store.Context{CtxID: "c", Principal: "user:a", Username: "alice", BlobHash: "b",
		AuthTime: auth, RefreshedAt: auth}, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := s.RefreshContext(ctx, k, store.ContextRefresh{AuthTime: now, RefreshedAt: now,
		GraceCutoff: now.Add(-10 * time.Minute)}, time.Hour); err != nil {
		t.Fatalf("a context with no ceiling: %v", err)
	}
	if c, _ := s.GetContext(ctx, k); !c.AuthTime.Equal(now) || !c.SessionExpires.IsZero() {
		t.Fatalf("a context with no ceiling was not refreshed as one: %+v", c)
	}
}

// WritesBindToTheRevision: a refresh with ExpectRev, and DeleteContextIf,
// act only on the record read; a write landing in between makes each
// ErrConflict and leaves the record (pre-flight M4).
func WritesBindToTheRevision(t *testing.T, newStore func() store.Store, now time.Time) {
	t.Helper()
	ctx := context.Background()
	k := store.ContextKey{NAS: "leaf-01", Username: "alice"}
	s := newStore()
	if err := s.PutContext(ctx, k, store.Context{CtxID: "c", Principal: "user:a", Username: "alice", BlobHash: "b",
		AuthTime: now, SessionExpires: now.Add(time.Hour), RefreshedAt: now}, time.Hour); err != nil {
		t.Fatal(err)
	}
	read, _ := s.GetContext(ctx, k)
	if err := s.SetPrivilege(ctx, k, 15); err != nil { // another writer lands
		t.Fatal(err)
	}
	landed, _ := s.GetContext(ctx, k)
	later := now.Add(time.Minute)
	if err := s.RefreshContext(ctx, k, store.ContextRefresh{AuthTime: later, RefreshedAt: later, ExpectRev: read.Rev},
		time.Hour); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("a refresh against a stale revision: %v", err)
	}
	if c, _ := s.GetContext(ctx, k); c.Rev != landed.Rev || !c.AuthTime.Equal(landed.AuthTime) {
		t.Fatal("a refused refresh wrote")
	}
	if err := s.DeleteContextIf(ctx, k, read.Rev); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("a delete against a stale revision: %v", err)
	}
	if err := s.DeleteContextIf(ctx, k, landed.Rev); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetContext(ctx, k); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("the delete at the current revision did not delete")
	}
}

// Backend is a store.Store implementation the properties run against. New
// returns a fresh, empty store whose clock is clock; a property moves time
// by changing what clock returns. A store that is also a Planter gets
// IdempotencyReservesOnce's holderless case.
type Backend struct {
	New func(t *testing.T, clock func() time.Time) store.Store
	// RaceRounds is how many rounds LoginRacesARevocationByMark and the
	// token family's races (races.go) run; zero is 10000, what memory's
	// few-instruction window needs. A backend whose rounds are network
	// round trips sets fewer, and its own tests show a mutation that splits
	// a check from its write is still caught at that count (plan 7d, R1).
	RaceRounds int
	// Stagger starts the short side of a race against a login a random
	// part of a login's time late: LoginRacesARevocationByMark's
	// revocation, and IndexWritesRaceAContextWrite's index write. A login
	// on a network backend is several round trips, and a write started
	// with it lands before the login reads: the window between that read
	// and the login's write is never met, at any count of rounds (plan 7d
	// Task 6, R1: 0 catches in 10000 rounds unstaggered). Memory's login is
	// one critical section and leaves it off.
	Stagger bool
}

func (b Backend) raceRounds() int {
	if b.RaceRounds > 0 {
		return b.RaceRounds
	}
	return 10000
}

// t0 is the instant the fixed-clock properties run at: far from the wall
// clock on purpose, so a backend that reads time.Now where it should read
// its clock fails.
var t0 = time.Unix(1_000_000, 0).UTC()

// Run runs every property against b, each as its own subtest.
func Run(t *testing.T, b Backend) {
	fixed := func(t *testing.T) func() store.Store {
		return func() store.Store { return b.New(t, func() time.Time { return t0 }) }
	}
	for _, p := range []struct {
		name string
		run  func(*testing.T)
	}{
		{"JoinRacesRevocation", func(t *testing.T) { JoinRacesRevocation(t, fixed(t), t0) }},
		{"PolicyRevision", func(t *testing.T) { PolicyRevision(t, fixed(t), t0) }},
		{"RevocationIsMonotonic", func(t *testing.T) { RevocationIsMonotonic(t, fixed(t), t0) }},
		{"IdempotencyReservesOnce", func(t *testing.T) { IdempotencyReservesOnce(t, fixed(t), t0) }},
		{"IdempotencyLeaseExpires", func(t *testing.T) {
			IdempotencyLeaseExpires(t, func() (store.Store, func(time.Duration)) {
				var mu sync.Mutex
				now := t0
				s := b.New(t, func() time.Time { mu.Lock(); defer mu.Unlock(); return now })
				return s, func(d time.Duration) { mu.Lock(); now = now.Add(d); mu.Unlock() }
			}, t0)
		}},
		{"TokenIndex", func(t *testing.T) { TokenIndex(t, fixed(t), t0) }},
		{"DeleteTokenRemovesOne", func(t *testing.T) { DeleteTokenRemovesOne(t, fixed(t), t0) }},
		{"DeleteTokenRacesRedeem", func(t *testing.T) { DeleteTokenRacesRedeem(t, fixed(t), t0) }},
		{"RevocationMarks", func(t *testing.T) { RevocationMarks(t, fixed(t), t0) }},
		{"CeilingShortensOnly", func(t *testing.T) { CeilingShortensOnly(t, fixed(t), t0) }},
		{"RefreshSetsTheCeiling", func(t *testing.T) { RefreshSetsTheCeiling(t, fixed(t), t0) }},
		{"RefreshStopsAtGrace", func(t *testing.T) { RefreshStopsAtGrace(t, fixed(t), t0) }},
		{"WritesBindToTheRevision", func(t *testing.T) { WritesBindToTheRevision(t, fixed(t), t0) }},
	} {
		t.Run(p.name, p.run)
	}
	for _, p := range lifted {
		p := p
		t.Run(p.name, func(t *testing.T) { p.run(t, b) })
	}
	for _, p := range []struct {
		name string
		run  func(*testing.T, Backend)
	}{
		{"SwapLoginIsOneStep", SwapLoginIsOneStep},
		{"LoginsRaceToOneIndex", LoginsRaceToOneIndex},
		{"JoinHonoursAStandingMark", JoinHonoursAStandingMark},
		{"LoginRacesARevocationByMark", LoginRacesARevocationByMark},
		{"PurgeTakesEveryToken", PurgeTakesEveryToken},
		{"SelfRevocationBindsToTheRead", SelfRevocationBindsToTheRead},
		{"RewriteBindsToTheRevision", RewriteBindsToTheRevision},
		{"IndexTokenKeepsTheLongestUnderARace", IndexTokenKeepsTheLongestUnderARace},
		{"IndexWritesRaceAContextWrite", IndexWritesRaceAContextWrite},
		{"FailReceiptSurvivesARacingExtend", FailReceiptSurvivesARacingExtend},
		{"RedeemOrDeleteNotBoth", RedeemOrDeleteNotBoth},
		{"IndexKeysAreExact", IndexKeysAreExact},
	} {
		p := p
		t.Run(p.name, func(t *testing.T) { p.run(t, b) })
	}
}
