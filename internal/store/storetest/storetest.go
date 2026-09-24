// Package storetest holds store.Store properties every implementation must
// have, written once and run against each: the memory store and the sealing
// layer over it today, a networked backend later. It is imported only by
// tests.
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
				_, err := store.JoinContext(ctx, s, k, login, mintedAt, now, time.Hour)
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
			_, err := store.JoinContext(ctx, s, k, login, now, now, time.Hour)
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
	if _, err := store.JoinContext(ctx, s, k, login, now.Add(-30*time.Minute), now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if got := read(s); !got.RevokedAt.Equal(revokedAt) {
		t.Fatalf("a token minted before the revocation lifted it: %+v", got)
	}
}
