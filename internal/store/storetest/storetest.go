// Package storetest holds store.Store properties every implementation must
// have, written once and run against each: the memory store and the sealing
// layer over it today, a networked backend later. It is imported only by
// tests.
package storetest

import (
	"context"
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
