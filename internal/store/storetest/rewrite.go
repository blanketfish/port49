package storetest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/store"
)

// RewriteBindsToTheRevision is RewriteContext (plan 7d; Ruling 17): it
// writes the record's fields only on the revision read, keeps the expiry
// and LastTouchedAt unless given a ttl, moves PolicyRev only when told,
// and writes nothing on a stale revision or an absent record.
func RewriteBindsToTheRevision(t *testing.T, b Backend) {
	ctx := context.Background()
	now := t0
	s := b.New(t, func() time.Time { return now })
	k := store.ContextKey{NAS: "leaf-01", Username: "alice"}
	if err := s.RewriteContext(ctx, k, 1, store.Context{CtxID: "x"}, 0, false); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a rewrite of no record: %v", err)
	}
	if err := s.PutContext(ctx, k, store.Context{CtxID: "c", Principal: "p", Username: "alice", PrivLvl: 1},
		time.Hour); err != nil {
		t.Fatal(err)
	}
	read, _ := s.GetContext(ctx, k)
	now = now.Add(time.Minute)
	next := read
	next.PrivLvl = 7
	if err := s.RewriteContext(ctx, k, read.Rev, next, 0, false); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetContext(ctx, k)
	if got.PrivLvl != 7 || got.Rev == read.Rev || got.PolicyRev != read.PolicyRev || !got.LastTouchedAt.Equal(read.LastTouchedAt) {
		t.Fatalf("a rewrite with no ttl, not a policy write: %+v (read %+v)", got, read)
	}
	// The expiry did not move: an hour from the put, not from now.
	now = t0.Add(time.Hour + time.Second)
	if _, err := s.GetContext(ctx, k); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a rewrite with no ttl extended the record: %v", err)
	}
	k2 := store.ContextKey{NAS: "leaf-02", Username: "alice"}
	if err := s.PutContext(ctx, k2, store.Context{CtxID: "c", Principal: "p", Username: "alice"}, time.Hour); err != nil {
		t.Fatal(err)
	}
	read, _ = s.GetContext(ctx, k2)
	now = now.Add(time.Minute)
	if err := s.RewriteContext(ctx, k2, read.Rev, read, 2*time.Hour, true); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetContext(ctx, k2)
	if got.PolicyRev == read.PolicyRev || !got.LastTouchedAt.Equal(now) {
		t.Fatalf("a rewrite with a ttl, a policy write: %+v (read %+v)", got, read)
	}
	now = now.Add(90 * time.Minute) // past the put's hour, inside the rewrite's two
	if _, err := s.GetContext(ctx, k2); err != nil {
		t.Fatalf("a rewrite with a ttl did not extend the record: %v", err)
	}
	stale := read
	stale.PrivLvl = 15
	if err := s.RewriteContext(ctx, k2, read.Rev, stale, 0, false); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("a rewrite on a stale revision: %v", err)
	}
	if got, _ := s.GetContext(ctx, k2); got.PrivLvl == 15 {
		t.Fatal("a refused rewrite wrote")
	}
}
