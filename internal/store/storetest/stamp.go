package storetest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/store"
)

// StampRaisesRefreshedAtAndKeepsPolicyRev: the scheduled refresh's stamp
// (plan 7g, Ruling 12) raises RefreshedAt, never lowers it, compares the
// policy revision the caller read and does not move it, so a stamp never
// costs a policy refresh its compare.
func StampRaisesRefreshedAtAndKeepsPolicyRev(t *testing.T, b Backend) {
	ctx := context.Background()
	s := b.New(t, func() time.Time { return t0 })
	k := store.ContextKey{NAS: "leaf-01", Username: "alice"}
	if err := s.PutContext(ctx, k, store.Context{CtxID: "c1", Principal: "user:alice@example.com", Username: "alice",
		BlobHash: "sha256:a", AuthTime: t0.Add(-time.Hour), RefreshedAt: t0.Add(-time.Hour)}, time.Hour); err != nil {
		t.Fatal(err)
	}
	c, err := s.GetContext(ctx, k)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.StampRefreshed(ctx, k, c.PolicyRev, t0.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetContext(ctx, k)
	if !got.RefreshedAt.Equal(t0.Add(-time.Minute)) || got.PolicyRev != c.PolicyRev {
		t.Fatalf("after a stamp: refreshed_at %v policy_rev %d (was %d)", got.RefreshedAt, got.PolicyRev, c.PolicyRev)
	}
	if err := s.StampRefreshed(ctx, k, got.PolicyRev, t0.Add(-30*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if again, _ := s.GetContext(ctx, k); !again.RefreshedAt.Equal(t0.Add(-time.Minute)) {
		t.Fatalf("an earlier stamp lowered refreshed_at to %v", again.RefreshedAt)
	}
	if err := s.SetPrivilege(ctx, k, 15); err != nil { // moves PolicyRev
		t.Fatal(err)
	}
	if err := s.StampRefreshed(ctx, k, c.PolicyRev, t0); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("a stamp on a moved policy revision: %v, want ErrConflict", err)
	}
	if err := s.StampRefreshed(ctx, store.ContextKey{NAS: "leaf-09", Username: "x"}, 1, t0); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a stamp on no context: %v, want ErrNotFound", err)
	}
}

// APolicyWriteCarriesItsRefreshedAt: a scheduled pass that changed a
// context stamps it in the same write; a policy reload's write (zero
// RefreshedAt) leaves the clock alone (spec §5.1.3).
func APolicyWriteCarriesItsRefreshedAt(t *testing.T, b Backend) {
	ctx := context.Background()
	s := b.New(t, func() time.Time { return t0 })
	k := store.ContextKey{NAS: "leaf-01", Username: "alice"}
	if err := s.PutContext(ctx, k, store.Context{CtxID: "c1", Principal: "user:alice@example.com", Username: "alice",
		BlobHash: "sha256:a", AuthTime: t0.Add(-time.Hour), RefreshedAt: t0.Add(-time.Hour)}, time.Hour); err != nil {
		t.Fatal(err)
	}
	c, _ := s.GetContext(ctx, k)
	if err := s.SetContextPolicy(ctx, k, c.PolicyRev, store.ContextPolicy{BlobHash: "sha256:b"}); err != nil {
		t.Fatal(err)
	}
	c, _ = s.GetContext(ctx, k)
	if !c.RefreshedAt.Equal(t0.Add(-time.Hour)) {
		t.Fatalf("a policy reload's write moved refreshed_at to %v", c.RefreshedAt)
	}
	if err := s.SetContextPolicy(ctx, k, c.PolicyRev, store.ContextPolicy{BlobHash: "sha256:c", RefreshedAt: t0}); err != nil {
		t.Fatal(err)
	}
	if c, _ = s.GetContext(ctx, k); !c.RefreshedAt.Equal(t0) || c.BlobHash != "sha256:c" {
		t.Fatalf("a scheduled write: %+v", c)
	}
}
