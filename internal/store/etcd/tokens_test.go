package etcd

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/store"
)

// A candidate carries the revision its record was created at: the restore
// floor's fence (pre-beta Task 2).
func TestCandidatesCarryTheTokensCreateRevision(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 11, 2, 9, 0, 0, 0, time.UTC)
	s := onShared(t, func() time.Time { return now })
	k := store.TokenKey{NAS: "leaf", Username: "alice"}
	for _, id := range []string{"t1", "t2"} {
		if _, err := s.PutToken(ctx, k, store.Token{ID: id, Kind: store.KindLogin, ExpiresAt: now.Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.Candidates(ctx, k)
	if err != nil || len(got) != 2 {
		t.Fatalf("candidates: %v %v", got, err)
	}
	byID := map[string]uint64{}
	for _, c := range got {
		resp, err := s.tok.Get(ctx, s.k.token(k, c.ID))
		if err != nil || len(resp.Kvs) != 1 {
			t.Fatalf("raw read of %s: %v", c.ID, err)
		}
		if c.Revision == 0 || c.Revision != uint64(resp.Kvs[0].CreateRevision) {
			t.Fatalf("%s: Revision %d, want create revision %d", c.ID, c.Revision, resp.Kvs[0].CreateRevision)
		}
		byID[c.ID] = c.Revision
	}
	if byID["t2"] <= byID["t1"] {
		t.Fatalf("the later put's revision %d is not above the earlier's %d", byID["t2"], byID["t1"])
	}
	// A rewrite of the record moves its ModRevision and never its create revision.
	raw, err := s.tok.Get(ctx, s.k.token(k, "t1"))
	if err != nil || len(raw.Kvs) != 1 {
		t.Fatalf("raw read of t1: %v", err)
	}
	if _, err := s.tok.Put(ctx, s.k.token(k, "t1"), string(raw.Kvs[0].Value)); err != nil {
		t.Fatal(err)
	}
	again, err := s.Candidates(ctx, k)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range again {
		if c.Revision != byID[c.ID] {
			t.Fatalf("%s: Revision %d after a rewrite, want its create revision %d", c.ID, c.Revision, byID[c.ID])
		}
	}
}

// A put over a key that exists is refused and writes nothing: the Txn is
// never hedged, and a late copy of it is a refused one, not a second token.
func TestAPutOverAnExistingTokenKeyFailsAndWritesNothing(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 11, 2, 9, 0, 0, 0, time.UTC)
	s := onShared(t, func() time.Time { return now })
	k := store.TokenKey{NAS: "leaf", Username: "alice"}
	key := s.k.token(k, "dup")
	const first = `{"id":"dup","kind":"login","expires_at":"2026-11-02T10:00:00Z"}`
	calls := 0
	beforeTokenTxn = func(ctx context.Context) {
		calls++
		if _, err := s.tok.Put(ctx, key, first); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(func() { beforeTokenTxn = nil })
	_, err := s.PutToken(ctx, k, store.Token{ID: "dup", Kind: store.KindLogin, Principal: "late", ExpiresAt: now.Add(time.Hour)})
	if !errors.Is(err, store.ErrConflict) {
		t.Fatalf("PutToken over an existing key: %v, want ErrConflict", err)
	}
	if calls != 1 {
		t.Fatalf("the put tried %d times, want 1", calls)
	}
	resp, err := s.tok.Get(ctx, key)
	if err != nil || len(resp.Kvs) != 1 || string(resp.Kvs[0].Value) != first {
		t.Fatalf("the key was overwritten: %v %v", resp, err)
	}
}

// An index entry that moves between the put's read and its Txn is not a taken
// ID: the put reads again and lands, as it did before the create-only compare.
func TestAPutWhoseIndexEntryMovedReadsAgainAndLands(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 11, 2, 9, 0, 0, 0, time.UTC)
	s := onShared(t, func() time.Time { return now })
	k := store.TokenKey{NAS: "leaf", Username: "alice"}
	ix := s.k.tokenIndexed(famTokByPrin, "user:alice", k)
	calls := 0
	beforeTokenTxn = func(ctx context.Context) {
		calls++
		if calls == 1 {
			if _, err := s.tok.Put(ctx, ix, `{"expires_at":"2026-11-02T09:30:00Z"}`); err != nil {
				t.Error(err)
			}
		}
	}
	t.Cleanup(func() { beforeTokenTxn = nil })
	n, err := s.PutToken(ctx, k, store.Token{ID: "t1", Kind: store.KindLogin, ExpiresAt: now.Add(time.Hour),
		IndexPrincipal: "user:alice", IndexTTL: time.Hour})
	if err != nil || n != 1 {
		t.Fatalf("PutToken = %d, %v; want 1, nil", n, err)
	}
	if calls != 2 {
		t.Fatalf("the put tried %d times, want 2 (one lost to the moved index entry, one landed)", calls)
	}
	if got, err := s.Candidates(ctx, k); err != nil || len(got) != 1 || got[0].ID != "t1" {
		t.Fatalf("candidates: %v %v", got, err)
	}
}
