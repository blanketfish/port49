package etcd

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/store"
)

// The latest expiry among the token records, across pages, is what port49d's
// restore guard waits for (plan 12c, Task 9a); a record that does not decode
// is an error, never skipped.
func TestLatestTokenExpiryIsTheLargestAndFailsOnABadRecord(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 11, 2, 9, 0, 0, 0, time.UTC)
	s := onShared(t, func() time.Time { return now })
	if got, err := s.LatestTokenExpiry(ctx, time.Time{}); err != nil || !got.IsZero() {
		t.Fatalf("no tokens: %v %v", got, err)
	}
	var want time.Time
	for i := 0; i < purgePage+5; i++ { // more than a page
		exp := now.Add(time.Duration(i%40) * time.Second).Add(10 * time.Minute)
		if exp.After(want) {
			want = exp
		}
		k := store.TokenKey{NAS: "leaf", Username: "u" + string(rune('a'+i%26))}
		if _, err := s.PutToken(ctx, k, store.Token{ID: "t" + string(rune('a'+i%26)) + time.Duration(i).String(),
			Kind: store.KindLogin, ExpiresAt: exp}); err != nil {
			t.Fatal(err)
		}
	}
	if got, err := s.LatestTokenExpiry(ctx, time.Time{}); err != nil || !got.Equal(want) {
		t.Fatalf("latest %v %v, want %v", got, err, want)
	}
	if _, err := s.tok.Put(ctx, s.k.token(store.TokenKey{NAS: "leaf", Username: "zz"}, "bad"), "not json"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LatestTokenExpiry(ctx, time.Time{}); !errors.Is(err, ErrTokenRecord) {
		t.Fatalf("a bad record: %v", err)
	}
}

// Only a token minted at or before the cutoff counts: a restore cannot have
// brought back one a running broker minted after it (final review I2).
func TestLatestTokenExpiryCountsOnlyTokensMintedByTheCutoff(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 11, 2, 9, 0, 0, 0, time.UTC)
	s := onShared(t, func() time.Time { return now })
	put := func(user string, minted, exp time.Time) {
		t.Helper()
		if _, err := s.PutToken(ctx, store.TokenKey{NAS: "leaf", Username: user},
			store.Token{ID: "t-" + user, Kind: store.KindLogin, MintedAt: minted, ExpiresAt: exp}); err != nil {
			t.Fatal(err)
		}
	}
	old, late := now.Add(10*time.Minute), now.Add(25*time.Minute)
	put("old", now.Add(-5*time.Minute), old)
	put("edge", now, old.Add(time.Minute))
	put("late", now.Add(time.Second), late)
	if got, err := s.LatestTokenExpiry(ctx, now); err != nil || !got.Equal(old.Add(time.Minute)) {
		t.Fatalf("cutoff now: %v %v, want %v", got, err, old.Add(time.Minute))
	}
	if got, err := s.LatestTokenExpiry(ctx, time.Time{}); err != nil || !got.Equal(late) {
		t.Fatalf("no cutoff: %v %v, want %v", got, err, late)
	}
	if got, err := s.LatestTokenExpiry(ctx, now.Add(-time.Hour)); err != nil || !got.IsZero() {
		t.Fatalf("cutoff before every mint: %v %v", got, err)
	}
}

// A candidate carries the revision its record was created at: the restore
// guard's fence (pre-beta Task 2).
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
