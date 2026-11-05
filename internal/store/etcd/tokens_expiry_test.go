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
