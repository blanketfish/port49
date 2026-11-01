package placement

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/store"
	"github.com/blanketfish/port49/internal/store/memory"
)

// R19: a copy past its ceiling answers every read of it store_unavailable:
// a mark, a logout and a cached pin.
func TestAnExpiredCopyAnswersUnavailable(t *testing.T) {
	ctx := context.Background()
	var expired error
	marks := store.NewMarks()
	marks.Set(store.Revocation{Kind: store.RevocationPrincipal, Key: alice, At: t0}, true)
	dir := memory.New(clock)
	s := Wrap(Config{Session: memory.New(clock), Directory: dir, Members: dir, Marks: marks,
		Logouts: store.NewLogoutSet(clock), LogoutDir: memory.New(clock), Expired: func() error { return expired },
		CallTimeout: time.Second, BulkTimeout: time.Second})
	if _, err := s.GetRevocation(ctx, store.RevocationPrincipal, alice); err != nil {
		t.Fatalf("before the ceiling: %v", err)
	}
	SeedPins(s, []store.Membership{{Principal: alice, EntryID: "uuid:1", MapKeys: []string{"k1"}}})
	if got, err := s.GetMembership(ctx, alice); err != nil || got.EntryID != "uuid:1" {
		t.Fatalf("a cached pin before the ceiling: %+v %v", got, err)
	}
	expired = errors.New("the snapshot is past the ceiling")
	if _, err := s.GetMembership(ctx, alice); !errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("a cached pin past the ceiling: %v, want ErrUnavailable", err)
	}
	if _, err := s.GetRevocation(ctx, store.RevocationPrincipal, alice); !errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("a mark past the ceiling: %v, want ErrUnavailable", err)
	}
	if _, err := s.GetLogout(ctx, store.SidKey("https://idp", "s1")); !errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("a logout past the ceiling: %v, want ErrUnavailable", err)
	}
}

// R19: the pins a snapshot carries seed the cache, and read back as cached.
func TestSeedPinsFillsTheCache(t *testing.T) {
	ctx := context.Background()
	a, _, _, _, _ := twoRegions(nil)
	SeedPins(a, []store.Membership{{Principal: alice, EntryID: "uuid:1", MapKeys: []string{"k1"}}})
	if !a.(*placed).cachedPin(alice) {
		t.Fatal("a seeded pin is not cached")
	}
	if got := CachedPins(a); len(got) != 1 || got[0].EntryID != "uuid:1" {
		t.Fatalf("%+v", got)
	}
	if got, err := a.GetMembership(ctx, alice); err != nil || got.EntryID != "uuid:1" {
		t.Fatalf("%+v %v", got, err)
	}
}
