package storetest

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/store"
)

// MembershipKeepsTheLaterAndIsFoundByKey: a membership is read back whole
// by principal and by each mapping key it lists; a write verified earlier
// than the one held never replaces it (a slow replica's stale answer must
// not undo a removal another replica verified); a record that stopped
// listing a key is not found by it (plan 7g, Ruling 10).
func MembershipKeepsTheLaterAndIsFoundByKey(t *testing.T, b Backend) {
	ctx := context.Background()
	s := b.New(t, func() time.Time { return t0 })
	k1, k2 := store.MapKey("issuer_serial", "X509:<I>CN=CA<SR>01"), store.MapKey("issuer_serial", "X509:<I>CN=CA<SR>02")
	alice := store.Membership{Principal: "user:alice@corp.example.com", DN: "CN=Alice,OU=Staff,DC=corp",
		EntryID: "guid:0a1b2c3d", Username: "alice", GroupDNs: []string{"CN=netops-oncall,OU=G,DC=corp"},
		GroupNames: []string{"netops-oncall"}, MapKeys: []string{k1}, VerifiedAt: t0.Add(-time.Minute),
		Server: "ldaps://dc-01", Site: "us-west"}
	if err := s.PutMembership(ctx, alice, time.Hour); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetMembership(ctx, alice.Principal)
	if err != nil || got.DN != alice.DN || got.EntryID != alice.EntryID || got.Username != "alice" ||
		!slices.Equal(got.GroupDNs, alice.GroupDNs) ||
		!slices.Equal(got.GroupNames, alice.GroupNames) || !slices.Equal(got.MapKeys, alice.MapKeys) ||
		!got.VerifiedAt.Equal(alice.VerifiedAt) || got.Site != "us-west" || got.Refused {
		t.Fatalf("by principal: %+v %v", got, err)
	}
	if byKey, err := s.MembershipByKey(ctx, k1); err != nil || byKey.Principal != alice.Principal {
		t.Fatalf("by key: %+v %v", byKey, err)
	}
	older := alice
	older.GroupDNs, older.GroupNames, older.VerifiedAt = nil, nil, t0.Add(-time.Hour)
	if err := s.PutMembership(ctx, older, time.Hour); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetMembership(ctx, alice.Principal); len(got.GroupDNs) != 1 {
		t.Fatalf("an earlier verification replaced a later one: %+v", got)
	}
	moved := alice
	moved.MapKeys, moved.VerifiedAt = []string{k2}, t0
	if err := s.PutMembership(ctx, moved, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := s.MembershipByKey(ctx, k1); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a key the record no longer lists: %v, want ErrNotFound", err)
	}
	if _, err := s.GetMembership(ctx, "user:nobody@corp.example.com"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("no record: %v", err)
	}
}

// MembershipKeyClaimedTwiceIsAmbiguous: a key a live record of another
// principal still lists is never repointed to the last writer. It is
// ambiguous, MembershipByKey answers ErrNotFound, and grace refuses the
// certificate (pre-flight I-5). Once the first record stops listing the
// key, the next verification of the second points it there.
func MembershipKeyClaimedTwiceIsAmbiguous(t *testing.T, b Backend) {
	ctx := context.Background()
	s := b.New(t, func() time.Time { return t0 })
	k := store.MapKey("san_email", "shared@corp.example.com")
	alice := store.Membership{Principal: "user:alice@corp.example.com", DN: "CN=Alice,DC=corp", Username: "alice",
		MapKeys: []string{k}, VerifiedAt: t0.Add(-2 * time.Minute)}
	bob := store.Membership{Principal: "user:bob@corp.example.com", DN: "CN=Bob,DC=corp", Username: "bob",
		MapKeys: []string{k}, VerifiedAt: t0.Add(-time.Minute)}
	for _, m := range []store.Membership{alice, bob} {
		if err := s.PutMembership(ctx, m, time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	if m, err := s.MembershipByKey(ctx, k); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a key two live records list: %+v %v, want ErrNotFound", m, err)
	}
	alice.MapKeys, alice.VerifiedAt = nil, t0.Add(-30*time.Second)
	bob.VerifiedAt = t0
	for _, m := range []store.Membership{alice, bob} {
		if err := s.PutMembership(ctx, m, time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	if m, err := s.MembershipByKey(ctx, k); err != nil || m.Principal != bob.Principal {
		t.Fatalf("once alice stops listing it: %+v %v, want bob", m, err)
	}
}

// MembershipRefusalSupersedes: a refusal (the directory answered
// identity_unmapped, identity_ambiguous or username_collision) replaces an
// older grant-bearing record on both indexes, and an older grant-bearing
// write after it never brings the groups back (pre-flight C-1). A key
// refused by itself answers ErrNotFound while the principal's record by
// name stands.
func MembershipRefusalSupersedes(t *testing.T, b Backend) {
	ctx := context.Background()
	s := b.New(t, func() time.Time { return t0 })
	k1, k3 := store.MapKey("sid", "S-1-5-21-1-2-3-1104"), store.MapKey("sid", "S-1-5-21-1-2-3-1105")
	alice := store.Membership{Principal: "user:alice@corp.example.com", DN: "CN=Alice,DC=corp", Username: "alice",
		GroupDNs: []string{"CN=netops-oncall,DC=corp"}, MapKeys: []string{k1}, VerifiedAt: t0.Add(-time.Minute)}
	if err := s.PutMembership(ctx, alice, time.Hour); err != nil {
		t.Fatal(err)
	}
	refusal := store.Membership{Principal: alice.Principal, EntryID: "guid:0a1b", Refused: true, VerifiedAt: t0}
	if err := s.PutMembership(ctx, refusal, time.Hour); err != nil {
		t.Fatal(err)
	}
	stale := alice
	stale.VerifiedAt = t0.Add(-30 * time.Second)
	if err := s.PutMembership(ctx, stale, time.Hour); err != nil {
		t.Fatal(err)
	}
	if got, err := s.GetMembership(ctx, alice.Principal); err != nil || !got.Refused || len(got.GroupDNs) != 0 ||
		got.EntryID != "guid:0a1b" {
		t.Fatalf("by principal after a refusal: %+v %v, want refused with no groups and its pin", got, err)
	}
	if _, err := s.MembershipByKey(ctx, k1); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("by key after a refusal: %v, want ErrNotFound", err)
	}
	carol := store.Membership{Principal: "user:carol@corp.example.com", DN: "CN=Carol,DC=corp", Username: "carol",
		MapKeys: []string{k3}, VerifiedAt: t0.Add(-time.Minute)}
	if err := s.PutMembership(ctx, carol, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := s.RefuseMapKeys(ctx, []string{k3}, t0, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := s.MembershipByKey(ctx, k3); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a refused key: %v, want ErrNotFound", err)
	}
	if got, err := s.GetMembership(ctx, carol.Principal); err != nil || got.Refused {
		t.Fatalf("a key refused leaves the principal's record: %+v %v", got, err)
	}
}

// MembershipPrincipalsListsTheLive: every principal with a live record,
// refused ones included, sorted (pre-flight I-13).
func MembershipPrincipalsListsTheLive(t *testing.T, b Backend) {
	ctx := context.Background()
	var mu sync.Mutex
	now := t0
	s := b.New(t, func() time.Time { mu.Lock(); defer mu.Unlock(); return now })
	for _, m := range []store.Membership{
		{Principal: "user:bob@corp.example.com", Username: "bob", VerifiedAt: t0},
		{Principal: "user:alice@corp.example.com", Refused: true, VerifiedAt: t0},
	} {
		if err := s.PutMembership(ctx, m, time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.PutMembership(ctx, store.Membership{Principal: "user:gone@corp.example.com", VerifiedAt: t0},
		time.Minute); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	now = now.Add(2 * time.Minute)
	mu.Unlock()
	got, err := s.MembershipPrincipals(ctx)
	if err != nil || !slices.Equal(got, []string{"user:alice@corp.example.com", "user:bob@corp.example.com"}) {
		t.Fatalf("%v %v", got, err)
	}
}

// MembershipExpires: past its ttl a membership is gone by principal and by
// key, so grace never reads a record the lease has reclaimed.
func MembershipExpires(t *testing.T, b Backend) {
	ctx := context.Background()
	var mu sync.Mutex
	now := t0
	s := b.New(t, func() time.Time { mu.Lock(); defer mu.Unlock(); return now })
	k := store.MapKey("san_email", "carol@corp.example.com")
	m := store.Membership{Principal: "user:carol@corp.example.com", DN: "CN=Carol,DC=corp", Username: "carol",
		MapKeys: []string{k}, VerifiedAt: t0}
	if err := s.PutMembership(ctx, m, time.Minute); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	now = now.Add(2 * time.Minute)
	mu.Unlock()
	if _, err := s.GetMembership(ctx, m.Principal); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("by principal past ttl: %v", err)
	}
	if _, err := s.MembershipByKey(ctx, k); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("by key past ttl: %v", err)
	}
}

// MembershipForgetRemovesThePin: DeleteMembership returns the record it
// removed, pin included, and leaves nothing to find by principal, by key or
// in the list. A refusal record is forgotten like a membership. A second
// forget finds nothing. Afterwards a write verified earlier than the
// forgotten record, but not before the forget itself, is taken, and pins the
// principal to another entry, and a key the forgotten record listed is another principal's to claim, never
// ambiguous (plan 7g, Ruling 3's escape).
func MembershipForgetRemovesThePin(t *testing.T, b Backend) {
	ctx := context.Background()
	s := b.New(t, func() time.Time { return t0 })
	k := store.MapKey("san_email", "alice@corp.example.com")
	alice := store.Membership{Principal: "user:alice@corp.example.com", DN: "CN=Alice,OU=Staff,DC=corp",
		EntryID: "guid:0a1b", Username: "alice", MapKeys: []string{k}, VerifiedAt: t0}
	if err := s.PutMembership(ctx, alice, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := s.PutMembership(ctx, store.Membership{Principal: alice.Principal, EntryID: "guid:0a1b", Refused: true,
		VerifiedAt: t0.Add(time.Second)}, time.Hour); err != nil {
		t.Fatal(err)
	}
	got, err := s.DeleteMembership(ctx, alice.Principal)
	if err != nil || got.EntryID != "guid:0a1b" || !got.Refused || !got.VerifiedAt.Equal(t0.Add(time.Second)) {
		t.Fatalf("forget: %+v %v, want the refusal with its pin", got, err)
	}
	if _, err := s.GetMembership(ctx, alice.Principal); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("by principal after forget: %v", err)
	}
	if _, err := s.MembershipByKey(ctx, k); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("by key after forget: %v", err)
	}
	if ps, err := s.MembershipPrincipals(ctx); err != nil || slices.Contains(ps, alice.Principal) {
		t.Fatalf("listed after forget: %v %v", ps, err)
	}
	if _, err := s.DeleteMembership(ctx, alice.Principal); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a second forget: %v", err)
	}
	rehired := alice
	rehired.EntryID, rehired.VerifiedAt = "guid:9f8e", t0
	if err := s.PutMembership(ctx, rehired, time.Hour); err != nil {
		t.Fatal(err)
	}
	if got, err := s.GetMembership(ctx, alice.Principal); err != nil || got.EntryID != "guid:9f8e" {
		t.Fatalf("after forget, the next write pins: %+v %v", got, err)
	}
	if got, err := s.DeleteMembership(ctx, alice.Principal); err != nil || got.EntryID != "guid:9f8e" {
		t.Fatalf("forget again: %+v %v", got, err)
	}
	bob := store.Membership{Principal: "user:bob@corp.example.com", EntryID: "guid:b0b0", Username: "bob",
		MapKeys: []string{k}, VerifiedAt: t0.Add(2 * time.Second)}
	if err := s.PutMembership(ctx, bob, time.Hour); err != nil {
		t.Fatal(err)
	}
	if got, err := s.MembershipByKey(ctx, k); err != nil || got.Principal != bob.Principal {
		t.Fatalf("a forgotten record's key: %+v %v, want bob's", got, err)
	}
}

// MembershipForgetBeatsAnInFlightVerification: a forget leaves a tombstone
// holding the time of the forget. A write for the principal verified before
// it is dropped, with no error and nothing written, so a verification that
// began before the forget can never put the old pin back; one verified after
// it writes normally. The tombstone is no record (plan 7g, PF7g-e).
func MembershipForgetBeatsAnInFlightVerification(t *testing.T, b Backend) {
	ctx := context.Background()
	var mu sync.Mutex
	now := t0
	s := b.New(t, func() time.Time { mu.Lock(); defer mu.Unlock(); return now })
	advance := func(d time.Duration) { mu.Lock(); now = now.Add(d); mu.Unlock() }
	k := store.MapKey("san_email", "alice@corp.example.com")
	alice := store.Membership{Principal: "user:alice@corp.example.com", DN: "CN=Alice,DC=corp", EntryID: "guid:A",
		Username: "alice", MapKeys: []string{k}, VerifiedAt: t0}
	if err := s.PutMembership(ctx, alice, time.Hour); err != nil {
		t.Fatal(err)
	}
	advance(time.Minute) // t1: the forget
	if _, err := s.DeleteMembership(ctx, alice.Principal); err != nil {
		t.Fatal(err)
	}
	inFlight := store.Membership{Principal: alice.Principal, EntryID: "guid:A", Refused: true,
		VerifiedAt: t0.Add(30 * time.Second)}
	if err := s.PutMembership(ctx, inFlight, time.Hour); err != nil {
		t.Fatalf("a write dropped for the forget is no error: %v", err)
	}
	stale := alice
	stale.VerifiedAt = t0.Add(45 * time.Second)
	if err := s.PutMembership(ctx, stale, time.Hour); err != nil {
		t.Fatal(err)
	}
	if got, err := s.GetMembership(ctx, alice.Principal); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a verification from before the forget wrote: %+v %v, want ErrNotFound", got, err)
	}
	if _, err := s.MembershipByKey(ctx, k); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("by key after a dropped write: %v", err)
	}
	if ps, err := s.MembershipPrincipals(ctx); err != nil || slices.Contains(ps, alice.Principal) {
		t.Fatalf("the tombstone is listed: %v %v", ps, err)
	}
	if _, err := s.DeleteMembership(ctx, alice.Principal); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a forget over a tombstone: %v, want ErrNotFound", err)
	}
	advance(time.Minute) // t2
	rehired := alice
	rehired.EntryID, rehired.VerifiedAt = "guid:B", now
	if err := s.PutMembership(ctx, rehired, time.Hour); err != nil {
		t.Fatal(err)
	}
	if got, err := s.GetMembership(ctx, alice.Principal); err != nil || got.EntryID != "guid:B" {
		t.Fatalf("a verification after the forget: %+v %v, want pinned to B", got, err)
	}
	if got, err := s.MembershipByKey(ctx, k); err != nil || got.EntryID != "guid:B" {
		t.Fatalf("by key after the rehire: %+v %v", got, err)
	}
}
