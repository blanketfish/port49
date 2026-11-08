package storetest

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/store"
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
	if got, err := s.GetMembership(ctx, alice.Principal); err != nil || len(got.GroupDNs) != 1 {
		t.Fatalf("an earlier verification replaced a later one: %+v %v", got, err)
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

// MembershipKeyClaimedInEitherOrderIsAmbiguous: whichever of two records
// listing a key is written last, the key is ambiguous while both are live
// (pre-flight I-5): a verification dated earlier that arrives second does
// not leave the key with the other principal.
func MembershipKeyClaimedInEitherOrderIsAmbiguous(t *testing.T, b Backend) {
	ctx := context.Background()
	k := store.MapKey("san_email", "shared@corp.example.com")
	carol := store.Membership{Principal: "user:carol@corp.example.com", Username: "carol", MapKeys: []string{k}, VerifiedAt: t0}
	dave := store.Membership{Principal: "user:dave@corp.example.com", Username: "dave", MapKeys: []string{k},
		VerifiedAt: t0.Add(-time.Minute)}
	for _, order := range [][]store.Membership{{carol, dave}, {dave, carol}} {
		s := b.New(t, func() time.Time { return t0 })
		for _, m := range order {
			if err := s.PutMembership(ctx, m, time.Hour); err != nil {
				t.Fatal(err)
			}
		}
		if m, err := s.MembershipByKey(ctx, k); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("written %s first: a key two live records list answered %q %v, want ErrNotFound",
				order[0].Username, m.Principal, err)
		}
	}
}

// MembershipAmbiguityHealsToTheSoleClaimant: an ambiguous key answers the
// one principal still claiming it once the others stop listing it, with no
// further verification, and a principal re-verifying with the key never
// keeps it ambiguous by itself.
func MembershipAmbiguityHealsToTheSoleClaimant(t *testing.T, b Backend) {
	ctx := context.Background()
	s := b.New(t, func() time.Time { return t0 })
	k := store.MapKey("san_email", "shared@corp.example.com")
	alice := store.Membership{Principal: "user:alice@corp.example.com", Username: "alice", MapKeys: []string{k},
		VerifiedAt: t0.Add(-3 * time.Minute)}
	bob := store.Membership{Principal: "user:bob@corp.example.com", Username: "bob", MapKeys: []string{k},
		VerifiedAt: t0.Add(-2 * time.Minute)}
	put := func(m store.Membership) {
		t.Helper()
		if err := s.PutMembership(ctx, m, time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	put(alice)
	put(bob)
	if _, err := s.MembershipByKey(ctx, k); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("two claimants: %v, want ErrNotFound", err)
	}
	bob.MapKeys, bob.VerifiedAt = nil, t0.Add(-time.Minute)
	put(bob)
	if m, err := s.MembershipByKey(ctx, k); err != nil || m.Principal != alice.Principal {
		t.Fatalf("bob stopped listing it: %+v %v, want alice", m, err)
	}
	alice.VerifiedAt = t0
	put(alice)
	if m, err := s.MembershipByKey(ctx, k); err != nil || m.Principal != alice.Principal {
		t.Fatalf("alice re-verified, the sole claimant: %+v %v, want alice", m, err)
	}
	bob.MapKeys, bob.VerifiedAt = []string{k}, t0
	put(bob)
	if _, err := s.MembershipByKey(ctx, k); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("bob claims it again: %v, want ErrNotFound", err)
	}
	if _, err := s.DeleteMembership(ctx, bob.Principal); err != nil {
		t.Fatal(err)
	}
	if m, err := s.MembershipByKey(ctx, k); err != nil || m.Principal != alice.Principal {
		t.Fatalf("bob forgotten: %+v %v, want alice", m, err)
	}
}

// MembershipTieKeepsTheRefusal: a grant and a refusal verified at the same
// instant leave the refusal, whichever is written last, on the record and on
// a key.
func MembershipTieKeepsTheRefusal(t *testing.T, b Backend) {
	ctx := context.Background()
	k := store.MapKey("sid", "S-1-5-21-1-2-3-1104")
	grant := store.Membership{Principal: "user:alice@corp.example.com", Username: "alice", MapKeys: []string{k}, VerifiedAt: t0}
	refusal := store.Membership{Principal: grant.Principal, Refused: true, VerifiedAt: t0}
	for _, order := range [][]store.Membership{{grant, refusal}, {refusal, grant}} {
		s := b.New(t, func() time.Time { return t0 })
		for _, m := range order {
			if err := s.PutMembership(ctx, m, time.Hour); err != nil {
				t.Fatal(err)
			}
		}
		if got, err := s.GetMembership(ctx, grant.Principal); err != nil || !got.Refused {
			t.Fatalf("a tie, refused=%v written first: %+v %v, want the refusal", order[0].Refused, got, err)
		}
	}
	s := b.New(t, func() time.Time { return t0 })
	if err := s.RefuseMapKeys(ctx, []string{k}, t0, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := s.PutMembership(ctx, grant, time.Hour); err != nil {
		t.Fatal(err)
	}
	if m, err := s.MembershipByKey(ctx, k); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a key refused at the instant a grant was verified: %+v %v, want ErrNotFound", m, err)
	}
}

// MembershipForgetTombstoneOutlivesTheRecord: a record forgotten seconds
// before its ttl ends still blocks a verification that began before the
// forget, a while after the record would have gone.
func MembershipForgetTombstoneOutlivesTheRecord(t *testing.T, b Backend) {
	ctx := context.Background()
	var mu sync.Mutex
	now := t0
	s := b.New(t, func() time.Time { mu.Lock(); defer mu.Unlock(); return now })
	advance := func(d time.Duration) { mu.Lock(); now = now.Add(d); mu.Unlock() }
	alice := store.Membership{Principal: "user:alice@corp.example.com", EntryID: "guid:A", Username: "alice", VerifiedAt: t0}
	if err := s.PutMembership(ctx, alice, time.Minute); err != nil {
		t.Fatal(err)
	}
	advance(50 * time.Second)
	if _, err := s.DeleteMembership(ctx, alice.Principal); err != nil {
		t.Fatal(err)
	}
	advance(time.Hour)
	inFlight := alice
	inFlight.VerifiedAt = t0.Add(40 * time.Second)
	if err := s.PutMembership(ctx, inFlight, time.Hour); err != nil {
		t.Fatal(err)
	}
	if got, err := s.GetMembership(ctx, alice.Principal); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a verification from before the forget wrote past the old record's ttl: %+v %v", got, err)
	}
}

// MembershipRefusedKeyKeepsItsClaimants: a refusal of a key does not forget
// who claimed it. A principal claiming the key afterwards, while another's
// live record still lists it, leaves it ambiguous, never the later
// claimant's; a claim older than the refusal is remembered too; and the
// marker lives as long as the record that claimed it (the directory said
// identity_ambiguous for the key).
func MembershipRefusedKeyKeepsItsClaimants(t *testing.T, b Backend) {
	ctx := context.Background()
	var mu sync.Mutex
	now := t0
	s := b.New(t, func() time.Time { mu.Lock(); defer mu.Unlock(); return now })
	advance := func(d time.Duration) { mu.Lock(); now = now.Add(d); mu.Unlock() }
	put := func(m store.Membership, ttl time.Duration) {
		t.Helper()
		if err := s.PutMembership(ctx, m, ttl); err != nil {
			t.Fatal(err)
		}
	}
	byKeyIs := func(k, want, what string) {
		t.Helper()
		m, err := s.MembershipByKey(ctx, k)
		switch {
		case want == "" && !errors.Is(err, store.ErrNotFound):
			t.Fatalf("%s: answered %q %v, want ErrNotFound", what, m.Principal, err)
		case want != "" && (err != nil || m.Principal != want):
			t.Fatalf("%s: %q %v, want %q", what, m.Principal, err, want)
		}
	}
	const alicep, bobp = "user:alice@corp.example.com", "user:bob@corp.example.com"

	// A claim after the refusal.
	k := store.MapKey("san_email", "shared@corp.example.com")
	alice := store.Membership{Principal: alicep, Username: "alice", MapKeys: []string{k}, VerifiedAt: t0.Add(-2 * time.Minute)}
	bob := store.Membership{Principal: bobp, Username: "bob", MapKeys: []string{k}, VerifiedAt: t0}
	put(alice, time.Hour)
	if err := s.RefuseMapKeys(ctx, []string{k}, t0.Add(-time.Minute), time.Hour); err != nil {
		t.Fatal(err)
	}
	byKeyIs(k, "", "a refused key")
	put(bob, time.Hour)
	byKeyIs(k, "", "bob claims a refused key alice's live record still lists")
	bob.MapKeys, bob.VerifiedAt = nil, t0.Add(time.Second)
	put(bob, time.Hour)
	byKeyIs(k, "", "bob stopped listing it, alice not verified since the refusal")
	alice.VerifiedAt = t0.Add(2 * time.Second)
	put(alice, time.Hour)
	byKeyIs(k, alicep, "alice verified after the refusal, the sole claimant")

	// A claim older than the refusal arrives after it.
	k2 := store.MapKey("san_email", "other@corp.example.com")
	alice2 := store.Membership{Principal: alicep, Username: "alice", MapKeys: []string{k2}, VerifiedAt: t0.Add(2 * time.Second)}
	bob2 := store.Membership{Principal: bobp, Username: "bob", MapKeys: []string{k2}, VerifiedAt: t0.Add(2 * time.Second)}
	if err := s.RefuseMapKeys(ctx, []string{k2}, t0.Add(10*time.Second), time.Hour); err != nil {
		t.Fatal(err)
	}
	put(bob2, time.Hour) // older than the refusal: it stands
	byKeyIs(k2, "", "a claim older than the refusal")
	alice2.VerifiedAt = t0.Add(20 * time.Second) // alice claims after it
	put(alice2, time.Hour)
	byKeyIs(k2, "", "alice claims after a refusal bob's record still lists the key under")
	bob2.MapKeys, bob2.VerifiedAt = nil, t0.Add(30*time.Second)
	put(bob2, time.Hour)
	byKeyIs(k2, alicep, "bob stopped listing it")

	// The marker outlives a shorter refusal while the claimant's record lives.
	k3 := store.MapKey("san_email", "third@corp.example.com")
	carol := store.Membership{Principal: "user:carol@corp.example.com", Username: "carol", MapKeys: []string{k3},
		VerifiedAt: t0.Add(time.Minute)}
	put(carol, time.Hour)
	if err := s.RefuseMapKeys(ctx, []string{k3}, t0.Add(2*time.Minute), time.Minute); err != nil {
		t.Fatal(err)
	}
	advance(5 * time.Minute)
	dave := store.Membership{Principal: "user:dave@corp.example.com", Username: "dave", MapKeys: []string{k3},
		VerifiedAt: now}
	put(dave, time.Hour)
	byKeyIs(k3, "", "dave claims after a short refusal expired, carol's record still lists the key")
}

// MembershipKeyOutlivesNoRecord: a key's marker lasts as long as the longest
// record that claimed it, however the claim arrived: a verification that
// leaves the key's holder unchanged still extends it, so a record never
// outlives the marker that keeps another principal from taking its key
// (review R2-a).
func MembershipKeyOutlivesNoRecord(t *testing.T, b Backend) {
	ctx := context.Background()
	var mu sync.Mutex
	now := t0
	s := b.New(t, func() time.Time { mu.Lock(); defer mu.Unlock(); return now })
	advance := func(d time.Duration) { mu.Lock(); now = now.Add(d); mu.Unlock() }
	put := func(m store.Membership) {
		t.Helper()
		if err := s.PutMembership(ctx, m, time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	k := store.MapKey("san_email", "shared@corp.example.com")
	p := store.Membership{Principal: "user:p@corp.example.com", Username: "p", MapKeys: []string{k}, VerifiedAt: t0.Add(-10 * time.Minute)}
	q := store.Membership{Principal: "user:q@corp.example.com", Username: "q", MapKeys: []string{k}, VerifiedAt: t0}
	put(p)
	put(q)
	q.MapKeys, q.VerifiedAt = nil, t0.Add(time.Second)
	put(q)
	advance(30 * time.Minute)
	p.VerifiedAt = t0.Add(-5 * time.Minute)
	put(p)
	advance(10 * time.Minute)
	p.VerifiedAt = t0.Add(-4 * time.Minute)
	put(p)
	advance(55 * time.Minute) // past the marker p's first write set, inside p's record
	q.MapKeys, q.VerifiedAt = []string{k}, now
	put(q)
	if m, err := s.MembershipByKey(ctx, k); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("q claimed a key p's live record still lists: answered %q %v, want ErrNotFound", m.Principal, err)
	}
}

// MembershipWithNoExpiryOutlivesAnyTTL: a record and its map key written
// with store.NoExpiry stand however far the clock moves, and so does the
// tombstone a forget leaves of one, which GetMembership answers as
// ErrForgotten (an ErrNotFound); a principal never written is ErrNotFound
// and not ErrForgotten; a verification from before the forget never puts
// the pin back (plan 11a, R13).
func MembershipWithNoExpiryOutlivesAnyTTL(t *testing.T, b Backend) {
	ctx := context.Background()
	var mu sync.Mutex
	now := t0
	s := b.New(t, func() time.Time { mu.Lock(); defer mu.Unlock(); return now })
	later := func(d time.Duration) { mu.Lock(); now = now.Add(d); mu.Unlock() }
	k := store.MapKey("san_email", "dave@corp.example.com")
	m := store.Membership{Principal: "user:dave@corp.example.com", EntryID: "guid:d", MapKeys: []string{k},
		VerifiedAt: t0}
	if err := s.PutMembership(ctx, m, store.NoExpiry); err != nil {
		t.Fatal(err)
	}
	later(10 * 365 * 24 * time.Hour)
	if got, err := s.GetMembership(ctx, m.Principal); err != nil || got.EntryID != "guid:d" {
		t.Fatalf("a pin with no expiry, years on: %+v %v", got, err)
	}
	if got, err := s.MembershipByKey(ctx, k); err != nil || got.Principal != m.Principal {
		t.Fatalf("its key, years on: %+v %v", got, err)
	}
	if _, err := s.GetMembership(ctx, "user:erin@corp.example.com"); !errors.Is(err, store.ErrNotFound) ||
		errors.Is(err, store.ErrForgotten) {
		t.Fatalf("never written: %v, want ErrNotFound and not ErrForgotten", err)
	}
	if _, err := s.DeleteMembership(ctx, m.Principal); err != nil {
		t.Fatal(err)
	}
	later(10 * 365 * 24 * time.Hour)
	if _, err := s.GetMembership(ctx, m.Principal); !errors.Is(err, store.ErrForgotten) ||
		!errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the forget's tombstone, years on: %v, want ErrForgotten", err)
	}
	if err := s.PutMembership(ctx, m, store.NoExpiry); err != nil { // verified at t0, before the forget
		t.Fatal(err)
	}
	if _, err := s.GetMembership(ctx, m.Principal); !errors.Is(err, store.ErrForgotten) {
		t.Fatalf("a verification from before the forget put the pin back: %v", err)
	}
}

// MembershipPinIsCompareAndSet: PutPin writes a record with no lease only
// when the record stands as the caller read it: absent, forgotten, or held
// at the Version GetMembership gave. Anything else is ErrConflict and
// writes nothing (plan 11a, review of 8a, I1).
func MembershipPinIsCompareAndSet(t *testing.T, b Backend) {
	ctx := context.Background()
	s := b.New(t, func() time.Time { return t0 })
	p := "user:fay@corp.example.com"
	pin := func(entry string, at time.Time) store.Membership {
		return store.Membership{Principal: p, EntryID: entry, VerifiedAt: at}
	}
	if err := s.PutPin(ctx, pin("guid:1", t0), store.PinExpect{Forgotten: true}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("expecting a tombstone of an absent record: %v", err)
	}
	if err := s.PutPin(ctx, pin("guid:1", t0), store.PinExpect{Version: 7}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("expecting a held record of an absent one: %v", err)
	}
	if err := s.PutPin(ctx, pin("guid:1", t0), store.PinExpect{Absent: true}); err != nil {
		t.Fatal(err)
	}
	if err := s.PutPin(ctx, pin("guid:2", t0.Add(time.Minute)), store.PinExpect{Absent: true}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("expecting absent of a held record: %v", err)
	}
	held, err := s.GetMembership(ctx, p)
	if err != nil || held.EntryID != "guid:1" || held.Version == 0 {
		t.Fatalf("%+v %v: want guid:1 with a version", held, err)
	}
	if err := s.PutPin(ctx, pin("guid:2", t0.Add(time.Minute)), store.PinExpect{Version: held.Version + 1}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("a stale version: %v", err)
	}
	if err := s.PutPin(ctx, pin("guid:1", t0.Add(time.Minute)), store.PinExpect{Version: held.Version}); err != nil {
		t.Fatal(err)
	}
	if err := s.PutPin(ctx, pin("guid:1", t0.Add(2*time.Minute)), store.PinExpect{Version: held.Version}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("the version the last write replaced: %v", err)
	}
	if got, _ := s.GetMembership(ctx, p); got.EntryID != "guid:1" {
		t.Fatalf("a refused PutPin wrote: %+v", got)
	}
	if _, err := s.DeleteMembership(ctx, p); err != nil {
		t.Fatal(err)
	}
	if err := s.PutPin(ctx, pin("guid:3", t0.Add(time.Hour)), store.PinExpect{Absent: true}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("expecting absent of a tombstone: %v", err)
	}
	if err := s.PutPin(ctx, pin("guid:3", t0.Add(time.Hour)), store.PinExpect{Forgotten: true}); err != nil {
		t.Fatal(err)
	}
	if got, err := s.GetMembership(ctx, p); err != nil || got.EntryID != "guid:3" {
		t.Fatalf("%+v %v", got, err)
	}
}

// MembershipForgetOfAnAbsentRecordLeavesAPermanentTombstone: a forget of a
// principal the store holds nothing for is ErrNotFound, and still leaves a
// tombstone with no lease, so a copy another region holds can never put the
// pin back (plan 11a, review of 8a, I2).
func MembershipForgetOfAnAbsentRecordLeavesAPermanentTombstone(t *testing.T, b Backend) {
	ctx := context.Background()
	var mu sync.Mutex
	now := t0
	s := b.New(t, func() time.Time { mu.Lock(); defer mu.Unlock(); return now })
	p := "user:gil@corp.example.com"
	if _, err := s.DeleteMembership(ctx, p); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a forget of nothing: %v", err)
	}
	mu.Lock()
	now = now.Add(10 * 365 * 24 * time.Hour)
	mu.Unlock()
	if _, err := s.GetMembership(ctx, p); !errors.Is(err, store.ErrForgotten) {
		t.Fatalf("years on: %v, want the tombstone", err)
	}
	if err := s.PutMembership(ctx, store.Membership{Principal: p, EntryID: "guid:old", VerifiedAt: t0.Add(-time.Minute)}, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetMembership(ctx, p); !errors.Is(err, store.ErrForgotten) {
		t.Fatalf("a verification from before the forget wrote the pin back: %v", err)
	}
}

// MembershipSealsListsTheLive: every live, unforgotten record, with the key
// id its sealed part's header names and the version GetMembership reads
// (decision 57). An expired record and a forget's tombstone are not listed.
func MembershipSealsListsTheLive(t *testing.T, b Backend) {
	if b.Sealed {
		t.Skip("the sealing layer writes the sealed part itself; TestMembershipSealsMarkTheCurrentKey covers it")
	}
	ctx := context.Background()
	var mu sync.Mutex
	now := t0
	s := b.New(t, func() time.Time { mu.Lock(); defer mu.Unlock(); return now })
	sealed := func(id string) []byte { return append([]byte{byte(len(id))}, id+"-not-a-ciphertext"...) }
	const alice, bob, carol = "user:alice@corp.example.com", "user:bob@corp.example.com", "user:carol@corp.example.com"
	if err := s.PutPin(ctx, store.Membership{Principal: bob, EntryID: "uuid:b", VerifiedAt: t0, Sealed: sealed("k2")},
		store.PinExpect{Absent: true}); err != nil {
		t.Fatal(err)
	}
	if err := s.PutMembership(ctx, store.Membership{Principal: alice, EntryID: "uuid:a", VerifiedAt: t0,
		Sealed: sealed("k1")}, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := s.PutMembership(ctx, store.Membership{Principal: "user:gone@corp.example.com", VerifiedAt: t0,
		Sealed: sealed("k1")}, time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := s.PutPin(ctx, store.Membership{Principal: carol, EntryID: "uuid:c", VerifiedAt: t0, Sealed: sealed("k1")},
		store.PinExpect{Absent: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeleteMembership(ctx, carol); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	now = now.Add(2 * time.Minute)
	mu.Unlock()
	got, err := s.MembershipSeals(ctx)
	if err != nil || len(got) != 2 || got[0].Principal != alice || got[0].KeyID != "k1" ||
		got[1].Principal != bob || got[1].KeyID != "k2" {
		t.Fatalf("the listing: %+v, %v", got, err)
	}
	for _, e := range got {
		m, err := s.GetMembership(ctx, e.Principal)
		if err != nil || e.Version == 0 || e.Version != m.Version || e.Current {
			t.Fatalf("%s listed at version %d (current %v), read at %d: %v", e.Principal, e.Version, e.Current, m.Version, err)
		}
	}
}
