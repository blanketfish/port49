package placement

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/store"
	"github.com/blanketfish/port49/internal/store/crypt"
	"github.com/blanketfish/port49/internal/store/memory"
)

const bob = "user:bob@example.com"

// sealKey is a key named id whose bytes are id repeated: test keys only.
func sealKey(id string) crypt.Key {
	var b [32]byte
	copy(b[:], strings.Repeat(id, 32))
	return crypt.NewKey(id, b)
}

// window is encryption: current, and previous when one is given.
func window(current string, previous ...string) crypt.Keys {
	k := crypt.Keys{Current: sealKey(current)}
	if len(previous) == 1 {
		p := sealKey(previous[0])
		k.Previous = &p
	}
	return k
}

// sealedRegion is a router over dir whose pins are sealed under ks, as
// port49-broker builds it (brokerd.go, lazyMembers); wrap, when set, stands
// between it and the sealed directory.
func sealedRegion(dir *memory.Store, ks crypt.Keys, wrap func(Members) Members) *placed {
	var members Members = crypt.Wrap(dir, ks, nil)
	if wrap != nil {
		members = wrap(members)
	}
	return Wrap(Config{Session: memory.New(clock), Directory: dir, Members: members, Marks: store.NewMarks(),
		CallTimeout: time.Second, BulkTimeout: time.Second}).(*placed)
}

// reseal is one pass that must find the router holding pins.
func reseal(t *testing.T, r *placed, unopened func(string, error)) (store.PinReseal, error) {
	t.Helper()
	rep, held, err := r.ResealPins(context.Background(), unopened)
	if !held {
		t.Fatal("a router with a directory of its own says it holds no pins")
	}
	return rep, err
}

func pinFor(principal, entry string) store.Membership {
	return store.Membership{Principal: principal, EntryID: entry, MapKeys: []string{"key-" + entry}, VerifiedAt: t0}
}

func pinned(t *testing.T, r store.Store, ms ...store.Membership) {
	t.Helper()
	for _, m := range ms {
		if err := r.PutMembership(context.Background(), m, time.Hour); err != nil {
			t.Fatal(m.Principal, err)
		}
	}
}

// sealedUnder is the key id the directory's raw record for principal names.
func sealedUnder(t *testing.T, dir *memory.Store, principal string) string {
	t.Helper()
	raw, err := dir.GetMembership(context.Background(), principal)
	if err != nil {
		t.Fatal(principal, err)
	}
	return crypt.SealedKeyID(raw.Sealed)
}

// opens fails the test for each principal whose pin does not open under ks.
func opens(t *testing.T, dir *memory.Store, ks crypt.Keys, principals ...string) {
	t.Helper()
	m := crypt.Wrap(dir, ks, nil)
	for _, p := range principals {
		if got, err := m.GetMembership(context.Background(), p); err != nil || got.EntryID == "" {
			t.Errorf("%s's pin does not open under current %s: %v", p, ks.Current.ID, err)
		}
	}
}

// reads is a directory that counts its pin reads.
type reads struct {
	Members
	n int
}

func (r *reads) GetMembership(ctx context.Context, p string) (store.Membership, error) {
	r.n++
	return r.Members.GetMembership(ctx, p)
}

// The pass writes each pin under the previous key again under the current
// one, keeping its entry and map keys, and a second pass reads and writes
// nothing.
func TestTheReSealPassMovesPinsOffThePreviousKey(t *testing.T) {
	ctx := context.Background()
	dir := memory.New(clock)
	pinned(t, sealedRegion(dir, window("k1"), nil), pinFor(alice, "uuid:a"), pinFor(bob, "uuid:b"))
	var rd *reads
	r := sealedRegion(dir, window("k2", "k1"), func(m Members) Members { rd = &reads{Members: m}; return rd })
	if rep, err := reseal(t, r, nil); err != nil || rep != (store.PinReseal{Sealed: 2}) {
		t.Fatalf("the pass: %+v, %v", rep, err)
	}
	for _, p := range []string{alice, bob} {
		if id := sealedUnder(t, dir, p); id != "k2" {
			t.Errorf("%s's pin is under %q after the pass, want k2", p, id)
		}
	}
	got, err := crypt.Wrap(dir, window("k2"), nil).GetMembership(ctx, alice)
	if err != nil || got.EntryID != "uuid:a" || !slices.Equal(got.MapKeys, []string{"key-uuid:a"}) {
		t.Fatalf("the re-sealed pin: entry %q, keys %v, %v", got.EntryID, got.MapKeys, err)
	}
	rd.n = 0
	if rep, err := reseal(t, r, nil); err != nil || rep != (store.PinReseal{}) || rd.n != 0 {
		t.Fatalf("a second pass: %+v, %d pin reads, %v (want none: every pin is on current)", rep, rd.n, err)
	}
}

// Pre-flight M2: a pass over pins all sealed under the current key reads
// the listing alone, never a pin.
func TestAPassWithEveryPinOnCurrentReadsNoPin(t *testing.T) {
	dir := memory.New(clock)
	pinned(t, sealedRegion(dir, window("k2"), nil), pinFor(alice, "uuid:a"), pinFor(bob, "uuid:b"))
	var rd *reads
	r := sealedRegion(dir, window("k2", "k1"), func(m Members) Members { rd = &reads{Members: m}; return rd })
	if rep, err := reseal(t, r, nil); err != nil || rep != (store.PinReseal{}) || rd.n != 0 {
		t.Fatalf("the pass: %+v, %d pin reads, %v", rep, rd.n, err)
	}
}

// A router with no directory of its own holds no pins: no pass, no count.
func TestARouterWithNoDirectoryHoldsNoPins(t *testing.T) {
	r := Wrap(Config{Session: memory.New(clock), Directory: memory.New(clock), Marks: store.NewMarks()}).(*placed)
	if rep, held, err := r.ResealPins(context.Background(), nil); held || err != nil || rep != (store.PinReseal{}) {
		t.Fatalf("held %v, %+v, %v", held, rep, err)
	}
}

// CAS: a pin another region wrote between the pass's read and its write
// stands, is counted as still under previous, and the next pass finds it
// current.
func TestTheReSealPassNeverOverwritesAPinChangedSinceItsRead(t *testing.T) {
	ctx := context.Background()
	dir := memory.New(clock)
	pinned(t, sealedRegion(dir, window("k1"), nil), pinFor(alice, "uuid:a"))
	other := sealedRegion(dir, window("k2", "k1"), nil)
	var rc *racing
	r := sealedRegion(dir, window("k2", "k1"), func(m Members) Members { rc = &racing{Members: m}; return rc })
	rc.during = func() { // a refusal keeps the entry and changes the pin
		refused := pinFor(alice, "uuid:a")
		refused.Refused, refused.VerifiedAt = true, t0.Add(time.Minute)
		if err := other.PutMembership(ctx, refused, time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	if rep, err := reseal(t, r, nil); err != nil || rep != (store.PinReseal{Previous: 1}) {
		t.Fatalf("the pass: %+v, %v (want the conflict counted under Previous)", rep, err)
	}
	got, err := crypt.Wrap(dir, window("k2"), nil).GetMembership(ctx, alice)
	if err != nil || !got.Refused {
		t.Fatalf("the other region's refusal was overwritten: %+v, %v", got, err)
	}
	if rep, err := reseal(t, r, nil); err != nil || rep != (store.PinReseal{}) {
		t.Fatalf("the next pass: %+v, %v", rep, err)
	}
}

// A pin under a key neither held is told, counted apart, and left exactly
// as it was: never rewritten, never deleted.
func TestTheReSealPassCountsAnUnopenablePinAndLeavesIt(t *testing.T) {
	ctx := context.Background()
	dir := memory.New(clock)
	if err := crypt.Wrap(dir, window("k0"), nil).PutPin(ctx, pinFor(alice, "uuid:a"), store.PinExpect{Absent: true}); err != nil {
		t.Fatal(err)
	}
	pinned(t, sealedRegion(dir, window("k1"), nil), pinFor(bob, "uuid:b"))
	var told []string
	rep, err := reseal(t, sealedRegion(dir, window("k2", "k1"), nil), func(p string, err error) {
		if !errors.Is(err, crypt.ErrUnknownKey) {
			t.Errorf("told %s with %v, want ErrUnknownKey", p, err)
		}
		told = append(told, p)
	})
	if err != nil || rep != (store.PinReseal{Sealed: 1, Unopened: 1}) || !slices.Equal(told, []string{alice}) {
		t.Fatalf("the pass: %+v, told %v, %v", rep, told, err)
	}
	if id := sealedUnder(t, dir, alice); id != "k0" {
		t.Fatalf("the unopenable pin was rewritten (now under %q)", id)
	}
}

// stopping is a directory whose pin reads stop answering after the first n.
type stopping struct {
	Members
	n int
}

func (s *stopping) GetMembership(ctx context.Context, p string) (store.Membership, error) {
	if s.n == 0 {
		return store.Membership{}, fmt.Errorf("%w: cut", store.ErrUnavailable)
	}
	s.n--
	return s.Members.GetMembership(ctx, p)
}

// A directory that stops answering mid-pass ends it with ErrUnavailable;
// the pins not reached are as they were and still open, and the next pass
// finishes. A directory known cut is not called at all. A ctx that ends
// mid-pass is the pass's error, never a nil one.
func TestADirectoryCutMidPassEndsItAndLeavesNothingHalfWritten(t *testing.T) {
	dir := memory.New(clock)
	pinned(t, sealedRegion(dir, window("k1"), nil), pinFor(alice, "uuid:a"), pinFor(bob, "uuid:b"))
	cut := sealedRegion(dir, window("k2", "k1"), func(m Members) Members { return &stopping{Members: m, n: 1} })
	rep, err := reseal(t, cut, nil)
	if !errors.Is(err, store.ErrUnavailable) || rep != (store.PinReseal{Sealed: 1}) {
		t.Fatalf("the cut pass: %+v, %v", rep, err)
	}
	if id := sealedUnder(t, dir, bob); id != "k1" {
		t.Fatalf("bob's pin, after the pass stopped before it, is under %q", id)
	}
	opens(t, dir, window("k2", "k1"), alice, bob)
	r := sealedRegion(dir, window("k2", "k1"), nil)
	r.c.Reachable = func() bool { return false }
	if _, err := reseal(t, r, nil); !errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("a pass with the directory known cut: %v", err)
	}
	r.c.Reachable = nil
	ctx, cancel := context.WithCancel(context.Background())
	var rc *racing
	ended := sealedRegion(dir, window("k2", "k1"), func(m Members) Members { rc = &racing{Members: m}; return rc })
	rc.during = cancel
	if rep, _, err := ended.ResealPins(ctx, nil); !errors.Is(err, context.Canceled) || rep != (store.PinReseal{}) {
		t.Fatalf("a pass whose ctx ended after a read that answered: %+v, %v, want context.Canceled and nothing counted", rep, err)
	}
	if id := sealedUnder(t, dir, bob); id != "k1" {
		t.Fatalf("bob's pin, read just before the ctx ended, was written (now under %q)", id)
	}
	if rep, err := reseal(t, r, nil); err != nil || rep != (store.PinReseal{Sealed: 1}) {
		t.Fatalf("the next pass: %+v, %v", rep, err)
	}
}

// Issue #52 end to end: rotate, pass, rotate again, pass; every pin opens
// under the last key alone.
func TestTwoRotationsWithAPassBetweenStrandNoPin(t *testing.T) {
	dir := memory.New(clock)
	pinned(t, sealedRegion(dir, window("k1"), nil), pinFor(alice, "uuid:a"), pinFor(bob, "uuid:b"))
	// First rotation, step 2 (k2, k1 previous), then the pass; step 3 drops k1.
	if rep, err := reseal(t, sealedRegion(dir, window("k2", "k1"), nil), nil); err != nil || rep.Sealed != 2 {
		t.Fatalf("the first rotation's pass: %+v, %v", rep, err)
	}
	opens(t, dir, window("k2"), alice, bob)
	// Second rotation, step 1 (k2, k3 previous): k1 is gone and nothing strands.
	opens(t, dir, window("k2", "k3"), alice, bob)
	// Step 2 (k3, k2 previous), the pass, then step 3 (k3 alone).
	if rep, err := reseal(t, sealedRegion(dir, window("k3", "k2"), nil), nil); err != nil || rep.Sealed != 2 {
		t.Fatalf("the second rotation's pass: %+v, %v", rep, err)
	}
	opens(t, dir, window("k3"), alice, bob)
}

// The control: with no pass, the second rotation's step 1 strands every pin
// (the bug #52 reports).
func TestWithoutThePassTheSecondRotationStrandsPins(t *testing.T) {
	ctx := context.Background()
	dir := memory.New(clock)
	pinned(t, sealedRegion(dir, window("k1"), nil), pinFor(alice, "uuid:a"))
	if _, err := crypt.Wrap(dir, window("k2", "k3"), nil).GetMembership(ctx, alice); !errors.Is(err, crypt.ErrUnknownKey) {
		t.Fatalf("a pin under k1 read under (k2, k3): %v, want ErrUnknownKey", err)
	}
}

// before is a directory that runs f once, ahead of its first pin read.
type before struct {
	Members
	f func()
}

func (b *before) GetMembership(ctx context.Context, p string) (store.Membership, error) {
	if f := b.f; f != nil {
		b.f = nil
		f()
	}
	return b.Members.GetMembership(ctx, p)
}

// A pin forgotten between the listing and the read is neither written nor
// counted as unopened: the tombstone stands.
func TestAPinForgottenSinceTheListingIsNeitherWrittenNorCounted(t *testing.T) {
	ctx := context.Background()
	dir := memory.New(clock)
	pinned(t, sealedRegion(dir, window("k1"), nil), pinFor(alice, "uuid:a"))
	var told []string
	var b *before
	r := sealedRegion(dir, window("k2", "k1"), func(m Members) Members { b = &before{Members: m}; return b })
	b.f = func() {
		if _, err := crypt.Wrap(dir, window("k2", "k1"), nil).DeleteMembership(ctx, alice); err != nil {
			t.Fatal(err)
		}
	}
	rep, err := reseal(t, r, func(p string, _ error) { told = append(told, p) })
	if err != nil || rep != (store.PinReseal{}) || len(told) != 0 {
		t.Fatalf("the pass: %+v, told %v, %v", rep, told, err)
	}
	if _, err := dir.GetMembership(ctx, alice); !errors.Is(err, store.ErrForgotten) {
		t.Fatalf("the forgotten pin's record after the pass: %v, want the tombstone", err)
	}
}

// refusing is a directory whose pin reads are refused this identity.
type refusing struct{ Members }

func (refusing) GetMembership(context.Context, string) (store.Membership, error) {
	return store.Membership{}, fmt.Errorf("%w: role revoked", store.ErrRefused)
}

// A directory that refuses the broker's identity mid-pass is the pass's
// error, not "opens under neither key": nothing is told, counted or written.
func TestARefusedPinReadEndsThePassAndIsNotCountedUnopened(t *testing.T) {
	dir := memory.New(clock)
	pinned(t, sealedRegion(dir, window("k1"), nil), pinFor(alice, "uuid:a"))
	var told []string
	r := sealedRegion(dir, window("k2", "k1"), func(m Members) Members { return refusing{m} })
	rep, err := reseal(t, r, func(p string, _ error) { told = append(told, p) })
	if !errors.Is(err, store.ErrRefused) || rep != (store.PinReseal{}) || len(told) != 0 {
		t.Fatalf("the pass: %+v, told %v, %v, want ErrRefused and nothing counted", rep, told, err)
	}
	if id := sealedUnder(t, dir, alice); id != "k1" {
		t.Fatalf("alice's pin is under %q after a refused pass", id)
	}
}
