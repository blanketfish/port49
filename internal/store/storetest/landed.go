package storetest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/store"
)

// Processes is two store.Store over one keyspace, as two port49-broker
// processes see it: a lift's record one writes is the other's to compare.
type Processes func(t *testing.T) (a, b store.Store)

// LandedAfterLift is the landed-after-lift flag (spec §13 decision 51, the
// cache), on a backend that keeps a lift's record (etcd; the memory store
// keeps none, MemoryKeepsNoLiftRecord). A mark created over a lift recorded
// above its writer's floor (store.WithMarkFloor) lands flagged, and one at
// or above it, or with no lift recorded, lands unflagged; either way it
// always lands, and a put on a standing mark changes nothing. A process's
// own lift of a key raises its floor for that key alone (final check
// F-I2): another process's lift of another key its feed has not delivered
// still flags. now is the time each lift and mark is made at.
func LandedAfterLift(t *testing.T, procs Processes, now time.Time) {
	t.Helper()
	ctx := context.Background()
	a, b := procs(t)
	mark := func(key string, at time.Time) store.Revocation {
		return store.Revocation{Kind: store.RevocationPrincipal, Key: key, At: at, Origin: "offline uid 0"}
	}
	lift := store.Lift{At: now, Origin: "offline uid 1000"}
	put := func(s store.Store, r store.Revocation, floor uint64) store.Revocation {
		t.Helper()
		if err := s.PutRevocation(store.WithMarkFloor(ctx, floor), r); err != nil {
			t.Fatalf("the put of %s: %v", r.Key, err)
		}
		got, err := s.GetRevocation(ctx, r.Kind, r.Key)
		if err != nil {
			t.Fatalf("the mark always lands: %s: %v", r.Key, err)
		}
		return got
	}
	lifted := func(s store.Store, key string) store.Lift {
		t.Helper()
		if err := s.DeleteRevocation(ctx, store.RevocationPrincipal, key, lift); err != nil {
			t.Fatalf("the lift of %s: %v", key, err)
		}
		l, err := s.GetLift(ctx, store.RevocationPrincipal, key)
		if err != nil || !l.At.Equal(lift.At) || l.Origin != lift.Origin || l.Revision == 0 {
			t.Fatalf("the lift's record of %s: %+v %v", key, l, err)
		}
		return l
	}

	if _, err := b.GetLift(ctx, store.RevocationPrincipal, "user:never@example.com"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a key never lifted has a lift's record: %v", err)
	}
	// Flag set: a writer whose floor is below another process's lift.
	alice := "user:alice@example.com"
	put(a, mark(alice, now.Add(-time.Hour)), 0)
	l := lifted(a, alice)
	if got := put(b, mark(alice, now.Add(-time.Minute)), l.Revision-1); !got.LandedAfterLift {
		t.Fatalf("a mark created over a lift above its writer's floor is not flagged: %+v", got)
	}
	// A put on the standing mark changes nothing: it keeps its time, its
	// origin and its flag.
	again := mark(alice, now.Add(time.Hour))
	again.Origin = "api user:carol@example.com"
	if got := put(a, again, 0); !got.LandedAfterLift || !got.At.Equal(now.Add(-time.Minute)) ||
		got.Origin != "offline uid 0" {
		t.Fatalf("a put on a standing mark changed it: %+v", got)
	}
	// Flag clear: the writer's floor is at the lift.
	bob := "user:bob@example.com"
	put(a, mark(bob, now.Add(-time.Hour)), 0)
	l = lifted(a, bob)
	if got := put(b, mark(bob, now), l.Revision); got.LandedAfterLift {
		t.Fatalf("a mark whose writer's floor is at the lift is flagged: %+v", got)
	}
	// ... and a standing unflagged mark stays so, whatever floor a repeat
	// carries.
	if got := put(b, mark(bob, now.Add(time.Hour)), 0); got.LandedAfterLift {
		t.Fatalf("a repeat put flagged a standing mark: %+v", got)
	}
	// Flag clear: no lift recorded, even with no floor at all.
	if got := put(b, mark("user:dan@example.com", now), 0); got.LandedAfterLift {
		t.Fatalf("a mark with no lift recorded is flagged: %+v", got)
	}

	// A process's own lift, then its own revoke before its feed has
	// delivered the lift (floor 0): not flagged (re-review R-I1).
	carol := "user:carol@example.com"
	put(b, mark(carol, now.Add(-time.Hour)), 0)
	lifted(a, carol)
	if got := put(a, mark(carol, now.Add(time.Minute)), 0); got.LandedAfterLift {
		t.Fatalf("a process's own lift flagged its own later revoke: %+v", got)
	}
	// ... and the other process, its feed behind, is flagged for it.
	lifted(b, carol)
	if got := put(a, mark(carol, now.Add(2*time.Minute)), 0); !got.LandedAfterLift {
		t.Fatalf("a revoke over another process's lift, undelivered, is not flagged: %+v", got)
	}

	// Per key, not process-wide (final check F-I2): b lifts erin and a's
	// feed has not delivered it; a then lifts frank, at a later revision,
	// and revokes erin: flagged.
	erin, frank := "user:erin@example.com", "user:frank@example.com"
	put(a, mark(erin, now.Add(-time.Hour)), 0)
	put(a, mark(frank, now.Add(-time.Hour)), 0)
	le := lifted(b, erin)
	lf := lifted(a, frank)
	if lf.Revision <= le.Revision {
		t.Fatalf("frank's lift at %d is not after erin's at %d", lf.Revision, le.Revision)
	}
	if got := put(a, mark(erin, now.Add(time.Minute)), 0); !got.LandedAfterLift {
		t.Fatalf("a process's own lift of one key hid another process's lift of another: %+v", got)
	}
	if got := put(a, mark(frank, now.Add(time.Minute)), 0); got.LandedAfterLift {
		t.Fatalf("a process's own lift flagged its own later revoke: %+v", got)
	}
	// The list carries the flag.
	list, err := b.ListRevocations(ctx)
	if err != nil {
		t.Fatal(err)
	}
	flagged := map[string]bool{}
	for _, r := range list {
		flagged[r.Key] = r.LandedAfterLift
	}
	if !flagged[alice] || flagged[bob] || !flagged[carol] || !flagged[erin] || flagged[frank] {
		t.Fatalf("the list's flags: %v", flagged)
	}
}

// MemoryKeepsNoLiftRecord is the memory store's side of the flag (final
// check F-M1): one process is the whole store, so no mark can land over a
// lift its writer had not seen. A lift writes no record, and a revoke
// within LiftTTL of it, with no floor at all, is not flagged.
func MemoryKeepsNoLiftRecord(t *testing.T, s store.Store, now time.Time) {
	t.Helper()
	ctx := context.Background()
	r := store.Revocation{Kind: store.RevocationPrincipal, Key: "user:alice@example.com", At: now}
	if err := s.PutRevocation(ctx, r); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteRevocation(ctx, r.Kind, r.Key, store.Lift{At: now, Origin: "offline uid 0"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetLift(ctx, r.Kind, r.Key); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the memory store kept a lift's record: %v", err)
	}
	r.At = now.Add(time.Minute)
	if err := s.PutRevocation(ctx, r); err != nil {
		t.Fatal(err)
	}
	if got, err := s.GetRevocation(ctx, r.Kind, r.Key); err != nil || got.LandedAfterLift {
		t.Fatalf("the memory store flagged a revoke after a lift: %+v %v", got, err)
	}
}
