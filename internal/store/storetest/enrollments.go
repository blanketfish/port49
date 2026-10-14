package storetest

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/store"
)

// EnrollmentsBackend is a store.Enrollments implementation the enrollment
// properties run against; New returns a fresh, empty one. Sealed says its
// Export is sealed (the crypt layer over it), so the clear-text check runs.
type EnrollmentsBackend struct {
	New    func(t *testing.T, clock func() time.Time) store.Enrollments
	Sealed bool
	// NewBelow, set for a backend with a sealing layer, returns a fresh
	// store and the store beneath its sealing layer, where a test writes as
	// a store writer would. SecondFactorClearCopiesAreChecked runs when set.
	NewBelow func(t *testing.T, clock func() time.Time) (above, below store.Enrollments)
}

// RunEnrollments runs every enrollment property against b.
func RunEnrollments(t *testing.T, b EnrollmentsBackend) {
	for _, p := range []struct {
		name string
		f    func(*testing.T, EnrollmentsBackend)
	}{
		{"SecondFactorSwapsByRevision", SecondFactorSwapsByRevision},
		{"EnrollmentMarkIsKept", EnrollmentMarkIsKept},
		{"EnrollmentMarkIsCreatedOnce", EnrollmentMarkIsCreatedOnce},
		{"ExportImportRoundTrips", ExportImportRoundTrips},
		{"SecondFactorClearCopiesAreChecked", SecondFactorClearCopiesAreChecked},
		{"EnrollmentMarkClearCopiesAreChecked", EnrollmentMarkClearCopiesAreChecked},
		{"EnrollmentMarkNeedsItsTime", EnrollmentMarkNeedsItsTime},
		{"ImportRefusesWhatDoesNotDecodeWithoutEchoingIt", ImportRefusesWhatDoesNotDecodeWithoutEchoingIt},
	} {
		t.Run(p.name, func(t *testing.T) { p.f(t, b) })
	}
}

// EnrollmentMarkIsKept: none is ErrNotFound; a put reads back; a second
// put replaces it whole.
func EnrollmentMarkIsKept(t *testing.T, b EnrollmentsBackend) {
	ctx := context.Background()
	e := b.New(t, func() time.Time { return t0 })
	if _, err := e.GetEnrollmentMark(ctx); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a new store has a mark: %v", err)
	}
	m := store.EnrollmentMark{CreatedAt: t0}
	if err := e.PutEnrollmentMark(ctx, m); err != nil {
		t.Fatal(err)
	}
	if got, err := e.GetEnrollmentMark(ctx); err != nil || !got.CreatedAt.Equal(t0) || !got.ReopenAllUntil.IsZero() {
		t.Fatalf("%+v %v", got, err)
	}
	m.ReopenAllUntil = t0.Add(24 * time.Hour)
	if err := e.PutEnrollmentMark(ctx, m); err != nil {
		t.Fatal(err)
	}
	if got, _ := e.GetEnrollmentMark(ctx); !got.ReopenAllUntil.Equal(t0.Add(24 * time.Hour)) {
		t.Fatalf("not replaced: %+v", got)
	}
}

// EnrollmentMarkIsCreatedOnce: CreateEnrollmentMark writes on an empty
// store alone; a second is ErrConflict and changes nothing; a store holding
// a record and no mark is ErrConflict too (init-enrollments never papers
// over a store that lost its mark, D7).
func EnrollmentMarkIsCreatedOnce(t *testing.T, b EnrollmentsBackend) {
	ctx := context.Background()
	e := b.New(t, func() time.Time { return t0 })
	if err := e.CreateEnrollmentMark(ctx, store.EnrollmentMark{CreatedAt: t0}); err != nil {
		t.Fatal(err)
	}
	if err := e.CreateEnrollmentMark(ctx, store.EnrollmentMark{CreatedAt: t0.Add(time.Hour)}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("a second create: %v", err)
	}
	if got, _ := e.GetEnrollmentMark(ctx); !got.CreatedAt.Equal(t0) {
		t.Fatalf("the refused create wrote: %+v", got)
	}
	r := b.New(t, func() time.Time { return t0 })
	if err := r.SwapSecondFactor(ctx, store.SecondFactor{Principal: "user:alice@example.com",
		State: store.SecondFactorActive, EntryID: "uuid:1", Secret: []byte("01234567890123456789")}, 0); err != nil {
		t.Fatal(err)
	}
	if err := r.CreateEnrollmentMark(ctx, store.EnrollmentMark{CreatedAt: t0}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("a create over records with no mark: %v", err)
	}
}

// ExportImportRoundTrips: an export imports into an empty store whole; into
// a store holding a later enrollment it is ErrConflict and writes nothing,
// unless replace (D13).
func ExportImportRoundTrips(t *testing.T, b EnrollmentsBackend) {
	ctx := context.Background()
	var mu sync.Mutex
	now := t0
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	src := b.New(t, clock)
	_ = src.PutEnrollmentMark(ctx, store.EnrollmentMark{CreatedAt: t0})
	f := store.SecondFactor{Principal: "user:alice@example.com", State: store.SecondFactorActive, EntryID: "uuid:1",
		Secret: []byte("01234567890123456789"), EnrolledAt: t0, EnrolledFrom: "192.0.2.0/32", LastStep: 7}
	if err := src.SwapSecondFactor(ctx, f, 0); err != nil {
		t.Fatal(err)
	}
	exp, err := src.Export(ctx)
	if err != nil || b.Sealed && (strings.Contains(string(exp), "01234567890123456789") || strings.Contains(string(exp), "uuid:1")) {
		t.Fatalf("an export in the clear, or %v", err)
	}
	dst := b.New(t, clock)
	if n, at, err := dst.Import(ctx, exp, false); err != nil || n != 1 || !at.Equal(t0) {
		t.Fatalf("%d %s %v", n, at, err)
	}
	if got, err := dst.GetSecondFactor(ctx, f.Principal); err != nil || string(got.Secret) != string(f.Secret) ||
		got.LastStep != 7 {
		t.Fatalf("the imported record: step %d, %v", got.LastStep, err) // never the secret
	}
	mu.Lock()
	now = t0.Add(time.Hour)
	mu.Unlock()
	later := f
	later.Principal, later.EnrolledAt = "user:bob@example.com", t0.Add(time.Hour)
	if err := dst.SwapSecondFactor(ctx, later, 0); err != nil {
		t.Fatal(err)
	}
	if _, _, err := dst.Import(ctx, exp, false); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("an older export over a later enrollment: %v", err)
	}
	if _, err := dst.GetSecondFactor(ctx, later.Principal); err != nil {
		t.Fatalf("the refused import wrote: %v", err)
	}
	if _, _, err := dst.Import(ctx, exp, true); err != nil {
		t.Fatal(err)
	}
	if _, err := dst.GetSecondFactor(ctx, later.Principal); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("--replace kept a record the export does not hold: %v", err)
	}
}

// EnrollmentMarkNeedsItsTime: a mark with no creation time is refused by
// Put and by Create, not written to be refused by the import of its own
// export (review M5).
func EnrollmentMarkNeedsItsTime(t *testing.T, b EnrollmentsBackend) {
	ctx := context.Background()
	e := b.New(t, func() time.Time { return t0 })
	if err := e.PutEnrollmentMark(ctx, store.EnrollmentMark{}); err == nil {
		t.Fatal("a mark with no time was put")
	}
	if err := e.CreateEnrollmentMark(ctx, store.EnrollmentMark{}); err == nil || errors.Is(err, store.ErrConflict) {
		t.Fatalf("a mark with no time was created, or read as a conflict: %v", err)
	}
	if _, err := e.GetEnrollmentMark(ctx); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a refused mark was written: %v", err)
	}
}

// ImportRefusesWhatDoesNotDecodeWithoutEchoingIt: the JSON decoder's text
// quotes its input, and an unvalidated body is never in an error (review M1).
func ImportRefusesWhatDoesNotDecodeWithoutEchoingIt(t *testing.T, b EnrollmentsBackend) {
	e := b.New(t, func() time.Time { return t0 })
	_, _, err := e.Import(context.Background(), []byte(`{"created_at": "SENTINEL-INPUT", "second_factors": 7}`), false)
	if err == nil || strings.Contains(err.Error(), "SENTINEL-INPUT") {
		t.Fatalf("an undecodable import: %v", err)
	}
}

// SecondFactorClearCopiesAreChecked: state, enrolled_at, last_step and until
// are sealed with the secret; a store writer who changes the clear copy of
// any one gets an error, never a record and never ErrNotFound, which would
// read as not enrolled (D7; review C1).
func SecondFactorClearCopiesAreChecked(t *testing.T, b EnrollmentsBackend) {
	if b.NewBelow == nil {
		t.Skip("no sealing layer to test")
	}
	for _, c := range []struct {
		field  string
		tamper func(f *store.SecondFactor)
	}{
		{"last_step", func(f *store.SecondFactor) { f.LastStep = 1 }},
		{"state", func(f *store.SecondFactor) { f.State, f.Until = store.SecondFactorReopened, t0.Add(24*time.Hour) }},
		{"state_alone", func(f *store.SecondFactor) { f.State = store.SecondFactorPending }},
		{"enrolled_at", func(f *store.SecondFactor) { f.EnrolledAt = f.EnrolledAt.Add(time.Hour) }},
		{"until", func(f *store.SecondFactor) { f.Until = f.Until.Add(24 * time.Hour) }},
	} {
		t.Run(c.field, func(t *testing.T) {
			ctx := context.Background()
			above, below := b.NewBelow(t, func() time.Time { return t0 })
			const p = "user:alice@example.com"
			f := store.SecondFactor{Principal: p, State: store.SecondFactorActive, EntryID: "uuid:1",
				Secret: []byte("01234567890123456789"), EnrolledAt: t0, EnrolledFrom: "192.0.2.0/32", LastStep: 42,
				Until: t0.Add(time.Hour)}
			if err := above.SwapSecondFactor(ctx, f, 0); err != nil {
				t.Fatal(err)
			}
			if got, err := above.GetSecondFactor(ctx, p); err != nil || got.LastStep != 42 {
				t.Fatalf("the untouched record: step %d, %v", got.LastStep, err)
			}
			raw, err := below.GetSecondFactor(ctx, p)
			if err != nil {
				t.Fatal(err)
			}
			c.tamper(&raw)
			if err := below.SwapSecondFactor(ctx, raw, raw.Rev); err != nil {
				t.Fatal(err)
			}
			if _, err := above.GetSecondFactor(ctx, p); err == nil || errors.Is(err, store.ErrNotFound) {
				t.Fatalf("a record whose clear %s was changed read as %v", c.field, err)
			}
		})
	}
}

// EnrollmentMarkClearCopiesAreChecked: created_at and reopen_all_until are
// sealed; a store writer who changes the clear copy of either, or writes a
// mark with no sealed part, gets a lost store: never a mark, and never
// ErrNotFound (D7; review X1: a raised reopen_all_until would open
// enrollment for every principal).
func EnrollmentMarkClearCopiesAreChecked(t *testing.T, b EnrollmentsBackend) {
	if b.NewBelow == nil {
		t.Skip("no sealing layer to test")
	}
	for _, c := range []struct {
		field  string
		tamper func(m *store.EnrollmentMark)
	}{
		{"reopen_all_until", func(m *store.EnrollmentMark) { m.ReopenAllUntil = t0.Add(24 * time.Hour) }},
		{"reopen_all_until_lowered", func(m *store.EnrollmentMark) { m.ReopenAllUntil = t0 }},
		{"created_at", func(m *store.EnrollmentMark) { m.CreatedAt = m.CreatedAt.Add(-time.Hour) }},
		{"sealed_part_absent", func(m *store.EnrollmentMark) { m.Sealed = nil }},
	} {
		t.Run(c.field, func(t *testing.T) {
			ctx := context.Background()
			above, below := b.NewBelow(t, func() time.Time { return t0 })
			if err := above.PutEnrollmentMark(ctx, store.EnrollmentMark{CreatedAt: t0, ReopenAllUntil: t0.Add(time.Hour)}); err != nil {
				t.Fatal(err)
			}
			if got, err := above.GetEnrollmentMark(ctx); err != nil || !got.ReopenAllUntil.Equal(t0.Add(time.Hour)) {
				t.Fatalf("the untouched mark: %+v, %v", got, err)
			}
			raw, err := below.GetEnrollmentMark(ctx)
			if err != nil {
				t.Fatal(err)
			}
			c.tamper(&raw)
			if err := below.PutEnrollmentMark(ctx, raw); err != nil {
				t.Fatal(err)
			}
			got, err := above.GetEnrollmentMark(ctx)
			if !errors.Is(err, store.ErrEnrollmentStoreLost) || errors.Is(err, store.ErrNotFound) {
				t.Fatalf("a mark whose clear %s was changed read as %+v, %v", c.field, got, err)
			}
		})
	}
}

// SecondFactorSwapsByRevision: a record is written only where none is, then
// only at the revision read; a stale revision writes nothing (plan 9e, Task 4).
func SecondFactorSwapsByRevision(t *testing.T, b EnrollmentsBackend) {
	ctx := context.Background()
	s := b.New(t, func() time.Time { return t0 })
	const p = "user:alice@example.com"
	if _, err := s.GetSecondFactor(ctx, p); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("none written: %v", err)
	}
	f := store.SecondFactor{Principal: p, State: store.SecondFactorPending, EntryID: "uuid:1",
		Secret: []byte("01234567890123456789"), Until: t0.Add(10 * time.Minute)}
	if err := s.SwapSecondFactor(ctx, f, 0); err != nil {
		t.Fatal(err)
	}
	if err := s.SwapSecondFactor(ctx, f, 0); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("a second first write: %v", err)
	}
	got, err := s.GetSecondFactor(ctx, p)
	if err != nil || got.State != store.SecondFactorPending || string(got.Secret) != string(f.Secret) ||
		got.EntryID != "uuid:1" || got.Rev == 0 {
		t.Fatalf("the record read back: state %q, rev %d, %v", got.State, got.Rev, err) // never the secret
	}
	active := got
	active.State, active.LastStep = store.SecondFactorActive, 42
	if err := s.SwapSecondFactor(ctx, active, got.Rev); err != nil {
		t.Fatal(err)
	}
	if err := s.SwapSecondFactor(ctx, active, got.Rev); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("a stale revision: %v", err)
	}
	if ps, err := s.SecondFactorPrincipals(ctx); err != nil || len(ps) != 1 || ps[0] != p {
		t.Fatalf("%v %v", ps, err)
	}
}
