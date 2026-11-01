package memory

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/blanketfish/port49/internal/store"
)

// enrollments is store.Enrollments in memory (plan 9e): for tests, and the
// sealing layer's reference. It keeps what it is given, so a store with no
// sealing layer over it holds a secret in the clear.
type enrollments struct {
	now     func() time.Time
	mu      sync.Mutex
	mark    *store.EnrollmentMark
	records map[string]store.SecondFactor
	unlocks map[string]time.Time
	seq     uint64 // the last revision handed out
}

// errNoMarkTime is a mark with no creation time, which an export would emit
// and an import refuse: every backend refuses it at the write.
var errNoMarkTime = errors.New("memory: a mark needs its creation time")

// NewEnrollments is an empty enrollment store: no mark, no records.
func NewEnrollments(now func() time.Time) store.Enrollments {
	return &enrollments{now: now, records: map[string]store.SecondFactor{}, unlocks: map[string]time.Time{}}
}

func (e *enrollments) GetSecondFactor(_ context.Context, principal string) (store.SecondFactor, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	f, ok := e.records[principal]
	if !ok {
		return store.SecondFactor{}, store.ErrNotFound
	}
	return cloneFactor(f), nil
}

func (e *enrollments) SwapSecondFactor(_ context.Context, f store.SecondFactor, rev uint64) error {
	if f.Principal == "" {
		return store.ErrNoPrincipal
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	cur, ok := e.records[f.Principal]
	if rev == 0 && ok || rev != 0 && (!ok || cur.Rev != rev) {
		return store.ErrConflict
	}
	e.seq++
	f.Rev, f.Stale = e.seq, false
	e.records[f.Principal] = cloneFactor(f)
	return nil
}

func (e *enrollments) SecondFactorPrincipals(context.Context) ([]string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]string, 0, len(e.records))
	for p := range e.records {
		out = append(out, p)
	}
	slices.Sort(out)
	return out, nil
}

func (e *enrollments) GetEnrollmentMark(context.Context) (store.EnrollmentMark, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.mark == nil {
		return store.EnrollmentMark{}, store.ErrNotFound
	}
	m := *e.mark
	m.Sealed = slices.Clone(m.Sealed)
	return m, nil
}

func (e *enrollments) CreateEnrollmentMark(_ context.Context, m store.EnrollmentMark) error {
	if m.CreatedAt.IsZero() {
		return errNoMarkTime
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.mark != nil || len(e.records) > 0 {
		return store.ErrConflict
	}
	e.setMark(m)
	return nil
}

func (e *enrollments) PutEnrollmentMark(_ context.Context, m store.EnrollmentMark) error {
	if m.CreatedAt.IsZero() {
		return errNoMarkTime
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.setMark(m)
	return nil
}

func (e *enrollments) SwapEnrollmentMark(_ context.Context, m store.EnrollmentMark, rev uint64) error {
	if m.CreatedAt.IsZero() {
		return errNoMarkTime
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.mark == nil || rev == 0 || e.mark.Rev != rev {
		return store.ErrConflict
	}
	e.setMark(m)
	return nil
}

// setMark keeps m, at a fresh revision, with its own copy of Sealed. The
// caller holds e.mu.
func (e *enrollments) setMark(m store.EnrollmentMark) {
	e.seq++
	m.Rev, m.Stale, m.Sealed = e.seq, false, slices.Clone(m.Sealed)
	e.mark = &m
}

func (e *enrollments) Export(context.Context) ([]byte, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.mark == nil {
		return nil, errors.New("memory: the enrollment store has no mark to export")
	}
	b := store.EnrollmentBody{CreatedAt: e.mark.CreatedAt, ReopenAllUntil: e.mark.ReopenAllUntil,
		MarkSealed: e.mark.Sealed, ExportedAt: e.now().UTC(), SecondFactors: make(map[string]store.EnrollmentRecord, len(e.records))}
	for p, f := range e.records {
		b.SecondFactors[p] = store.RecordOf(f)
	}
	return json.Marshal(b)
}

func (e *enrollments) Import(_ context.Context, raw []byte, replace bool) (int, time.Time, error) {
	var b store.EnrollmentBody
	if err := json.Unmarshal(raw, &b); err != nil { // the decoder's text quotes its input: never wrapped
		return 0, time.Time{}, errors.New("memory: the export does not decode")
	}
	if b.CreatedAt.IsZero() || b.ExportedAt.IsZero() {
		return 0, time.Time{}, errors.New("memory: the export holds no creation mark or no export time")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if !replace {
		for _, f := range e.records {
			if store.EnrolledAfter(store.RecordOf(f), b.ExportedAt) {
				return 0, time.Time{}, store.ErrConflict
			}
		}
	}
	next := make(map[string]store.SecondFactor, len(b.SecondFactors))
	for p, r := range b.SecondFactors {
		e.seq++ // a fresh revision: no reader's old one matches an imported record
		f := store.SecondFactorOf(p, r)
		f.Rev = e.seq
		next[p] = f
	}
	e.records = next
	e.setMark(store.EnrollmentMark{CreatedAt: b.CreatedAt, ReopenAllUntil: b.ReopenAllUntil, Sealed: b.MarkSealed})
	return len(next), b.ExportedAt, nil
}

func cloneFactor(f store.SecondFactor) store.SecondFactor {
	f.Secret, f.Sealed = slices.Clone(f.Secret), slices.Clone(f.Sealed)
	return f
}

func (e *enrollments) GetUnlock(_ context.Context, principal string) (time.Time, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	at, ok := e.unlocks[principal]
	if !ok {
		return time.Time{}, store.ErrNotFound
	}
	return at, nil
}

func (e *enrollments) PutUnlock(_ context.Context, principal string, at time.Time) error {
	switch {
	case principal == "":
		return store.ErrNoPrincipal
	case at.IsZero():
		return store.ErrBadUnlock
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if cur, ok := e.unlocks[principal]; ok && !at.After(cur) {
		at = cur.Add(time.Nanosecond)
	}
	e.unlocks[principal] = at.UTC()
	return nil
}
