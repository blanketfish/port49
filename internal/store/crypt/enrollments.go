package crypt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/rhwendt/port49/internal/store"
)

// secondFactorSecret is a second factor's sealed part, bound to its
// principal: the secret, the entry it was enrolled for, where from, and
// every field a sign-in trusts: its state, when it was enrolled, the used
// step and the window's end. The clear copies stay in the record, for the
// store's own import check, and a read refuses a record whose copy differs
// from the sealed one: a store writer who lowers last_step or reopens a
// record is not obeyed (D7, review C1).
type secondFactorSecret struct {
	V            int       `json:"v"`
	Secret       []byte    `json:"secret"`
	EntryID      string    `json:"entry_id"`
	EnrolledFrom string    `json:"enrolled_from"`
	State        string    `json:"state"`
	EnrolledAt   time.Time `json:"enrolled_at"`
	LastStep     int64     `json:"last_step"`
	Until        time.Time `json:"until"`
}

const secondFactorForm = 1

var (
	errSecondFactorMoved = errors.New("crypt: a second factor's plaintext state, enrolment time, used step or " +
		"window differs from its sealed one")
	errSecondFactorForm = errors.New("crypt: a second factor's sealed part is of a form this broker does not read")
	errSecondFactorBody = errors.New("crypt: a second factor's sealed part does not decode")
)

func secondFactorAAD(principal string) []byte { return []byte("second_factor\x00" + principal) }

// exportAAD is what an enrollment export is sealed bound to, so a sealed
// record of another kind is never read as one.
var exportAAD = []byte("enrollments_export")

// exportVersion is the export envelope's port49_enrollments member, the
// shape the enrollment file's envelope has.
const exportVersion = 1

type exportEnvelope struct {
	Version int    `json:"port49_enrollments"`
	KeyID   string `json:"key_id"`
	Sealed  []byte `json:"sealed"`
}

type wrappedEnrollments struct {
	store.Enrollments // SecondFactorPrincipals passes through
	w                 *wrapped
}

// WrapEnrollments decorates inner so a second factor's secret, entry id and
// source are sealed under k before they reach the backend (plan 9e, D7),
// bound to the principal, and an export is sealed whole (D13). openFailures
// may be nil.
func WrapEnrollments(inner store.Enrollments, k Keys, openFailures *prometheus.CounterVec, opts ...Option) store.Enrollments {
	w := &wrapped{keys: k, openFailures: openFailures}
	for _, o := range opts {
		o(w)
	}
	return &wrappedEnrollments{Enrollments: inner, w: w}
}

func (e *wrappedEnrollments) SwapSecondFactor(ctx context.Context, f store.SecondFactor, rev uint64) error {
	b, err := json.Marshal(secondFactorSecret{V: secondFactorForm, Secret: f.Secret, EntryID: f.EntryID,
		EnrolledFrom: f.EnrolledFrom, State: f.State, EnrolledAt: f.EnrolledAt, LastStep: f.LastStep, Until: f.Until})
	if err != nil {
		return err
	}
	sealed, err := e.w.keys.SealBound(b, secondFactorAAD(f.Principal))
	if err != nil {
		return err
	}
	f.Secret, f.EntryID, f.EnrolledFrom, f.Sealed, f.Stale = nil, "", "", sealed, false
	return e.Enrollments.SwapSecondFactor(ctx, f, rev)
}

// GetSecondFactor opens the record with the principal asked for, not the
// one the record names: a record a store writer copied under another
// principal fails to open there. A record that will not open is an error,
// never store.ErrNotFound: not enrolled would reopen enrollment (D7).
func (e *wrappedEnrollments) GetSecondFactor(ctx context.Context, principal string) (store.SecondFactor, error) {
	f, err := e.Enrollments.GetSecondFactor(ctx, principal)
	if err != nil {
		return store.SecondFactor{}, err
	}
	f.Principal = principal
	b, err := e.w.keys.OpenBound(f.Sealed, secondFactorAAD(principal))
	if err != nil {
		return store.SecondFactor{}, e.w.openErr("second factor", f.Sealed, err)
	}
	var s secondFactorSecret
	if err := json.Unmarshal(b, &s); err != nil {
		return store.SecondFactor{}, e.w.openErr("second factor", f.Sealed, errSecondFactorBody)
	}
	switch {
	case s.V != secondFactorForm:
		return store.SecondFactor{}, e.w.openErr("second factor", f.Sealed, errSecondFactorForm)
	case s.State != f.State || !s.EnrolledAt.Equal(f.EnrolledAt) || s.LastStep != f.LastStep || !s.Until.Equal(f.Until):
		return store.SecondFactor{}, e.w.openErr("second factor", f.Sealed, errSecondFactorMoved)
	}
	k := e.w.keys
	f.Stale = k.Previous != nil && SealedKeyID(f.Sealed) == LineKeyID(k.Previous.ID)
	f.Secret, f.EntryID, f.EnrolledFrom, f.Sealed = s.Secret, s.EntryID, s.EnrolledFrom, nil
	return f, nil
}

// enrollmentMarkSecret is the mark's sealed copy of what a sign-in trusts of
// it: its creation time and the window --all opened. A writer to the mark who
// raises reopen_all_until would open enrollment for every principal, so a
// read refuses a mark whose clear times differ from the sealed ones (X1).
type enrollmentMarkSecret struct {
	V              int       `json:"v"`
	CreatedAt      time.Time `json:"created_at"`
	ReopenAllUntil time.Time `json:"reopen_all_until"`
}

const enrollmentMarkForm = 1

var (
	errEnrollmentMarkMoved = errors.New("crypt: the enrollment mark's plaintext creation time or reopen window " +
		"differs from its sealed one")
	errEnrollmentMarkForm = errors.New("crypt: the enrollment mark's sealed part is of a form this broker does not read")
	errEnrollmentMarkBody = errors.New("crypt: the enrollment mark's sealed part does not decode")
)

var enrollmentMarkAAD = []byte("enrollment_mark")

func (e *wrappedEnrollments) sealMark(m store.EnrollmentMark) (store.EnrollmentMark, error) {
	b, err := json.Marshal(enrollmentMarkSecret{V: enrollmentMarkForm, CreatedAt: m.CreatedAt, ReopenAllUntil: m.ReopenAllUntil})
	if err != nil {
		return m, err
	}
	m.Sealed, err = e.w.keys.SealBound(b, enrollmentMarkAAD)
	return m, err
}

func (e *wrappedEnrollments) CreateEnrollmentMark(ctx context.Context, m store.EnrollmentMark) error {
	m, err := e.sealMark(m)
	if err != nil {
		return err
	}
	return e.Enrollments.CreateEnrollmentMark(ctx, m)
}

func (e *wrappedEnrollments) PutEnrollmentMark(ctx context.Context, m store.EnrollmentMark) error {
	m, err := e.sealMark(m)
	if err != nil {
		return err
	}
	return e.Enrollments.PutEnrollmentMark(ctx, m)
}

// GetEnrollmentMark opens the mark and refuses one whose clear times differ
// from the sealed ones. A mark that will not open is never store.ErrNotFound
// and is never a valid mark: it is store.ErrEnrollmentStoreLost, wrapping why
// (D7), so password sign-in fails closed and the rest serves.
func (e *wrappedEnrollments) GetEnrollmentMark(ctx context.Context) (store.EnrollmentMark, error) {
	m, err := e.Enrollments.GetEnrollmentMark(ctx)
	if err != nil {
		return store.EnrollmentMark{}, err
	}
	lost := func(err error) error {
		return fmt.Errorf("%w: %w", store.ErrEnrollmentStoreLost, e.w.openErr("enrollment mark", m.Sealed, err))
	}
	b, err := e.w.keys.OpenBound(m.Sealed, enrollmentMarkAAD)
	if err != nil {
		return store.EnrollmentMark{}, lost(err)
	}
	var s enrollmentMarkSecret
	if err := json.Unmarshal(b, &s); err != nil {
		return store.EnrollmentMark{}, lost(errEnrollmentMarkBody)
	}
	switch {
	case s.V != enrollmentMarkForm:
		return store.EnrollmentMark{}, lost(errEnrollmentMarkForm)
	case !s.CreatedAt.Equal(m.CreatedAt) || !s.ReopenAllUntil.Equal(m.ReopenAllUntil):
		return store.EnrollmentMark{}, lost(errEnrollmentMarkMoved)
	}
	// Stale, as a record's is: opened under the previous key, so the
	// scheduled pass seals it again before encryption.previous is retired.
	k := e.w.keys
	m.Stale = k.Previous != nil && SealedKeyID(m.Sealed) == LineKeyID(k.Previous.ID)
	m.Sealed = nil
	return m, nil
}

// SwapEnrollmentMark seals m afresh under the current key and writes it only
// where the mark is still at rev (the re-seal of a Stale mark).
func (e *wrappedEnrollments) SwapEnrollmentMark(ctx context.Context, m store.EnrollmentMark, rev uint64) error {
	m, err := e.sealMark(m)
	if err != nil {
		return err
	}
	return e.Enrollments.SwapEnrollmentMark(ctx, m, rev)
}

func (e *wrappedEnrollments) Export(ctx context.Context) ([]byte, error) {
	raw, err := e.Enrollments.Export(ctx)
	if err != nil {
		return nil, err
	}
	sealed, err := e.w.keys.SealBound(raw, exportAAD)
	if err != nil {
		return nil, err
	}
	return json.Marshal(exportEnvelope{Version: exportVersion, KeyID: e.w.keys.Current.ID, Sealed: sealed})
}

func (e *wrappedEnrollments) Import(ctx context.Context, sealed []byte, replace bool) (int, time.Time, error) {
	var env exportEnvelope
	if err := json.Unmarshal(sealed, &env); err != nil || env.Version != exportVersion {
		return 0, time.Time{}, errors.New("crypt: the file is not an enrollment export")
	}
	raw, err := e.w.keys.OpenBound(env.Sealed, exportAAD)
	switch {
	case errors.Is(err, ErrUnknownKey):
		return 0, time.Time{}, fmt.Errorf("crypt: the export is sealed under key id %q, which this broker does not "+
			"hold: set encryption.previous to it: %w", SealedKeyID(env.Sealed), err)
	case err != nil:
		return 0, time.Time{}, fmt.Errorf("crypt: the export does not open (damaged, or not an export): %w", err)
	}
	return e.Enrollments.Import(ctx, raw, replace)
}
