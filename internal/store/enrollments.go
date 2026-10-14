package store

import "time"

// EnrollmentBody is an enrollment store's content as Export carries it and
// the sealed file keeps it (plan 9e, D7, D13): the mark and every record,
// by principal. ExportedAt is set in an export alone.
type EnrollmentBody struct {
	CreatedAt      time.Time                   `json:"created_at"`
	ReopenAllUntil time.Time                   `json:"reopen_all_until,omitzero"`
	ExportedAt     time.Time                   `json:"exported_at,omitzero"`
	SecondFactors  map[string]EnrollmentRecord `json:"second_factors"`
}

// EnrollmentRecord is a SecondFactor as a body keeps it. Over the sealing
// layer Sealed holds the secret, entry id and source, and the three clear
// members are empty; a store with no sealing layer over it keeps them in
// the clear, as the in-memory store does in tests.
type EnrollmentRecord struct {
	State        string    `json:"state"`
	EnrolledAt   time.Time `json:"enrolled_at,omitzero"`
	LastStep     int64     `json:"last_step,omitempty"`
	Until        time.Time `json:"until,omitzero"`
	Rev          uint64    `json:"rev"`
	Sealed       []byte    `json:"sealed,omitempty"`
	EntryID      string    `json:"entry_id,omitempty"`
	Secret       []byte    `json:"secret,omitempty"`
	EnrolledFrom string    `json:"enrolled_from,omitempty"`
}

// RecordOf is f as a body keeps it.
func RecordOf(f SecondFactor) EnrollmentRecord {
	return EnrollmentRecord{State: f.State, EnrolledAt: f.EnrolledAt, LastStep: f.LastStep, Until: f.Until,
		Rev: f.Rev, Sealed: f.Sealed, EntryID: f.EntryID, Secret: f.Secret, EnrolledFrom: f.EnrolledFrom}
}

// SecondFactorOf is the record kept for principal, as a SecondFactor.
func SecondFactorOf(principal string, r EnrollmentRecord) SecondFactor {
	return SecondFactor{Principal: principal, State: r.State, EntryID: r.EntryID, Secret: r.Secret,
		EnrolledAt: r.EnrolledAt, EnrolledFrom: r.EnrolledFrom, LastStep: r.LastStep, Until: r.Until,
		Rev: r.Rev, Sealed: r.Sealed}
}

// EnrolledAfter reports whether r was enrolled or reset after at, the check
// an Import makes of what it would overwrite (D13). A reopened record's
// reset time is not kept, only its end, and the store does not know
// enrollment.reopen_for: a reopened record ending after at may have been
// reset after it, and counts, so a restore is refused where it might undo a
// reset and an operator says --replace.
func EnrolledAfter(r EnrollmentRecord, at time.Time) bool {
	return r.EnrolledAt.After(at) || r.State == SecondFactorReopened && r.Until.After(at)
}
