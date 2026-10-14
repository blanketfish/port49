package store

import (
	"testing"
	"time"
)

// An import over a store holding a record enrolled after the export, or a
// reopened one that may have been reset after it, is refused (D13).
func TestEnrolledAfterCountsAnEnrollmentAndAPossibleReset(t *testing.T) {
	at := time.Unix(1_000_000, 0).UTC()
	for _, c := range []struct {
		name string
		r    EnrollmentRecord
		want bool
	}{
		{"enrolled before", EnrollmentRecord{State: SecondFactorActive, EnrolledAt: at.Add(-time.Hour)}, false},
		{"enrolled at the export", EnrollmentRecord{State: SecondFactorActive, EnrolledAt: at}, false},
		{"enrolled after", EnrollmentRecord{State: SecondFactorActive, EnrolledAt: at.Add(time.Second)}, true},
		{"reopened, ended before", EnrollmentRecord{State: SecondFactorReopened, EnrolledAt: at.Add(-time.Hour),
			Until: at.Add(-time.Minute)}, false},
		{"reopened, ends after", EnrollmentRecord{State: SecondFactorReopened, EnrolledAt: at.Add(-time.Hour),
			Until: at.Add(time.Minute)}, true},
		{"a pending record's confirm-by is not a reset", EnrollmentRecord{State: SecondFactorPending,
			EnrolledAt: at.Add(-time.Hour), Until: at.Add(time.Minute)}, false},
	} {
		if got := EnrolledAfter(c.r, at); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}
