package author

import (
	"errors"
	"testing"

	"github.com/blanketfish/port49/internal/store"
)

// A record the sealing layer cannot open is not a store outage, and the
// metric must not send the on-call to check a store that is up (spec §5.6).
func TestStoreOutcomeNamesAnUnreadableRecord(t *testing.T) {
	err := error(&store.UnreadableContextError{Err: errors.New("crypt: no key v0")})
	if got := storeOutcome(err); got != "unreadable" {
		t.Fatalf("storeOutcome(unreadable) = %q, want unreadable", got)
	}
	if got := storeOutcome(errors.New("connection refused")); got != "error" {
		t.Fatalf("storeOutcome(outage) = %q, want error", got)
	}
}
