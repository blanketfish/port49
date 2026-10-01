package store_test

import (
	"reflect"
	"testing"

	"github.com/rhwendt/port49/internal/store"
)

// An idempotency record is written only by a reservation and the
// compare-and-set on its holder: a plain write would skip the holder check
// that keeps two requests under one key from both minting, and a plain read
// has no caller (final review M9). A test that needs either uses
// storetest.Planter or storetest.Peek.
func TestTheStoreHasNoPlainIdempotencyReadOrWrite(t *testing.T) {
	st := reflect.TypeOf((*store.Store)(nil)).Elem()
	for _, m := range []string{"PutIdempotency", "GetIdempotency"} {
		if _, ok := st.MethodByName(m); ok {
			t.Errorf("store.Store has %s", m)
		}
	}
}
