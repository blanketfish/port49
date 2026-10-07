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

func TestOIDCKeysAreIssuerQualified(t *testing.T) {
	a := store.SidKey("https://a.example.com", "s1")
	b := store.SidKey("https://b.example.com", "s1")
	if a == b {
		t.Fatal("one sid at two issuers is one key")
	}
	if store.SidKey("https://a.example.com", "s1") != store.OIDCKey(store.OIDCSid, "https://a.example.com", "s1") {
		t.Fatal("SidKey is not OIDCKey(OIDCSid, …)")
	}
	if store.OIDCKey(store.OIDCSid, "https://a.example.com", "x") == store.OIDCKey(store.OIDCSub, "https://a.example.com", "x") {
		t.Fatal("a sid and a sub with one value are one key")
	}
	// The separator cannot be forged by an issuer or a value that holds it.
	if store.OIDCKey(store.OIDCSid, "https://a.example.com s", "1") ==
		store.OIDCKey(store.OIDCSid, "https://a.example.com", "s 1") {
		t.Fatal("the key is ambiguous across its parts")
	}
	if store.SidKey("", "s1") != "" {
		t.Fatal("an empty issuer has a key: a blank half must not become one index entry (ruling P8)")
	}
	if store.SidKey("https://a.example.com", "") != "" {
		t.Fatal("an empty sid has a key: every OIDC login without one would share it (spec §5.6)")
	}
}
