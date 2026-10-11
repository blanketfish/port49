package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

// The nonce names one key: 43 base64url characters, the same for the same
// key, another for another (decision 43 ruling 3).
func TestIssuanceNonceNamesTheKey(t *testing.T) {
	a, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	b, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	na, err := IssuanceNonce(a.Public())
	nb, _ := IssuanceNonce(b.Public())
	na2, _ := IssuanceNonce(a.Public())
	if err != nil || len(na) != 43 || na == nb || na != na2 {
		t.Fatalf("%q %q %q %v", na, nb, na2, err)
	}
	if _, err := IssuanceNonce("not a key"); err == nil {
		t.Fatal("a value that is no key named one")
	}
}
