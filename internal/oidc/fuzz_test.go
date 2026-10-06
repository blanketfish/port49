package oidc_test

import (
	"crypto"
	"strings"
	"testing"

	"github.com/rhwendt/port49/internal/oidc"
	"github.com/rhwendt/port49/internal/oidc/oidctest"
)

// No input panics ParseCompact or Verify, and a JWS that parses came from
// exactly three parts within MaxToken (pre-flight M-1).
func FuzzParseCompact(f *testing.F) {
	signers := map[oidc.Alg]crypto.Signer{oidc.RS256: oidctest.NewKey(f, oidc.RS256),
		oidc.ES256: oidctest.NewKey(f, oidc.ES256), oidc.EdDSA: oidctest.NewKey(f, oidc.EdDSA)}
	var keys []oidc.Key
	for alg, s := range signers {
		f.Add(oidctest.Sign(f, alg, s, map[string]any{"kid": "k"}, map[string]any{"sub": "x"}))
		keys = append(keys, oidc.Key{Pub: s.Public()})
	}
	for _, seed := range []string{"", "a.b.c", "a.b.c.d.e", "...", "eyJhbGciOiJub25lIn0.e30."} {
		f.Add(seed)
	}
	all := []oidc.Alg{oidc.RS256, oidc.PS256, oidc.ES256, oidc.ES384, oidc.EdDSA}
	f.Fuzz(func(t *testing.T, raw string) {
		j, err := oidc.ParseCompact(raw)
		if err != nil {
			if j != nil {
				t.Fatal("an error and a JWS")
			}
			return
		}
		if j == nil || len(raw) > oidc.MaxToken || strings.Count(raw, ".") != 2 || j.Header.Alg == "" {
			t.Fatalf("parsed %d bytes, %d dots, alg %q", len(raw), strings.Count(raw, "."), j.Header.Alg)
		}
		for _, k := range keys {
			_ = j.Verify(k, all)
		}
	})
}

// No body panics ParseJWKS, and every key it keeps fits its own alg.
func FuzzParseJWKS(f *testing.F) {
	for _, seed := range []string{`{"keys":[]}`, `{"keys":[{"kty":"RSA","n":"","e":"AQAB"}]}`,
		`{"keys":[{"kty":"EC","crv":"P-256","x":"","y":""}]}`, `{"keys":[{"kty":"OKP","crv":"Ed25519","x":""}]}`} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		keys, _, err := oidc.ParseJWKS(b)
		if err != nil && keys != nil {
			t.Fatal("an error and keys")
		}
		for _, k := range keys {
			if k.Pub == nil || (k.Alg != "" && !k.Fits(k.Alg)) {
				t.Fatalf("kept %+v", k)
			}
		}
	})
}
