package oidc_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/rhwendt/port49/internal/oidc"
	"github.com/rhwendt/port49/internal/oidc/oidctest"
)

func jwks(t *testing.T, keys ...map[string]any) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{"keys": keys})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestJWKSParsesTheThreeKinds(t *testing.T) {
	r, e, o := oidctest.NewKey(t, oidc.RS256), oidctest.NewKey(t, oidc.ES384), oidctest.NewKey(t, oidc.EdDSA)
	keys, skipped, err := oidc.ParseJWKS(jwks(t, oidctest.JWK("r", oidc.RS256, r.Public()),
		oidctest.JWK("e", "", e.Public()), oidctest.JWK("o", oidc.EdDSA, o.Public())))
	if err != nil || len(skipped) != 0 || len(keys) != 3 {
		t.Fatalf("%d keys, skipped %v, %v", len(keys), skipped, err)
	}
	if keys[0].Kid != "r" || keys[0].Alg != oidc.RS256 || !keys[0].Fits(oidc.RS256) || !keys[0].Fits(oidc.PS256) {
		t.Fatalf("the RSA key: %+v", keys[0])
	}
	if keys[1].Alg != "" || !keys[1].Fits(oidc.ES384) || keys[1].Fits(oidc.ES256) {
		t.Fatalf("the P-384 key: %+v", keys[1])
	}
	if !keys[2].Fits(oidc.EdDSA) {
		t.Fatalf("the Ed25519 key: %+v", keys[2])
	}
}

// Every key that cannot be a verification key under Ruling 3 is skipped with
// a reason, and the rest of the set stands.
func TestJWKSSkipsWhatIsNotAVerificationKey(t *testing.T) {
	good := oidctest.NewKey(t, oidc.ES256)
	small, _ := rsa.GenerateKey(rand.Reader, 1024)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	withUse := func(m map[string]any, k string, v any) map[string]any { m[k] = v; return m }
	off := oidctest.JWK("off", "", other.Public())
	off["y"] = off["x"] // a point not on the curve
	keys, skipped, err := oidc.ParseJWKS(jwks(t,
		oidctest.JWK("good", oidc.ES256, good.Public()),
		withUse(oidctest.JWK("enc", "", other.Public()), "use", "enc"),
		withUse(oidctest.JWK("ops", "", other.Public()), "key_ops", []string{"encrypt"}),
		oidctest.JWK("small", "", &small.PublicKey),
		map[string]any{"kty": "oct", "kid": "hmac", "k": "c2VjcmV0"},
		withUse(oidctest.JWK("priv", "", other.Public()), "d", "AAAA"),
		map[string]any{"kty": "XYZ", "kid": "odd"},
		withUse(oidctest.JWK("hs", "", other.Public()), "alg", "HS256"),
		off,
	))
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0].Kid != "good" {
		t.Fatalf("kept %+v", keys)
	}
	joined := strings.Join(skipped, "\n")
	for _, want := range []string{`"enc": use enc`, `"ops": key_ops`, `"small": RSA key of 1024 bits`,
		`"hmac": kty oct`, `"priv": carries private key material`, `"odd": kty XYZ`, `"hs": alg HS256`,
		`"off": not a point`} {
		if !strings.Contains(joined, want) {
			t.Errorf("no skip reason %q in:\n%s", want, joined)
		}
	}
}

func TestJWKSThatIsNotASetIsAnError(t *testing.T) {
	for _, body := range []string{`[]`, `{"keys": {}}`, `{}`, `not json`} {
		if _, _, err := oidc.ParseJWKS([]byte(body)); err == nil {
			t.Errorf("%s parsed", body)
		}
	}
}

// An RSA modulus over MaxRSABits is skipped: a provider-published 16384-bit
// key would make every verification under it expensive (pre-flight M-1).
func TestJWKSSkipsAnOversizedRSAKey(t *testing.T) {
	n := make([]byte, oidc.MaxRSABits/8+1)
	n[0], n[len(n)-1] = 0x80, 1
	_, skipped, err := oidc.ParseJWKS(jwks(t, map[string]any{"kty": "RSA", "kid": "big",
		"n": base64.RawURLEncoding.EncodeToString(n), "e": "AQAB"}))
	if err != nil || len(skipped) != 1 || !strings.Contains(skipped[0], `"big": RSA key of 8200 bits, over 8192`) {
		t.Fatalf("skipped %v, %v", skipped, err)
	}
}

// A set of more than MaxKeys keys is not a set port49 uses (pre-flight M-3):
// the fetch fails, and the last good set stands (Task 4).
func TestJWKSOverMaxKeysIsAnError(t *testing.T) {
	pub := oidctest.NewKey(t, oidc.ES256).Public()
	var many []map[string]any
	for i := range oidc.MaxKeys + 1 {
		many = append(many, oidctest.JWK(fmt.Sprint(i), "", pub))
	}
	if _, _, err := oidc.ParseJWKS(jwks(t, many...)); err == nil || !strings.Contains(err.Error(), "over 100 keys") {
		t.Fatalf("%d keys: %v", len(many), err)
	}
}
