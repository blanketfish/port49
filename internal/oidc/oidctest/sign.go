// Package oidctest is an OpenID provider for tests: keys, signed tokens,
// and (Issuer, plan 7h Task 4) a TLS server publishing discovery and a
// JWKS. Never for production.
package oidctest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/blanketfish/port49/internal/oidc"
)

// NewKey is a fresh key for alg: RSA 2048, P-256, P-384 or Ed25519.
func NewKey(t testing.TB, alg oidc.Alg) crypto.Signer {
	t.Helper()
	var k crypto.Signer
	var err error
	switch alg {
	case oidc.RS256, oidc.PS256:
		k, err = rsa.GenerateKey(rand.Reader, 2048)
	case oidc.ES256:
		k, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case oidc.ES384:
		k, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case oidc.EdDSA:
		_, k, err = ed25519.GenerateKey(rand.Reader)
	default:
		t.Fatalf("oidctest: no key for %s", alg)
	}
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// Sign is a compact JWS of claims under header (alg is set from alg),
// signed by key as alg says.
func Sign(t testing.TB, alg oidc.Alg, key crypto.Signer, header, claims map[string]any) string {
	t.Helper()
	b, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return SignRaw(t, alg, key, header, b)
}

// SignRaw is Sign over a payload given as bytes, to be exactly what the
// caller wrote: a member named twice, which a map cannot say.
func SignRaw(t testing.TB, alg oidc.Alg, key crypto.Signer, header map[string]any, payload []byte) string {
	t.Helper()
	h := map[string]any{"alg": string(alg)}
	for k, v := range header {
		h[k] = v
	}
	enc := func(v any) string {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(b)
	}
	input := enc(h) + "." + base64.RawURLEncoding.EncodeToString(payload)
	var sig []byte
	var err error
	switch alg {
	case oidc.RS256:
		sum := sha256.Sum256([]byte(input))
		sig, err = key.Sign(rand.Reader, sum[:], crypto.SHA256)
	case oidc.PS256:
		sum := sha256.Sum256([]byte(input))
		sig, err = key.Sign(rand.Reader, sum[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256})
	case oidc.ES256, oidc.ES384:
		var digest []byte
		if alg == oidc.ES256 {
			s := sha256.Sum256([]byte(input))
			digest = s[:]
		} else {
			s := sha512.Sum384([]byte(input))
			digest = s[:]
		}
		priv := key.(*ecdsa.PrivateKey)
		r, s, e := ecdsa.Sign(rand.Reader, priv, digest)
		size := (priv.Curve.Params().BitSize + 7) / 8
		sig, err = append(r.FillBytes(make([]byte, size)), s.FillBytes(make([]byte, size))...), e
	case oidc.EdDSA:
		sig, err = key.Sign(rand.Reader, []byte(input), crypto.Hash(0))
	}
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// JWK is pub as a JWK, with kid, and alg when not "".
func JWK(kid string, alg oidc.Alg, pub crypto.PublicKey) map[string]any {
	b64 := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	m := map[string]any{"kid": kid, "use": "sig"}
	if alg != "" {
		m["alg"] = string(alg)
	}
	switch p := pub.(type) {
	case *rsa.PublicKey:
		m["kty"], m["n"], m["e"] = "RSA", b64(p.N.Bytes()), b64(big.NewInt(int64(p.E)).Bytes())
	case *ecdsa.PublicKey:
		size := (p.Curve.Params().BitSize + 7) / 8
		point, _ := p.Bytes() // 0x04 || X || Y
		m["kty"], m["crv"] = "EC", p.Curve.Params().Name
		m["x"], m["y"] = b64(point[1:1+size]), b64(point[1+size:])
	case ed25519.PublicKey:
		m["kty"], m["crv"], m["x"] = "OKP", "Ed25519", b64(p)
	}
	return m
}
