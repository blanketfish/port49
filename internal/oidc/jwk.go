package oidc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"slices"

	"github.com/blanketfish/port49/internal/printsafe"
)

// Key is one verification key from a JWKS. Alg is the JWK's own alg, ""
// when it named none.
type Key struct {
	Kid string
	Alg Alg
	Pub crypto.PublicKey
}

// Fits reports whether k is a key of a's type: RSA for RS256 and PS256,
// P-256 for ES256, P-384 for ES384, Ed25519 for EdDSA.
func (k Key) Fits(a Alg) bool {
	// A key built by hand is checked whole, so Verify cannot panic on it.
	switch pub := k.Pub.(type) {
	case *rsa.PublicKey:
		return pub != nil && pub.N != nil && (a == RS256 || a == PS256)
	case *ecdsa.PublicKey:
		return pub != nil && pub.Curve != nil && pub.X != nil && pub.Y != nil &&
			((a == ES256 && pub.Curve == elliptic.P256()) || (a == ES384 && pub.Curve == elliptic.P384()))
	case ed25519.PublicKey:
		return len(pub) == ed25519.PublicKeySize && a == EdDSA
	}
	return false
}

type jwk struct {
	Kty    string   `json:"kty"`
	Kid    string   `json:"kid"`
	Use    string   `json:"use"`
	Alg    string   `json:"alg"`
	KeyOps []string `json:"key_ops"`
	Crv    string   `json:"crv"`
	N      string   `json:"n"`
	E      string   `json:"e"`
	X      string   `json:"x"`
	Y      string   `json:"y"`
	D      string   `json:"d"`
}

// minRSABits is the least RSA modulus a key may have (RFC 7518 §3.3).
// MaxRSABits is the most: a larger key makes every verification under it
// expensive, and no provider needs one.
const (
	minRSABits = 2048
	MaxRSABits = 8192
)

// MaxKeys bounds a JWKS: a provider publishes a handful, and a set of more
// is refused whole, as a failed fetch (pre-flight M-3).
const MaxKeys = 100

// ParseJWKS reads a JWK Set. A key that cannot verify a token under
// decision 39 Ruling 3 is skipped, with one line in skipped naming its
// kid and why; the rest stand. A body that is not a set, or holds more
// than MaxKeys keys, is an error.
func ParseJWKS(b []byte) (keys []Key, skipped []string, err error) {
	var members []json.RawMessage
	top, err := exactObject(b)
	if err == nil {
		err = json.Unmarshal(top["keys"], &members)
	}
	if err != nil || members == nil {
		return nil, nil, errors.New("oidc: the JWKS is not a JSON object with one keys array")
	}
	if len(members) > MaxKeys {
		return nil, nil, fmt.Errorf("oidc: the JWKS holds %d keys, over %d keys", len(members), MaxKeys)
	}
	for _, raw := range members {
		j, ok := readJWK(raw)
		if !ok {
			skipped = append(skipped, "a key that is not a JSON object of distinct members")
			continue
		}
		k, why := j.key()
		if why != "" {
			skipped = append(skipped, fmt.Sprintf("%q: %s", printsafe.Line(j.Kid, 80), why))
			continue
		}
		keys = append(keys, k)
	}
	return keys, skipped, nil
}

// readJWK reads a JWK's members by exact name, none repeated (the rule of a
// JWS header): "N" is not n, and the last of two "d" does not win.
func readJWK(raw []byte) (jwk, bool) {
	var j jwk
	fields, err := exactObject(raw)
	if err != nil {
		return j, false
	}
	for name, dst := range map[string]any{"kty": &j.Kty, "kid": &j.Kid, "use": &j.Use, "alg": &j.Alg,
		"key_ops": &j.KeyOps, "crv": &j.Crv, "n": &j.N, "e": &j.E, "x": &j.X, "y": &j.Y, "d": &j.D} {
		if v, ok := fields[name]; ok && json.Unmarshal(v, dst) != nil {
			return j, false
		}
	}
	return j, true
}

// key is j as a verification key, or why it is not one.
func (j jwk) key() (Key, string) {
	switch {
	case j.D != "":
		return Key{}, "carries private key material; the provider has published a signing key, and no key from it is used"
	case j.Use != "" && j.Use != "sig":
		return Key{}, "use " + printsafe.Line(j.Use, 20) + ", not sig"
	case j.KeyOps != nil && !slices.Contains(j.KeyOps, "verify"):
		return Key{}, "key_ops without verify"
	case j.Alg != "" && !slices.Contains(known, Alg(j.Alg)):
		return Key{}, "alg " + printsafe.Line(j.Alg, 20) + " is not one port49 verifies"
	}
	k := Key{Kid: j.Kid, Alg: Alg(j.Alg)}
	dec := base64.RawURLEncoding.Strict()
	switch j.Kty {
	case "RSA":
		n, err1 := dec.DecodeString(j.N)
		e, err2 := dec.DecodeString(j.E)
		if errors.Join(err1, err2) != nil || len(e) == 0 || len(e) > 4 {
			return Key{}, "an RSA key whose n or e does not decode"
		}
		pub := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
		if pub.N.BitLen() < minRSABits {
			return Key{}, fmt.Sprintf("RSA key of %d bits, under %d", pub.N.BitLen(), minRSABits)
		}
		if pub.N.BitLen() > MaxRSABits {
			return Key{}, fmt.Sprintf("RSA key of %d bits, over %d", pub.N.BitLen(), MaxRSABits)
		}
		if e := new(big.Int).SetBytes(e); !e.IsInt64() || e.Int64() > 1<<31-1 {
			return Key{}, "an RSA exponent over 2^31-1, more than the standard library takes"
		}
		if pub.E < 3 || pub.E%2 == 0 {
			return Key{}, "an RSA exponent that is not odd and at least 3"
		}
		k.Pub = pub
	case "EC":
		var curve elliptic.Curve
		switch j.Crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		default:
			return Key{}, "crv " + printsafe.Line(j.Crv, 20) + ", not P-256 or P-384"
		}
		x, err1 := dec.DecodeString(j.X)
		y, err2 := dec.DecodeString(j.Y)
		size := (curve.Params().BitSize + 7) / 8
		if errors.Join(err1, err2) != nil || len(x) != size || len(y) != size {
			return Key{}, "an EC key whose x or y does not decode to its curve's size"
		}
		pub, err := ecdsa.ParseUncompressedPublicKey(curve, append(append([]byte{4}, x...), y...))
		if err != nil {
			return Key{}, "not a point on " + j.Crv
		}
		k.Pub = pub
	case "OKP":
		x, err := dec.DecodeString(j.X)
		if j.Crv != "Ed25519" || err != nil || len(x) != ed25519.PublicKeySize {
			return Key{}, "an OKP key that is not an Ed25519 public key"
		}
		k.Pub = ed25519.PublicKey(x)
	default:
		return Key{}, "kty " + printsafe.Line(j.Kty, 20) + "; a shared secret is never a verification key"
	}
	if k.Alg != "" && !k.Fits(k.Alg) {
		return Key{}, "alg " + string(k.Alg) + " is not for this key's type"
	}
	return k, ""
}
