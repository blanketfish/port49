package oidc_test

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"testing"

	"github.com/rhwendt/port49/internal/oidc"
	"github.com/rhwendt/port49/internal/oidc/oidctest"
)

// wycheFile is Wycheproof's testvectors_v1 schema, as far as these five
// files use it.
type wycheFile struct {
	NumberOfTests int `json:"numberOfTests"`
	TestGroups    []struct {
		PublicKey struct {
			Modulus        string `json:"modulus"`        // RSA, hex
			PublicExponent string `json:"publicExponent"` // RSA, hex
		} `json:"publicKey"`
		PublicKeyDer string `json:"publicKeyDer"` // EC and Ed25519: a hex SubjectPublicKeyInfo
		Tests        []struct {
			TcID    int      `json:"tcId"`
			Comment string   `json:"comment"`
			Msg     string   `json:"msg"`
			Sig     string   `json:"sig"`
			Result  string   `json:"result"`
			Flags   []string `json:"flags"`
		} `json:"tests"`
	} `json:"testGroups"`
}

// wycheKey is a group's public key, taken through the JWK path a provider's
// key takes, so ParseJWKS's checks run on it too.
func wycheKey(t *testing.T, alg oidc.Alg, modulus, exponent, der string) oidc.Key {
	t.Helper()
	var pub crypto.PublicKey
	if alg == oidc.RS256 || alg == oidc.PS256 {
		n, err1 := hex.DecodeString(modulus)
		e, err2 := hex.DecodeString(exponent)
		if errors.Join(err1, err2) != nil || len(n) == 0 || len(e) == 0 {
			t.Fatal("a group with no RSA key: the schema differs from wycheFile; fix the reader")
		}
		pub = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
	} else {
		b, err := hex.DecodeString(der)
		if err == nil {
			pub, err = x509.ParsePKIXPublicKey(b)
		}
		if err != nil || len(b) == 0 {
			t.Fatalf("a group with no key (%v): the schema differs from wycheFile; fix the reader", err)
		}
	}
	keys, skipped, err := oidc.ParseJWKS(jwks(t, oidctest.JWK("w", "", pub)))
	if err != nil || len(keys) != 1 {
		t.Fatalf("the group's key is not a JWKS key: %v, skipped %v", err, skipped)
	}
	return keys[0]
}

// Project Wycheproof's vectors for the five algorithms (pre-flight M-1; OR-1):
// every valid signature verifies, and no invalid one does. "acceptable" is
// Wycheproof's word for a case either answer is safe for. Every vector in
// the file runs: a count that differs is a schema change to fix in
// wycheFile, never a vector to skip.
func TestWycheproof(t *testing.T) {
	for _, c := range []struct {
		file string
		alg  oidc.Alg
	}{
		{"ecdsa_secp256r1_sha256_p1363_test.json", oidc.ES256},
		{"ecdsa_secp384r1_sha384_p1363_test.json", oidc.ES384},
		{"rsa_signature_2048_sha256_test.json", oidc.RS256},
		{"rsa_pss_2048_sha256_mgf1_32_test.json", oidc.PS256},
		{"ed25519_test.json", oidc.EdDSA},
	} {
		t.Run(c.file, func(t *testing.T) {
			raw, err := os.ReadFile("testdata/wycheproof/" + c.file)
			if err != nil {
				t.Fatal(err)
			}
			var f wycheFile
			if err := json.Unmarshal(raw, &f); err != nil {
				t.Fatal(err)
			}
			ran := 0
			for _, g := range f.TestGroups {
				key := wycheKey(t, c.alg, g.PublicKey.Modulus, g.PublicKey.PublicExponent, g.PublicKeyDer)
				for _, tc := range g.Tests {
					msg, err1 := hex.DecodeString(tc.Msg)
					sig, err2 := hex.DecodeString(tc.Sig)
					if errors.Join(err1, err2) != nil {
						t.Fatalf("tc %d: %v", tc.TcID, errors.Join(err1, err2))
					}
					err := oidc.NewJWSForTest(c.alg, msg, sig).Verify(key, []oidc.Alg{c.alg})
					switch tc.Result {
					case "valid":
						if err != nil {
							t.Errorf("tc %d (%s): a valid signature is refused: %v", tc.TcID, tc.Comment, err)
						}
					case "invalid":
						if err == nil {
							t.Errorf("tc %d (%s; %v): an invalid signature verifies", tc.TcID, tc.Comment, tc.Flags)
						}
					case "acceptable":
					default:
						t.Fatalf("tc %d: result %q", tc.TcID, tc.Result)
					}
					ran++
				}
			}
			if ran == 0 || ran != f.NumberOfTests {
				t.Fatalf("ran %d of %d vectors: fix wycheFile, never skip a vector", ran, f.NumberOfTests)
			}
		})
	}
}
