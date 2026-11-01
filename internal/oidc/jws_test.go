package oidc_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/blanketfish/port49/internal/oidc"
	"github.com/blanketfish/port49/internal/oidc/oidctest"
)

// rfcExample is one RFC example: its public key as a JWK and its JWS.
func rfcExample(t *testing.T, file string) (oidc.Key, string) {
	t.Helper()
	raw, err := os.ReadFile("testdata/" + file)
	if err != nil {
		t.Fatal(err)
	}
	var ex struct {
		JWK json.RawMessage `json:"jwk"`
		JWS string          `json:"jws"`
	}
	if err := json.Unmarshal(raw, &ex); err != nil {
		t.Fatal(err)
	}
	keys, skipped, err := oidc.ParseJWKS([]byte(`{"keys":[` + string(ex.JWK) + `]}`))
	if err != nil || len(keys) != 1 {
		t.Fatalf("%s: %d keys, skipped %v, %v", file, len(keys), skipped, err)
	}
	return keys[0], ex.JWS
}

// The RFCs' own examples verify, and a single changed byte does not.
func TestTheRFCExamplesVerify(t *testing.T) {
	for _, c := range []struct {
		file string
		alg  oidc.Alg
	}{{"rfc7515-a2.json", oidc.RS256}, {"rfc7515-a3.json", oidc.ES256}, {"rfc8037-a4.json", oidc.EdDSA}} {
		key, raw := rfcExample(t, c.file)
		j, err := oidc.ParseCompact(raw)
		if err != nil {
			t.Fatalf("%s: %v", c.file, err)
		}
		if err := j.Verify(key, []oidc.Alg{c.alg}); err != nil {
			t.Fatalf("%s: %v", c.file, err)
		}
		parts := strings.Split(raw, ".")
		sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
		sig[len(sig)/2] ^= 1
		bad, _ := oidc.ParseCompact(parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(sig))
		if err := bad.Verify(key, []oidc.Alg{c.alg}); !errors.Is(err, oidc.ErrSignature) {
			t.Fatalf("%s: a changed signature verifies: %v", c.file, err)
		}
	}
}

// Each of the five algorithms verifies a token its key signed, and refuses
// one signed by another key of the same type.
func TestEachAlgorithmVerifiesItsOwn(t *testing.T) {
	for _, alg := range []oidc.Alg{oidc.RS256, oidc.PS256, oidc.ES256, oidc.ES384, oidc.EdDSA} {
		k1, k2 := oidctest.NewKey(t, alg), oidctest.NewKey(t, alg)
		raw := oidctest.Sign(t, alg, k1, map[string]any{"kid": "k1"}, map[string]any{"sub": "x"})
		j, err := oidc.ParseCompact(raw)
		if err != nil {
			t.Fatal(err)
		}
		if err := j.Verify(oidc.Key{Kid: "k1", Pub: k1.Public()}, []oidc.Alg{alg}); err != nil {
			t.Fatalf("%s: %v", alg, err)
		}
		if err := j.Verify(oidc.Key{Kid: "k1", Pub: k2.Public()}, []oidc.Alg{alg}); !errors.Is(err, oidc.ErrSignature) {
			t.Fatalf("%s: another key's verifies: %v", alg, err)
		}
	}
}

// Review Focus 1: none and an HMAC are refused before any key is used,
// including the classic confusion, an HS256 whose secret is the provider's
// RSA public key.
func TestNoneAndHMACAreRefusedBeforeAnyKey(t *testing.T) {
	rsaKey := oidctest.NewKey(t, oidc.RS256)
	pub := rsaKey.Public()
	enc := func(v any) string { b, _ := json.Marshal(v); return base64.RawURLEncoding.EncodeToString(b) }
	unsigned := enc(map[string]any{"alg": "none"}) + "." + enc(map[string]any{"sub": "x"}) + "."
	if _, err := oidc.ParseCompact(unsigned); !errors.Is(err, oidc.ErrMalformed) {
		t.Fatalf("an unsigned token parses: %v", err)
	}
	der, _ := x509.MarshalPKIXPublicKey(pub)
	input := enc(map[string]any{"alg": "HS256"}) + "." + enc(map[string]any{"sub": "x"})
	mac := hmac.New(sha256.New, der)
	mac.Write([]byte(input))
	confused := input + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	j, err := oidc.ParseCompact(confused)
	if err != nil {
		t.Fatal(err)
	}
	for _, algs := range [][]oidc.Alg{{oidc.RS256}, {oidc.RS256, oidc.PS256, oidc.ES256, oidc.ES384, oidc.EdDSA}} {
		if err := j.Verify(oidc.Key{Pub: pub}, algs); !errors.Is(err, oidc.ErrAlgorithm) {
			t.Fatalf("an HS256 token under %v: %v", algs, err)
		}
	}
	for _, name := range []string{"none", "None", "HS256", "HS384", "HS512", "hs256", "RS1", "ES512"} {
		if _, err := oidc.ParseAlgs([]string{name}); err == nil {
			t.Fatalf("ParseAlgs accepted %s", name)
		}
	}
	if got, err := oidc.ParseAlgs(nil); err != nil || len(got) != 1 || got[0] != oidc.RS256 {
		t.Fatalf("the default is %v, %v", got, err)
	}
}

// A JWS whose header names its own key (jwk, jku, x5u, x5c) is verified only
// against the key the caller passes: the header names nothing that is used.
func TestAHeaderNamedKeyIsNeverUsed(t *testing.T) {
	real, attacker := oidctest.NewKey(t, oidc.RS256), oidctest.NewKey(t, oidc.RS256)
	raw := oidctest.Sign(t, oidc.RS256, attacker, map[string]any{
		"jwk": oidctest.JWK("a", oidc.RS256, attacker.Public()), "jku": "https://attacker.example/jwks",
		"x5u": "https://attacker.example/c.pem", "x5c": []string{"MIIB"}}, map[string]any{"sub": "x"})
	j, err := oidc.ParseCompact(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.Verify(oidc.Key{Pub: real.Public()}, []oidc.Alg{oidc.RS256}); !errors.Is(err, oidc.ErrSignature) {
		t.Fatalf("the header's own key was used: %v", err)
	}
}

func TestACritHeaderIsRefused(t *testing.T) {
	k := oidctest.NewKey(t, oidc.ES256)
	raw := oidctest.Sign(t, oidc.ES256, k, map[string]any{"crit": []string{"exp"}, "exp": 1}, map[string]any{"sub": "x"})
	if _, err := oidc.ParseCompact(raw); !errors.Is(err, oidc.ErrCrit) {
		t.Fatalf("a crit header: %v", err)
	}
}

func TestAnEncryptedOrMalformedTokenIsRefused(t *testing.T) {
	k := oidctest.NewKey(t, oidc.ES256)
	good := oidctest.Sign(t, oidc.ES256, k, nil, map[string]any{"sub": "x"})
	parts := strings.Split(good, ".")
	for name, raw := range map[string]string{
		"five parts (JWE)":  "a.b.c.d.e",
		"two parts":         parts[0] + "." + parts[1],
		"padded":            parts[0] + "=." + parts[1] + "." + parts[2],
		"standard alphabet": strings.ReplaceAll(parts[0], "-", "+") + "+." + parts[1] + "." + parts[2],
		"header not object": base64.RawURLEncoding.EncodeToString([]byte(`["RS256"]`)) + "." + parts[1] + "." + parts[2],
		"no alg":            base64.RawURLEncoding.EncodeToString([]byte(`{"kid":"k"}`)) + "." + parts[1] + "." + parts[2],
		"oversized":         strings.Repeat("a", oidc.MaxToken+1),
		"empty signature":   parts[0] + "." + parts[1] + ".",
		// Go's base64 decoder skips CR and LF, so these decode to the same bytes (I1).
		"CRLF in the header":       parts[0][:5] + "\r\n" + parts[0][5:] + "." + parts[1] + "." + parts[2],
		"LF in the payload":        parts[0] + "." + parts[1][:5] + "\n" + parts[1][5:] + "." + parts[2],
		"CRLF in the signature":    parts[0] + "." + parts[1] + "." + parts[2][:5] + "\r\n" + parts[2][5:],
		"CR in the signature":      parts[0] + "." + parts[1] + "." + parts[2] + "\r",
		"space in the header":      parts[0][:5] + " " + parts[0][5:] + "." + parts[1] + "." + parts[2],
		"space in the payload":     parts[0] + "." + parts[1] + " ." + parts[2],
		"space in the signature":   parts[0] + "." + parts[1] + "." + parts[2][:5] + " " + parts[2][5:],
		"padding in the payload":   parts[0] + "." + parts[1] + "=." + parts[2],
		"padding in the signature": parts[0] + "." + parts[1] + "." + parts[2] + "==",
		// "c2l" decodes leniently to the same two bytes as "c2k": trailing bits are not zero.
		"non-canonical trailing bits": parts[0] + "." + parts[1] + ".c2l",
	} {
		if _, err := oidc.ParseCompact(raw); !errors.Is(err, oidc.ErrMalformed) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// The algorithm, the key's type, and a JWK's own alg must agree.
func TestAlgorithmAndKeyMustAgree(t *testing.T) {
	rsaKey, p256, p384 := oidctest.NewKey(t, oidc.RS256), oidctest.NewKey(t, oidc.ES256), oidctest.NewKey(t, oidc.ES384)
	es256 := oidctest.Sign(t, oidc.ES256, p256, nil, map[string]any{"sub": "x"})
	j, _ := oidc.ParseCompact(es256)
	for name, k := range map[string]oidc.Key{
		"an RSA key for ES256":     {Pub: rsaKey.Public()},
		"a P-384 key for ES256":    {Pub: p384.Public()},
		"a JWK whose alg is ES384": {Alg: oidc.ES384, Pub: p256.Public()},
	} {
		if err := j.Verify(k, []oidc.Alg{oidc.ES256, oidc.ES384}); !errors.Is(err, oidc.ErrAlgorithm) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := j.Verify(oidc.Key{Pub: p256.Public()}, []oidc.Alg{oidc.RS256}); !errors.Is(err, oidc.ErrAlgorithm) {
		t.Errorf("an algorithm the verifier does not pin: %v", err)
	}
}

// Every algorithm against every key type (pre-flight M-1): only the five
// pairs Ruling 3 names fit, a token verifies only under its own pair, and
// every other pair is ErrAlgorithm before any cryptography runs. A key of a
// type no algorithm takes (P-521) fits nothing.
func TestTheAlgorithmKeyTypeMatrix(t *testing.T) {
	p521, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]crypto.Signer{
		"RSA": oidctest.NewKey(t, oidc.RS256), "P-256": oidctest.NewKey(t, oidc.ES256),
		"P-384": oidctest.NewKey(t, oidc.ES384), "Ed25519": oidctest.NewKey(t, oidc.EdDSA), "P-521": p521,
	}
	fits := map[oidc.Alg]string{oidc.RS256: "RSA", oidc.PS256: "RSA", oidc.ES256: "P-256",
		oidc.ES384: "P-384", oidc.EdDSA: "Ed25519"}
	all := []oidc.Alg{oidc.RS256, oidc.PS256, oidc.ES256, oidc.ES384, oidc.EdDSA}
	pairs := 0
	for _, alg := range all {
		j, err := oidc.ParseCompact(oidctest.Sign(t, alg, keys[fits[alg]], nil, map[string]any{"sub": "x"}))
		if err != nil {
			t.Fatal(err)
		}
		for name, k := range keys {
			key := oidc.Key{Pub: k.Public()}
			own := name == fits[alg]
			if key.Fits(alg) != own {
				t.Errorf("%s with a %s key: Fits is %v", alg, name, !own)
			}
			err := j.Verify(key, all)
			switch {
			case own && err != nil:
				t.Errorf("%s under its own %s key: %v", alg, name, err)
			case !own && !errors.Is(err, oidc.ErrAlgorithm):
				t.Errorf("%s under a %s key: %v, not ErrAlgorithm", alg, name, err)
			}
			if own {
				pairs++
			}
		}
	}
	if pairs != 5 {
		t.Fatalf("%d pairs fit, not 5", pairs)
	}
	// One RSA key, two algorithms: a JWK that declares the other is refused.
	rs, _ := oidc.ParseCompact(oidctest.Sign(t, oidc.RS256, keys["RSA"], nil, map[string]any{"sub": "x"}))
	if err := rs.Verify(oidc.Key{Alg: oidc.PS256, Pub: keys["RSA"].Public()}, all); !errors.Is(err, oidc.ErrAlgorithm) {
		t.Fatalf("an RS256 token under a JWK declaring PS256: %v", err)
	}
}

// String formats nothing a token carries: until Verify returns nil its alg
// is attacker text, up to MaxToken of it (Ruling 18; pre-flight M-1).
func TestAJWSStringSaysNothingItCarries(t *testing.T) {
	enc := func(v any) string { b, _ := json.Marshal(v); return base64.RawURLEncoding.EncodeToString(b) }
	j, err := oidc.ParseCompact(enc(map[string]any{"alg": "RS256\nport49-broker: forged"}) + "." +
		enc(map[string]any{"sub": "x"}) + ".c2ln")
	if err != nil {
		t.Fatal(err)
	}
	if s := j.String(); strings.Contains(s, "forged") || strings.Contains(s, "RS256") {
		t.Fatalf("String says the unverified alg: %q", s)
	}
}

// A header member is its exact name (RFC 7515 §4: names are case-sensitive),
// and a repeated member is refused whatever its case (I2).
func TestHeaderMembersAreExactAndNeverRepeated(t *testing.T) {
	enc := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	tok := func(h string) string { return enc(h) + "." + enc(`{"sub":"x"}`) + ".c2ln" }
	for name, h := range map[string]string{
		"ALG alone":             `{"ALG":"ES256"}`,
		"Alg alone":             `{"Alg":"ES256"}`,
		"alg twice, none first": `{"alg":"none","alg":"ES256"}`,
		"alg twice, same value": `{"alg":"ES256","alg":"ES256"}`,
		"kid twice":             `{"alg":"ES256","kid":"a","kid":"b"}`,
		"unknown member twice":  `{"alg":"ES256","x":1,"x":2}`,
		"a trailing value":      `{"alg":"ES256"} {}`,
		"a null header":         `null`,
		"a non-string alg":      `{"alg":5}`,
	} {
		if _, err := oidc.ParseCompact(tok(h)); !errors.Is(err, oidc.ErrMalformed) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A case variant is an unknown member: it neither supplies nor overrides.
	j, err := oidc.ParseCompact(tok(`{"alg":"RS256","Alg":"ES256","KID":"k","Typ":"t"}`))
	if err != nil || j.Header.Alg != oidc.RS256 || j.Header.Kid != "" || j.Header.Typ != "" {
		t.Fatalf("%+v, %v", j, err)
	}
	// CRIT is not crit: it is an unknown member.
	if _, err := oidc.ParseCompact(tok(`{"alg":"ES256","CRIT":["x"]}`)); err != nil {
		t.Fatalf("CRIT: %v", err)
	}
}

// An ECDSA signature in ASN.1 DER, the form most libraries emit, is not the
// r||s of RFC 7518 §3.4 and never verifies.
func TestADERECDSASignatureIsRefused(t *testing.T) {
	for _, alg := range []oidc.Alg{oidc.ES256, oidc.ES384} {
		k := oidctest.NewKey(t, alg).(*ecdsa.PrivateKey)
		good := oidctest.Sign(t, alg, k, nil, map[string]any{"sub": "x"})
		parts := strings.Split(good, ".")
		input := []byte(parts[0] + "." + parts[1])
		digest := func() []byte { d := sha256.Sum256(input); return d[:] }()
		if alg == oidc.ES384 {
			digest = func() []byte { d := sha512.Sum384(input); return d[:] }()
		}
		der, err := ecdsa.SignASN1(rand.Reader, k, digest)
		if err != nil {
			t.Fatal(err)
		}
		j, err := oidc.ParseCompact(parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(der))
		if err != nil {
			t.Fatal(err)
		}
		if err := j.Verify(oidc.Key{Pub: k.Public()}, []oidc.Alg{alg}); !errors.Is(err, oidc.ErrSignature) {
			t.Errorf("%s: a DER signature: %v", alg, err)
		}
	}
}

// A Key a caller builds by hand never panics Verify: Fits is false for a
// nil key and for an Ed25519 key of the wrong length (M7).
func TestAHandBuiltKeyFitsNothingUnlessItIsWhole(t *testing.T) {
	all := []oidc.Alg{oidc.RS256, oidc.PS256, oidc.ES256, oidc.ES384, oidc.EdDSA}
	for name, k := range map[string]oidc.Key{
		"no key":                 {},
		"a nil RSA key":          {Pub: (*rsa.PublicKey)(nil)},
		"an RSA key, no N":       {Pub: &rsa.PublicKey{E: 65537}},
		"a nil ECDSA key":        {Pub: (*ecdsa.PublicKey)(nil)},
		"an ECDSA key, no XY":    {Pub: &ecdsa.PublicKey{Curve: elliptic.P256()}},
		"an ECDSA key, no curve": {Pub: &ecdsa.PublicKey{}},
		"a 2-byte Ed25519 key":   {Pub: ed25519.PublicKey{1, 2}},
		"a 33-byte Ed25519 key":  {Pub: ed25519.PublicKey(make([]byte, 33))},
		"a nil Ed25519 key":      {Pub: ed25519.PublicKey(nil)},
	} {
		for _, a := range all {
			if k.Fits(a) {
				t.Errorf("%s fits %s", name, a)
			}
		}
		for _, a := range all {
			j, err := oidc.ParseCompact(oidctest.Sign(t, a, oidctest.NewKey(t, a), nil, map[string]any{"sub": "x"}))
			if err != nil {
				t.Fatal(err)
			}
			if err := j.Verify(k, all); !errors.Is(err, oidc.ErrAlgorithm) {
				t.Errorf("%s, %s token: %v", name, a, err)
			}
		}
	}
}
