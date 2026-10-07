package oidc

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"slices"
	"strings"
)

// Alg is a JWS algorithm a verifier may pin (Ruling 3).
type Alg string

const (
	RS256 Alg = "RS256"
	PS256 Alg = "PS256"
	ES256 Alg = "ES256"
	ES384 Alg = "ES384"
	EdDSA Alg = "EdDSA"
)

var known = []Alg{RS256, PS256, ES256, ES384, EdDSA}

// MaxToken bounds a token before anything reads it.
const MaxToken = 16 << 10

var (
	// ErrMalformed is a token that is not one compact JWS: the wrong number
	// of parts (five is an encrypted token), a part that is not base64url
	// without padding, a header that is not a JSON object with an alg, no
	// signature, or more than MaxToken bytes.
	ErrMalformed = errors.New("oidc: not a compact JWS")
	// ErrAlgorithm is an algorithm the verifier does not pin, or one its key
	// is not for.
	ErrAlgorithm = errors.New("oidc: an algorithm the verifier does not accept for this key")
	// ErrSignature is a signature the key does not verify.
	ErrSignature = errors.New("oidc: the signature does not verify")
	// ErrCrit is a header naming a critical extension: none is understood,
	// so none may be ignored (RFC 7515 §4.1.11).
	ErrCrit = errors.New("oidc: the header names a critical extension")
)

// ParseAlgs is a verifier's algorithms list: RS256 alone when none is
// given (OpenID Connect Core §15.1), and a refusal naming why for none,
// an HMAC, or anything not in the five.
func ParseAlgs(names []string) ([]Alg, error) {
	if len(names) == 0 {
		return []Alg{RS256}, nil
	}
	var out []Alg
	for _, n := range names {
		switch {
		case strings.EqualFold(n, "none"):
			return nil, fmt.Errorf("%s is refused: an unsigned token is anyone's (RFC 8725 §3.2)", n)
		case strings.HasPrefix(strings.ToUpper(n), "HS"):
			return nil, fmt.Errorf("%s is refused: a shared-secret signature lets anyone holding the secret "+
				"sign as the provider (RFC 8725 §3.2)", n)
		case !slices.Contains(known, Alg(n)):
			return nil, fmt.Errorf("%s: one of RS256, PS256, ES256, ES384 or EdDSA", n)
		}
		if !slices.Contains(out, Alg(n)) {
			out = append(out, Alg(n))
		}
	}
	return out, nil
}

// Header is what port49 reads of a protected header. jku, jwk, x5u and x5c
// are not fields: a key a token names for itself is never used (RFC 8725
// §3.10).
type Header struct {
	Alg Alg    `json:"alg"`
	Kid string `json:"kid,omitempty"`
	Typ string `json:"typ,omitempty"`
}

// JWS is one compact JWS, parsed, its signature not yet verified: nothing
// in Header or Payload may be trusted or said until Verify returns nil.
type JWS struct {
	Header  Header
	Payload []byte
	input   []byte
	sig     []byte
}

// String withholds the header, the payload and the signature: until Verify
// returns nil the alg is attacker text (Ruling 18).
func (j *JWS) String() string { return fmt.Sprintf("JWS{%d payload bytes}", len(j.Payload)) }

// ParseCompact splits raw into a JWS, refusing anything that is not one
// (ErrMalformed) and a crit header (ErrCrit). It verifies nothing.
func ParseCompact(raw string) (*JWS, error) {
	if len(raw) > MaxToken {
		return nil, fmt.Errorf("%w: over %d bytes", ErrMalformed, MaxToken)
	}
	// Go's base64 decoder skips CR and LF even when Strict, so a token with
	// one inside a part would decode, and verify, as the same token: refuse
	// every byte base64url and the separator do not use.
	for i := 0; i < len(raw); i++ {
		if c := raw[i]; !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return nil, fmt.Errorf("%w: a byte outside base64url", ErrMalformed)
		}
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: %d parts, not 3 (an encrypted token is refused)", ErrMalformed, len(parts))
	}
	dec := base64.RawURLEncoding.Strict()
	hb, err1 := dec.DecodeString(parts[0])
	pb, err2 := dec.DecodeString(parts[1])
	sig, err3 := dec.DecodeString(parts[2])
	if errors.Join(err1, err2, err3) != nil {
		return nil, fmt.Errorf("%w: a part is not base64url without padding", ErrMalformed)
	}
	if len(sig) == 0 {
		return nil, fmt.Errorf("%w: no signature", ErrMalformed)
	}
	fields, err := exactObject(hb)
	if err != nil {
		return nil, fmt.Errorf("%w: the header is not a JSON object of distinct members", ErrMalformed)
	}
	if _, ok := fields["crit"]; ok {
		return nil, ErrCrit
	}
	// Members are read by exact name (RFC 7515 §4): "ALG" is not "alg".
	var h Header
	if json.Unmarshal(fields["alg"], &h.Alg) != nil || h.Alg == "" {
		return nil, fmt.Errorf("%w: the header has no alg string", ErrMalformed)
	}
	for name, dst := range map[string]*string{"kid": &h.Kid, "typ": &h.Typ} {
		if raw, ok := fields[name]; ok && json.Unmarshal(raw, dst) != nil {
			return nil, fmt.Errorf("%w: the header's %s is not a string", ErrMalformed, name)
		}
	}
	return &JWS{Header: h, Payload: pb, input: []byte(parts[0] + "." + parts[1]), sig: sig}, nil
}

// Verify checks j's signature with k: the header's alg must be one of
// algs, k must be a key of that algorithm's type, and k's own Alg, when
// its JWK named one, must be the same.
//
// ECDSA signatures are malleable ((r, s) and (r, n-s) both verify, and
// Wycheproof marks both valid): nothing may treat a hash of the raw token
// as the token's identity.
func (j *JWS) Verify(k Key, algs []Alg) error {
	a := j.Header.Alg
	if !slices.Contains(algs, a) || !k.Fits(a) || (k.Alg != "" && k.Alg != a) {
		return ErrAlgorithm
	}
	ok := false
	switch a {
	case RS256, PS256:
		pub := k.Pub.(*rsa.PublicKey)
		sum := sha256.Sum256(j.input)
		if a == RS256 {
			ok = rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], j.sig) == nil
		} else {
			ok = rsa.VerifyPSS(pub, crypto.SHA256, sum[:], j.sig,
				&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}) == nil
		}
	case ES256, ES384:
		pub := k.Pub.(*ecdsa.PublicKey)
		size := (pub.Curve.Params().BitSize + 7) / 8
		if len(j.sig) != 2*size {
			return ErrSignature
		}
		r, s := new(big.Int).SetBytes(j.sig[:size]), new(big.Int).SetBytes(j.sig[size:])
		if a == ES256 {
			sum := sha256.Sum256(j.input)
			ok = ecdsa.Verify(pub, sum[:], r, s)
		} else {
			sum := sha512.Sum384(j.input)
			ok = ecdsa.Verify(pub, sum[:], r, s)
		}
	case EdDSA:
		ok = ed25519.Verify(k.Pub.(ed25519.PublicKey), j.input, j.sig)
	}
	if !ok {
		return ErrSignature
	}
	return nil
}

// exactObject is the members of the JSON object b by exact name. A repeated
// member, whatever its value, is an error: which of two a consumer reads is
// a difference between parsers (RFC 7515 §5.2; RFC 8725 §3.9 is the class).
func exactObject(b []byte) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return nil, errors.New("not an object")
	}
	m := map[string]json.RawMessage{}
	for dec.More() {
		t, err := dec.Token()
		name, ok := t.(string)
		if err != nil || !ok {
			return nil, errors.New("bad member name")
		}
		if _, dup := m[name]; dup {
			return nil, errors.New("repeated member")
		}
		var v json.RawMessage
		if dec.Decode(&v) != nil {
			return nil, errors.New("bad member value")
		}
		m[name] = v
	}
	if t, err := dec.Token(); err != nil || t != json.Delim('}') {
		return nil, errors.New("unterminated object")
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("data after the object")
	}
	return m, nil
}
