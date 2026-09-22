// Package token defines the device token: a keyed device tag followed by a
// random secret (design §8 "Device binding"), and the Minter that issues them.
package token

import (
	"crypto/hmac"
	"crypto/sha256"
	"io"
	"math/big"
)

// TagLen, SecretLen, and Len are the fixed sizes of the token format: a
// device tag followed by a random secret, with no separator and no prefix.
const (
	TagLen    = 6
	SecretLen = 24
	Len       = TagLen + SecretLen
)

const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// TagKey derives the tag key from the current encryption-at-rest key so no new
// secret has to be distributed (design §8: "the same place the RFC 8907 shared
// keys already live"). It is derived rather than reused so that a compromise of
// one does not hand over the other in usable form.
func TagKey(currentEncryptionKey []byte) []byte {
	m := hmac.New(sha256.New, currentEncryptionKey)
	m.Write([]byte("port49/tag"))
	return m.Sum(nil)
}

// Tag is the first six characters of every token minted for deviceName. A
// daemon computes its own once and compares it before any store access, so a
// token cut for another device is recognized rather than merely absent.
func Tag(tagKey []byte, deviceName string) string {
	m := hmac.New(sha256.New, tagKey)
	m.Write([]byte(deviceName))
	return Base62(m.Sum(nil))[:TagLen]
}

// New mints a token: the device's tag followed by SecretLen random characters.
func New(r io.Reader, tagKey []byte, deviceName string) (string, error) {
	secret := make([]byte, SecretLen)
	for i := range secret {
		n, err := randInt(r, len(alphabet))
		if err != nil {
			return "", err
		}
		secret[i] = alphabet[n]
	}
	return Tag(tagKey, deviceName) + string(secret), nil
}

// Parse returns the tag of a presented credential if it has the token shape.
// A credential that is not token-shaped — a mistyped password — returns false
// and is never reported as a wrong device.
func Parse(presented []byte) (string, bool) {
	if len(presented) != Len {
		return "", false
	}
	for _, c := range presented {
		if !isAlphabet(c) {
			return "", false
		}
	}
	return string(presented[:TagLen]), true
}

// isAlphabet reports whether c is one of the base62 alphabet characters.
func isAlphabet(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
}

// Base62 encodes bytes as a big-endian integer in the alphabet. Not
// length-preserving; used for tags, where only the prefix matters.
func Base62(b []byte) string {
	n := new(big.Int).SetBytes(b)
	if n.Sign() == 0 {
		return "0"
	}
	base := big.NewInt(int64(len(alphabet)))
	var out []byte
	mod := new(big.Int)
	for n.Sign() > 0 {
		n.DivMod(n, base, mod)
		out = append([]byte{alphabet[mod.Int64()]}, out...)
	}
	return string(out)
}

// randInt returns a uniform integer in [0, n) by rejection sampling: a plain
// modulo would bias the alphabet, and 143 bits of secret is the only thing
// standing between a guess and a device.
func randInt(r io.Reader, n int) (int, error) {
	limit := 256 - 256%n
	var b [1]byte
	for {
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return 0, err
		}
		if int(b[0]) < limit {
			return int(b[0]) % n, nil
		}
	}
}
