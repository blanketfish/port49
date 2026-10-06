package oidc

import "net/url"

// NewJWSForTest is a JWS over an arbitrary signing input, so a test vector
// whose message is not a compact JWS's header.payload (Wycheproof's) reaches
// Verify. It is compiled into tests alone.
func NewJWSForTest(alg Alg, input, sig []byte) *JWS {
	return &JWS{Header: Header{Alg: alg}, input: input, sig: sig}
}

// ParseProxyForTest is parseProxy, for the proxy table.
func ParseProxyForTest(raw string) (*url.URL, error) { return parseProxy(raw) }

// SetLoadForTest points a key set at another file, for a restore over a set
// already held.
func (s *KeySet) SetLoadForTest(load func() ([]byte, error)) { s.c.Load = load }
