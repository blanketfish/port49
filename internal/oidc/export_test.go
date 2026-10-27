package oidc

// NewJWSForTest is a JWS over an arbitrary signing input, so a test vector
// whose message is not a compact JWS's header.payload (Wycheproof's) reaches
// Verify. It is compiled into tests alone.
func NewJWSForTest(alg Alg, input, sig []byte) *JWS {
	return &JWS{Header: Header{Alg: alg}, input: input, sig: sig}
}

// SetLoadForTest points a key set at another file, for a restore over a set
// already held.
func (s *KeySet) SetLoadForTest(load func() ([]byte, error)) { s.c.Load = load }

// SetAfterFirstTryForTest runs f in Key between its first look at the set
// and the minute gate, where another caller's fetch can land.
func (s *KeySet) SetAfterFirstTryForTest(f func()) { s.afterFirstTry = f }

// WaitDiscoveryForTest waits for the discovery reads a fetch started, which
// run after Fetch returns.
func (s *KeySet) WaitDiscoveryForTest() { s.WaitNotes() }
