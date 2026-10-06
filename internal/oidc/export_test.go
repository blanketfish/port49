package oidc

// NewJWSForTest is a JWS over an arbitrary signing input, so a test vector
// whose message is not a compact JWS's header.payload (Wycheproof's) reaches
// Verify. It is compiled into tests alone.
func NewJWSForTest(alg Alg, input, sig []byte) *JWS {
	return &JWS{Header: Header{Alg: alg}, input: input, sig: sig}
}
