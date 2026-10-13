package pkcs11

import (
	"errors"
	"math/big"

	"golang.org/x/crypto/cryptobyte"
)

// rawECDSAToDER turns the r‖s a token returns (each size bytes, big endian,
// zero padded) into the DER SEQUENCE of two INTEGERs Go's ecdsa.VerifyASN1
// and TLS read.
func rawECDSAToDER(raw []byte, size int) ([]byte, error) {
	if size <= 0 || len(raw) != 2*size {
		return nil, errors.New("pkcs11: the token's ECDSA signature is not r‖s of the curve's size")
	}
	r := new(big.Int).SetBytes(raw[:size])
	s := new(big.Int).SetBytes(raw[size:])
	var b cryptobyte.Builder
	b.AddASN1(0x30, func(b *cryptobyte.Builder) {
		b.AddASN1BigInt(r)
		b.AddASN1BigInt(s)
	})
	return b.Bytes()
}
