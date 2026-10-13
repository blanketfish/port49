package pkcs11

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"testing"
)

func TestRawECDSAToDER(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sum := sha256.Sum256([]byte("port49"))
	for i := 0; i < 64; i++ {
		r, s, err := ecdsa.Sign(rand.Reader, key, sum[:])
		if err != nil {
			t.Fatal(err)
		}
		raw := make([]byte, 64)
		r.FillBytes(raw[:32])
		s.FillBytes(raw[32:])
		der, err := rawECDSAToDER(raw, 32)
		if err != nil {
			t.Fatal(err)
		}
		if !ecdsa.VerifyASN1(&key.PublicKey, sum[:], der) {
			t.Fatalf("round %d: the DER form does not verify", i)
		}
	}
	if _, err := rawECDSAToDER(make([]byte, 63), 32); err == nil {
		t.Fatal("an odd-length signature was taken")
	}
}
