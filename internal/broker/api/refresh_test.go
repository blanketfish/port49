package api

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// selfSigned is a certificate for signer's key, signed by itself.
func selfSigned(t *testing.T, signer crypto.Signer) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "refresh"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, signer.Public(), signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// A refresh signed by each key type verifies with the algorithm
// RefreshAlgorithm names for it, and a one-byte change to the message does
// not.
func TestSignRefreshVerifiesForEachKeyType(t *testing.T) {
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rs, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for name, signer := range map[string]crypto.Signer{"ecdsa_p256": ec, "rsa_2048": rs, "ed25519": ed} {
		t.Run(name, func(t *testing.T) {
			cert := selfSigned(t, signer)
			alg, ok := RefreshAlgorithm(cert.PublicKey)
			if !ok {
				t.Fatalf("no algorithm for %T", cert.PublicKey)
			}
			msg := RefreshMessage(bytes.Repeat([]byte{1}, RefreshNonceLen), bytes.Repeat([]byte{2}, 32))
			sig, err := SignRefresh(signer, msg)
			if err != nil {
				t.Fatal(err)
			}
			if err := cert.CheckSignature(alg, msg, sig); err != nil {
				t.Fatalf("a correct signature: %v", err)
			}
			msg[len(msg)-1] ^= 1
			if cert.CheckSignature(alg, msg, sig) == nil {
				t.Fatal("a signature verified over a changed message")
			}
		})
	}
}

// The message is the context string, the nonce and the exporter value, in
// that order: 26 + 32 + 32 bytes.
func TestRefreshMessageLayout(t *testing.T) {
	nonce := bytes.Repeat([]byte{0xaa}, RefreshNonceLen)
	ekm := bytes.Repeat([]byte{0xbb}, 32)
	msg := RefreshMessage(nonce, ekm)
	want := append(append([]byte("port49 session refresh v1\x00"), nonce...), ekm...)
	if len(msg) != 26+32+32 || !bytes.Equal(msg, want) {
		t.Fatalf("%d bytes %x", len(msg), msg)
	}
}

func TestRefreshAlgorithmRefusesAnUnknownKey(t *testing.T) {
	if _, ok := RefreshAlgorithm(struct{}{}); ok {
		t.Fatal("an unknown key type has an algorithm")
	}
}
