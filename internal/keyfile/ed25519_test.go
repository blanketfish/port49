package keyfile

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func writeKey(t *testing.T, body []byte, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "signing.key")
	if err := os.WriteFile(p, body, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestAnEd25519KeyRoundTrips(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	privPEM, pubPEM, err := EncodeEd25519(priv)
	if err != nil {
		t.Fatal(err)
	}
	got, err := LoadEd25519(writeKey(t, privPEM, 0o600))
	if err != nil || !got.Equal(priv) {
		t.Fatalf("private: %v", err)
	}
	pubPath := filepath.Join(t.TempDir(), "signing.pub")
	if err := os.WriteFile(pubPath, pubPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	pub, err := ParseEd25519Public(pubPEM, pubPath)
	if err != nil || !pub.Equal(priv.Public()) {
		t.Fatalf("public: %v", err)
	}
	if id := Ed25519KeyID(pub); !regexp.MustCompile(`^ed25519:[0-9a-f]{16}$`).MatchString(id) {
		t.Fatalf("key id %q", id)
	}
}

// The signing key is read as every private key is: owner-only.
func TestAGroupReadableSigningKeyIsRefused(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	privPEM, _, _ := EncodeEd25519(priv)
	if _, err := LoadEd25519(writeKey(t, privPEM, 0o640)); err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Fatalf("got %v", err)
	}
}

// A key of another kind, and a file that is not a key, are refused, and the
// refusal never quotes the file: it may be a secret pasted in the wrong place.
func TestAnythingButAnEd25519KeyIsRefusedWithoutEchoingIt(t *testing.T) {
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(ec)
	for name, body := range map[string][]byte{
		"ecdsa":   pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}),
		"garbage": []byte("SECRET-hunter2-not-a-key\n"),
		"broken":  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("SECRET-bytes")}),
	} {
		_, err := LoadEd25519(writeKey(t, body, 0o600))
		if err == nil || strings.Contains(err.Error(), "SECRET") {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := ParseEd25519Public([]byte("SECRET-not-a-public-key"), "x.pub"); err == nil ||
		strings.Contains(err.Error(), "SECRET") {
		t.Errorf("public: %v", err)
	}
}

// A key file is one block and nothing else: pem.Decode skips text before a
// block and returns what follows it, so a second key concatenated into one
// verify key file would otherwise be dropped without a word.
func TestAKeyFileHoldsOneBlockAndNothingElse(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	privPEM, pubPEM, _ := EncodeEd25519(priv)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	otherPriv, otherPub, _ := EncodeEd25519(other)
	cat := func(parts ...[]byte) []byte { return bytes.Join(parts, nil) }
	for name, c := range map[string]struct {
		priv, pub []byte
		want      string
	}{
		"a second block": {cat(privPEM, otherPriv), cat(pubPEM, otherPub), "more than one PEM block"},
		"text after":     {cat(privPEM, []byte("SECRET-trailer\n")), cat(pubPEM, []byte("SECRET-trailer\n")), "more than one PEM block"},
		"text before":    {cat([]byte("SECRET-preamble\n"), privPEM), cat([]byte("SECRET-preamble\n"), pubPEM), "text before its PEM block"},
	} {
		if _, err := LoadEd25519(writeKey(t, c.priv, 0o600)); err == nil || !strings.Contains(err.Error(), c.want) ||
			strings.Contains(err.Error(), "SECRET") {
			t.Errorf("%s, private: %v", name, err)
		}
		if _, err := ParseEd25519Public(c.pub, "x.pub"); err == nil || !strings.Contains(err.Error(), c.want) ||
			strings.Contains(err.Error(), "SECRET") {
			t.Errorf("%s, public: %v", name, err)
		}
	}
	// Surrounding whitespace is no text.
	if _, err := ParseEd25519Public(cat([]byte("\n  \n"), pubPEM, []byte("\n\n")), "x.pub"); err != nil {
		t.Errorf("whitespace: %v", err)
	}
}

// A verify key of another kind, and the private half handed over by
// mistake, are refused.
func TestAVerifyKeyMustBeAnEd25519PublicKey(t *testing.T) {
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(ec.Public())
	if _, err := ParseEd25519Public(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), "x.pub"); err == nil ||
		!strings.Contains(err.Error(), "not ed25519") {
		t.Errorf("ecdsa: %v", err)
	}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	privPEM, _, _ := EncodeEd25519(priv)
	if _, err := ParseEd25519Public(privPEM, "x.pub"); err == nil || !strings.Contains(err.Error(), "no PUBLIC KEY block") {
		t.Errorf("private: %v", err)
	}
}
