package clientkey

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// pair writes a self-signed certificate for certKey and the PEM of keyKey as
// the key file, in a 0700 directory, and returns both paths.
func pair(t *testing.T, certKey, keyKey *ecdsa.PrivateKey) (certPath, keyPath string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "op"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &certKey.PublicKey, certKey)
	if err != nil {
		t.Fatal(err)
	}
	kder, err := x509.MarshalPKCS8PrivateKey(keyKey)
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath = filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

func genKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// A path goes to keyfile unchanged, so a file key under a certificate for
// another key is refused as it is today.
func TestLoadPairRefusesAMismatchedCertificate(t *testing.T) {
	a, b := genKey(t), genKey(t)
	certPath, keyPath := pair(t, a, b)
	if _, err := LoadPair(certPath, keyPath, nil); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("a certificate for another key: %v", err)
	}
	certPath, keyPath = pair(t, a, a)
	if c, err := LoadPair(certPath, keyPath, nil); err != nil || len(c.Certificate) != 1 {
		t.Fatalf("a matching pair: %v", err)
	}
}

func TestOpenRefusesAnUnknownScheme(t *testing.T) {
	_, err := Open("yubikey:slot=9a", nil)
	if err == nil || !strings.Contains(err.Error(), "yubikey:") {
		t.Fatalf("%v", err)
	}
	if _, err := Open("/a/path/to/a.key", nil); err == nil {
		t.Fatal("a path is not a key reference")
	}
}

func TestStoreOfNamesTheStoreNeverTheReference(t *testing.T) {
	for ref, want := range map[string]string{
		"pkcs11:token=YubiKey%20PIV%20%2312345678;id=%01": "pkcs11",
		"tpm:file=/home/u/.port49/k.tpm":                  "tpm",
		"secure-enclave:label=x":                          "secure_enclave",
		"/home/u/.port49/key.pem":                         "file",
		"":                                                "file",
	} {
		if got := StoreOf(ref); got != want {
			t.Errorf("StoreOf(%q) = %q, want %q", ref, got, want)
		}
	}
}
