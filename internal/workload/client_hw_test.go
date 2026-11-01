//go:build hwkey && hwkey_dlopen

package workload

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/hwkey"
	"github.com/blanketfish/port49/internal/hwkey/hwtest"
	"github.com/blanketfish/port49/internal/hwkey/pkcs11"
	"github.com/blanketfish/port49/internal/testpki"
)

// SoftHSM2 reads SOFTHSM2_CONF once, at C_Initialize: one configuration and
// token directory per test binary, set before a test runs.
func TestMain(m *testing.M) { os.Exit(hwtest.SoftHSMMain(m)) }

// A workload's --key may be a reference (ruling 21; pre-flight I7). Its PIN
// comes from the URI's pin-source alone: a workload has no terminal and no
// agent to ask, so a key that needs a PIN without one is refused, naming
// pin-source, and the PIN is in no text.
func TestAWorkloadKeyMayBeAReference(t *testing.T) {
	module, label := hwtest.SoftHSM(t)
	now := time.Now()
	s, err := pkcs11.Open(pkcs11.URI{Token: label, ID: []byte{1}, ModulePath: module}, []byte(hwtest.SoftHSMUserPIN))
	if err != nil {
		t.Fatal(err)
	}
	pub := s.Public()
	s.Close()
	ca, err := testpki.NewCA("workloads", now.Add(-time.Hour), now.Add(48*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(77),
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, pub, ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile := filepath.Join(dir, "w.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	pinFile := filepath.Join(dir, "pin")
	if err := os.WriteFile(pinFile, []byte(hwtest.SoftHSMUserPIN+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	base := "pkcs11:token=" + label + ";id=%01?module-path=" + module

	cert, err := LoadCertificate(certFile, base+"&pin-source=file://"+pinFile, now, nil)
	if err != nil {
		t.Fatal(err)
	}
	key, ok := cert.PrivateKey.(hwkey.Key)
	if !ok {
		t.Fatalf("the key is %T, not a hardware key", cert.PrivateKey)
	}
	t.Cleanup(func() { key.Close() })
	sum := sha256.Sum256([]byte("a handshake"))
	sig, err := key.Sign(rand.Reader, sum[:], crypto.SHA256)
	if err != nil || !ecdsa.VerifyASN1(pub.(*ecdsa.PublicKey), sum[:], sig) {
		t.Fatalf("the key the pin-source opened does not sign: %v", err)
	}

	_, err = LoadCertificate(certFile, base, now, nil)
	if err == nil || !strings.Contains(err.Error(), "pin-source") || strings.Contains(err.Error(), hwtest.SoftHSMUserPIN) {
		t.Fatalf("a reference needing a PIN with no pin-source: %v", err)
	}

	// The token says a try failed since the last success: the pin-source
	// PIN, which a timer would re-read on every run, is not tried (final
	// review client I5).
	restore := pkcs11.PINTriesLow(false)
	defer restore()
	before := hwtest.SoftHSMLoginAttempts(t)
	_, err = LoadCertificate(certFile, base+"&pin-source=file://"+pinFile, now, nil)
	if !errors.Is(err, pkcs11.ErrPINTriesLow) || hwtest.SoftHSMLoginAttempts(t) != before {
		t.Fatalf("a pin-source PIN while tries are low: %v (%d logins)", err, hwtest.SoftHSMLoginAttempts(t)-before)
	}
}
