//go:build hwkey && hwkey_dlopen

package pkcs11_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/hwkey"
	"github.com/rhwendt/port49/internal/hwkey/hwtest"
	"github.com/rhwendt/port49/internal/hwkey/pkcs11"
)

func uriFor(t *testing.T, module, label string) pkcs11.URI {
	t.Helper()
	u, err := pkcs11.ParseURI("pkcs11:token=" + label + ";id=%01?module-path=" + module)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func pin() []byte { return []byte(hwtest.SoftHSMUserPIN) }

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "port49 test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCA{c, key}
}

// issue signs a leaf for pub.
func (ca *testCA) issue(t *testing.T, cn string, pub crypto.PublicKey, usage x509.ExtKeyUsage) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, pub, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// assertMutualTLS runs an httptest TLS 1.3 server that requires a client
// certificate signed by a test CA for s.Public(), and connects with s behind
// tls.Certificate.
func assertMutualTLS(t *testing.T, s *pkcs11.Signer) {
	t.Helper()
	ca := newCA(t)
	srvKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	srvCert := ca.issue(t, "server", &srvKey.PublicKey, x509.ExtKeyUsageServerAuth)
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.TLS.PeerCertificates) != 1 || r.TLS.PeerCertificates[0].Subject.CommonName != "alice" {
			http.Error(w, "no client certificate", http.StatusForbidden)
		}
	}))
	srv.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{{Certificate: [][]byte{srvCert.Raw}, PrivateKey: srvKey}},
		ClientAuth:   tls.RequireAndVerifyClientCert, ClientCAs: pool,
	}
	srv.StartTLS()
	defer srv.Close()

	leaf := ca.issue(t, "alice", s.Public(), x509.ExtKeyUsageClientAuth)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS13, RootCAs: pool,
		Certificates: []tls.Certificate{{Certificate: [][]byte{leaf.Raw}, PrivateKey: s}},
	}}}
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("the mutual TLS 1.3 handshake with the token's key: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.TLS.Version != tls.VersionTLS13 {
		t.Fatalf("status %d, TLS version %x", resp.StatusCode, resp.TLS.Version)
	}
}

func TestASoftHSMKeySignsATLSHandshakeAndARefresh(t *testing.T) {
	module, label := hwtest.SoftHSM(t)
	gen, create := pkcs11.GenerateKeyPairCalls(), pkcs11.CreateObjectCalls()
	s, err := pkcs11.Open(uriFor(t, module, label), pin())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.State() != hwkey.Present {
		t.Fatalf("a PIN given at Open: state %v", s.State())
	}
	// A refresh signature verifies with the public key, as the broker
	// verifies it (api.RefreshAlgorithm).
	msg := api.RefreshMessage(make([]byte, api.RefreshNonceLen), make([]byte, 32))
	sig, err := api.SignRefresh(s, msg)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(msg)
	if !ecdsa.VerifyASN1(s.Public().(*ecdsa.PublicKey), sum[:], sig) {
		t.Fatal("the refresh signature does not verify")
	}
	// A TLS 1.3 mutual handshake with the key behind tls.Certificate.
	assertMutualTLS(t, s)
	// port49 signs; it never generates a key or writes an object.
	if g, c := pkcs11.GenerateKeyPairCalls()-gen, pkcs11.CreateObjectCalls()-create; g != 0 || c != 0 {
		t.Fatalf("Open and Sign made %d C_GenerateKeyPair and %d C_CreateObject calls", g, c)
	}
}

func TestAWrongPINIsTriedOnce(t *testing.T) {
	module, label := hwtest.SoftHSM(t)
	s, err := pkcs11.Open(uriFor(t, module, label), nil)
	if err != nil {
		t.Fatalf("Open with no PIN: %v", err)
	}
	defer s.Close()
	if s.State() != hwkey.Locked {
		t.Fatalf("Open with no PIN: state %v, want Locked", s.State())
	}
	if _, err := s.Sign(rand.Reader, make([]byte, 32), crypto.SHA256); !errors.Is(err, hwkey.ErrLocked) {
		t.Fatalf("Sign while locked = %v, want ErrLocked", err)
	}
	before := hwtest.SoftHSMLoginAttempts(t)
	var pe *hwkey.PINError
	if err := s.Unlock([]byte("000000")); !errors.As(err, &pe) {
		t.Fatalf("Unlock(wrong) = %v, want a *PINError", err)
	}
	if got := hwtest.SoftHSMLoginAttempts(t) - before; got != 1 {
		t.Fatalf("the module saw %d logins, want 1", got)
	}
	if err := s.Unlock(pin()); err != nil || s.State() != hwkey.Present {
		t.Fatalf("Unlock(right) = %v, state %v", err, s.State())
	}
	if _, err := s.Sign(rand.Reader, make([]byte, 32), crypto.SHA256); err != nil {
		t.Fatalf("Sign after Unlock: %v", err)
	}
}

func TestTwoTokensHoldingTheIDAreRefused(t *testing.T) {
	module, label1 := hwtest.SoftHSM(t)
	_, label2 := hwtest.SoftHSM(t)
	u, err := pkcs11.ParseURI("pkcs11:id=%01?module-path=" + module)
	if err != nil {
		t.Fatal(err)
	}
	s, err := pkcs11.Open(u, nil)
	if err == nil {
		s.Close()
		t.Fatal("two tokens hold id 01 and Open took one")
	}
	for _, l := range []string{label1, label2} {
		if !strings.Contains(err.Error(), l) {
			t.Fatalf("the refusal does not name %s: %v", l, err)
		}
	}
}

func TestTheCertificateComesFromTheToken(t *testing.T) {
	module, label := hwtest.SoftHSM(t)
	s, err := pkcs11.Open(uriFor(t, module, label), pin())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.Certificate(); err == nil {
		t.Fatal("a token with no certificate object returned one")
	}
	ca := newCA(t)
	cert := ca.issue(t, "alice", s.Public(), x509.ExtKeyUsageClientAuth)
	if err := pkcs11.StoreCertificate(uriFor(t, module, label), cert, pin()); err != nil {
		t.Fatal(err)
	}
	got, err := s.Certificate()
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(cert) {
		t.Fatal("Certificate() is not the object the harness wrote")
	}
	if pub := got.PublicKey.(*ecdsa.PublicKey); !pub.Equal(s.Public()) {
		t.Fatal("the certificate's key is not the signer's")
	}
	all, err := s.Certificates()
	if err != nil || len(all) != 1 {
		t.Fatalf("Certificates() = %d, %v", len(all), err)
	}
	if s.TokenSerial() == "" {
		t.Fatal("no token serial")
	}
}

// The held connection never drops, so no handshake signs: State must see the
// token come back with nothing signing between (pre-flight C2).
func TestAReinsertedTokenIsSeenByState(t *testing.T) {
	module, label := hwtest.SoftHSMBare(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	u := uriFor(t, module, label)
	ca := newCA(t)
	cert := ca.issue(t, "alice", &key.PublicKey, x509.ExtKeyUsageClientAuth)
	// An imported key has no public object on the token: the certificate is
	// what shows it, as a PIV token's does.
	plug := func() {
		hwtest.SoftHSMImport(t, label, key)
		if err := pkcs11.StoreCertificate(u, cert, pin()); err != nil {
			t.Fatal(err)
		}
	}
	plug()
	s, err := pkcs11.Open(u, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Unlock(pin()); err != nil || s.State() != hwkey.Present {
		t.Fatalf("Unlock = %v, state %v", err, s.State())
	}
	digest := sha256.Sum256([]byte("port49"))
	if _, err := s.Sign(rand.Reader, digest[:], crypto.SHA256); err != nil {
		t.Fatal(err)
	}

	hwtest.SoftHSMUnplug(t, label)
	if _, err := s.Sign(rand.Reader, digest[:], crypto.SHA256); !errors.Is(err, hwkey.ErrKeyAbsent) {
		t.Fatalf("Sign with the token gone = %v, want ErrKeyAbsent", err)
	}
	if got := s.State(); got != hwkey.Absent {
		t.Fatalf("the token is gone: state %v", got)
	}

	// Back, with the same key, and nothing signing in between.
	hwtest.SoftHSMReinit(t, label)
	plug()
	if got := s.State(); got != hwkey.Locked {
		t.Fatalf("the token is back and State says %v, want locked", got)
	}
	if err := s.Unlock(pin()); err != nil || s.State() != hwkey.Present {
		t.Fatalf("Unlock after the return = %v, state %v", err, s.State())
	}
	sig, err := s.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil || !ecdsa.VerifyASN1(&key.PublicKey, digest[:], sig) {
		t.Fatalf("Sign after the return: %v", err)
	}
}
