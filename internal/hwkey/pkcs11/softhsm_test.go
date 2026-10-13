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

// A URI no present token matches is ErrKeyAbsent that carries what is present
// (label, serial, manufacturer: never a PIN or an object), so the caller can
// tell a token that is out from a reference that is wrong; with the token
// unplugged nothing is present.
func TestOpenWithNoMatchingTokenSaysWhatIsPresent(t *testing.T) {
	module, label := hwtest.SoftHSM(t)
	wrong := uriFor(t, module, label+"-typo")
	_, err := pkcs11.Open(wrong, nil)
	var nm *hwkey.NoMatchError
	if !errors.Is(err, hwkey.ErrKeyAbsent) || !errors.As(err, &nm) {
		t.Fatalf("Open = %v, want ErrKeyAbsent carrying the tokens present", err)
	}
	found := false
	for _, ti := range nm.Present {
		found = found || ti.Label == label && ti.Serial != ""
	}
	if !found {
		t.Fatalf("the tokens present %+v do not include %q with its serial", nm.Present, label)
	}
	hwtest.SoftHSMUnplug(t, label)
	_, err = pkcs11.Open(uriFor(t, module, label), nil)
	if !errors.As(err, &nm) || len(nm.Present) != 0 {
		t.Fatalf("with the token out: %v, present %+v", err, nm)
	}
}

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

// A PIN no person typed (pin-source) never reaches C_Login while the token
// says a try failed since the last success, or one try is left: a timer
// re-reading a wrong file would block the token in three runs. A typed PIN is
// tried as before, and with the flags clear so is the unattended one (final
// review client I5).
func TestAnUnattendedPINIsNotTriedWhileTriesAreLow(t *testing.T) {
	module, label := hwtest.SoftHSM(t)
	for _, final := range []bool{false, true} {
		restore := pkcs11.PINTriesLow(final)
		before := hwtest.SoftHSMLoginAttempts(t)
		s, err := pkcs11.OpenUnattended(uriFor(t, module, label), pin())
		if err == nil {
			s.Close()
		}
		if !errors.Is(err, pkcs11.ErrPINTriesLow) || !strings.Contains(err.Error(), "port49 login") ||
			!strings.Contains(err.Error(), "ykman piv info") ||
			!strings.Contains(err.Error(), "will not spend one unattended. Run `port49 login` at a terminal and type the PIN") {
			restore()
			t.Fatalf("final %v: OpenUnattended = %v, want ErrPINTriesLow", final, err)
		}
		if got := hwtest.SoftHSMLoginAttempts(t) - before; got != 0 {
			restore()
			t.Fatalf("final %v: the unattended PIN reached C_Login %d time(s)", final, got)
		}
		s, err = pkcs11.Open(uriFor(t, module, label), pin())
		restore()
		if err != nil || s.State() != hwkey.Present {
			t.Fatalf("final %v: a typed PIN while tries are low: %v", final, err)
		}
		s.Close()
	}
	s, err := pkcs11.OpenUnattended(uriFor(t, module, label), pin())
	if err != nil || s.State() != hwkey.Present {
		t.Fatalf("an unattended PIN with the flags clear: %v", err)
	}
	s.Close()
}

// A token whose PIN-tries state cannot be read is no token whose tries are
// known to be fine: the unattended PIN is not tried, no C_Login is made, and
// the refusal says why. A typed PIN is not held up by it (final re-review N2).
func TestAnUnreadableTriesStateFailsAnUnattendedPINClosed(t *testing.T) {
	module, label := hwtest.SoftHSM(t)
	restore := pkcs11.PINTriesUnreadable()
	before := hwtest.SoftHSMLoginAttempts(t)
	s, err := pkcs11.OpenUnattended(uriFor(t, module, label), pin())
	if err == nil {
		s.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "could not read the token's PIN-tries state") ||
		!strings.Contains(err.Error(), "run again") {
		restore()
		t.Fatalf("OpenUnattended with an unreadable state = %v", err)
	}
	if got := hwtest.SoftHSMLoginAttempts(t) - before; got != 0 {
		restore()
		t.Fatalf("the unattended PIN reached C_Login %d time(s)", got)
	}
	s, err = pkcs11.Open(uriFor(t, module, label), pin())
	restore()
	if err != nil || s.State() != hwkey.Present {
		t.Fatalf("a typed PIN with an unreadable state: %v", err)
	}
	s.Close()
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

// plugged is a token carrying an imported key and its certificate, as a PIV
// token does, and the means to take it away and bring it back.
type plugged struct {
	t      *testing.T
	module string
	label  string
	u      pkcs11.URI
	key    *ecdsa.PrivateKey
	cert   *x509.Certificate
}

func newPlugged(t *testing.T) *plugged {
	t.Helper()
	module, label := hwtest.SoftHSMBare(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := &plugged{t: t, module: module, label: label, u: uriFor(t, module, label), key: key}
	p.cert = newCA(t).issue(t, "alice", &key.PublicKey, x509.ExtKeyUsageClientAuth)
	p.plug()
	return p
}

func (p *plugged) plug() {
	p.t.Helper()
	hwtest.SoftHSMImport(p.t, p.label, p.key)
	if err := pkcs11.StoreCertificate(p.u, p.cert, pin()); err != nil {
		p.t.Fatal(err)
	}
}

// Two Signers on one token re-probe side by side (touch_key and issued_key,
// decision 45). A Signer must not close, on a later re-probe, the session
// handle it lost with the token: the module may have given the number to the
// other Signer's new session.
func TestAStaleSessionHandleIsNotClosedAgain(t *testing.T) {
	p := newPlugged(t)
	a, err := pkcs11.Open(p.u, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := pkcs11.Open(p.u, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	for _, s := range []*pkcs11.Signer{a, b} {
		if err := s.Unlock(pin()); err != nil {
			t.Fatal(err)
		}
	}
	lost := pkcs11.SessionHandle(a)
	digest := sha256.Sum256([]byte("port49"))
	hwtest.SoftHSMUnplug(t, p.label)
	for _, s := range []*pkcs11.Signer{a, b} {
		if _, err := s.Sign(rand.Reader, digest[:], crypto.SHA256); !errors.Is(err, hwkey.ErrKeyAbsent) {
			t.Fatalf("Sign with the token gone = %v, want ErrKeyAbsent", err)
		}
	}
	hwtest.SoftHSMReinit(t, p.label)
	p.plug()
	// b reopens first, so its new session takes the number a lost; a's
	// re-probe then holds a stale a.session equal to b's live one.
	for _, s := range []*pkcs11.Signer{b, a} {
		if got := s.State(); got != hwkey.Locked {
			t.Fatalf("the token is back and State says %v, want locked", got)
		}
	}
	if err := b.Unlock(pin()); err != nil {
		t.Fatal(err)
	}
	if got := pkcs11.SessionHandle(b); got != lost {
		t.Fatalf("precondition: b's new session is %d, not the %d a lost; the module did not reuse the number, so this test checks nothing", got, lost)
	}
	if _, err := b.Sign(rand.Reader, digest[:], crypto.SHA256); err != nil {
		t.Fatalf("b's session was closed by a's re-probe: %v", err)
	}
}

// C_CloseSession is called with the module's session lock released (Task 3's
// re-review): a module that blocks in it must not hold every Signer's gate.
func TestCloseSessionRunsWithTheSessionLockReleased(t *testing.T) {
	p := newPlugged(t)
	s, err := pkcs11.Open(p.u, nil)
	if err != nil {
		t.Fatal(err)
	}
	var calls, held int
	restore := pkcs11.SessMuHeldDuringClose(func(h bool) {
		calls++
		if h {
			held++
		}
	})
	defer restore()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || held != 0 {
		t.Fatalf("C_CloseSession ran %d times, %d of them with the session lock held", calls, held)
	}
}

// A Signer that learns of the loss late, after another has reopened under the
// number it lost, must neither use nor close that session (re-review I1).
func TestALateLearnerDoesNotTouchAnotherSignersSession(t *testing.T) {
	p := newPlugged(t)
	a, err := pkcs11.Open(p.u, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := pkcs11.Open(p.u, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	for _, s := range []*pkcs11.Signer{a, b} {
		if err := s.Unlock(pin()); err != nil {
			t.Fatal(err)
		}
	}
	lost := pkcs11.SessionHandle(a)
	digest := sha256.Sum256([]byte("port49"))
	hwtest.SoftHSMUnplug(t, p.label)
	// Only b signs during the outage, so only b sees the loss.
	if _, err := b.Sign(rand.Reader, digest[:], crypto.SHA256); !errors.Is(err, hwkey.ErrKeyAbsent) {
		t.Fatalf("b's Sign with the token gone = %v, want ErrKeyAbsent", err)
	}
	hwtest.SoftHSMReinit(t, p.label)
	p.plug()
	if got := b.State(); got != hwkey.Locked {
		t.Fatalf("the token is back and b's State says %v, want locked", got)
	}
	if err := b.Unlock(pin()); err != nil {
		t.Fatal(err)
	}
	if got := pkcs11.SessionHandle(b); got != lost {
		t.Fatalf("precondition: b's new session is %d, not the %d a lost; the module did not reuse the number, so this test checks nothing", got, lost)
	}
	// a knows nothing of the outage: it must see that its number is b's now and
	// reopen on a session of its own (Locked), not send a call on b's.
	_, err = a.Sign(rand.Reader, digest[:], crypto.SHA256)
	if !errors.Is(err, hwkey.ErrLocked) {
		t.Fatalf("a's late Sign = %v, want ErrLocked (the token is back and a is not logged in)", err)
	}
	if got := pkcs11.SessionHandle(a); got == pkcs11.SessionHandle(b) {
		t.Fatalf("a and b both hold session %d", got)
	}
	if _, err := b.Sign(rand.Reader, digest[:], crypto.SHA256); err != nil {
		t.Fatalf("b's session was used or closed by a's late detection: %v", err)
	}
}

// A stranger's token under the same label, with a different key and
// certificate under the same id, is not this key: State stays Absent and
// Unlock spends no PIN try on it.
func TestAStrangersKeyUnderTheSameLabelAndIDIsNotThisKey(t *testing.T) {
	p := newPlugged(t)
	s, err := pkcs11.Open(p.u, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Unlock(pin()); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("port49"))
	hwtest.SoftHSMUnplug(t, p.label)
	if _, err := s.Sign(rand.Reader, digest[:], crypto.SHA256); !errors.Is(err, hwkey.ErrKeyAbsent) {
		t.Fatalf("Sign with the token gone = %v, want ErrKeyAbsent", err)
	}
	// Another token with the label and id 01, holding another key.
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hwtest.SoftHSMReinit(t, p.label)
	hwtest.SoftHSMImport(t, p.label, other)
	cert := newCA(t).issue(t, "mallory", &other.PublicKey, x509.ExtKeyUsageClientAuth)
	if err := pkcs11.StoreCertificate(p.u, cert, pin()); err != nil {
		t.Fatal(err)
	}
	if got := s.State(); got != hwkey.Absent {
		t.Fatalf("another key came back under the label and id and State says %v, want absent", got)
	}
	before := hwtest.SoftHSMLoginAttempts(t)
	if err := s.Unlock(pin()); !errors.Is(err, hwkey.ErrKeyAbsent) {
		t.Fatalf("Unlock = %v, want ErrKeyAbsent", err)
	}
	if got := hwtest.SoftHSMLoginAttempts(t) - before; got != 0 {
		t.Fatalf("Unlock spent %d PIN tries on another key's token", got)
	}
}

// A token that comes back under the label but is not the one that left is
// not this key's: State must not say Locked for it, or Unlock would spend a
// PIN try on a stranger (review M6).
func TestAnotherTokenUnderTheSameLabelIsNotThisKey(t *testing.T) {
	p := newPlugged(t)
	s, err := pkcs11.Open(p.u, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Unlock(pin()); err != nil {
		t.Fatal(err)
	}
	hwtest.SoftHSMUnplug(t, p.label)
	digest := sha256.Sum256([]byte("port49"))
	if _, err := s.Sign(rand.Reader, digest[:], crypto.SHA256); !errors.Is(err, hwkey.ErrKeyAbsent) {
		t.Fatalf("Sign with the token gone = %v, want ErrKeyAbsent", err)
	}
	// A blank token with the same label: a new serial, no key, no certificate.
	hwtest.SoftHSMReinit(t, p.label)
	if got := s.State(); got != hwkey.Absent {
		t.Fatalf("a blank token with the same label came back and State says %v, want absent", got)
	}
	before := hwtest.SoftHSMLoginAttempts(t)
	if err := s.Unlock(pin()); !errors.Is(err, hwkey.ErrKeyAbsent) {
		t.Fatalf("Unlock = %v, want ErrKeyAbsent", err)
	}
	if got := hwtest.SoftHSMLoginAttempts(t) - before; got != 0 {
		t.Fatalf("Unlock spent %d PIN tries on another token", got)
	}
}

// The PIN is zeroed by the call that was given it, whatever the token said.
func TestThePINBufferIsZeroedAfterOpenAndUnlock(t *testing.T) {
	module, label := hwtest.SoftHSM(t)
	zero := func(what string, b []byte) {
		t.Helper()
		for _, c := range b {
			if c != 0 {
				t.Fatalf("%s left the PIN buffer as %v", what, b)
			}
		}
	}
	buf := pin()
	s, err := pkcs11.Open(uriFor(t, module, label), buf)
	if err != nil {
		t.Fatal(err)
	}
	zero("Open", buf)
	s.Close() // the last session closing logs the token out

	// Open with a wrong PIN fails and still zeroes it.
	bad := []byte("000000")
	if s2, err := pkcs11.Open(uriFor(t, module, label), bad); err == nil {
		s2.Close()
		t.Fatal("Open with a wrong PIN succeeded")
	}
	zero("a failed Open", bad)

	s, err = pkcs11.Open(uriFor(t, module, label), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	wrong := []byte("000000")
	var pe *hwkey.PINError
	if err := s.Unlock(wrong); !errors.As(err, &pe) {
		t.Fatalf("Unlock(wrong) = %v, want a *PINError", err)
	}
	zero("a failed Unlock", wrong)
	right := pin()
	if err := s.Unlock(right); err != nil {
		t.Fatal(err)
	}
	zero("Unlock", right)
}
