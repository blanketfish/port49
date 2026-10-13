//go:build hwkey && hwkey_dlopen

package pkcs11_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/hwkey"
	"github.com/rhwendt/port49/internal/hwkey/hwtest"
	"github.com/rhwendt/port49/internal/hwkey/pkcs11"
	"github.com/rhwendt/port49/internal/pivattest"
)

// libykcs11 reports an untouched sign as CKR_USER_NOT_LOGGED_IN after about
// 14.4s while the token stays logged in (L60, 2026-10-13). A not-logged-in
// that took 5s or more is a touch timeout; one that answers at once is a lock.
func signAfter(t *testing.T, took time.Duration) (s *pkcs11.Signer, err error, calls func() int) {
	t.Helper()
	return signWith(t, nil, "C_Sign", took)
}

// attestation is a slot attestation object to put on the token before the key
// is opened: its subject CN and the touch policy byte of its Yubico policy
// extension (1.3.6.1.4.1.41482.3.8, PIN policy once then the touch byte).
type attestation struct {
	cn    string
	touch byte
}

func storeAttestation(t *testing.T, module, label string, a attestation) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: a.cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 8},
			Value: []byte{pivattest.PINOnce, a.touch}}},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if err := pkcs11.StoreCertificate(uriFor(t, module, label), cert, pin()); err != nil {
		t.Fatal(err)
	}
}

// signWith is signAfter on a token that holds att (when set), with fn the
// module function that answers not-logged-in.
func signWith(t *testing.T, att *attestation, fn string, took time.Duration) (s *pkcs11.Signer, err error, calls func() int) {
	t.Helper()
	module, label := hwtest.SoftHSM(t)
	if att != nil {
		storeAttestation(t, module, label, *att)
	}
	s, err = pkcs11.Open(uriFor(t, module, label), pin())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	calls, restore := pkcs11.FakeSignAs(s, fn, pkcs11.RVUserNotLoggedIn, took)
	t.Cleanup(restore)
	_, err = s.Sign(nil, make([]byte, 32), crypto.SHA256)
	return s, err, calls
}

// A key whose slot attestation says touch never has no touch to miss: a
// not-logged-in is a lock however long it took (a slow transport must not
// turn the PIN prompt into "touch the key" forever). Always and cached keep
// the timing rule, and so does a token with no attestation.
func TestATouchNeverKeysSlowNotLoggedInIsStillALock(t *testing.T) {
	s, err, _ := signWith(t, &attestation{"YubiKey PIV Attestation 9a", pivattest.TouchNever}, "C_Sign", 14400*time.Millisecond)
	if !errors.Is(err, hwkey.ErrLocked) || errors.Is(err, hwkey.ErrTouchTimeout) || s.State() != hwkey.Locked {
		t.Fatalf("Sign = %v (state %v), want ErrLocked and Locked", err, s.State())
	}
}

func TestATouchAlwaysOrCachedKeysSlowNotLoggedInIsATouchTimeout(t *testing.T) {
	for name, touch := range map[string]byte{"always": pivattest.TouchAlways, "cached": pivattest.TouchCached} {
		s, err, _ := signWith(t, &attestation{"YubiKey PIV Attestation 9c", touch}, "C_Sign", 14400*time.Millisecond)
		if !errors.Is(err, hwkey.ErrTouchTimeout) || s.State() != hwkey.Present {
			t.Errorf("touch %s: Sign = %v (state %v), want ErrTouchTimeout and Present", name, err, s.State())
		}
	}
}

// Only a certificate named as a slot attestation tells the policy: the slot's
// own certificate (or any other on the id) that happens to say touch never is
// not read, and the timing rule stands.
func TestACertificateThatIsNotASlotAttestationSaysNothingOfTouch(t *testing.T) {
	_, err, _ := signWith(t, &attestation{"alice", pivattest.TouchNever}, "C_Sign", 14400*time.Millisecond)
	if !errors.Is(err, hwkey.ErrTouchTimeout) {
		t.Fatalf("Sign = %v, want ErrTouchTimeout (the object is not an attestation)", err)
	}
}

// libykcs11 gives a slot's attestation certificate the same CKA_ID as the
// slot's own certificate (measured on a YubiKey 5C Nano FIPS, 2026-10-13). It
// is never the client certificate, alone or beside the real one in either order.
func TestASlotAttestationIsNeverTheSlotsCertificate(t *testing.T) {
	att := attestation{"YubiKey PIV Attestation 9a", pivattest.TouchNever}
	for _, order := range []string{"attestation alone", "attestation then certificate", "certificate then attestation"} {
		module, label := hwtest.SoftHSM(t)
		s, err := pkcs11.Open(uriFor(t, module, label), pin())
		if err != nil {
			t.Fatal(err)
		}
		real := newCA(t).issue(t, "alice", s.Public(), x509.ExtKeyUsageClientAuth)
		storeReal := func() {
			if err := pkcs11.StoreCertificate(uriFor(t, module, label), real, pin()); err != nil {
				t.Fatal(err)
			}
		}
		switch order {
		case "attestation alone":
			storeAttestation(t, module, label, att)
		case "attestation then certificate":
			storeAttestation(t, module, label, att)
			storeReal()
		case "certificate then attestation":
			storeReal()
			storeAttestation(t, module, label, att)
		}
		got, err := s.Certificate()
		if order == "attestation alone" {
			if err == nil {
				t.Errorf("%s: Certificate() = %q, want an error (the slot holds no certificate)", order, got.Subject.CommonName)
			}
		} else if err != nil || !got.Equal(real) {
			t.Errorf("%s: Certificate() = %v, %v, want the real certificate", order, got, err)
		}
		s.Close()
	}
}

// A slow not-logged-in from another call (C_SignInit) is not a missed touch:
// only C_Sign waits for one.
func TestASlowNotLoggedInFromCSignInitIsNotATouchTimeout(t *testing.T) {
	s, err, _ := signWith(t, nil, "C_SignInit", 14400*time.Millisecond)
	if !errors.Is(err, hwkey.ErrLocked) || errors.Is(err, hwkey.ErrTouchTimeout) || s.State() != hwkey.Locked {
		t.Fatalf("Sign = %v (state %v), want ErrLocked and Locked", err, s.State())
	}
}

func TestAnUntouchedSignThatTook14sIsATouchTimeoutAndTheKeyStaysUnlocked(t *testing.T) {
	s, err, calls := signAfter(t, 14400*time.Millisecond)
	if !errors.Is(err, hwkey.ErrTouchTimeout) || errors.Is(err, hwkey.ErrLocked) {
		t.Fatalf("Sign = %v, want ErrTouchTimeout", err)
	}
	if s.State() != hwkey.Present {
		t.Fatalf("state %v after a touch timeout, want Present", s.State())
	}
	if got, want := err.Error(), "hwkey: no touch within 15s; touch the key when it blinks and try again"; got != want {
		t.Fatalf("message %q, want %q", got, want)
	}
	// The next Sign asks the token again instead of refusing at once.
	if calls() != 1 {
		t.Fatalf("%d C_Sign calls, want 1", calls())
	}
	s.Sign(nil, make([]byte, 32), crypto.SHA256)
	if calls() != 2 {
		t.Fatalf("%d C_Sign calls after a second Sign, want 2", calls())
	}
}

func TestANotLoggedInAnsweredAtOnceIsLockedAndTheNextSignRefusesWithoutTheToken(t *testing.T) {
	s, err, calls := signAfter(t, 0)
	if !errors.Is(err, hwkey.ErrLocked) || errors.Is(err, hwkey.ErrTouchTimeout) {
		t.Fatalf("Sign = %v, want ErrLocked", err)
	}
	if s.State() != hwkey.Locked {
		t.Fatalf("state %v, want Locked", s.State())
	}
	if _, err := s.Sign(nil, make([]byte, 32), crypto.SHA256); !errors.Is(err, hwkey.ErrLocked) || calls() != 1 {
		t.Fatalf("second Sign = %v after %d C_Sign calls, want ErrLocked with 1", err, calls())
	}
}

func TestExactlyFiveSecondsIsATouchTimeoutAndJustUnderIsNot(t *testing.T) {
	if _, err, _ := signAfter(t, 5*time.Second); !errors.Is(err, hwkey.ErrTouchTimeout) {
		t.Fatalf("a not-logged-in after exactly 5s: %v, want ErrTouchTimeout", err)
	}
	if s, err, _ := signAfter(t, 5*time.Second-time.Nanosecond); !errors.Is(err, hwkey.ErrLocked) || s.State() != hwkey.Locked {
		t.Fatalf("a not-logged-in after just under 5s: %v, want ErrLocked", err)
	}
}
