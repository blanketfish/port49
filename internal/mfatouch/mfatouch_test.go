package mfatouch

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/pivattest"
	"github.com/rhwendt/port49/internal/testpki"
)

func key(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// The chain is [touch slot, f9 device, session slot] whatever order the token
// lists its objects in, and any of the three missing is ErrNoAttestation.
func TestChainIsTouchDeviceSessionInThatOrder(t *testing.T) {
	piv, err := testpki.NewPIV(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	touch, session := key(t), key(t)
	touchAtt, err := piv.Slot(&touch.PublicKey, pivattest.TouchAlways)
	if err != nil {
		t.Fatal(err)
	}
	sessionAtt, err := piv.Slot(&session.PublicKey, pivattest.TouchNever)
	if err != nil {
		t.Fatal(err)
	}
	all := []*x509.Certificate{sessionAtt, piv.Device, touchAtt}
	got, err := Chain(all, &touch.PublicKey, &session.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	for i, want := range []*x509.Certificate{touchAtt, piv.Device, sessionAtt} {
		if got[i] != base64.RawURLEncoding.EncodeToString(want.Raw) {
			t.Errorf("chain[%d] is not the %s", i, []string{"touch slot", "device", "session slot"}[i])
		}
	}
	for name, list := range map[string][]*x509.Certificate{
		"no touch slot":   {sessionAtt, piv.Device},
		"no session slot": {touchAtt, piv.Device},
		"no device":       {touchAtt, sessionAtt},
		"none":            nil,
	} {
		if _, err := Chain(list, &touch.PublicKey, &session.PublicKey); !errors.Is(err, ErrNoAttestation) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A slot that holds its own certificate beside its attestation, both with the
// slot's key (spec ruling 2's fleet shape): the attestation is the one the f9
// device certificate issued, whichever the token lists first (final review I1).
func TestChainPicksTheAttestationNotTheSlotsOwnCertificate(t *testing.T) {
	piv, err := testpki.NewPIV(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	touch, session := key(t), key(t)
	touchAtt, err := piv.Slot(&touch.PublicKey, pivattest.TouchAlways)
	if err != nil {
		t.Fatal(err)
	}
	sessionAtt, err := piv.Slot(&session.PublicKey, pivattest.TouchNever)
	if err != nil {
		t.Fatal(err)
	}
	own := func(k *ecdsa.PrivateKey, cn string) *x509.Certificate {
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: cn},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
		if err != nil {
			t.Fatal(err)
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	client, touchOwn := own(session, "alice"), own(touch, "touch")
	// Named for the device but signed by the session key itself.
	parent := &x509.Certificate{RawSubject: piv.Device.RawSubject}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(8), Subject: pkix.Name{CommonName: "forged"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &session.PublicKey, session)
	if err != nil {
		t.Fatal(err)
	}
	forged, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	for name, list := range map[string][]*x509.Certificate{
		"own certificates first": {forged, client, touchOwn, sessionAtt, piv.Device, touchAtt},
		"own certificates last":  {sessionAtt, piv.Device, touchAtt, client, touchOwn},
	} {
		got, err := Chain(list, &touch.PublicKey, &session.PublicKey)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		for i, want := range []*x509.Certificate{touchAtt, piv.Device, sessionAtt} {
			if got[i] != base64.RawURLEncoding.EncodeToString(want.Raw) {
				t.Errorf("%s: chain[%d] is not the %s", name, i, []string{"touch slot", "device", "session slot"}[i])
			}
		}
	}
}

func TestChallengeIsExactlyThirtyTwoBytes(t *testing.T) {
	ok := base64.RawURLEncoding.EncodeToString(make([]byte, api.MFAChallengeLen))
	if _, err := Challenge(ok); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "AAAA", ok + "A", "not base64 !"} {
		if _, err := Challenge(bad); err == nil {
			t.Errorf("%q was taken", bad)
		}
	}
}
