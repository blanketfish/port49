package mfatouch

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
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
