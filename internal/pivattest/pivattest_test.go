package pivattest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/testpki"
)

type slotOpts struct {
	serial     int64
	pin, touch byte
	rawPolicy  []byte // used instead of pin and touch when set
	noPolicy   bool
	noSerial   bool
	rawSerial  []byte // used instead of serial when set
	notBefore  time.Time
	notAfter   time.Time
}

// deviceCert signs a v3 certificate with no basic constraints and no key
// usage, as some YubiKeys' f9 certificates are, under parent.
func deviceCert(t *testing.T, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, notBefore, notAfter time.Time) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:   pkix.Name{CommonName: "YubiKey PIV Attestation F9"},
		NotBefore: notBefore, NotAfter: notAfter}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if cert.BasicConstraintsValid {
		t.Fatal("the device certificate carries basic constraints; the test means it not to")
	}
	return cert, key
}

func yubicoLike(t *testing.T) (*testpki.CA, *x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	now := time.Now()
	root, err := testpki.NewCA("Yubico PIV Root", now.Add(-time.Hour), now.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	device, key := deviceCert(t, root.Cert, root.Key, now.Add(-time.Hour), now.Add(24*time.Hour))
	return root, device, key
}

func yubicoLikeWithIntermediate(t *testing.T) ([]byte, *x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	now := time.Now()
	root, err := testpki.NewCA("Yubico PIV Root", now.Add(-time.Hour), now.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	inter, err := root.IssueCA("Yubico PIV Intermediate", now.Add(-time.Hour), now.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	device, key := deviceCert(t, inter.Cert, inter.Key, now.Add(-time.Hour), now.Add(24*time.Hour))
	return append(root.PEM(), inter.PEM()...), device, key
}

func otherDevice(t *testing.T, root *testpki.CA) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	now := time.Now()
	return deviceCert(t, root.Cert, root.Key, now.Add(-time.Hour), now.Add(24*time.Hour))
}

func slotCert(t *testing.T, device *x509.Certificate, deviceKey *ecdsa.PrivateKey, o slotOpts) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var exts []pkix.Extension
	if !o.noSerial {
		v := o.rawSerial
		if v == nil {
			v, err = asn1.Marshal(big.NewInt(o.serial))
			if err != nil {
				t.Fatal(err)
			}
		}
		exts = append(exts, pkix.Extension{Id: oidSerial, Value: v})
	}
	if !o.noPolicy {
		v := o.rawPolicy
		if v == nil {
			v = []byte{o.pin, o.touch}
		}
		exts = append(exts, pkix.Extension{Id: oidPolicy, Value: v})
	}
	nb, na := o.notBefore, o.notAfter
	if nb.IsZero() {
		nb = time.Now().Add(-time.Hour)
	}
	if na.IsZero() {
		na = time.Now().Add(24 * time.Hour)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "YubiKey PIV Attestation 9a"},
		NotBefore: nb, NotAfter: na, ExtraExtensions: exts}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, device, &key.PublicKey, deviceKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestVerify(t *testing.T) {
	root, device, deviceKey := yubicoLike(t)
	roots := Anchors{Roots: x509.NewCertPool(), Intermediates: x509.NewCertPool()}
	roots.Roots.AddCert(root.Cert)
	now := time.Now()
	slot := slotCert(t, device, deviceKey, slotOpts{serial: 12345678, pin: 0x02, touch: TouchAlways})
	a, err := Verify(roots, device, slot, now)
	if err != nil || a.Serial != 12345678 || a.TouchPolicy != TouchAlways || a.PINPolicy != 0x02 {
		t.Fatalf("Verify = %+v, %v", a, err)
	}
	if a.Device != device {
		t.Error("Attestation.Device is not the f9 certificate")
	}
	if pub, ok := a.Key.(*ecdsa.PublicKey); !ok || !pub.Equal(slot.PublicKey) {
		t.Errorf("Attestation.Key is not the slot's key: %T", a.Key)
	}

	// A three-level hierarchy (root, intermediate, f9), the anchors file
	// holding both: verifies; holding the root alone: refused.
	both, device3, deviceKey3 := yubicoLikeWithIntermediate(t)
	anchors, err := ParseAnchors(both)
	if err != nil {
		t.Fatal(err)
	}
	slot3 := slotCert(t, device3, deviceKey3, slotOpts{serial: 7, pin: 2, touch: TouchAlways})
	if _, err := Verify(anchors, device3, slot3, now); err != nil {
		t.Fatalf("three levels with the intermediate listed: %v", err)
	}
	if _, err := Verify(Anchors{Roots: anchors.Roots}, device3, slot3, now); err == nil {
		t.Fatal("three levels verified with the intermediate missing")
	}

	other, otherKey := otherDevice(t, root)
	for _, bad := range []struct {
		name  string
		slot  *x509.Certificate
		roots Anchors
		now   time.Time
	}{
		{"another root", slot, Anchors{Roots: x509.NewCertPool()}, now},
		{"no roots at all", slot, Anchors{}, now},
		{"a slot another device signed", slotCert(t, other, otherKey, slotOpts{serial: 1, pin: 2, touch: TouchAlways}), roots, now},
		{"a key policy of three bytes", slotCert(t, device, deviceKey, slotOpts{rawPolicy: []byte{2, 2, 2}}), roots, now},
		{"a key policy of one byte", slotCert(t, device, deviceKey, slotOpts{rawPolicy: []byte{2}}), roots, now},
		{"no key policy", slotCert(t, device, deviceKey, slotOpts{noPolicy: true}), roots, now},
		{"an unknown touch byte", slotCert(t, device, deviceKey, slotOpts{pin: 2, touch: 0x09}), roots, now},
		{"an unknown pin byte", slotCert(t, device, deviceKey, slotOpts{pin: 0x00, touch: 2}), roots, now},
		{"no serial", slotCert(t, device, deviceKey, slotOpts{noSerial: true, pin: 2, touch: 2}), roots, now},
		{"a negative serial", slotCert(t, device, deviceKey, slotOpts{serial: -1, pin: 2, touch: 2}), roots, now},
		{"a serial over 32 bits", slotCert(t, device, deviceKey, slotOpts{serial: 1 << 32, pin: 2, touch: 2}), roots, now},
		{"a serial with trailing bytes", slotCert(t, device, deviceKey, slotOpts{rawSerial: []byte{2, 1, 7, 0}, pin: 2, touch: 2}), roots, now},
		{"a serial that is not an integer", slotCert(t, device, deviceKey, slotOpts{rawSerial: []byte{4, 1, 7}, pin: 2, touch: 2}), roots, now},
		{"an expired slot", slotCert(t, device, deviceKey, slotOpts{serial: 1, pin: 2, touch: 2,
			notBefore: now.Add(-48 * time.Hour), notAfter: now.Add(-24 * time.Hour)}), roots, now},
		{"a slot not yet valid", slotCert(t, device, deviceKey, slotOpts{serial: 1, pin: 2, touch: 2,
			notBefore: now.Add(24 * time.Hour), notAfter: now.Add(48 * time.Hour)}), roots, now},
		{"a zero clock", slot, roots, time.Time{}},
	} {
		if _, err := Verify(bad.roots, device, bad.slot, bad.now); err == nil {
			t.Errorf("%s: verified", bad.name)
		}
	}
	if _, err := Verify(roots, nil, slot, now); err == nil {
		t.Error("a nil device verified")
	}
	if _, err := Verify(roots, device, nil, now); err == nil {
		t.Error("a nil slot verified")
	}
}

// TestNilRootsAreRefusedBeforeAnyChainCheck: with a nil Roots pool x509.Verify
// falls back to the system roots, where a public-CA leaf the attacker holds a
// key for would pass as a "device". Verify must refuse before it gets there.
func TestNilRootsAreRefusedBeforeAnyChainCheck(t *testing.T) {
	_, device, deviceKey := yubicoLike(t)
	slot := slotCert(t, device, deviceKey, slotOpts{serial: 1, pin: 2, touch: TouchAlways})
	for name, a := range map[string]Anchors{"zero": {}, "intermediates only": {Intermediates: x509.NewCertPool()}} {
		if _, err := Verify(a, device, slot, time.Now()); !errors.Is(err, errNoRoots) {
			t.Errorf("%s: err = %v, want errNoRoots", name, err)
		}
	}
}

func TestAZeroClockIsRefusedByName(t *testing.T) {
	root, device, deviceKey := yubicoLike(t)
	slot := slotCert(t, device, deviceKey, slotOpts{serial: 1, pin: 2, touch: TouchAlways})
	if _, err := Verify(Anchors{Roots: root.Pool()}, device, slot, time.Time{}); !errors.Is(err, errNoClock) {
		t.Errorf("err = %v, want errNoClock", err)
	}
}

// TestADuplicateExtensionIsRefused: ParseCertificate rejects duplicates, so the
// certificate is built by hand; its signature still covers the original TBS.
func TestADuplicateExtensionIsRefused(t *testing.T) {
	root, device, deviceKey := yubicoLike(t)
	roots := Anchors{Roots: root.Pool()}
	slot := slotCert(t, device, deviceKey, slotOpts{serial: 1, pin: 2, touch: TouchAlways})
	if _, err := Verify(roots, device, slot, time.Now()); err != nil {
		t.Fatalf("control: %v", err)
	}
	dup := *slot
	dup.Extensions = append(append([]pkix.Extension{}, slot.Extensions...),
		pkix.Extension{Id: oidPolicy, Value: []byte{PINOnce, TouchNever}})
	if _, err := Verify(roots, device, &dup, time.Now()); err == nil || !strings.Contains(err.Error(), "twice") {
		t.Errorf("err = %v, want the twice error", err)
	}
}

// TestTheDeviceCertificateIsCheckedAtTheInjectedClock: the slot stays valid
// past the device certificate's NotAfter, so only the device check can refuse.
func TestTheDeviceCertificateIsCheckedAtTheInjectedClock(t *testing.T) {
	root, device, deviceKey := yubicoLike(t)
	roots := Anchors{Roots: root.Pool()}
	now := time.Now()
	slot := slotCert(t, device, deviceKey, slotOpts{serial: 1, pin: 2, touch: 2, notAfter: now.Add(96 * time.Hour)})
	if _, err := Verify(roots, device, slot, now); err != nil {
		t.Fatalf("control: %v", err)
	}
	_, err := Verify(roots, device, slot, now.Add(48*time.Hour))
	if err == nil || !strings.Contains(err.Error(), "device certificate") {
		t.Errorf("err = %v, want the device certificate refused", err)
	}
}

func TestTheSlotValidityErrorNamesTheTimes(t *testing.T) {
	root, device, deviceKey := yubicoLike(t)
	now := time.Now()
	slot := slotCert(t, device, deviceKey, slotOpts{serial: 1, pin: 2, touch: 2,
		notBefore: now.Add(-48 * time.Hour), notAfter: now.Add(-24 * time.Hour)})
	_, err := Verify(Anchors{Roots: root.Pool()}, device, slot, now)
	if err == nil {
		t.Fatal("an expired slot verified")
	}
	for _, want := range []time.Time{now, slot.NotBefore, slot.NotAfter} {
		if !strings.Contains(err.Error(), want.UTC().Format(time.RFC3339)) {
			t.Errorf("err = %q, missing %s", err, want.UTC().Format(time.RFC3339))
		}
	}
}

func TestASlotMustNameTheDeviceAsItsIssuer(t *testing.T) {
	root, device, deviceKey := yubicoLike(t)
	roots := Anchors{Roots: root.Pool()}
	slot := slotCert(t, device, deviceKey, slotOpts{serial: 1, pin: 2, touch: TouchAlways})
	if _, err := Verify(roots, device, slot, time.Now()); err != nil {
		t.Fatalf("control: %v", err)
	}
	// The signature still covers the original TBS, so only the issuer link refuses.
	wrong := *slot
	wrong.RawIssuer = []byte("another issuer")
	if _, err := Verify(roots, device, &wrong, time.Now()); !errors.Is(err, errIssuerMismatch) {
		t.Errorf("err = %v, want errIssuerMismatch", err)
	}
}

// TestAnAnchorWithoutTheCABitIsStillARoot: trust comes from the operator
// listing the certificate, not from its basic constraints.
func TestAnAnchorWithoutTheCABitIsStillARoot(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "no CA bit"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	if c, _ := x509.ParseCertificate(der); c.BasicConstraintsValid {
		t.Fatal("the certificate has basic constraints; the test means it not to")
	}
	a, err := ParseAnchors(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Roots.Subjects()) != 1 || len(a.Intermediates.Subjects()) != 0 { //nolint:staticcheck // counting only
		t.Errorf("roots %d, intermediates %d; want 1 and 0", len(a.Roots.Subjects()), len(a.Intermediates.Subjects())) //nolint:staticcheck
	}
}

// TestAForgedExtensionOnAnUnverifiedSlotIsNotRead: a slot certificate carrying
// perfect extensions but signed by a key no anchor vouches for is refused, so
// the extensions are never trusted before the chain verifies.
func TestAForgedExtensionOnAnUnverifiedSlotIsNotRead(t *testing.T) {
	root, device, _ := yubicoLike(t)
	roots := Anchors{Roots: root.Pool()}
	// The attacker's own "device", self-made, signs a slot claiming touch always.
	_, evilDevice, evilKey := yubicoLike(t)
	slot := slotCert(t, evilDevice, evilKey, slotOpts{serial: 1, pin: 2, touch: TouchAlways})
	if _, err := Verify(roots, evilDevice, slot, time.Now()); err == nil {
		t.Fatal("a device under another root verified")
	}
	// The real device certificate with the attacker's slot: the signature fails.
	if _, err := Verify(roots, device, slot, time.Now()); err == nil {
		t.Fatal("a slot signed by another device verified under the real device")
	}
}

func TestParseAnchors(t *testing.T) {
	both, _, _ := yubicoLikeWithIntermediate(t)
	a, err := ParseAnchors(both)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Roots.Subjects()) != 1 || len(a.Intermediates.Subjects()) != 1 { //nolint:staticcheck // counting only
		t.Errorf("roots %d, intermediates %d; want 1 and 1", len(a.Roots.Subjects()), len(a.Intermediates.Subjects())) //nolint:staticcheck
	}
	for name, in := range map[string][]byte{
		"empty":       nil,
		"no PEM":      []byte("not a certificate"),
		"a bad body":  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("junk")}),
		"a key block": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("x")}),
		"a key block after the certificates": append(append([]byte{}, both...),
			pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("x")})...),
	} {
		if _, err := ParseAnchors(in); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
	// Text outside the PEM blocks is ignored, as openssl does: a comment
	// appended to the bundle must not take touch away fleet-wide.
	commented := append([]byte("# Yubico PIV root\n"), both...)
	commented = append(commented, []byte("# trailing comment\n")...)
	a, err = ParseAnchors(commented)
	if err != nil {
		t.Fatalf("a bundle with comments: %v", err)
	}
	if len(a.Roots.Subjects()) != 1 || len(a.Intermediates.Subjects()) != 1 { //nolint:staticcheck // counting only
		t.Error("comments changed what the bundle holds")
	}
	// Only an intermediate: no root, an error.
	root, err := testpki.NewCA("r", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	inter, err := root.IssueCA("i", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseAnchors(inter.PEM()); err == nil {
		t.Error("an intermediate alone parsed as anchors")
	}
}
