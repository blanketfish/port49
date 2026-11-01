//go:build l60probe

// The L60 attestation probe as it ran on 2026-10-13 (tests/lab/results/L60-ser8.md),
// kept as the capture of that run. It is package pkcs11 and calls the module's
// unexported functions, so it builds only as a file of internal/hwkey/pkcs11:
// it ran through `go test -tags hwkey_dlopen -overlay` with this file mapped to
// internal/hwkey/pkcs11/l60_probe_test.go and the build tag removed. The
// l60probe tag keeps it out of every other build, `make test` included. It
// opens a read-only session, logs in to nothing and writes nothing. The roots
// file was Yubico's https://developers.yubico.com/PKI/yubico-piv-ca-1.pem.
// Its output names the device serial; that output is kept locally, not here.

package pkcs11

import (
	"crypto/x509"
	"os"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/pivattest"
)

// TestL60ProbeAttestationObjects lists the certificate objects libykcs11
// exposes in a read-only session with no login, and verifies each slot
// attestation against the f9 certificate and Yubico's root. Lab probe only;
// lives in scratch and runs through -overlay.
func TestL60ProbeAttestationObjects(t *testing.T) {
	m, err := Load("/usr/lib/x86_64-linux-gnu/libykcs11.so")
	if err != nil {
		t.Fatal(err)
	}
	slots, err := m.slotList()
	if err != nil || len(slots) != 1 {
		t.Fatalf("slots %v, err %v", slots, err)
	}
	s, err := m.openSession(slots[0], false)
	if err != nil {
		t.Fatal(err)
	}
	defer m.closeSession(s)
	objs, err := m.findObjects(s, []attr{{ckaClass, uintBytes(ckoCertificate)}})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%d certificate objects with no login", len(objs))
	certs := map[string]*x509.Certificate{}
	for _, o := range objs {
		label, _ := m.attrValue(s, o, ckaLabel)
		id, _ := m.attrValue(s, o, ckaID)
		der, err := m.attrValue(s, o, ckaValue)
		if err != nil {
			t.Logf("object %q id %x: value unreadable: %v", label, id, err)
			continue
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			t.Logf("object %q id %x: does not parse: %v", label, id, err)
			continue
		}
		t.Logf("object %q id %x: subject %q issuer %q", label, id, c.Subject.String(), c.Issuer.String())
		certs[string(label)] = c
	}
	roots, err := os.ReadFile("/tmp/claude-1000/l60/yubico-piv-ca.pem")
	if err != nil {
		t.Fatal(err)
	}
	a, err := pivattest.ParseAnchors(roots)
	if err != nil {
		t.Fatal(err)
	}
	var device *x509.Certificate
	for l, c := range certs {
		if l == "X.509 Certificate for PIV Attestation" {
			device = c
		}
	}
	if device == nil {
		t.Fatal("no f9 device attestation certificate among the objects (labels above)")
	}
	for l, c := range certs {
		if c == device {
			continue
		}
		at, err := pivattest.Verify(a, device, c, time.Now())
		if err != nil {
			t.Logf("%q: Verify: %v", l, err)
			continue
		}
		t.Logf("%q: verified: %+v", l, at)
	}
}
