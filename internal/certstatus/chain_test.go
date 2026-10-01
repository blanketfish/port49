package certstatus

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// crlFile writes der to a new file and returns its path.
func crlFile(t *testing.T, der []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "list.crl")
	if err := os.WriteFile(path, der, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestChain checks every certificate in the chain but the anchor, each
// against the one above it (pre-flight I2).
func TestChain(t *testing.T) {
	root := newCA(t, "root CA")
	inter := subCA(t, root, "issuing CA")
	user := leaf(t, inter, 100)
	chain := []*x509.Certificate{user, inter.Cert, root.Cert}

	// withLists is a checker holding the intermediate's list and the root's.
	withLists := func(t *testing.T, interList, rootList []byte) *Checker {
		t.Helper()
		var srcs []CRLSource
		if interList != nil {
			srcs = append(srcs, CRLSource{Name: "issuing", File: crlFile(t, interList), Issuer: inter.Cert})
		}
		if rootList != nil {
			srcs = append(srcs, CRLSource{Name: "root", File: crlFile(t, rootList), Issuer: root.Cert})
		}
		c, _, _ := newChecker(t, Config{CRLs: srcs}, newClock())
		if errs := c.LoadAll(context.Background()); len(errs) != 0 {
			t.Fatal(errs)
		}
		return c
	}
	userOnly := pkix.Extension{Id: oidIssuingDistPt, Critical: true, Value: []byte{0x30, 0x03, 0x81, 0x01, 0xff}}

	t.Run("a leaf under a good intermediate is good", func(t *testing.T) {
		c := withLists(t, signCRL(t, inter, crlSpec{number: 1}), signCRL(t, root, crlSpec{number: 1}))
		if r := check(t, c, chain...); r.Verdict != Good || r.Depth != 0 {
			t.Errorf("%+v, want good at depth 0", r)
		}
	})

	t.Run("the root's list naming the intermediate revokes the leaf", func(t *testing.T) {
		c := withLists(t, signCRL(t, inter, crlSpec{number: 1}), signCRL(t, root, crlSpec{number: 1,
			revoked: []x509.RevocationListEntry{{SerialNumber: inter.Cert.SerialNumber, RevocationTime: t0}}}))
		r := check(t, c, chain...)
		if r.Verdict != Revoked || r.Depth != 1 || r.Subject != inter.Cert.Subject.String() || r.Name != "root" {
			t.Errorf("%+v, want revoked at depth 1 by root, subject %q", r, inter.Cert.Subject.String())
		}
	})

	t.Run("a revoked leaf decides at depth 0 though its intermediate is revoked too", func(t *testing.T) {
		c := withLists(t, signCRL(t, inter, crlSpec{number: 1, revoked: []x509.RevocationListEntry{revoked(100, t0)}}),
			signCRL(t, root, crlSpec{number: 1,
				revoked: []x509.RevocationListEntry{{SerialNumber: inter.Cert.SerialNumber, RevocationTime: t0}}}))
		if r := check(t, c, chain...); r.Verdict != Revoked || r.Depth != 0 || r.Subject != "" {
			t.Errorf("%+v, want revoked at depth 0", r)
		}
	})

	t.Run("a root list scoped to user certificates does not cover the intermediate", func(t *testing.T) {
		c := withLists(t, signCRL(t, inter, crlSpec{number: 1}),
			signCRL(t, root, crlSpec{number: 1, ext: []pkix.Extension{userOnly}}))
		r := check(t, c, chain...)
		if r.Verdict != Unknown || r.Depth != 1 || r.Subject != inter.Cert.Subject.String() {
			t.Errorf("%+v, want unknown at depth 1", r)
		}
		// Even naming the intermediate, it is not read for one.
		c = withLists(t, signCRL(t, inter, crlSpec{number: 1}), signCRL(t, root, crlSpec{number: 1,
			ext:     []pkix.Extension{userOnly},
			revoked: []x509.RevocationListEntry{{SerialNumber: inter.Cert.SerialNumber, RevocationTime: t0}}}))
		if r := check(t, c, chain...); r.Verdict != Unknown {
			t.Errorf("%+v, want unknown: a user-certificate list says nothing of a CA", r)
		}
	})

	t.Run("a user-certificates list does not cover a CA certificate at depth 0", func(t *testing.T) {
		c := withLists(t, nil, signCRL(t, root, crlSpec{number: 1, ext: []pkix.Extension{userOnly}}))
		if r := check(t, c, inter.Cert, root.Cert); r.Verdict != Unknown || r.Depth != 0 {
			t.Errorf("%+v, want unknown at depth 0", r)
		}
		c = withLists(t, nil, signCRL(t, root, crlSpec{number: 1}))
		if r := check(t, c, inter.Cert, root.Cert); r.Verdict != Good {
			t.Errorf("under a full list: %+v, want good", r)
		}
	})

	t.Run("only the issuing CA's list leaves the intermediate unknown", func(t *testing.T) {
		c := withLists(t, signCRL(t, inter, crlSpec{number: 1}), nil)
		r := check(t, c, chain...)
		if r.Verdict != Unknown || r.Depth != 1 || !strings.Contains(r.Detail, "root CA") {
			t.Errorf("%+v, want unknown at depth 1 naming the root as uncovered", r)
		}
	})

	t.Run("a list is matched by its issuer certificate, not its name", func(t *testing.T) {
		twin := newCA(t, "issuing CA") // inter's name, another key and certificate
		c, _, _ := newChecker(t, Config{CRLs: []CRLSource{
			{Name: "twin", File: crlFile(t, signCRL(t, twin, crlSpec{number: 1})), Issuer: twin.Cert},
			{Name: "root", File: crlFile(t, signCRL(t, root, crlSpec{number: 1})), Issuer: root.Cert},
		}}, newClock())
		if errs := c.LoadAll(context.Background()); len(errs) != 0 {
			t.Fatal(errs)
		}
		if r := check(t, c, chain...); r.Verdict != Unknown || r.Depth != 0 {
			t.Errorf("%+v, want unknown at depth 0: the twin's list does not cover inter's leaves", r)
		}
	})

	t.Run("a lone self-issued certificate is checked against itself", func(t *testing.T) {
		c, _, _ := newChecker(t, Config{CRLs: []CRLSource{
			{Name: "root", File: crlFile(t, signCRL(t, root, crlSpec{number: 1,
				revoked: []x509.RevocationListEntry{{SerialNumber: root.Cert.SerialNumber, RevocationTime: t0}}})),
				Issuer: root.Cert}}}, newClock())
		if errs := c.LoadAll(context.Background()); len(errs) != 0 {
			t.Fatal(errs)
		}
		if r := check(t, c, root.Cert); r.Verdict != Revoked {
			t.Errorf("%+v, want revoked", r)
		}
	})

	t.Run("an empty chain is unknown", func(t *testing.T) {
		c, m, _ := newChecker(t, Config{}, newClock())
		if r := check(t, c); r.Verdict != Unknown {
			t.Errorf("%+v, want unknown", r)
		}
		if got := testutil.ToFloat64(m.CertStatusUnavailable); got != 1 {
			t.Errorf("unavailable = %v, want 1", got)
		}
	})

	t.Run("each check is counted by source and result", func(t *testing.T) {
		ca := newCA(t, "issuing CA")
		c, m, _ := newChecker(t, Config{CRLs: []CRLSource{
			{Name: "issuing", File: crlFile(t, signCRL(t, ca, crlSpec{number: 1, next: t0.Add(time.Hour),
				revoked: []x509.RevocationListEntry{revoked(2, t0)}})), Issuer: ca.Cert}}}, newClock())
		if errs := c.LoadAll(context.Background()); len(errs) != 0 {
			t.Fatal(errs)
		}
		check(t, c, leaf(t, ca, 1), ca.Cert)
		check(t, c, leaf(t, ca, 2), ca.Cert)
		check(t, c, leaf(t, inter, 3), inter.Cert, root.Cert)
		for _, tc := range []struct {
			source, result string
		}{{"crl", "good"}, {"crl", "revoked"}, {"none", "unknown"}} {
			if got := testutil.ToFloat64(m.CertStatusChecks.WithLabelValues(tc.source, tc.result)); got != 1 {
				t.Errorf("checks{%s,%s} = %v, want 1", tc.source, tc.result, got)
			}
		}
		if got := testutil.ToFloat64(m.CertStatusUnavailable); got != 1 {
			t.Errorf("unavailable = %v, want 1", got)
		}
		if got := testutil.ToFloat64(m.CRLNextUpdate.WithLabelValues("issuing")); got != float64(t0.Add(time.Hour).Unix()) {
			t.Errorf("next update gauge = %v, want %d", got, t0.Add(time.Hour).Unix())
		}
	})

	t.Run("Describe", func(t *testing.T) {
		c, _, _ := newChecker(t, Config{CRLs: []CRLSource{
			{Name: "issuing", File: crlFile(t, signCRL(t, inter, crlSpec{number: 1})), Issuer: inter.Cert},
			{Name: "root", File: "/nonexistent", Issuer: root.Cert}},
			OCSP: &OCSPConfig{Responder: "http://ocsp.example.com"}}, newClock())
		c.LoadAll(context.Background())
		want := "CRL issuing (next update " + t0.Add(time.Hour).Format(time.RFC3339) +
			"), CRL root (not loaded yet), OCSP http://ocsp.example.com"
		if got := c.Describe(); got != want {
			t.Errorf("Describe() = %q, want %q", got, want)
		}
	})
}
