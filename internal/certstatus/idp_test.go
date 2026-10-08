package certstatus

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/testpki"
)

// A list scoped to a distribution point by its issuing distribution point
// covers only the certificates whose CRL distribution points name it, byte
// for byte (RFC 5280 §5.2.5; spec §13, decision 40, ruling 17). L48 measured
// step-ca 0.30.2's list in this shape: a critical IDP naming its own URL by
// fullName, and nothing else.

const stepCRL = "https://step-ca.port49.lab/1.0/crl"

// uriName is a GeneralName uniformResourceIdentifier ([6] IA5String).
func uriName(uri string) asn1.RawValue {
	return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 6, Bytes: []byte(uri)}
}

// idpExt is a critical issuing distribution point: a distributionPoint whose
// fullName holds names (none: no distributionPoint), and the boolean fields
// asked for.
func idpExt(t *testing.T, names []asn1.RawValue, userOnly bool, more ...asn1.RawValue) pkix.Extension {
	t.Helper()
	var body []byte
	if len(names) > 0 {
		var gns []byte
		for _, n := range names {
			b, err := asn1.Marshal(n)
			if err != nil {
				t.Fatal(err)
			}
			gns = append(gns, b...)
		}
		full, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: gns})
		if err != nil {
			t.Fatal(err)
		}
		dp, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: full})
		if err != nil {
			t.Fatal(err)
		}
		body = append(body, dp...)
	}
	if userOnly {
		body = append(body, 0x81, 0x01, 0xff)
	}
	for _, m := range more {
		b, err := asn1.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		body = append(body, b...)
	}
	seq, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: body})
	if err != nil {
		t.Fatal(err)
	}
	return pkix.Extension{Id: oidIssuingDistPt, Critical: true, Value: seq}
}

// leafDP is a client certificate ca issues with serial, its CRL distribution
// points the URIs given (none: no extension).
func leafDP(t *testing.T, ca *testpki.CA, serial int64, dps ...string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return sign(t, ca, &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "workload"},
		NotBefore: t0.Add(-time.Hour), NotAfter: t0.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, CRLDistributionPoints: dps}, key)
}

// subCADP is an intermediate parent signs, with the CRL distribution points given.
func subCADP(t *testing.T, parent *testpki.CA, cn string, dps ...string) *testpki.CA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := sign(t, parent, &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{CommonName: cn}, NotBefore: t0.Add(-24 * time.Hour), NotAfter: t0.Add(5 * 365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		CRLDistributionPoints: dps}, key)
	return &testpki.CA{Cert: cert, Key: key}
}

// fileChecker holds one source per list, each read from a file and kept in a
// state directory, all loaded.
func fileChecker(t *testing.T, srcs ...CRLSource) (*Checker, string) {
	t.Helper()
	dir := stateDir(t)
	c, _, _ := newChecker(t, Config{CRLs: srcs, StateDir: dir}, newClock())
	if errs := c.LoadAll(context.Background()); len(errs) != 0 {
		t.Fatal(errs)
	}
	return c, dir
}

func TestDistributionPointScope(t *testing.T) {
	ca := newCA(t, "port49 lab workloads Intermediate CA")
	stepShape := idpExt(t, []asn1.RawValue{uriName(stepCRL)}, false)
	list := func(revokedSerials ...int64) []byte {
		var rs []x509.RevocationListEntry
		for _, s := range revokedSerials {
			rs = append(rs, revoked(s, t0.Add(-time.Minute)))
		}
		return signCRL(t, ca, crlSpec{number: 1, ext: []pkix.Extension{stepShape}, revoked: rs})
	}

	t.Run("the step-ca shape covers a leaf naming it: revoked when listed, good when not", func(t *testing.T) {
		c, _ := fileChecker(t, CRLSource{Name: "step_ca", File: crlFile(t, list(7)), Issuer: ca.Cert})
		if r := check(t, c, leafDP(t, ca, 7, stepCRL), ca.Cert); r.Verdict != Revoked || r.Name != "step_ca" {
			t.Errorf("listed: %+v, want revoked by step_ca", r)
		}
		if r := check(t, c, leafDP(t, ca, 8, stepCRL), ca.Cert); r.Verdict != Good || r.Name != "step_ca" {
			t.Errorf("not listed: %+v, want good from step_ca", r)
		}
	})

	for _, tc := range []struct {
		name string
		dps  []string
	}{
		{"a leaf with no CRL distribution point", nil},
		{"a leaf naming another distribution point", []string{"https://other.port49.lab/1.0/crl"}},
		{"a leaf naming it in another encoding (a trailing slash)", []string{stepCRL + "/"}},
	} {
		t.Run(tc.name+" is undecided, never good", func(t *testing.T) {
			c, _ := fileChecker(t, CRLSource{Name: "step_ca", File: crlFile(t, list(7)), Issuer: ca.Cert})
			r := check(t, c, leafDP(t, ca, 8, tc.dps...), ca.Cert)
			if r.Verdict != Unknown {
				t.Errorf("not listed: %+v, want unknown", r)
			}
			// Final to port49 workload, as an uncovered issuer is (nothing changes
			// until the certificate is issued again), and it says why.
			if !strings.HasPrefix(r.Detail, api.UncoveredStatus) ||
				!strings.Contains(r.Detail, "CRL step_ca is scoped to the distribution point "+stepCRL) {
				t.Errorf("detail %q", r.Detail)
			}
			// Listed or not, a list that does not cover the certificate says nothing of it.
			if r := check(t, c, leafDP(t, ca, 7, tc.dps...), ca.Cert); r.Verdict != Unknown {
				t.Errorf("listed: %+v, want unknown", r)
			}
		})
	}

	t.Run("a leaf naming one of several distribution points is covered", func(t *testing.T) {
		two := signCRL(t, ca, crlSpec{number: 1, ext: []pkix.Extension{
			idpExt(t, []asn1.RawValue{uriName("https://a.port49.lab/crl"), uriName(stepCRL)}, false)}})
		c, _ := fileChecker(t, CRLSource{Name: "step_ca", File: crlFile(t, two), Issuer: ca.Cert})
		if r := check(t, c, leafDP(t, ca, 8, "https://elsewhere.port49.lab/crl", stepCRL), ca.Cert); r.Verdict != Good {
			t.Errorf("%+v, want good", r)
		}
	})

	t.Run("a distribution point with onlyContainsUserCerts covers a naming leaf, never a CA", func(t *testing.T) {
		both := signCRL(t, ca, crlSpec{number: 1, ext: []pkix.Extension{idpExt(t, []asn1.RawValue{uriName(stepCRL)}, true)}})
		c, _ := fileChecker(t, CRLSource{Name: "step_ca", File: crlFile(t, both), Issuer: ca.Cert})
		if r := check(t, c, leafDP(t, ca, 8, stepCRL), ca.Cert); r.Verdict != Good {
			t.Errorf("a leaf: %+v, want good", r)
		}
		sub := subCADP(t, ca, "sub CA", stepCRL)
		if r := check(t, c, sub.Cert, ca.Cert); r.Verdict != Unknown {
			t.Errorf("a CA naming it: %+v, want unknown", r)
		}
	})

	t.Run("an intermediate under a list scoped to a distribution point", func(t *testing.T) {
		root := newCA(t, "root CA")
		const rootCRL = "https://root.port49.lab/crl"
		named, unnamed := subCADP(t, root, "named CA", rootCRL), subCADP(t, root, "unnamed CA")
		rootList := signCRL(t, root, crlSpec{number: 1, ext: []pkix.Extension{idpExt(t, []asn1.RawValue{uriName(rootCRL)}, false)},
			revoked: []x509.RevocationListEntry{{SerialNumber: named.Cert.SerialNumber, RevocationTime: t0.Add(-time.Minute)}}})
		namedList := signCRL(t, named, crlSpec{number: 1})
		unnamedList := signCRL(t, unnamed, crlSpec{number: 1})
		c, _ := fileChecker(t, CRLSource{Name: "root", File: crlFile(t, rootList), Issuer: root.Cert},
			CRLSource{Name: "named", File: crlFile(t, namedList), Issuer: named.Cert},
			CRLSource{Name: "unnamed", File: crlFile(t, unnamedList), Issuer: unnamed.Cert})
		r := check(t, c, leaf(t, named, 100), named.Cert, root.Cert)
		if r.Verdict != Revoked || r.Depth != 1 || r.Name != "root" {
			t.Errorf("the intermediate naming the list, listed: %+v, want revoked at depth 1 by root", r)
		}
		r = check(t, c, leaf(t, unnamed, 100), unnamed.Cert, root.Cert)
		if r.Verdict != Unknown || r.Depth != 1 {
			t.Errorf("the intermediate naming no distribution point: %+v, want unknown at depth 1", r)
		}
	})

	t.Run("a kept list scoped to a distribution point loads again at a restart", func(t *testing.T) {
		src := CRLSource{Name: "step_ca", File: crlFile(t, list(7)), Issuer: ca.Cert}
		_, dir := fileChecker(t, src)
		restarted, _, _ := newChecker(t, Config{CRLs: []CRLSource{src}, StateDir: dir}, newClock())
		if errs := restarted.LoadPersisted(); len(errs) != 0 {
			t.Fatal(errs)
		}
		if r := check(t, restarted, leafDP(t, ca, 7, stepCRL), ca.Cert); r.Verdict != Revoked {
			t.Errorf("a naming leaf, listed: %+v, want revoked", r)
		}
		if r := check(t, restarted, leafDP(t, ca, 7), ca.Cert); r.Verdict != Unknown {
			t.Errorf("a leaf naming none: %+v, want unknown", r)
		}
	})

	t.Run("an issuing distribution point saying anything else is still refused", func(t *testing.T) {
		dp := []asn1.RawValue{uriName(stepCRL)}
		// distributionPoint [0] { nameRelativeToCRLIssuer [1] { CN=crl } }
		atv, err := asn1.Marshal(pkix.AttributeTypeAndValue{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "crl"})
		if err != nil {
			t.Fatal(err)
		}
		relative, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 1, IsCompound: true, Bytes: atv})
		if err != nil {
			t.Fatal(err)
		}
		relDP := asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: relative}
		for _, tc := range []struct {
			name, want string
			ext        pkix.Extension
		}{
			{"onlySomeReasons beside a distribution point", "some reasons",
				idpExt(t, dp, false, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 3, Bytes: []byte{0x06, 0x40}})},
			{"indirectCRL beside a distribution point", "indirect",
				idpExt(t, dp, false, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 4, Bytes: []byte{0xff}})},
			{"nameRelativeToCRLIssuer", "relative", idpExt(t, nil, false, relDP)},
			{"onlyContainsCACerts beside a distribution point", "CA certificates",
				idpExt(t, dp, false, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 2, Bytes: []byte{0xff}})},
		} {
			t.Run(tc.name, func(t *testing.T) {
				c, _, _ := newChecker(t, Config{CRLs: []CRLSource{{Name: "step_ca", Issuer: ca.Cert,
					File: crlFile(t, signCRL(t, ca, crlSpec{number: 1, ext: []pkix.Extension{tc.ext}}))}}}, newClock())
				errs := c.LoadAll(context.Background())
				if len(errs) != 1 || !strings.Contains(errs[0].Error(), tc.want) {
					t.Fatalf("errs = %v, want one naming %q", errs, tc.want)
				}
				if r := check(t, c, leafDP(t, ca, 8, stepCRL), ca.Cert); r.Verdict != Unknown {
					t.Errorf("%+v, want unknown: the refused list is not in force", r)
				}
			})
		}
	})
}
