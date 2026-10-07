package broker

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/testpki"
)

// workloadID is the fixture workload's SPIFFE ID, in workloadPolicy's
// svc_oxidized subject.
const workloadID = "spiffe://corp.example.com/host/oxidized-01"

// withWorkload gives f's broker a workload verifier on its own CA, for
// corp.example.com, and returns that CA.
func (f *fixture) withWorkload(t *testing.T) *testpki.CA {
	t.Helper()
	wca, err := testpki.NewCA("port49 test workloads ca", f.now.Add(-time.Hour), f.now.Add(48*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	f.b.Workload = &Workload{Anchor: wca.Cert, TrustDomains: []string{"corp.example.com"}}
	return wca
}

// workloadCert issues a client certificate from ca naming uris, valid for a
// day from an hour ago.
func (f *fixture) workloadCert(t *testing.T, ca *testpki.CA, uris ...string) tls.Certificate {
	t.Helper()
	l := testpki.Leaf{CommonName: "oxidized-01", Client: true, NotBefore: f.now.Add(-time.Hour),
		NotAfter: f.now.Add(23 * time.Hour)}
	for _, u := range uris {
		p, err := url.Parse(u)
		if err != nil {
			t.Fatal(err)
		}
		l.URIs = append(l.URIs, p)
	}
	c, err := ca.Issue(l)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// chainState is a connection whose one verified chain is c then ca.
func chainState(c tls.Certificate, ca *testpki.CA) *tls.ConnectionState {
	return &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{c.Leaf, ca.Cert}}}
}

func TestAWorkloadCertificateIsAMachine(t *testing.T) {
	f := newFixture(t, 8)
	wca := f.withWorkload(t)
	cc, err := f.b.CertCallerOf(chainState(f.workloadCert(t, wca, workloadID), wca), f.now)
	if err != nil || cc.Domain != DomainMachines || cc.Principal != workloadID || cc.Legacy != "" ||
		cc.Cred.Method != "cert" || cc.Leaf == nil {
		t.Fatalf("%+v %v", cc, err)
	}
}

// A person's certificate on the same broker is read exactly as before plan 8.
func TestAHumanCertificateStaysAHuman(t *testing.T) {
	f := newFixture(t, 8)
	f.withWorkload(t)
	cc, err := f.b.CertCallerOf(f.state(f.alice), f.now)
	if err != nil || cc.Domain != DomainHumans || cc.Principal != alicePrincipal {
		t.Fatalf("%+v %v", cc, err)
	}
}

// Chains ending at both anchors are no one's (decision 40 ruling 2).
func TestAChainEndingAtBothAnchorsIsRefused(t *testing.T) {
	f := newFixture(t, 8)
	wca := f.withWorkload(t)
	w := f.workloadCert(t, wca, workloadID)
	cs := &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{w.Leaf, wca.Cert}, {w.Leaf, f.ca.Cert}}}
	if _, err := f.b.CertCallerOf(cs, f.now); !errors.Is(err, ErrUntrusted) ||
		!strings.Contains(err.Error(), "chains to both the human and the workload trust anchor") {
		t.Fatalf("got %v", err)
	}
}

// People by OIDC, workloads by certificate: a chain that does not end at the
// workload anchor has no verifier (decision 40 ruling 2).
func TestWithNoHumanX509OnlyTheWorkloadAnchorAccepts(t *testing.T) {
	f := newFixture(t, 8)
	f.withWorkload(t)
	f.b.NoX509 = true
	if _, err := f.b.CertCallerOf(f.state(f.alice), f.now); !errors.Is(err, ErrUntrusted) ||
		!strings.Contains(err.Error(), "no human x509 verifier") {
		t.Fatalf("got %v", err)
	}
}

func TestTheWorkloadPrincipalTable(t *testing.T) {
	f := newFixture(t, 8)
	wca := f.withWorkload(t)
	for name, c := range map[string]struct {
		uris []string
		want string
	}{
		"none":           {nil, "carries 0 URI SANs; exactly one SPIFFE ID names a workload"},
		"two":            {[]string{workloadID, "spiffe://corp.example.com/host/other"}, "carries 2 URI SANs"},
		"https":          {[]string{"https://corp.example.com/host/oxidized-01"}, "not a SPIFFE ID"},
		"upper case":     {[]string{"spiffe://Corp.example.com/host/oxidized-01"}, "not a SPIFFE ID"},
		"no path":        {[]string{"spiffe://corp.example.com"}, "names the trust domain itself, not a workload"},
		"trailing slash": {[]string{"spiffe://corp.example.com/host/"}, "not a SPIFFE ID"},
		"unlisted":       {[]string{"spiffe://lab.example.net/host/x"}, "outside broker.identity.machines spiffe_trust_domains (corp.example.com)"},
	} {
		_, err := f.b.CertCallerOf(chainState(f.workloadCert(t, wca, c.uris...), wca), f.now)
		if !errors.Is(err, ErrWorkloadUnmapped) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want %q", name, err, c.want)
		}
	}
}

// An email SAN on a workload certificate is never read: no human mark names
// it, and it is no principal (decision 40 ruling 3).
func TestAWorkloadsEmailSANIsIgnored(t *testing.T) {
	f := newFixture(t, 8)
	wca := f.withWorkload(t)
	u, _ := url.Parse(workloadID)
	c, err := wca.Issue(testpki.Leaf{CommonName: "x", Emails: []string{"alice@example.com"}, URIs: []*url.URL{u},
		Client: true, NotBefore: f.now.Add(-time.Hour), NotAfter: f.now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	cc, err := f.b.CertCallerOf(chainState(c, wca), f.now)
	if err != nil || cc.Principal != workloadID || cc.Legacy != "" {
		t.Fatalf("%+v %v", cc, err)
	}
}

// A CA certificate is no workload (X.509-SVID §4.1).
func TestACACertificateIsNoWorkload(t *testing.T) {
	f := newFixture(t, 8)
	f.withWorkload(t)
	if _, err := WorkloadPrincipal(f.ca.Cert, []string{"corp.example.com"}); !errors.Is(err, ErrWorkloadUnmapped) ||
		!strings.Contains(err.Error(), "a CA certificate") {
		t.Fatalf("got %v", err)
	}
}

// Expiry is refused as a person's is: trust_domain_unresolved, the validity
// named, and the credential kept for the record.
func TestAnExpiredWorkloadCertificateIsUntrusted(t *testing.T) {
	f := newFixture(t, 8)
	wca := f.withWorkload(t)
	w := f.workloadCert(t, wca, workloadID)
	cc, err := f.b.CertCallerOf(chainState(w, wca), f.now.Add(24*time.Hour))
	if !errors.Is(err, ErrUntrusted) || !strings.Contains(err.Error(), "is valid") || cc.Cred.Fingerprint == "" ||
		cc.Domain != DomainMachines {
		t.Fatalf("%+v %v", cc, err)
	}
}

// With no workload verifier every certificate is read as before plan 8: a
// URI SAN beside the email is not a workload.
func TestNoWorkloadVerifierKeepsTodaysReading(t *testing.T) {
	f := newFixture(t, 8)
	u, _ := url.Parse(workloadID)
	c, err := f.ca.Issue(testpki.Leaf{CommonName: "a", Emails: []string{"alice@example.com"}, URIs: []*url.URL{u},
		Client: true, NotBefore: f.now.Add(-time.Hour), NotAfter: f.now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	cc, err := f.b.CertCallerOf(f.state(c), f.now)
	if err != nil || cc.Domain != DomainHumans || cc.Principal != alicePrincipal {
		t.Fatalf("%+v %v", cc, err)
	}
}

// rawURISAN is a subjectAltName extension carrying uris byte for byte, as
// crypto/x509 would not write them.
func rawURISAN(t *testing.T, uris ...string) []pkix.Extension {
	t.Helper()
	var gns []asn1.RawValue
	for _, u := range uris {
		gns = append(gns, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 6, Bytes: []byte(u)})
	}
	der, err := asn1.Marshal(gns)
	if err != nil {
		t.Fatal(err)
	}
	return []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: der}}
}

// crypto/x509 runs a URI SAN through url.Parse, which lower-cases the scheme
// and drops an empty fragment; the strict parse must see the SAN's own bytes.
func TestTheWorkloadPrincipalIsReadFromTheSANsOwnBytes(t *testing.T) {
	f := newFixture(t, 8)
	wca := f.withWorkload(t)
	for name, san := range map[string]string{
		"upper-case scheme":      "SPIFFE://corp.example.com/host/oxidized-01",
		"mixed-case scheme":      "Spiffe://corp.example.com/host/oxidized-01",
		"empty fragment":         "spiffe://corp.example.com/host/oxidized-01#",
		"empty query":            "spiffe://corp.example.com/host/oxidized-01?",
		"upper-case scheme+frag": "SPIFFE://corp.example.com/host/oxidized-01#",
	} {
		c, err := wca.Issue(testpki.Leaf{CommonName: "x", Client: true, NotBefore: f.now.Add(-time.Hour),
			NotAfter: f.now.Add(time.Hour), ExtraExtensions: rawURISAN(t, san)})
		if err != nil {
			t.Fatal(err)
		}
		_, err = f.b.CertCallerOf(chainState(c, wca), f.now)
		if !errors.Is(err, ErrWorkloadUnmapped) {
			t.Errorf("%s: got %v, want refused", name, err)
		}
	}
}

// Two URI SANs are counted over the raw names, whatever url.Parse makes of them.
func TestTwoRawURISANsNameNoWorkload(t *testing.T) {
	f := newFixture(t, 8)
	wca := f.withWorkload(t)
	c, err := wca.Issue(testpki.Leaf{CommonName: "x", Client: true, NotBefore: f.now.Add(-time.Hour),
		NotAfter: f.now.Add(time.Hour), ExtraExtensions: rawURISAN(t, workloadID, workloadID)})
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.b.CertCallerOf(chainState(c, wca), f.now)
	if !errors.Is(err, ErrWorkloadUnmapped) || !strings.Contains(err.Error(), "carries 2 URI SANs") {
		t.Fatalf("got %v", err)
	}
}

// The exact bytes of a good ID are the principal.
func TestARawSANThatIsAGoodIDIsTheWorkload(t *testing.T) {
	f := newFixture(t, 8)
	wca := f.withWorkload(t)
	c, err := wca.Issue(testpki.Leaf{CommonName: "x", Client: true, NotBefore: f.now.Add(-time.Hour),
		NotAfter: f.now.Add(time.Hour), ExtraExtensions: rawURISAN(t, workloadID)})
	if err != nil {
		t.Fatal(err)
	}
	cc, err := f.b.CertCallerOf(chainState(c, wca), f.now)
	if err != nil || cc.Principal != workloadID {
		t.Fatalf("%+v %v", cc, err)
	}
}

// rawNames is a subjectAltName extension of the given GeneralNames as written.
func rawNames(t *testing.T, gns ...asn1.RawValue) []pkix.Extension {
	t.Helper()
	der, err := asn1.Marshal(gns)
	if err != nil {
		t.Fatal(err)
	}
	return []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: der}}
}

// constructedURI is a [6] GeneralName in the constructed form (0xA6), which
// crypto/x509 skips: it is no URI to it, and no URI to a name constraint.
func constructedURI(id string) asn1.RawValue {
	return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 6, IsCompound: true, Bytes: []byte(id)}
}

func TestAConstructedURISANIsRefused(t *testing.T) {
	f := newFixture(t, 8)
	wca := f.withWorkload(t)
	c, err := wca.Issue(testpki.Leaf{CommonName: "x", Client: true, NotBefore: f.now.Add(-time.Hour),
		NotAfter: f.now.Add(time.Hour), ExtraExtensions: rawNames(t, constructedURI(workloadID))})
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Leaf.URIs) != 0 {
		t.Fatalf("crypto/x509 read %v; the premise of the test is that it reads none", c.Leaf.URIs)
	}
	_, err = f.b.CertCallerOf(chainState(c, wca), f.now)
	if !errors.Is(err, ErrWorkloadUnmapped) {
		t.Fatalf("got %v", err)
	}
}

// A workload CA name-constrained to other.example.com must not name a
// workload in corp.example.com by a form its name-constraint check skips.
func TestANameConstrainedCAMayNotNameAWorkloadByAConstructedSAN(t *testing.T) {
	f := newFixture(t, 8)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(77), Subject: pkix.Name{CommonName: "constrained workloads ca"},
		NotBefore: f.now.Add(-time.Hour), NotAfter: f.now.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign, PermittedURIDomains: []string{"other.example.com"}, PermittedDNSDomainsCritical: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	wca := &testpki.CA{Cert: cert, Key: key}
	f.b.Workload = &Workload{Anchor: cert, TrustDomains: []string{"corp.example.com"}}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	verify := func(ext []pkix.Extension) ([][]*x509.Certificate, error) {
		c, err := wca.Issue(testpki.Leaf{CommonName: "x", Client: true, NotBefore: f.now.Add(-time.Hour),
			NotAfter: f.now.Add(time.Hour), ExtraExtensions: ext})
		if err != nil {
			t.Fatal(err)
		}
		return c.Leaf.Verify(x509.VerifyOptions{Roots: pool, CurrentTime: f.now,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	}
	if _, err := verify(rawURISAN(t, workloadID)); err == nil {
		t.Fatal("the primitive form passed the name constraint; the premise is that it does not")
	}
	chains, err := verify(rawNames(t, constructedURI(workloadID)))
	if err != nil {
		t.Skipf("this Go refuses the constructed form at Verify already: %v", err)
	}
	cc, err := f.b.CertCallerOf(&tls.ConnectionState{VerifiedChains: chains}, f.now)
	if !errors.Is(err, ErrWorkloadUnmapped) || cc.Principal != "" {
		t.Fatalf("%+v %v", cc, err)
	}
}
