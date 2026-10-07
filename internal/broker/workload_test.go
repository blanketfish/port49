package broker

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
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
