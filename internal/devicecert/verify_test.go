package devicecert

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/testpki"
)

var dev01 = admission.Device{Name: "leaf-01", Transport: admission.TransportTLS,
	Addresses: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}

type pki struct {
	root, issuing *testpki.CA
	now           time.Time
}

func newPKI(t *testing.T) pki {
	t.Helper()
	now := time.Now()
	root, err := testpki.NewCA("Device Root", now.Add(-time.Hour), now.Add(48*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	issuing, err := root.IssueCA("Device Issuing", now.Add(-time.Hour), now.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return pki{root: root, issuing: issuing, now: now}
}

func (p pki) leaf(t *testing.T, l testpki.Leaf) *x509.Certificate {
	t.Helper()
	if l.NotBefore.IsZero() {
		l.NotBefore, l.NotAfter = p.now.Add(-time.Minute), p.now.Add(time.Hour)
	}
	c, err := p.issuing.Issue(l)
	if err != nil {
		t.Fatal(err)
	}
	return c.Leaf
}

// verifier has status answer both the waiting and the cached question; nil
// is certificate_status disabled.
func (p pki) verifier(status StatusFunc, allow bool) *Verifier {
	v := &Verifier{Anchors: p.root.Pool(), Intermediates: []*x509.Certificate{p.issuing.Cert},
		Rule: Rule{DNSName: true, IPAddress: true}, Status: status, AllowUnknown: allow,
		Now: func() time.Time { return p.now }}
	if status != nil {
		v.CachedStatus = func(chain []*x509.Certificate) (Status, string) { return status(context.Background(), chain) }
	}
	return v
}

func good(context.Context, []*x509.Certificate) (Status, string) { return StatusGood, "" }

func TestVerify(t *testing.T) {
	p := newPKI(t)
	other, err := testpki.NewCA("Other", p.now.Add(-time.Hour), p.now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	strange, err := other.Issue(testpki.Leaf{DNSNames: []string{"leaf-01"}, Client: true,
		NotBefore: p.now.Add(-time.Minute), NotAfter: p.now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		certs []*x509.Certificate
		want  Outcome
	}{
		"a client leaf naming the device":      {[]*x509.Certificate{p.leaf(t, testpki.Leaf{DNSNames: []string{"leaf-01"}, Client: true})}, OK},
		"no extended key usage is any purpose": {[]*x509.Certificate{p.leaf(t, testpki.Leaf{DNSNames: []string{"leaf-01"}, NoExtKeyUsage: true})}, OK},
		"by address":                           {[]*x509.Certificate{p.leaf(t, testpki.Leaf{IPs: []net.IP{net.ParseIP("127.0.0.1")}, Client: true})}, OK},
		"no certificate":                       {nil, NoClientCertificate},
		"another CA":                           {[]*x509.Certificate{strange.Leaf}, UnknownCA},
		"expired": {[]*x509.Certificate{p.leaf(t, testpki.Leaf{DNSNames: []string{"leaf-01"}, Client: true,
			NotBefore: p.now.Add(-2 * time.Hour), NotAfter: p.now.Add(-time.Hour)})}, CertificateExpired},
		"not yet valid": {[]*x509.Certificate{p.leaf(t, testpki.Leaf{DNSNames: []string{"leaf-01"}, Client: true,
			NotBefore: p.now.Add(time.Hour), NotAfter: p.now.Add(2 * time.Hour)})}, CertificateExpired},
		"serverAuth only": {[]*x509.Certificate{p.leaf(t, testpki.Leaf{DNSNames: []string{"leaf-01"}})}, CertificateInvalid},
		"another device":  {[]*x509.Certificate{p.leaf(t, testpki.Leaf{DNSNames: []string{"leaf-02"}, Client: true})}, IdentityMismatch},
	} {
		v := p.verifier(good, false).Verify(c.certs, dev01)
		if v.Outcome != c.want {
			t.Errorf("%s: %s (%s), want %s", name, v.Outcome, v.Detail, c.want)
		}
		if c.want == OK && (len(v.Chain) != 3 || v.Chain[2] != p.root.Cert) {
			t.Errorf("%s: chain %d long, want leaf, issuing, root", name, len(v.Chain))
		}
	}
}

func TestVerifyUsesStoredIntermediates(t *testing.T) {
	p := newPKI(t)
	leaf := p.leaf(t, testpki.Leaf{DNSNames: []string{"leaf-01"}, Client: true})
	v := p.verifier(good, false)
	v.Intermediates = nil
	if got := v.Verify([]*x509.Certificate{leaf}, dev01); got.Outcome != UnknownCA {
		t.Fatalf("leaf alone, no stored intermediate: %s", got.Outcome)
	}
	if got := v.Verify([]*x509.Certificate{leaf, p.issuing.Cert}, dev01); got.Outcome != OK {
		t.Fatalf("leaf with its intermediate sent: %s %s", got.Outcome, got.Detail)
	}
	v.Intermediates = []*x509.Certificate{p.issuing.Cert}
	if got := v.Verify([]*x509.Certificate{leaf}, dev01); got.Outcome != OK {
		t.Fatalf("leaf alone, intermediate stored (RFC 9887 §3.4.1): %s %s", got.Outcome, got.Detail)
	}
}

// Verify is the path and the identity alone: it never asks the status, which
// runs only after the handshake has proven possession (decision 50 ruling 8).
func TestVerifyNeverAsksTheStatus(t *testing.T) {
	p := newPKI(t)
	leaf := p.leaf(t, testpki.Leaf{DNSNames: []string{"leaf-01"}, Client: true})
	asked := 0
	v := p.verifier(func(context.Context, []*x509.Certificate) (Status, string) { asked++; return StatusRevoked, "" }, false)
	if got := v.Verify([]*x509.Certificate{leaf}, dev01); got.Outcome != OK || asked != 0 {
		t.Fatalf("Verify: %s, status asked %d times", got.Outcome, asked)
	}
}

func TestCheckStatus(t *testing.T) {
	p := newPKI(t)
	leaf := p.leaf(t, testpki.Leaf{DNSNames: []string{"leaf-01"}, Client: true})
	revoked := func(context.Context, []*x509.Certificate) (Status, string) {
		return StatusRevoked, "crl issuing: revoked"
	}
	unknown := func(context.Context, []*x509.Certificate) (Status, string) {
		return StatusUnknown, "crl issuing: stale"
	}
	verified := func(v *Verifier) Verdict { return v.Verify([]*x509.Certificate{leaf}, dev01) }
	if v := p.verifier(revoked, false); v.CheckStatus(context.Background(), verified(v)).Outcome != CertificateRevoked {
		t.Fatal("revoked")
	}
	if v := p.verifier(unknown, false); v.CheckStatus(context.Background(), verified(v)).Outcome != StatusUnavailable {
		t.Fatal("unknown under refuse")
	}
	v := p.verifier(unknown, true)
	got := v.CheckStatus(context.Background(), verified(v))
	if got.Outcome != OK || !got.StatusUnknown || got.Detail != "crl issuing: stale" {
		t.Fatalf("unknown under allow: %+v", got)
	}
	if v := p.verifier(nil, false); v.CheckStatus(context.Background(), verified(v)).Outcome != OK {
		t.Fatal("certificate_status disabled")
	}
}

func TestRecheck(t *testing.T) {
	p := newPKI(t)
	leaf := p.leaf(t, testpki.Leaf{DNSNames: []string{"leaf-01"}, Client: true})
	st := StatusGood
	ver := p.verifier(good, false)
	// At a packet only the cached answer is read: the waiting question is
	// never asked (decision 50 ruling 9).
	ver.Status = func(context.Context, []*x509.Certificate) (Status, string) {
		t.Fatal("Recheck asked the status that may wait on the network")
		return StatusUnknown, ""
	}
	ver.CachedStatus = func([]*x509.Certificate) (Status, string) { return st, "per crl" }
	was := ver.Verify([]*x509.Certificate{leaf}, dev01)
	if got := ver.Recheck(was); got.Outcome != OK {
		t.Fatalf("unchanged: %s", got.Outcome)
	}
	st = StatusRevoked
	if got := ver.Recheck(was); got.Outcome != CertificateRevoked {
		t.Fatalf("revoked since: %s", got.Outcome)
	}
	st = StatusUnknown // the cached answer expired: R8, as at the handshake
	if got := ver.Recheck(was); got.Outcome != StatusUnavailable {
		t.Fatalf("no fresh cached answer: %s", got.Outcome)
	}
	st = StatusGood
	ver.Now = func() time.Time { return leaf.NotAfter.Add(time.Second) }
	if got := ver.Recheck(was); got.Outcome != CertificateExpired {
		t.Fatalf("expired since: %s", got.Outcome)
	}
}

func TestFingerprint(t *testing.T) {
	p := newPKI(t)
	leaf := p.leaf(t, testpki.Leaf{DNSNames: []string{"leaf-01"}, Client: true})
	sum := sha256.Sum256(leaf.Raw)
	if f := Fingerprint(leaf); f != hex.EncodeToString(sum[:]) || Fingerprint(nil) != "" {
		t.Fatalf("%q", f)
	}
}

func TestRefusalUnwrapsToItsVerdict(t *testing.T) {
	err := error(&Refusal{Verdict: Verdict{Outcome: IdentityMismatch, Detail: "x"}})
	var r *Refusal
	if !errors.As(err, &r) || Classify(err, false) != IdentityMismatch {
		t.Fatal(err)
	}
}

// An unrecognised Status is not Good: it goes through ruling 8 as unknown.
func TestAnUnrecognisedStatusFailsClosed(t *testing.T) {
	p := newPKI(t)
	leaf := p.leaf(t, testpki.Leaf{DNSNames: []string{"leaf-01"}, Client: true})
	odd := func(context.Context, []*x509.Certificate) (Status, string) { return Status(99), "pending" }
	for _, allow := range []bool{false, true} {
		v := p.verifier(odd, allow)
		was := v.Verify([]*x509.Certificate{leaf}, dev01)
		for name, got := range map[string]Verdict{"CheckStatus": v.CheckStatus(context.Background(), was), "Recheck": v.Recheck(was)} {
			if allow && (got.Outcome != OK || !got.StatusUnknown) {
				t.Errorf("%s allow: %+v", name, got)
			}
			if !allow && got.Outcome != StatusUnavailable {
				t.Errorf("%s refuse: %+v", name, got)
			}
		}
	}
}

func TestRecheckAndCheckStatusNeverAdmitWhatWasNotAdmitted(t *testing.T) {
	p := newPKI(t)
	v := p.verifier(nil, false) // no status check: nothing else could refuse
	asked := false
	w := p.verifier(func(context.Context, []*x509.Certificate) (Status, string) { asked = true; return StatusGood, "" }, false)
	for name, was := range map[string]Verdict{"zero": {}, "mismatch": {Outcome: IdentityMismatch, Detail: "x"},
		"ok without a chain": {Outcome: OK}} {
		if got := v.Recheck(was); got.Outcome == OK {
			t.Errorf("Recheck %s came back OK", name)
		}
		if got := w.Recheck(was); got.Outcome == OK {
			t.Errorf("Recheck %s with a status came back OK", name)
		}
		if got := w.CheckStatus(context.Background(), was); got.Outcome == OK {
			t.Errorf("CheckStatus %s came back OK", name)
		}
	}
	if asked {
		t.Error("the status was asked about a verdict with no verified chain")
	}
	if got := v.CheckStatus(context.Background(), Verdict{Outcome: OK}); got.Outcome != CertificateInvalid {
		t.Errorf("CheckStatus, OK without a chain, status disabled: %s", got.Outcome)
	}
	if got := w.CheckStatus(context.Background(), Verdict{Outcome: OK}); got.Outcome != CertificateInvalid {
		t.Errorf("CheckStatus, OK without a chain: %s", got.Outcome)
	}
	if got := v.Recheck(Verdict{Outcome: OK}); got.Outcome != CertificateInvalid {
		t.Errorf("OK without a chain: %s", got.Outcome)
	}
}

func TestANilAnchorPoolRefusesAndANilClockDefaults(t *testing.T) {
	p := newPKI(t)
	leaf := p.leaf(t, testpki.Leaf{DNSNames: []string{"leaf-01"}, Client: true})
	v := p.verifier(good, false)
	v.Anchors = nil
	if got := v.Verify([]*x509.Certificate{leaf}, dev01); got.Outcome != UnknownCA {
		t.Fatalf("nil anchors: %s", got.Outcome)
	}
	v = p.verifier(good, false)
	v.Now = nil
	if got := v.Verify([]*x509.Certificate{leaf}, dev01); got.Outcome != OK {
		t.Fatalf("nil clock: %s %s", got.Outcome, got.Detail)
	}
	if got := v.Recheck(v.Verify([]*x509.Certificate{leaf}, dev01)); got.Outcome != OK {
		t.Fatalf("nil clock at a packet: %s", got.Outcome)
	}
}
