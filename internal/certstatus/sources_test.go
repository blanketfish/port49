package certstatus

import (
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/testpki"
)

// renewed is ca's certificate reissued: same name, same key, other serial.
func renewed(t *testing.T, ca *testpki.CA) *testpki.CA {
	t.Helper()
	tmpl := *ca.Cert
	tmpl.SerialNumber = big.NewInt(424242)
	tmpl.Raw, tmpl.RawTBSCertificate, tmpl.Signature = nil, nil, nil
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, ca.Cert.PublicKey, ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testpki.CA{Cert: cert, Key: ca.Key}
}

func fileSource(name string, ca *testpki.CA) CRLSource {
	return CRLSource{Name: name, URL: "http://127.0.0.1:1/x", Issuer: ca.Cert}
}

// SetCRLSources drops a list whose issuer is no longer the source's: it
// was verified against a certificate the source no longer names.
func TestSetCRLSourcesDropsAListWhoseIssuerChanged(t *testing.T) {
	oldCA, newCA2 := newCA(t, "old CA"), newCA(t, "new CA")
	clk := newClock()
	c, _, _ := newChecker(t, Config{CRLs: []CRLSource{fileSource("dev", oldCA)}, RefreshInterval: time.Hour}, clk)
	l, err := c.accept(fileSource("dev", oldCA), signCRL(t, oldCA, crlSpec{number: 500}))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.install(fileSource("dev", oldCA), l, false); err != nil {
		t.Fatal(err)
	}
	user := leaf(t, oldCA, 7)
	if r := c.CheckCached([]*x509.Certificate{user, oldCA.Cert}); r.Verdict != Good {
		t.Fatalf("the list in force: %+v", r)
	}
	c.SetCRLSources([]CRLSource{fileSource("dev", newCA2)})
	if r := c.CheckCached([]*x509.Certificate{user, oldCA.Cert}); r.Verdict == Good {
		t.Fatalf("the old issuer's list must not outlive its source: %+v", r)
	}
	if len(c.crls) != 0 {
		t.Fatalf("lists in force: %d", len(c.crls))
	}
}

// A load in flight when its source is replaced finishes against the old
// issuer. Its list is discarded, and the new CA's list, numbered from 1, is
// not refused as a rollback of it.
func TestAnInFlightLoadOfAReplacedSourceIsDiscarded(t *testing.T) {
	oldCA, newCA2 := newCA(t, "old CA"), newCA(t, "new CA")
	oldSrc, newSrc := fileSource("dev", oldCA), fileSource("dev", newCA2)
	c, _, _ := newChecker(t, Config{CRLs: []CRLSource{oldSrc}, RefreshInterval: time.Hour}, newClock())
	inFlight, err := c.accept(oldSrc, signCRL(t, oldCA, crlSpec{number: 500}))
	if err != nil {
		t.Fatal(err) // fetched and verified before the rotation
	}
	c.SetCRLSources([]CRLSource{newSrc})
	if err := c.install(oldSrc, inFlight, true); err != errSourceReplaced {
		t.Fatalf("the old source's list is refused: %v", err)
	}
	if len(c.crls) != 0 {
		t.Fatal("the replaced source's list came back")
	}
	fresh, err := c.accept(newSrc, signCRL(t, newCA2, crlSpec{number: 1}))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.install(newSrc, fresh, true); err != nil {
		t.Fatalf("the new CA's list numbered 1: %v", err)
	}
	// And across issuers a lower number is not a rollback, even when the
	// old list did get in.
	c.crls["dev"] = inFlight
	if err := c.install(newSrc, fresh, true); err != nil {
		t.Fatalf("a rollback is judged within one issuer: %v", err)
	}
	// Within one issuer it still is.
	older, err := c.accept(newSrc, signCRL(t, newCA2, crlSpec{number: 0}))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.install(newSrc, older, true); err == nil {
		t.Fatal("an older list of the same issuer is a rollback")
	}
}

// A CA renewed with the same key and name still signs the list in force:
// the list stays.
func TestSetCRLSourcesKeepsAListTheRenewedCAVerifies(t *testing.T) {
	ca := newCA(t, "CA")
	ren := renewed(t, ca)
	c, _, _ := newChecker(t, Config{CRLs: []CRLSource{fileSource("dev", ca)}, RefreshInterval: time.Hour}, newClock())
	l, err := c.accept(fileSource("dev", ca), signCRL(t, ca, crlSpec{number: 5}))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.install(fileSource("dev", ca), l, false); err != nil {
		t.Fatal(err)
	}
	c.SetCRLSources([]CRLSource{fileSource("dev", ren)})
	if got := c.crls["dev"]; got == nil || string(got.issuer.Raw) != string(ren.Cert.Raw) {
		t.Fatalf("the list is kept, now judged against the renewed certificate: %+v", got)
	}
	user := leaf(t, ca, 9)
	if r := c.CheckCached([]*x509.Certificate{user, ren.Cert}); r.Verdict != Good {
		t.Fatalf("status for a device under the renewed CA: %+v", r)
	}
}

// A CA renewed with the same name and a NEW key cannot have signed the list
// in force: it is dropped, whatever the subject says.
func TestSetCRLSourcesDropsAListWhenTheSameNamedCAHasANewKey(t *testing.T) {
	ca, rekeyed := newCA(t, "CA"), newCA(t, "CA")
	if string(ca.Cert.RawSubject) != string(rekeyed.Cert.RawSubject) {
		t.Fatal("the fixture needs one subject")
	}
	c, _, _ := newChecker(t, Config{CRLs: []CRLSource{fileSource("dev", ca)}, RefreshInterval: time.Hour}, newClock())
	l, err := c.accept(fileSource("dev", ca), signCRL(t, ca, crlSpec{number: 5}))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.install(fileSource("dev", ca), l, false); err != nil {
		t.Fatal(err)
	}
	c.SetCRLSources([]CRLSource{fileSource("dev", rekeyed)})
	if len(c.crls) != 0 {
		t.Fatalf("a list the new key never signed was kept: %d", len(c.crls))
	}
}
