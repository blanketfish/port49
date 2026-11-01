package agent

import (
	"crypto/x509"
	"slices"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/testpki"
)

// A rotation by cross-signing verifies the server's certificate to the old
// root and the new: every verified chain's root is kept, each once, so a CA
// bundle holding either is the connection's (decision 43 ruling 25).
func TestChainRootsKeepsEveryVerifiedChainsRoot(t *testing.T) {
	now := time.Now()
	oldCA, err := testpki.NewCA("old root", now.Add(-time.Hour), now.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	newCA, err := testpki.NewCA("old root", now.Add(-time.Hour), now.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	cross, err := newCA.CrossSign(oldCA)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := newCA.Issue(testpki.Leaf{CommonName: "broker", DNSNames: []string{"broker.example"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(oldCA.Cert)
	roots.AddCert(newCA.Cert)
	inter := x509.NewCertPool()
	inter.AddCert(cross)
	chains, err := srv.Leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, DNSName: "broker.example"})
	if err != nil {
		t.Fatal(err)
	}
	got := chainRoots(chains)
	if len(chains) < 2 || len(got) != 2 || !slices.ContainsFunc(got, oldCA.Cert.Equal) || !slices.ContainsFunc(got, newCA.Cert.Equal) {
		t.Fatalf("%d chains, %d roots", len(chains), len(got))
	}
	// Control: one chain is one root.
	if got := chainRoots(chains[:1:1]); len(got) != 1 {
		t.Fatalf("one chain, %d roots", len(got))
	}
	if chainRoots(nil) != nil {
		t.Fatal("no chain, a root")
	}
}
