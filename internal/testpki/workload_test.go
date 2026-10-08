package testpki

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func readLeaf(t *testing.T, dir string) *x509.Certificate {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, WorkloadCert))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := pem.Decode(raw)
	if b == nil {
		t.Fatal("no certificate PEM")
	}
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// The workload lab writes a CA, its key and a leaf naming one SPIFFE ID, keys
// 0600; a renewal and a second workload verify under the same CA.
func TestWorkloadLabWritesRenewsAndIssuesFromOneCA(t *testing.T) {
	const id, id2 = "spiffe://port49.test/host/a", "spiffe://port49.test/host/b"
	dir, other := t.TempDir(), t.TempDir()
	now := time.Now()
	if err := WriteWorkloadLab(dir, id, now); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{WorkloadCAKey, WorkloadKey} {
		if fi, err := os.Stat(filepath.Join(dir, name)); err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v %v", name, fi, err)
		}
	}
	first := readLeaf(t, dir)
	if err := RenewWorkload(dir, id, now); err != nil {
		t.Fatal(err)
	}
	renewed := readLeaf(t, dir)
	if renewed.SerialNumber.Cmp(first.SerialNumber) == 0 || string(renewed.RawSubjectPublicKeyInfo) == string(first.RawSubjectPublicKeyInfo) {
		t.Fatal("a renewal kept the serial or the key")
	}
	if err := WriteWorkloadLabFrom(dir, other, id2, now); err != nil {
		t.Fatal(err)
	}
	second := readLeaf(t, other)
	ca := readCAPool(t, dir)
	for _, c := range []*x509.Certificate{renewed, second} {
		if _, err := c.Verify(x509.VerifyOptions{Roots: ca, CurrentTime: now,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
			t.Fatal(err)
		}
	}
	if len(renewed.URIs) != 1 || renewed.URIs[0].String() != id || len(second.URIs) != 1 || second.URIs[0].String() != id2 {
		t.Fatalf("%v %v", renewed.URIs, second.URIs)
	}
	if fi, err := os.Stat(filepath.Join(other, WorkloadKey)); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("the second key: %v %v", fi, err)
	}
}

func readCAPool(t *testing.T, dir string) *x509.CertPool {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, WorkloadCA))
	if err != nil {
		t.Fatal(err)
	}
	p := x509.NewCertPool()
	if !p.AppendCertsFromPEM(raw) {
		t.Fatal("no CA in the file")
	}
	return p
}

func TestRenewWorkloadWithoutACAIsAnError(t *testing.T) {
	if err := RenewWorkload(t.TempDir(), "spiffe://port49.test/host/a", time.Now()); err == nil {
		t.Fatal("renewed with no CA")
	}
}
