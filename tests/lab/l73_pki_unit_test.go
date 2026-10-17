package lab

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"net"
	"slices"
	"strings"
	"testing"
	"time"
)

func l73TestCSR(t *testing.T, key any, tmpl *x509.CertificateRequest) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func TestL73SignCSRCopiesTheRequestAndChainsToTheRoot(t *testing.T) {
	now := time.Now()
	for _, alg := range []string{"ecdsa", "rsa"} {
		pki, err := l73NewPKI(alg, now)
		if err != nil {
			t.Fatal(err)
		}
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		csr := l73TestCSR(t, key, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "srx1"},
			DNSNames: []string{"srx1"}, IPAddresses: []net.IP{net.ParseIP("172.100.100.21")}})
		cert, added, err := l73SignCSR(csr, pki.Inter, now.Add(-time.Minute), now.Add(time.Hour), "srx1", net.ParseIP("172.100.100.21"))
		if err != nil || added {
			t.Fatalf("%s: %v added=%v", alg, err, added)
		}
		roots, inters := x509.NewCertPool(), x509.NewCertPool()
		roots.AddCert(pki.Root.Cert)
		inters.AddCert(pki.Inter.Cert)
		if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inters, CurrentTime: now,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
			t.Fatalf("%s: %v", alg, err)
		}
		if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err == nil {
			t.Fatalf("%s: the leaf verified without its intermediate; cell (e)'s chain test would prove nothing", alg)
		}
		if !slices.Equal(cert.DNSNames, []string{"srx1"}) || len(cert.IPAddresses) != 1 {
			t.Fatalf("%s: %v %v", alg, cert.DNSNames, cert.IPAddresses)
		}
	}
}

func TestL73SignCSRAddsNamesOnlyWhenTheRequestHasNone(t *testing.T) {
	now := time.Now()
	pki, _ := l73NewPKI("ecdsa", now)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr := l73TestCSR(t, key, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "srx1"}})
	cert, added, err := l73SignCSR(csr, pki.Inter, now, now.Add(time.Hour), "srx1", net.ParseIP("172.100.100.21"))
	if err != nil || !added || !slices.Equal(cert.DNSNames, []string{"srx1"}) || !cert.IPAddresses[0].Equal(net.ParseIP("172.100.100.21")) {
		t.Fatalf("%v %v %v %v", err, added, cert.DNSNames, cert.IPAddresses)
	}
}

func TestL73CSRFactsReadWhatTheDeviceAsked(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	eku, _ := asn1.Marshal([]asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 1}})
	csr := l73TestCSR(t, key, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "srx1"}, DNSNames: []string{"srx1"},
		ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 37}, Value: eku}}})
	f, err := l73CSRFacts(csr)
	if err != nil {
		t.Fatal(err)
	}
	if f.KeyAlg != "RSA-2048" || !slices.Equal(f.EKU, []string{"serverAuth"}) || !slices.Equal(f.DNSNames, []string{"srx1"}) ||
		!slices.Contains(f.Requested, "2.5.29.37") || f.Subject != "CN=srx1" {
		t.Fatalf("%+v", f)
	}
}

func TestL73CSRWithABadSignatureIsRefused(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr := l73TestCSR(t, key, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "srx1"}})
	b, _ := pem.Decode(csr)
	b.Bytes[len(b.Bytes)-3] ^= 0xff
	if _, err := l73CSRFacts(pem.EncodeToMemory(b)); err == nil {
		t.Fatal("a tampered request read as good")
	}
}

func TestL73ServerCertificateNamesWhatItIsGiven(t *testing.T) {
	now := time.Now()
	pki, _ := l73NewPKI("ecdsa", now)
	c, err := pki.Server(pki.Root, l73ServerLeaf{IPs: []net.IP{net.ParseIP("172.100.100.1")},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(pki.Root.Cert)
	if _, err := c.Cert.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now}); err != nil {
		t.Fatal(err)
	}
	if err := c.Cert.VerifyHostname("172.100.100.1"); err != nil {
		t.Fatal(err)
	}
	if facts := l73CertFacts(c.Cert); !strings.Contains(facts, "iPAddress [172.100.100.1]") || !strings.Contains(facts, "EKU [serverAuth]") {
		t.Fatal(facts)
	}
	if k, err := c.KeyPEM(); err != nil || !strings.Contains(string(k), "PRIVATE KEY") {
		t.Fatalf("%v", err)
	}
}
