// Package testpki cuts throwaway certificates for tests and for the lab: one
// CA, and leaves for a TLS server and for a client. Nothing in a shipping
// binary imports it, and nothing it writes protects anything real — the lab
// broker listens on the loopback and the files land in a git-ignored
// directory.
package testpki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// CA is a self-signed certificate authority.
type CA struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
}

// NewCA makes a CA valid from notBefore to notAfter.
func NewCA(cn string, notBefore, notAfter time.Time) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	sn, err := serial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{SerialNumber: sn, Subject: pkix.Name{CommonName: cn},
		NotBefore: notBefore, NotAfter: notAfter, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{Cert: cert, Key: key}, nil
}

// Leaf describes one certificate to issue. Client selects the clientAuth
// extended key usage; otherwise it is serverAuth. NoExtKeyUsage issues one
// with no extended key usage at all, which RFC 5280 reads as any purpose, as
// many enterprise user certificates are.
type Leaf struct {
	CommonName          string
	Emails              []string
	IPs                 []net.IP
	Client              bool
	NoExtKeyUsage       bool
	NotBefore, NotAfter time.Time
}

// Issue signs a leaf and returns it ready for crypto/tls, Leaf set.
func (ca *CA) Issue(l Leaf) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	sn, err := serial()
	if err != nil {
		return tls.Certificate{}, err
	}
	eku := x509.ExtKeyUsageServerAuth
	if l.Client {
		eku = x509.ExtKeyUsageClientAuth
	}
	tmpl := &x509.Certificate{SerialNumber: sn, Subject: pkix.Name{CommonName: l.CommonName},
		EmailAddresses: l.Emails, IPAddresses: l.IPs, NotBefore: l.NotBefore, NotAfter: l.NotAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{eku}}
	if l.NoExtKeyUsage {
		tmpl.ExtKeyUsage = nil
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
}

// Pool is a certificate pool holding only this CA.
func (ca *CA) Pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(ca.Cert)
	return p
}

// PEM is the CA certificate, PEM-encoded.
func (ca *CA) PEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Cert.Raw})
}

// PEMs renders a leaf as a certificate file and a PKCS#8 key file.
func PEMs(c tls.Certificate) (certPEM, keyPEM []byte, err error) {
	der, err := x509.MarshalPKCS8PrivateKey(c.PrivateKey)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Certificate[0]}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// The file names WriteLab writes, and tests/lab/slice/broker.yaml reads.
const (
	LabCA         = "broker-ca.pem"
	LabServerCert = "broker.pem"
	LabServerKey  = "broker-key.pem"
	LabClientCert = "client.pem"
	LabClientKey  = "client-key.pem"
)

// WriteLab writes the vertical slice's lab PKI into dir: one CA that is both
// the broker's client trust anchor and the issuer of its server certificate
// (for 127.0.0.1), and one client certificate for email. Everything is valid
// for a day from now. Keys are 0600.
func WriteLab(dir, email string, now time.Time) error {
	// MkdirAll and WriteFile keep an existing mode; a set left loose by an
	// earlier run is tightened, not inherited.
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	ca, err := NewCA("port49 lab slice CA", now.Add(-time.Hour), now.Add(24*time.Hour))
	if err != nil {
		return err
	}
	srv, err := ca.Issue(Leaf{CommonName: "port49 lab broker", IPs: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour)})
	if err != nil {
		return err
	}
	cli, err := ca.Issue(Leaf{CommonName: email, Emails: []string{email}, Client: true,
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour)})
	if err != nil {
		return err
	}
	files := map[string][]byte{LabCA: ca.PEM()}
	for _, l := range []struct {
		c         tls.Certificate
		cert, key string
	}{{srv, LabServerCert, LabServerKey}, {cli, LabClientCert, LabClientKey}} {
		c, k, err := PEMs(l.c)
		if err != nil {
			return err
		}
		files[l.cert], files[l.key] = c, k
	}
	for name, body := range files {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, body, 0o600); err != nil {
			return fmt.Errorf("testpki: %s: %w", name, err)
		}
		if err := os.Chmod(path, 0o600); err != nil {
			return fmt.Errorf("testpki: %s: %w", name, err)
		}
	}
	return nil
}

func serial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
}
