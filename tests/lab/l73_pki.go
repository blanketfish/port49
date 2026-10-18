package lab

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"
)

// L73's PKI. The device and port49d both anchor at Root. The device's own
// certificate comes from Inter, so cell (e) can see whether the device
// sends its chain. Other is a CA neither side trusts. Every key is made
// here and held in memory; a later task writes the keys port49d needs
// 0600 and registers them for the leak check. The device's key is made on
// the device and never leaves it.

type l73Cert struct {
	Cert *x509.Certificate
	Key  crypto.Signer
}

func (c l73Cert) PEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Cert.Raw})
}

func (c l73Cert) KeyPEM() ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(c.Key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func l73Key(alg string) (crypto.Signer, error) {
	switch alg {
	case "ecdsa":
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "rsa":
		return rsa.GenerateKey(rand.Reader, 2048)
	}
	return nil, fmt.Errorf("key algorithm %q: want ecdsa or rsa", alg)
}

// l73Issue signs tmpl for pub with issuer; with issuer.Cert nil, tmpl is
// self-signed by issuer.Key.
func l73Issue(tmpl *x509.Certificate, pub crypto.PublicKey, issuer l73Cert) (*x509.Certificate, error) {
	sn, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 126))
	if err != nil {
		return nil, err
	}
	tmpl.SerialNumber = sn
	parent := issuer.Cert
	if parent == nil {
		parent = tmpl
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, issuer.Key)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

func l73CA(alg, cn string, now time.Time, parent *l73Cert) (l73Cert, error) {
	key, err := l73Key(alg)
	if err != nil {
		return l73Cert{}, err
	}
	tmpl := &x509.Certificate{Subject: pkix.Name{CommonName: cn}, NotBefore: now.Add(-time.Hour),
		NotAfter: now.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature}
	signer := l73Cert{Key: key}
	if parent != nil {
		signer = *parent
	}
	cert, err := l73Issue(tmpl, key.Public(), signer)
	if err != nil {
		return l73Cert{}, err
	}
	return l73Cert{Cert: cert, Key: key}, nil
}

type l73PKI struct {
	Alg                string
	Root, Inter, Other l73Cert
}

func l73NewPKI(alg string, now time.Time) (*l73PKI, error) {
	root, err := l73CA(alg, "L73 Lab Root", now, nil)
	if err != nil {
		return nil, err
	}
	inter, err := l73CA(alg, "L73 Lab Device Intermediate", now, &root)
	if err != nil {
		return nil, err
	}
	other, err := l73CA(alg, "L73 Untrusted CA", now, nil)
	if err != nil {
		return nil, err
	}
	return &l73PKI{Alg: alg, Root: root, Inter: inter, Other: other}, nil
}

// l73ServerLeaf is one server certificate port49d presents in a cell.
type l73ServerLeaf struct {
	DNSNames            []string
	IPs                 []net.IP
	NotBefore, NotAfter time.Time
}

func (p *l73PKI) Server(from l73Cert, l l73ServerLeaf) (l73Cert, error) {
	key, err := l73Key(p.Alg)
	if err != nil {
		return l73Cert{}, err
	}
	tmpl := &x509.Certificate{Subject: pkix.Name{CommonName: "port49 L73"}, DNSNames: l.DNSNames, IPAddresses: l.IPs,
		NotBefore: l.NotBefore, NotAfter: l.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if p.Alg == "rsa" {
		tmpl.KeyUsage |= x509.KeyUsageKeyEncipherment
	}
	cert, err := l73Issue(tmpl, key.Public(), from)
	if err != nil {
		return l73Cert{}, err
	}
	return l73Cert{Cert: cert, Key: key}, nil
}

// l73CSR is what a device's certificate request asks for.
type l73CSR struct {
	Subject   string
	DNSNames  []string
	IPs       []string
	Emails    []string
	KeyAlg    string
	Requested []string // extension OIDs the request carries, dotted
	EKU       []string // extended key usages it asks for; none when empty
}

var l73OIDEKU = asn1.ObjectIdentifier{2, 5, 29, 37}

func l73ParseCSR(csrPEM []byte) (*x509.CertificateRequest, error) {
	b, _ := pem.Decode(csrPEM)
	if b == nil || !strings.Contains(b.Type, "CERTIFICATE REQUEST") {
		return nil, errors.New("no PEM certificate request")
	}
	csr, err := x509.ParseCertificateRequest(b.Bytes)
	if err != nil {
		return nil, err
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("the request's signature does not verify: %w", err)
	}
	return csr, nil
}

func l73CSRFacts(csrPEM []byte) (l73CSR, error) {
	csr, err := l73ParseCSR(csrPEM)
	if err != nil {
		return l73CSR{}, err
	}
	f := l73CSR{Subject: csr.Subject.String(), DNSNames: csr.DNSNames, Emails: csr.EmailAddresses, KeyAlg: l73KeyName(csr.PublicKey)}
	for _, ip := range csr.IPAddresses {
		f.IPs = append(f.IPs, ip.String())
	}
	for _, e := range csr.Extensions {
		f.Requested = append(f.Requested, e.Id.String())
		if e.Id.Equal(l73OIDEKU) {
			var oids []asn1.ObjectIdentifier
			if _, err := asn1.Unmarshal(e.Value, &oids); err != nil {
				return f, fmt.Errorf("the requested extended key usage: %w", err)
			}
			for _, o := range oids {
				f.EKU = append(f.EKU, l73EKUName(o.String()))
			}
		}
	}
	return f, nil
}

func l73EKUName(oid string) string {
	switch oid {
	case "1.3.6.1.5.5.7.3.1":
		return "serverAuth"
	case "1.3.6.1.5.5.7.3.2":
		return "clientAuth"
	}
	return oid
}

func l73KeyName(pub any) string {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA-%d", k.N.BitLen())
	case *ecdsa.PublicKey:
		return "ECDSA-" + k.Curve.Params().Name
	}
	return fmt.Sprintf("%T", pub)
}

// l73SignCSR is the lab CA's answer to the device's request: its subject and
// names as asked, clientAuth (what port49 requires, decision 50 ruling 7).
// A request that names neither a dNSName nor an iPAddress cannot name the
// device to port49, so name and addr are added and added says so.
func l73SignCSR(csrPEM []byte, issuer l73Cert, notBefore, notAfter time.Time, name string, addr net.IP) (*x509.Certificate, bool, error) {
	csr, err := l73ParseCSR(csrPEM)
	if err != nil {
		return nil, false, err
	}
	tmpl := &x509.Certificate{Subject: csr.Subject, DNSNames: csr.DNSNames, IPAddresses: csr.IPAddresses,
		EmailAddresses: csr.EmailAddresses, NotBefore: notBefore, NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	if _, ok := csr.PublicKey.(*rsa.PublicKey); ok {
		tmpl.KeyUsage |= x509.KeyUsageKeyEncipherment
	}
	added := len(csr.DNSNames) == 0 && len(csr.IPAddresses) == 0
	if added {
		tmpl.DNSNames, tmpl.IPAddresses = []string{name}, []net.IP{addr}
	}
	cert, err := l73Issue(tmpl, csr.PublicKey, issuer)
	return cert, added, err
}

// l73CertFacts is a certificate as one note line.
func l73CertFacts(c *x509.Certificate) string {
	var ips, ekus []string
	for _, ip := range c.IPAddresses {
		ips = append(ips, ip.String())
	}
	for _, u := range c.ExtKeyUsage {
		switch u {
		case x509.ExtKeyUsageClientAuth:
			ekus = append(ekus, "clientAuth")
		case x509.ExtKeyUsageServerAuth:
			ekus = append(ekus, "serverAuth")
		default:
			ekus = append(ekus, fmt.Sprint(int(u)))
		}
	}
	if len(ekus) == 0 {
		ekus = []string{"none"}
	}
	return fmt.Sprintf("subject %q, issuer %q, dNSName %v, iPAddress %v, EKU %v, key %s, valid %s to %s",
		c.Subject.String(), c.Issuer.String(), c.DNSNames, ips, ekus, l73KeyName(c.PublicKey),
		c.NotBefore.UTC().Format(time.RFC3339), c.NotAfter.UTC().Format(time.RFC3339))
}
