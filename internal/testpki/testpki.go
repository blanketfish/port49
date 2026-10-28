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
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// CA is a self-signed certificate authority.
type CA struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
}

// NewCA makes a CA valid from notBefore to notAfter. It may sign CRLs.
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
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature}
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

// CrossSign is this CA's name and key certified by signer: the certificate a
// rotation by cross-signing gives out, so a server certificate this CA issued
// verifies to this CA's own root and, through the cross certificate, to the
// signer's.
func (ca *CA) CrossSign(signer *CA) (*x509.Certificate, error) {
	sn, err := serial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{SerialNumber: sn, Subject: ca.Cert.Subject,
		NotBefore: ca.Cert.NotBefore, NotAfter: ca.Cert.NotAfter, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer.Cert, &ca.Key.PublicKey, signer.Key)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// Leaf describes one certificate to issue. Client selects the clientAuth
// extended key usage; otherwise it is serverAuth. NoExtKeyUsage issues one
// with no extended key usage at all, which RFC 5280 reads as any purpose, as
// many enterprise user certificates are. Serial, when set, is the
// certificate's serial; nil is a random one.
type Leaf struct {
	CommonName          string
	Emails              []string
	DNSNames            []string
	IPs                 []net.IP
	URIs                []*url.URL
	Client              bool
	NoExtKeyUsage       bool
	NotBefore, NotAfter time.Time
	Serial              *big.Int
	// ExtraExtensions are added as given; one for subjectAltName replaces the
	// generated one, for a SAN whose bytes crypto/x509 would normalize.
	ExtraExtensions []pkix.Extension
	// CRLDistributionPoints are the URLs the certificate names for its CRL.
	CRLDistributionPoints []string
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
	if l.Serial != nil {
		sn = l.Serial
	}
	eku := x509.ExtKeyUsageServerAuth
	if l.Client {
		eku = x509.ExtKeyUsageClientAuth
	}
	tmpl := &x509.Certificate{SerialNumber: sn, Subject: pkix.Name{CommonName: l.CommonName},
		EmailAddresses: l.Emails, DNSNames: l.DNSNames, IPAddresses: l.IPs, URIs: l.URIs, NotBefore: l.NotBefore, NotAfter: l.NotAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{eku}}
	if l.NoExtKeyUsage {
		tmpl.ExtKeyUsage = nil
	}
	tmpl.ExtraExtensions = l.ExtraExtensions
	tmpl.CRLDistributionPoints = l.CRLDistributionPoints
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

// Loopback is 127.0.0.1, the address a test or lab server's certificate names.
func Loopback() []net.IP { return []net.IP{net.ParseIP("127.0.0.1")} }

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
func WriteLab(dir, email string, now time.Time) error { return WriteLabWith(dir, email, nil, now) }

// LabClientFiles names the certificate and key WriteLabWith writes for an
// extra person: client-<local part>.pem and client-<local part>-key.pem.
func LabClientFiles(email string) (cert, key string) {
	local, _, _ := strings.Cut(email, "@")
	return "client-" + local + ".pem", "client-" + local + "-key.pem"
}

// WriteLabWith is WriteLab with a client certificate for each of others
// too, from the same CA, under LabClientFiles' names: the lab's on-call
// and peer beside its operator (plan 7c).
func WriteLabWith(dir, email string, others []string, now time.Time) error {
	return WriteLabAt(dir, email, others, nil, now)
}

// WriteLabAt is WriteLabWith with the broker's server certificate also valid
// for serverIPs, for a lab whose brokers listen on addresses of their own
// (the regions' namespaces); 127.0.0.1 stays.
func WriteLabAt(dir, email string, others []string, serverIPs []net.IP, now time.Time) error {
	// MkdirAll keeps an existing mode; a directory left loose by an earlier
	// run is tightened, not inherited. The files are written fresh
	// (writeFresh).
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
	srv, err := ca.Issue(Leaf{CommonName: "port49 lab broker", DNSNames: []string{"port49-broker"}, IPs: append([]net.IP{net.ParseIP("127.0.0.1")}, serverIPs...),
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
	for _, o := range others {
		oc, err := ca.Issue(Leaf{CommonName: o, Emails: []string{o}, Client: true,
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour)})
		if err != nil {
			return err
		}
		c, k, err := PEMs(oc)
		if err != nil {
			return err
		}
		certName, keyName := LabClientFiles(o)
		files[certName], files[keyName] = c, k
	}
	for name, body := range files {
		if err := writeFresh(filepath.Join(dir, name), body); err != nil {
			return fmt.Errorf("testpki: %s: %w", name, err)
		}
	}
	return nil
}

// The file names WriteInventoryLab writes, and the identity its port49d
// client certificate names.
const (
	InvCA           = "inventory-ca.pem"
	InvServerCert   = "inventory.pem"
	InvServerKey    = "inventory-key.pem"
	InvDaemonCert   = "port49d.pem"
	InvDaemonKey    = "port49d-key.pem"
	InvOperatorCert = "operator.pem"
	InvOperatorKey  = "operator-key.pem"
	InvDaemonID     = "spiffe://port49.test/port49d"
)

// WriteInventoryLab writes the inventory service's lab PKI into dir, as
// WriteLab writes the slice's: one CA that is both the service's client trust
// anchor and the issuer of its server certificate (for 127.0.0.1); a client
// certificate for port49d, named by the URI SAN InvDaemonID; and one for an
// operator, named by the email alice@slice.port49.test. Everything is valid
// for a day from now. Keys are 0600.
func WriteInventoryLab(dir string, now time.Time) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	nb, na := now.Add(-time.Hour), now.Add(24*time.Hour)
	ca, err := NewCA("port49 lab inventory CA", nb, na)
	if err != nil {
		return err
	}
	daemonID, err := url.Parse(InvDaemonID)
	if err != nil {
		return err
	}
	files := map[string][]byte{InvCA: ca.PEM()}
	for _, l := range []struct {
		leaf      Leaf
		cert, key string
	}{
		{Leaf{CommonName: "port49 lab inventory", IPs: Loopback()}, InvServerCert, InvServerKey},
		{Leaf{CommonName: "port49d", URIs: []*url.URL{daemonID}, Client: true}, InvDaemonCert, InvDaemonKey},
		{Leaf{CommonName: "alice", Emails: []string{"alice@slice.port49.test"}, Client: true}, InvOperatorCert,
			InvOperatorKey},
	} {
		l.leaf.NotBefore, l.leaf.NotAfter = nb, na
		c, err := ca.Issue(l.leaf)
		if err != nil {
			return err
		}
		certPEM, keyPEM, err := PEMs(c)
		if err != nil {
			return err
		}
		files[l.cert], files[l.key] = certPEM, keyPEM
	}
	for name, body := range files {
		if err := writeFresh(filepath.Join(dir, name), body); err != nil {
			return fmt.Errorf("testpki: %s: %w", name, err)
		}
	}
	return nil
}

// The file names WriteWorkloadLab writes (plan 8): a workload CA of its own,
// its key (so RenewWorkload can issue again), and one workload certificate.
const (
	WorkloadCA    = "workload-ca.pem"
	WorkloadCAKey = "workload-ca-key.pem"
	WorkloadCert  = "workload.pem"
	WorkloadKey   = "workload-key.pem"
)

// WriteWorkloadLab writes a workload PKI into dir: a CA, and a client
// certificate whose one URI SAN is id, valid for a day from now. Keys are
// 0600.
func WriteWorkloadLab(dir, id string, now time.Time) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	ca, err := NewCA("port49 lab workloads CA", now.Add(-time.Hour), now.Add(48*time.Hour))
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalECPrivateKey(ca.Key)
	if err != nil {
		return err
	}
	if err := writeFresh(filepath.Join(dir, WorkloadCA), ca.PEM()); err != nil {
		return err
	}
	if err := writeFresh(filepath.Join(dir, WorkloadCAKey), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY",
		Bytes: keyDER})); err != nil {
		return err
	}
	return issueWorkload(ca, dir, id, now)
}

// RenewWorkload issues dir's workload certificate again from the CA
// WriteWorkloadLab wrote there: the same id, a new key and serial, as a
// renewal against a real CA gives.
func RenewWorkload(dir, id string, now time.Time) error {
	ca, err := readWorkloadCA(dir)
	if err != nil {
		return err
	}
	return issueWorkload(ca, dir, id, now)
}

// WriteWorkloadLabFrom issues a second workload certificate for id from the
// CA in caDir, into dir: a second workload under one anchor.
func WriteWorkloadLabFrom(caDir, dir, id string, now time.Time) error {
	ca, err := readWorkloadCA(caDir)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return issueWorkload(ca, dir, id, now)
}

func issueWorkload(ca *CA, dir, id string, now time.Time) error {
	u, err := url.Parse(id)
	if err != nil {
		return err
	}
	c, err := ca.Issue(Leaf{CommonName: id, URIs: []*url.URL{u}, Client: true, NotBefore: now.Add(-time.Hour),
		NotAfter: now.Add(24 * time.Hour)})
	if err != nil {
		return err
	}
	certPEM, keyPEM, err := PEMs(c)
	if err != nil {
		return err
	}
	if err := writeFresh(filepath.Join(dir, WorkloadCert), certPEM); err != nil {
		return err
	}
	return writeFresh(filepath.Join(dir, WorkloadKey), keyPEM)
}

func readWorkloadCA(dir string) (*CA, error) {
	certPEM, err := os.ReadFile(filepath.Join(dir, WorkloadCA))
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(filepath.Join(dir, WorkloadCAKey))
	if err != nil {
		return nil, err
	}
	cb, _ := pem.Decode(certPEM)
	kb, _ := pem.Decode(keyPEM)
	if cb == nil || kb == nil {
		return nil, fmt.Errorf("testpki: %s holds no workload CA", dir)
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, err
	}
	key, err := x509.ParseECPrivateKey(kb.Bytes)
	if err != nil {
		return nil, err
	}
	return &CA{Cert: cert, Key: key}, nil
}

// writeFresh writes body to a new 0600 file at path, removing whatever was
// there first. os.WriteFile would truncate an existing file and keep its mode,
// so a key left loose by an earlier run would hold the new key, if only until
// a chmod, and any reader that already had it open could read it.
func writeFresh(path string, body []byte) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(body); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// IssueCA signs a subordinate CA under ca, valid from notBefore to notAfter:
// an issuing CA beneath a root, as the workload anchor's tests need.
func (ca *CA) IssueCA(cn string, notBefore, notAfter time.Time) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	sn, err := serial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{SerialNumber: sn, Subject: pkix.Name{CommonName: cn}, NotBefore: notBefore,
		NotAfter: notAfter, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{Cert: cert, Key: key}, nil
}

func serial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
}
