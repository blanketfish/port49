// Package issuer is the broker's issuing CA (plan 9b; spec §13 decision
// 43): the short-lived client certificates it issues a person over an OIDC
// sign-in, and the files the CA is kept in. port49 is a relying party, not a
// certificate authority, but for these: they are port49's own trust
// domain's, no device sees one, and only the broker trusts them.
package issuer

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"time"
)

// The files, in the broker's state directory (decision 43 ruling 14).
const (
	CertFile         = "issuing-ca.pem"
	KeyFile          = "issuing-ca.key"
	NextCertFile     = "issuing-ca-next.pem"
	NextKeyFile      = "issuing-ca-next.key"
	PreviousCertFile = "issuing-ca-previous.pem"
)

// broker.identity.issuance.certificate_lifetime's default and bounds
// (decision 43 ruling 9).
const (
	DefaultLifetime = 12 * time.Hour
	MinLifetime     = time.Hour
	MaxLifetime     = 24 * time.Hour
)

// caLife is a new issuing CA's validity; a rotation replaces it long before.
const caLife = 5 * 365 * 24 * time.Hour

// New is a new issuing CA: a P-256 key, and a certificate it signs itself,
// valid caLife from now, named "port49 issuing CA" and 8 random hex digits,
// both PEM (the key PKCS #8).
func New(now time.Time) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	var tag [4]byte
	if _, err := rand.Read(tag[:]); err != nil {
		return nil, nil, err
	}
	serial, err := newSerial()
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{SerialNumber: serial,
		Subject:   pkix.Name{Organization: []string{"port49"}, CommonName: "port49 issuing CA " + hex.EncodeToString(tag[:])},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(caLife),
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, BasicConstraintsValid: true, IsCA: true,
		MaxPathLenZero: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, nil, err
	}
	pk, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk}), nil
}

// newSerial is 128 random bits, never zero.
func newSerial() (*big.Int, error) {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	return n.Add(n, big.NewInt(1)), nil
}

// Files reads the CA's files by name, from wherever the broker keeps them:
// (nil, nil) for a file that is not there.
type Files struct {
	Cert func(name string) ([]byte, error)
	Key  func(name string) ([]byte, error)
}

// Mem is Files over m, for tests and Ephemeral: a name m lacks is no file.
func Mem(m map[string][]byte) Files {
	get := func(name string) ([]byte, error) { return m[name], nil }
	return Files{Cert: get, Key: get}
}

// CA is the issuing CA as a broker holds it.
type CA struct {
	// Cert is the CA that signs, from CertFile; nil when there is none
	// usable.
	Cert *x509.Certificate
	// Trusted is every CA a chain may end at: Cert, the staged next and the
	// previous, those present (decision 43 ruling 14).
	Trusted []*x509.Certificate
	// Unavailable is why Issue refuses: nil when it issues.
	Unavailable error

	signer crypto.Signer
}

// Fingerprint is "sha256:" and the hex SHA-256 of c's DER, as the broker's
// records name a certificate.
func Fingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func rfc(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// Load reads the CA's files (decision 43 ruling 14). It never fails: a
// broker that cannot issue still starts and serves everything else, since
// port49d answers device AAA in the same process, and Unavailable says why
// nothing is issued. lines are what the start says, one fact each.
func Load(f Files, now time.Time) (*CA, []string) {
	c := &CA{}
	var lines []string
	cert, err := readCA(f, CertFile)
	switch {
	case err != nil:
		c.Unavailable = fmt.Errorf("%s is not usable: %v", CertFile, err)
		lines = append(lines, fmt.Sprintf("%s is not usable (%v), so no certificate is issued and none it issued is "+
			"trusted; fix it and restart", CertFile, err))
	case cert == nil:
		c.Unavailable = fmt.Errorf("%s is missing", CertFile)
		lines = append(lines, CertFile+" is missing, so no certificate is issued and none it issued is trusted: on a "+
			"first install run init-issuer once, as the broker's user; on each further broker on this store, copy "+
			CertFile+" and "+KeyFile+" from the first into its broker.state_dir")
	case now.Before(cert.NotBefore):
		c.Unavailable = fmt.Errorf("%s is not valid until %s", CertFile, rfc(cert.NotBefore))
		lines = append(lines, fmt.Sprintf("%s is not valid until %s, so no certificate is issued and none it issued is "+
			"trusted: check this broker's clock against the one that ran init-issuer", CertFile, rfc(cert.NotBefore)))
	case !now.Before(cert.NotAfter):
		c.Unavailable = fmt.Errorf("%s expired at %s", CertFile, rfc(cert.NotAfter))
		lines = append(lines, fmt.Sprintf("%s expired at %s, so no certificate is issued and none it issued is "+
			"trusted: run rotate-issuer twice, restarting every broker after each, to make and promote another",
			CertFile, rfc(cert.NotAfter)))
	default:
		c.Cert = cert
		c.Trusted = append(c.Trusted, cert)
		if c.signer, err = readKey(f, KeyFile, cert); err != nil {
			c.Unavailable = fmt.Errorf("%s is not usable: %v", KeyFile, err)
			lines = append(lines, fmt.Sprintf("%s is not usable (%v), so no certificate is issued; the certificates "+
				"already issued are trusted; restore it beside %s (0600, the broker's user's) and restart",
				KeyFile, err, CertFile))
		}
	}
	for _, o := range []struct{ name, what string }{{NextCertFile, "the staged next CA"},
		{PreviousCertFile, "the previous CA"}} {
		cert, err := readCA(f, o.name)
		switch {
		case err != nil:
			lines = append(lines, fmt.Sprintf("%s is not usable (%v), so %s is not trusted", o.name, err, o.what))
		case cert != nil && !now.Before(cert.NotAfter):
			lines = append(lines, fmt.Sprintf("%s has expired (%s), so %s is not trusted; remove it and restart",
				o.name, rfc(cert.NotAfter), o.what))
		case cert != nil:
			c.Trusted = append(c.Trusted, cert)
			line := fmt.Sprintf("trusting %s too, %s (%s), valid until %s", o.what, cert.Subject, Fingerprint(cert),
				rfc(cert.NotAfter))
			if o.name == PreviousCertFile {
				line += "; remove " + PreviousCertFile + " once every certificate it issued has expired " +
					"(certificate_lifetime after the promotion), and restart"
			}
			lines = append(lines, line)
		}
	}
	if c.Unavailable == nil {
		lines = append([]string{fmt.Sprintf("issuing as %s (%s), valid until %s", c.Cert.Subject,
			Fingerprint(c.Cert), rfc(c.Cert.NotAfter))}, lines...)
	}
	return c, lines
}

// readCA is the one CA certificate in the PEM file name; nil for no file.
func readCA(f Files, name string) (*x509.Certificate, error) {
	raw, err := f.Cert(name)
	if err != nil || raw == nil {
		return nil, err
	}
	blk, rest := pem.Decode(raw)
	if blk == nil || blk.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("not one PEM certificate")
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return nil, err
	}
	if !c.BasicConstraintsValid || !c.IsCA || c.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, errors.New("not a CA certificate")
	}
	return c, nil
}

// readKey is the PKCS #8 key in name, which must be cert's.
func readKey(f Files, name string, cert *x509.Certificate) (crypto.Signer, error) {
	raw, err := f.Key(name)
	if err != nil {
		return nil, err
	}
	if raw == nil {
		return nil, errors.New("missing")
	}
	blk, _ := pem.Decode(raw)
	if blk == nil || blk.Type != "PRIVATE KEY" {
		return nil, errors.New("not a PEM PKCS #8 private key")
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	s, ok := k.(crypto.Signer)
	pub, okPub := cert.PublicKey.(interface{ Equal(crypto.PublicKey) bool })
	if !ok || !okPub || !pub.Equal(s.Public()) {
		return nil, fmt.Errorf("it is not the key of %s", CertFile)
	}
	return s, nil
}

// Ephemeral is a new CA held in memory alone (New, then Load over Mem): for
// tests.
func Ephemeral(now time.Time) (*CA, error) {
	certPEM, keyPEM, err := New(now)
	if err != nil {
		return nil, err
	}
	c, _ := Load(Mem(map[string][]byte{CertFile: certPEM, KeyFile: keyPEM}), now)
	return c, c.Unavailable
}

// Issue signs a client certificate for pub over s (decision 43 ruling 9):
// CN the principal, one URI SAN carrying the sign-in (SignIn.URI),
// clientAuth, valid from a minute before now for lifetime, and never past
// the CA's own end.
func (c *CA) Issue(pub crypto.PublicKey, s SignIn, now time.Time, lifetime time.Duration) (*x509.Certificate, error) {
	switch {
	case c == nil:
		return nil, errors.New("issuer: no issuing CA")
	case c.Unavailable != nil:
		return nil, c.Unavailable
	case c.Cert == nil:
		return nil, errors.New("issuer: no issuing CA certificate")
	case now.Before(c.Cert.NotBefore) || !now.Before(c.Cert.NotAfter):
		return nil, fmt.Errorf("issuer: now is outside the issuing CA's validity, %s to %s",
			rfc(c.Cert.NotBefore), rfc(c.Cert.NotAfter))
	case lifetime < MinLifetime || lifetime > MaxLifetime:
		return nil, fmt.Errorf("issuer: certificate lifetime %s is outside %s to %s", lifetime, MinLifetime, MaxLifetime)
	}
	if err := s.validate(); err != nil {
		return nil, fmt.Errorf("issuer: the sign-in cannot be certified: %v", err)
	}
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}
	notAfter := now.Add(lifetime)
	if notAfter.After(c.Cert.NotAfter) {
		notAfter = c.Cert.NotAfter
	}
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: s.Principal},
		URIs: []*url.URL{s.URI()}, NotBefore: now.Add(-time.Minute), NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.Cert, pub, c.signer)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// Ends reports whether chains, a connection's verified chains, end at a CA
// c trusts: issued when every one does, mixed when some do and some do not,
// which the broker refuses (decision 43 ruling 10). A nil c issued nothing.
func (c *CA) Ends(chains [][]*x509.Certificate) (issued, mixed bool) {
	if c == nil || len(c.Trusted) == 0 {
		return false, false
	}
	var ours, other bool
	for _, ch := range chains {
		if len(ch) == 0 {
			continue
		}
		if c.trusts(ch[len(ch)-1]) {
			ours = true
		} else {
			other = true
		}
	}
	return ours && !other, ours && other
}

func (c *CA) trusts(cert *x509.Certificate) bool {
	for _, t := range c.Trusted {
		if bytes.Equal(t.Raw, cert.Raw) {
			return true
		}
	}
	return false
}

// PEM is cert, then the CA that signs, as POST /v1/certificate answers it.
func (c *CA) PEM(cert *x509.Certificate) []byte {
	return append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Cert.Raw})...)
}
