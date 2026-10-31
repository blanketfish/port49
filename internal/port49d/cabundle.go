package port49d

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/fence"
)

// loadCABundle is broker.tls_ca_bundle_file's CAs, PEM, which GET
// /v1/config sends every client (spec §13 decision 43 ruling 25), or nil.
// A bundle that cannot be read, is out of api.ParseCABundle's bounds, or
// does not verify the server certificate being served is not sent, and is
// said in one line; the start goes on. refused is then true, and GET
// /v1/config says so (broker_ca_bundle_refused), so clients keep the CAs
// they hold rather than read the broker as one that sends none.
func loadCABundle(path string, cert tls.Certificate, say func(string, ...any)) (bundle []byte, refused bool) {
	if path == "" {
		return nil, false
	}
	certs, err := readCABundle(path)
	if err == nil {
		err = verifiesServer(certs, cert)
	}
	if err != nil {
		say("broker: tls_ca_bundle_file %s: %v; no CA bundle is sent, so clients keep the CAs they hold", path, err)
		return nil, true
	}
	say("broker: tls_ca_bundle_file %s, sent to every client: %s", path, api.CAFingerprints(certs))
	return api.EncodeCABundle(certs), false
}

func readCABundle(path string) ([]*x509.Certificate, error) {
	raw, err := fence.Read(path, api.MaxCABundleBytes+1, "tls_ca_bundle_file")
	if err != nil {
		return nil, err
	}
	return api.ParseCABundle(raw)
}

// verifiesServer refuses a bundle that does not hold the CA of the server
// certificate in use: a client would refuse it, and no rotation can start
// from it.
func verifiesServer(certs []*x509.Certificate, cert tls.Certificate) error {
	if len(cert.Certificate) == 0 {
		return errors.New("no server certificate")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return err
	}
	roots, inter := x509.NewCertPool(), x509.NewCertPool()
	for _, c := range certs {
		roots.AddCert(c)
	}
	for _, der := range cert.Certificate[1:] {
		if c, err := x509.ParseCertificate(der); err == nil {
			inter.AddCert(c)
		}
	}
	// Judged inside the leaf's own validity: an expired server certificate
	// is said on its own line, and is not this bundle's fault.
	at := leaf.NotBefore.Add(leaf.NotAfter.Sub(leaf.NotBefore) / 2)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, CurrentTime: at,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return fmt.Errorf("it does not hold the CA of the server certificate in tls_cert_file (%v)", err)
	}
	return nil
}
