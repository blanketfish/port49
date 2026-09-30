package inventory

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/rhwendt/port49/internal/bundle"
)

var errUntrusted = errors.New("no client certificate the trust anchor verified")

// CallerOf names a request's caller by its verified client certificate
// (design §17, "Internal interfaces"; spec §10): the leaf's one URI SAN,
// verbatim — a workload (design §7, the workload x509 row of spec §2) — or,
// with no URI SAN, `user:` and its one email SAN, lower-cased, as the broker
// names a person. Several of either, neither, a certificate outside its
// validity now, or a leaf not issued for client authentication is refused:
// ambiguity fails closed. Only VerifiedChains is read. The name is checked to
// be printable before any line carries it.
func CallerOf(cs *tls.ConnectionState, now time.Time) (string, error) {
	if cs == nil || len(cs.VerifiedChains) == 0 || len(cs.VerifiedChains[0]) == 0 {
		return "", errUntrusted
	}
	chain := cs.VerifiedChains[0]
	for _, c := range chain {
		if now.Before(c.NotBefore) || now.After(c.NotAfter) {
			return "", errors.New("a certificate in the chain is outside its validity")
		}
	}
	leaf := chain[0]
	if len(leaf.ExtKeyUsage) > 0 && !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageClientAuth) {
		return "", errors.New("the certificate is not issued for client authentication")
	}
	switch {
	case len(leaf.URIs) > 1:
		return "", fmt.Errorf("the certificate names %d URI SANs; a caller is one", len(leaf.URIs))
	case len(leaf.URIs) == 1:
		id := leaf.URIs[0].String()
		if !bundle.NameOK(id) {
			return "", errors.New("the certificate's URI SAN is not printable ASCII")
		}
		return id, nil
	case len(leaf.EmailAddresses) == 1:
		// Lower-cased because an email's case names no one different in
		// practice, and the broker names a person the same way; Load refuses
		// a `user:` entry with a capital, so API.gate's exact match
		// compares like with like.
		e := strings.ToLower(leaf.EmailAddresses[0])
		if !bundle.NameOK(e) || strings.Count(e, "@") != 1 {
			return "", errors.New("the certificate's email SAN is not one printable address")
		}
		return "user:" + e, nil
	case len(leaf.EmailAddresses) > 1:
		return "", fmt.Errorf("the certificate names %d email SANs and no URI SAN; a caller is one", len(leaf.EmailAddresses))
	}
	return "", errors.New("the certificate names no URI SAN and no email SAN")
}
