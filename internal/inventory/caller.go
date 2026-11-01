package inventory

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/blanketfish/port49/internal/bundle"
)

var errUntrusted = errors.New("no client certificate the trust anchor verified")

// uriIdentity is the shape of a workload's name: a hierarchical URI, scheme
// and `://`, printable ASCII with no space. port49-inventory.yaml's entries
// and CallerOf's URI SANs share it (identityShape). An opaque URI such as
// `user:alice@example.com` does not have it, so a URI SAN can never be
// spelled as a person's name.
const uriIdentity = `[a-z][a-z0-9+.-]*://[!-~]+`

var uriIdentityShape = regexp.MustCompile(`^` + uriIdentity + `$`)

// CallerOf names a request's caller by its verified client certificate
// (design §17, "Internal interfaces"; spec §10): the leaf's one URI SAN,
// verbatim — a workload (design §7, the workload x509 row of spec §2) — or,
// with no URI SAN, `user:` and its one email SAN, lower-cased, as the broker
// names a person. The two never share a name: a URI SAN must be hierarchical
// (uriIdentity) and not of the `user` scheme, so a workload's certificate
// cannot take a person's rights, and `user:` comes only from an email SAN.
//
// A leaf with one URI SAN and one email SAN is the workload, by the rule
// above; its email grants nothing. It is not refused: one name, fixed by
// the certificate alone, cannot match under the other, and a workload
// certificate that also carries a contact address is common.
//
// Several of either, neither, a URI SAN of another shape, a certificate
// outside its validity now, or a leaf not issued for client authentication
// is refused: ambiguity fails closed. Only VerifiedChains is read. An error
// is fixed text and a count, never the certificate's text.
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
		if !bundle.NameOK(id) || !uriIdentityShape.MatchString(id) || strings.HasPrefix(id, "user:") {
			return "", errors.New("the certificate's URI SAN is not a workload's name: scheme://..., printable " +
				"ASCII, not user:")
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
