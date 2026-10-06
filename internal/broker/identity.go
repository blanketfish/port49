package broker

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/rhwendt/port49/internal/store"
)

// ErrUntrusted is a caller the trust anchor does not vouch for, now: no
// verified client certificate on the connection, one that has expired since
// the handshake, or one that maps to no principal or to several. It is
// `trust_domain_unresolved` in the log (spec §5.7).
var ErrUntrusted = errors.New("broker: no trusted client certificate")

// Identity maps the connection's verified client certificate to a principal
// (design §7): `user:` and the certificate's one rfc822Name SAN, lower-cased
// (spec §2, the human x509 row). Zero or several email SANs are refused —
// ambiguity fails closed (design §7). An email mapping is a weak mapping and
// must be issuer-pinned; the broker trusts exactly one anchor (LoadTLS), which
// pins it. Only VerifiedChains is read: PeerCertificates is what the client
// sent, not what the anchor vouched for. A leaf that lists extended key
// usages must list clientAuth: crypto/tls's client verification already
// requires it, and Identity does not rely on every caller having gone through
// that. A leaf with none at all is any purpose (RFC 5280, and crypto/tls
// agrees), as many enterprise user certificates are, and is accepted.
//
// An rfc822Name is an IA5String, which admits spaces and control characters.
// The policy accepts only printable ASCII with an @ (policy.checkIdentity), so
// a SAN outside that form could match no subject; it is refused here, before
// it reaches a principal or the log.
//
// It is called per request, against the broker's clock, because the session
// is a held connection and a certificate can expire under it: one that has
// stops minting (spec §13, decision 12), whatever the handshake said. Every
// certificate in the chain is checked, the anchor included.
//
// The credential is identity, not a secret (spec §5.1.4): the certificate's
// fingerprint, issuer, serial and subject, which revocation by certificate
// indexes on.
//
// A refusal of a chain the anchor verified still returns the credential, and
// the principal when the leaf's one email SAN is well formed: those fields
// are anchor-vouched, not an unvalidated body, and the refusal record uses
// them to say whose certificate it was (final review, Minor 3). They name the
// refused certificate; they authorize nothing. With no verified chain both
// are empty.
func Identity(cs *tls.ConnectionState, now time.Time) (string, store.Credential, error) {
	cred, leaf, err := CertIdentity(cs, now)
	if leaf == nil {
		return "", cred, err
	}
	principal, mapErr := principalOf(leaf)
	if err != nil {
		return principal, cred, err
	}
	if mapErr != nil {
		return "", cred, mapErr
	}
	return principal, cred, nil
}

// CertIdentity is Identity up to and including the clientAuth check, for a
// broker with a directory: the credential and the leaf of the connection's
// verified chain, with no principal, which the directory's mapping gives
// (plan 7g). A leaf with no email SAN is fine here. Its refusals are
// Identity's, and a refusal of a chain the anchor verified returns the
// credential as Identity does; with no verified chain
// the credential is zero and the leaf nil.
func CertIdentity(cs *tls.ConnectionState, now time.Time) (store.Credential, *x509.Certificate, error) {
	if cs == nil || len(cs.VerifiedChains) == 0 || len(cs.VerifiedChains[0]) == 0 {
		return store.Credential{}, nil, fmt.Errorf("%w: the connection presented no certificate the trust anchor verified", ErrUntrusted)
	}
	chain := cs.VerifiedChains[0]
	leaf := chain[0]
	sum := sha256.Sum256(leaf.Raw)
	cred := store.Credential{Method: "cert", Fingerprint: "sha256:" + hex.EncodeToString(sum[:]),
		Issuer: leaf.Issuer.String(), Serial: leaf.SerialNumber.Text(16), Subject: leaf.Subject.String()}
	for _, c := range chain {
		if now.Before(c.NotBefore) || now.After(c.NotAfter) {
			return cred, leaf, fmt.Errorf("%w: certificate %q is valid %s to %s", ErrUntrusted,
				c.Subject.String(), c.NotBefore.UTC().Format(time.RFC3339), c.NotAfter.UTC().Format(time.RFC3339))
		}
	}
	if !clientAuth(leaf) {
		return cred, leaf, fmt.Errorf("%w: the certificate is not issued for client authentication",
			ErrUntrusted)
	}
	return cred, leaf, nil
}

// principalOf is `user:` and the leaf's one email SAN, lower-cased, or why
// there is none.
func principalOf(leaf *x509.Certificate) (string, error) {
	if len(leaf.EmailAddresses) != 1 {
		return "", fmt.Errorf("%w: the certificate carries %d email SANs; exactly one maps to a "+
			"principal", ErrUntrusted, len(leaf.EmailAddresses))
	}
	email := leaf.EmailAddresses[0]
	unprintable := func(r rune) bool { return r < 0x21 || r > 0x7e }
	if strings.IndexFunc(email, unprintable) >= 0 || !strings.Contains(email, "@") {
		return "", fmt.Errorf("%w: the certificate's email SAN is not printable ASCII with an @",
			ErrUntrusted)
	}
	return "user:" + strings.ToLower(email), nil
}

func clientAuth(c *x509.Certificate) bool {
	if len(c.ExtKeyUsage) == 0 && len(c.UnknownExtKeyUsage) == 0 {
		return true
	}
	for _, u := range c.ExtKeyUsage {
		if u == x509.ExtKeyUsageClientAuth || u == x509.ExtKeyUsageAny {
			return true
		}
	}
	return false
}
