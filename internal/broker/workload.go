package broker

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/rhwendt/port49/internal/spiffe"
	"github.com/rhwendt/port49/internal/store"
)

// Workload is the broker's workload certificate verifier (plan 8; spec §13
// decision 40 ruling 1): its one trust anchor, and the SPIFFE trust domains
// a certificate it verifies may name. It is used through a pointer: Tasks 5
// and 7 add the state it keeps under a mutex.
type Workload struct {
	Anchor       *x509.Certificate
	TrustDomains []string
}

// The trust domains, as broker.identity's lists name them.
const (
	DomainHumans   = "humans"
	DomainMachines = "machines"
)

// ErrWorkloadUnmapped is a certificate the workload anchor verified that names
// no workload: identity_unmapped (spec §5.7; decision 40 ruling 3), answered
// 401 at bind over HTTP, never as a TLS alert.
var ErrWorkloadUnmapped = errors.New("broker: the workload certificate names no principal")

// CertCaller is a connection's verified client certificate as the broker
// reads it (plan 8).
type CertCaller struct {
	// Domain is DomainHumans or DomainMachines: the list whose anchor the
	// chain ends at (decision 40 ruling 2).
	Domain string
	// Principal is a workload's SPIFFE ID; a person's user: and email SAN
	// without a directory; "" for a person under a directory, whom the
	// listener's Map names at bind.
	Principal string
	// Legacy is a person's email-SAN principal under a directory, for the
	// marks made before it (pre-flight I-16); "" otherwise, and always "" for
	// a workload.
	Legacy string
	Cred   store.Credential
	Leaf   *x509.Certificate
}

// CertCallerOf reads cs's verified certificate. With no workload verifier it
// is exactly what the broker read before plan 8: Identity, or, under a
// directory, CertIdentity and the legacy principal. With one, the chain's
// anchor decides the domain first (machineChain); a person's certificate is
// then read as before, and a workload's principal is its SPIFFE ID
// (WorkloadPrincipal). A refusal of a chain an anchor verified keeps the
// credential and the leaf, so the record can say whose certificate it was.
func (b *Broker) CertCallerOf(cs *tls.ConnectionState, now time.Time) (CertCaller, error) {
	machine, chainErr := b.machineChain(cs)
	if machine || chainErr != nil {
		cred, leaf, err := CertIdentity(cs, now)
		cc := CertCaller{Domain: DomainMachines, Cred: cred, Leaf: leaf}
		if chainErr != nil {
			cc.Domain = ""
			return cc, chainErr
		}
		if err != nil {
			return cc, err
		}
		p, err := WorkloadPrincipal(leaf, b.Workload.TrustDomains)
		if err != nil {
			return cc, err
		}
		cc.Principal = p
		return cc, nil
	}
	if b.Directory != nil {
		cred, leaf, err := CertIdentity(cs, now)
		cc := CertCaller{Domain: DomainHumans, Cred: cred, Leaf: leaf}
		if leaf != nil {
			cc.Legacy = legacyPrincipal(leaf)
		}
		return cc, err
	}
	p, cred, err := Identity(cs, now)
	cc := CertCaller{Domain: DomainHumans, Principal: p, Cred: cred}
	if cs != nil && len(cs.VerifiedChains) > 0 && len(cs.VerifiedChains[0]) > 0 {
		cc.Leaf = cs.VerifiedChains[0][0]
	}
	return cc, err
}

// machineChain reports whether cs's verified chains end at the workload
// anchor. crypto/tls verified them against one pool of both anchors (Server),
// so a chain ends at one or the other; chains ending at both are no one's,
// since exactly one verifier must accept (decision 40 ruling 2). On a broker
// with no human x509 verifier, a chain not ending at the workload anchor has
// none. With no workload verifier, or no verified chain (CertIdentity refuses
// that), it is false and nil.
func (b *Broker) machineChain(cs *tls.ConnectionState) (bool, error) {
	if b.Workload == nil || cs == nil || len(cs.VerifiedChains) == 0 {
		return false, nil
	}
	var human, machine bool
	for _, ch := range cs.VerifiedChains {
		if len(ch) == 0 {
			continue
		}
		if bytes.Equal(ch[len(ch)-1].Raw, b.Workload.Anchor.Raw) {
			machine = true
		} else {
			human = true
		}
	}
	switch {
	case human && machine:
		// The start refuses an anchor that signs the other directly; one
		// further down the other's hierarchy is found only here (M-2).
		return false, fmt.Errorf("%w: the certificate chains to both the human and the workload trust anchor, so "+
			"neither verifier may take it; anchor each list at its own issuing CA, in unrelated hierarchies (the "+
			"start refuses only an anchor that signs the other directly)", ErrUntrusted)
	case human && b.NoX509:
		return false, fmt.Errorf("%w: this broker has no human x509 verifier, and the certificate does not chain to "+
			"the workload trust anchor", ErrUntrusted)
	}
	return machine, nil
}

// WorkloadPrincipal is a workload certificate's principal (spec §2; decision
// 40 rulings 3 and 4): its one URI SAN, verbatim, a SPIFFE ID with a path in
// one of trustDomains. A CA certificate, zero or several URI SANs, another
// URI, an ID with no path or an unlisted trust domain is ErrWorkloadUnmapped,
// saying which. Its email SANs are never read.
func WorkloadPrincipal(leaf *x509.Certificate, trustDomains []string) (string, error) {
	if leaf.BasicConstraintsValid && leaf.IsCA {
		return "", fmt.Errorf("%w: it is a CA certificate, which no workload presents (X.509-SVID §4.1)",
			ErrWorkloadUnmapped)
	}
	uris, err := rawURISANs(leaf)
	if err != nil {
		return "", fmt.Errorf("%w: its subjectAltName cannot be read: %v", ErrWorkloadUnmapped, err)
	}
	if len(uris) != 1 {
		return "", fmt.Errorf("%w: it carries %d URI SANs; exactly one SPIFFE ID names a workload",
			ErrWorkloadUnmapped, len(uris))
	}
	raw := uris[0]
	id, err := spiffe.ParseWorkload(raw)
	if err != nil {
		return "", fmt.Errorf("%w: its URI SAN is %v", ErrWorkloadUnmapped, err)
	}
	if !slices.Contains(trustDomains, id.TrustDomain) {
		return "", fmt.Errorf("%w: %s is outside broker.identity.machines spiffe_trust_domains (%s)",
			ErrWorkloadUnmapped, raw, strings.Join(trustDomains, ", "))
	}
	return raw, nil
}

var oidSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}

// rawURISANs is leaf's URI SANs as the certificate carries them, byte for
// byte. crypto/x509's URIs have been through url.Parse, which lower-cases the
// scheme and drops an empty fragment, so a SAN the SPIFFE grammar refuses
// would read as one it accepts; a workload's principal is never read from
// them. A subjectAltName that does not parse is an error, never a fallback.
func rawURISANs(leaf *x509.Certificate) ([]string, error) {
	var ext []byte
	for _, e := range leaf.Extensions {
		if e.Id.Equal(oidSubjectAltName) {
			ext = e.Value
			break
		}
	}
	if ext == nil {
		return nil, nil
	}
	var seq asn1.RawValue
	if rest, err := asn1.Unmarshal(ext, &seq); err != nil || len(rest) != 0 ||
		seq.Class != asn1.ClassUniversal || seq.Tag != asn1.TagSequence || !seq.IsCompound {
		return nil, errors.New("not a GeneralNames sequence")
	}
	var uris []string
	for rest := seq.Bytes; len(rest) > 0; {
		var gn asn1.RawValue
		var err error
		if rest, err = asn1.Unmarshal(rest, &gn); err != nil {
			return nil, err
		}
		if gn.Class == asn1.ClassContextSpecific && gn.Tag == 6 { // uniformResourceIdentifier
			uris = append(uris, string(gn.Bytes))
		}
	}
	return uris, nil
}
