package devicecert

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/printsafe"
)

// Status is a verified chain's revocation status.
type Status int

const (
	StatusGood Status = iota
	StatusRevoked
	StatusUnknown
)

// StatusFunc is a verified chain's status, leaf first and anchor last, and a
// line saying which source decided and, when unknown, why. It may wait on an
// OCSP responder within ctx. port49d adapts certstatus.Checker.Check to it.
type StatusFunc func(ctx context.Context, chain []*x509.Certificate) (Status, string)

// CachedStatusFunc is StatusFunc from what the checker holds now, never a
// network wait: a CRL in force, or a cached OCSP answer. None fresh is
// StatusUnknown. port49d adapts certstatus.Checker.CheckCached to it.
type CachedStatusFunc func(chain []*x509.Certificate) (Status, string)

// Verdict is one judgement of a device's certificate.
type Verdict struct {
	Outcome Outcome
	// Detail is a bounded, printable line for the record and stderr.
	Detail string
	// Leaf is the device's certificate, when it sent one; Chain the verified
	// path, leaf first and anchor last, on OK.
	Leaf  *x509.Certificate
	Chain []*x509.Certificate
	// StatusUnknown is an OK under on_unavailable: allow whose status could
	// not be established; Detail says why.
	StatusUnknown bool
}

// Verifier is one load of tls_listener's anchors and rules (decision 50
// rulings 6–8). It is immutable once built: a reload builds another.
type Verifier struct {
	Anchors       *x509.CertPool
	Intermediates []*x509.Certificate // intermediates_file's (RFC 9887 §3.4.1)
	Rule          Rule
	// Status is asked once a handshake has completed; CachedStatus at each
	// later packet (rulings 8, 9). Both nil when certificate_status is
	// disabled.
	Status       StatusFunc
	CachedStatus CachedStatusFunc
	AllowUnknown bool // on_unavailable: allow
	Now          func() time.Time
}

// now is Now, or the clock when none is set: a nil func must not panic a
// handshake.
func (v *Verifier) now() time.Time {
	if v.Now == nil {
		return time.Now()
	}
	return v.Now()
}

// Verify judges certs, as the device sent them, leaf first, for dev: a path
// to an anchor through the sent and stored intermediates, with the
// clientAuth usage (or none), then the device's identity. Both are local and
// cheap. It runs in VerifyConnection, at a full handshake and at a
// resumption alike. crypto/tls calls that before it checks the client's
// CertificateVerify, so the peer has proven nothing yet: the status, which
// may wait on the network, is CheckStatus's, after the handshake (ruling 8).
func (v *Verifier) Verify(certs []*x509.Certificate, dev admission.Device) Verdict {
	if len(certs) == 0 {
		return Verdict{Outcome: NoClientCertificate, Detail: "the device sent no certificate"}
	}
	leaf := certs[0]
	if v.Anchors == nil {
		// Never the platform's roots: Verify falls back to them on nil.
		return Verdict{Outcome: UnknownCA, Detail: "no client_ca_file anchors are loaded", Leaf: leaf}
	}
	pool := x509.NewCertPool()
	for _, c := range certs[1:] {
		pool.AddCert(c)
	}
	for _, c := range v.Intermediates {
		pool.AddCert(c)
	}
	chains, err := leaf.Verify(x509.VerifyOptions{Roots: v.Anchors, Intermediates: pool, CurrentTime: v.now(),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	if err != nil {
		return Verdict{Outcome: chainOutcome(err), Detail: printsafe.Line(err.Error(), 300), Leaf: leaf}
	}
	if err := v.Rule.Match(leaf, dev); err != nil {
		return Verdict{Outcome: IdentityMismatch, Detail: err.Error(), Leaf: leaf}
	}
	return Verdict{Outcome: OK, Leaf: leaf, Chain: chains[0]}
}

// CheckStatus judges an OK verdict's chain status once its handshake has
// completed, waiting within ctx (the handshake's deadline) for an OCSP
// answer not cached (ruling 8).
func (v *Verifier) CheckStatus(ctx context.Context, ok Verdict) Verdict {
	if ok.Outcome != OK || v.Status == nil {
		return ok
	}
	if len(ok.Chain) == 0 {
		return noChain(ok)
	}
	st, detail := v.Status(ctx, ok.Chain)
	return v.judge(ok, st, detail)
}

// Recheck judges an open connection's chain again at a later packet: expiry
// of every certificate in it, then its status as the checker holds it now,
// with no network wait (ruling 9). The path itself is verified again only by
// Verify, when the anchors changed. A verdict that was not OK is returned
// as it is: there is no chain to recheck, and none is ever admitted.
func (v *Verifier) Recheck(was Verdict) Verdict {
	if was.Outcome != OK {
		return was
	}
	if len(was.Chain) == 0 {
		return noChain(was)
	}
	now := v.now()
	for _, c := range was.Chain {
		if now.After(c.NotAfter) {
			return Verdict{Outcome: CertificateExpired, Leaf: was.Leaf, Detail: printsafe.Line(fmt.Sprintf(
				"%s expired at %s", c.Subject, c.NotAfter.UTC().Format(time.RFC3339)), 300)}
		}
	}
	ok := Verdict{Outcome: OK, Leaf: was.Leaf, Chain: was.Chain}
	if v.CachedStatus == nil {
		return ok
	}
	st, detail := v.CachedStatus(ok.Chain)
	return v.judge(ok, st, detail)
}

// judge applies a status to an OK verdict: revoked refuses; unknown refuses
// as status_unavailable, or under on_unavailable: allow admits and says so.
func (v *Verifier) judge(ok Verdict, st Status, detail string) Verdict {
	switch st {
	case StatusGood:
		return ok
	case StatusRevoked:
		return Verdict{Outcome: CertificateRevoked, Detail: printsafe.Line(detail, 300), Leaf: ok.Leaf}
	default: // StatusUnknown, and any value this code does not know: fail closed
		if v.AllowUnknown {
			ok.StatusUnknown, ok.Detail = true, printsafe.Line(detail, 300)
			return ok
		}
		return Verdict{Outcome: StatusUnavailable, Detail: printsafe.Line(detail, 300), Leaf: ok.Leaf}
	}
}

// noChain refuses an OK verdict that carries no verified chain: there is
// nothing its status or expiry could be judged on.
func noChain(was Verdict) Verdict {
	return Verdict{Outcome: CertificateInvalid, Leaf: was.Leaf, Detail: "no verified chain"}
}

func chainOutcome(err error) Outcome {
	var unknown x509.UnknownAuthorityError
	if errors.As(err, &unknown) {
		return UnknownCA
	}
	var invalid x509.CertificateInvalidError
	if errors.As(err, &invalid) && invalid.Reason == x509.Expired {
		return CertificateExpired
	}
	return CertificateInvalid
}

// Fingerprint is leaf's SHA-256, lower-case hex, as records carry it: ""
// when there is no leaf.
func Fingerprint(leaf *x509.Certificate) string {
	if leaf == nil {
		return ""
	}
	sum := sha256.Sum256(leaf.Raw)
	return hex.EncodeToString(sum[:])
}
