// Package devicecert decides whether a device's TLS client certificate
// admits it on the RFC 9887 listener (spec §10; §13 decision 50): a path to
// a configured anchor, the device's own identity in its subjectAltName, and
// its revocation status. It decides nothing about policy.
package devicecert

import (
	"context"
	"errors"
	"os"
	"strings"
)

// Outcome is a handshake's result: the record's tls_outcome and
// port49_tls_handshakes_total's outcome, one closed vocabulary (spec §10).
type Outcome string

const (
	OK                  Outcome = "ok"
	Resumed             Outcome = "resumed"
	VersionRefused      Outcome = "version_refused"
	NoClientCertificate Outcome = "no_client_certificate"
	UnknownCA           Outcome = "unknown_ca"
	CertificateExpired  Outcome = "certificate_expired"
	CertificateInvalid  Outcome = "certificate_invalid"
	CertificateRevoked  Outcome = "certificate_revoked"
	StatusUnavailable   Outcome = "status_unavailable"
	IdentityMismatch    Outcome = "identity_mismatch"
	SNIMismatch         Outcome = "sni_mismatch"
	EarlyDataRefused    Outcome = "early_data_refused"
	HandshakeTimeout    Outcome = "handshake_timeout"
	HandshakeFailed     Outcome = "handshake_failed"
)

// Outcomes is every refusal, in spec §10's order.
var Outcomes = []Outcome{VersionRefused, NoClientCertificate, UnknownCA, CertificateExpired, CertificateInvalid,
	CertificateRevoked, StatusUnavailable, IdentityMismatch, SNIMismatch, EarlyDataRefused, HandshakeTimeout,
	HandshakeFailed}

// Struck reports whether a refusal counts against its source, as a key
// miss does. Only status_unavailable does not: the status could not be
// established, which is port49's fault, so it is a decline (decision 50
// ruling 8).
func (o Outcome) Struck() bool {
	switch o {
	case OK, Resumed, StatusUnavailable:
		return false
	}
	return true
}

// Refusal is the error a handshake fails with when port49 refused it; its
// Verdict says why.
type Refusal struct{ Verdict Verdict }

func (r *Refusal) Error() string {
	return "devicecert: " + string(r.Verdict.Outcome) + ": " + r.Verdict.Detail
}

// Classify names a failed handshake from crypto/tls's error when no Verdict
// did. timedOut is whether the handshake's own deadline passed. The three
// texts are crypto/tls's (handshake_server.go, handshake_server_tls13.go,
// Go 1.26); TestClassify pins them, and L72 measures them.
func Classify(err error, timedOut bool) Outcome {
	var r *Refusal
	switch {
	case errors.As(err, &r):
		return r.Verdict.Outcome
	case timedOut, errors.Is(err, context.DeadlineExceeded), errors.Is(err, os.ErrDeadlineExceeded):
		return HandshakeTimeout
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "unexpected early data"):
		return EarlyDataRefused
	case strings.Contains(msg, "didn't provide a certificate"):
		return NoClientCertificate
	case strings.Contains(msg, "unsupported versions"):
		return VersionRefused
	}
	return HandshakeFailed
}
