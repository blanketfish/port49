// Package api is the broker's wire format (design §17), shared by the broker
// and every client of it — the agent first — so the two cannot drift. Every
// key is snake_case.
package api

import (
	"crypto/x509"
	"fmt"
	"time"
)

// UncoveredStatus opens the broker's detail when no certificate status source
// covers a certificate's issuer (certstatus's "uncovered" Unknown). The broker
// answers it 503 certificate_status_unavailable with Retry-After, but nothing
// changes until the operator adds a CRL or OCSP for that issuer, so port49
// workload treats it as final (spec §13 decision 40 ruling 7).
const UncoveredStatus = "no fresh CRL or OCSP answer covers"

// LateRenewalFraction: a workload certificate with less than 1/4 of its
// validity left is late to renew (spec §13 decision 40 ruling 9). The broker
// says it and counts it; port49 workload warns.
const LateRenewalFraction = 4

// LateRenewal reports whether c, presented at now, has under a quarter of its
// validity left.
func LateRenewal(c *x509.Certificate, now time.Time) bool {
	life := c.NotAfter.Sub(c.NotBefore)
	return life > 0 && c.NotAfter.Sub(now) < life/LateRenewalFraction
}

// Config is GET /v1/config: discovery data, never fleet information.
type Config struct {
	Methods              []string `json:"methods"`
	MaxSessionAgeSeconds int      `json:"max_session_age_seconds"`
	BatchMax             int      `json:"batch_max"`
	// CeilingWarningSeconds is session.ceiling_warning: how near a device's
	// ceiling `port49 token` warns (plan 7b).
	CeilingWarningSeconds int `json:"ceiling_warning_seconds,omitempty"`
	// OIDC is each human OIDC verifier a public client may authenticate
	// against (plan 7h; design §17): discovery data, never fleet data.
	// Machine verifiers are not listed.
	OIDC []OIDCProvider `json:"oidc,omitempty"`
	// Issuance is set when the broker issues a person a certificate over an
	// OIDC sign-in (plan 9b; spec §13 decision 43 ruling 18).
	Issuance *Issuance `json:"issuance,omitempty"`
	// BrokerCABundle is the CAs a client trusts for this broker's server
	// certificate, PEM: the one in use and, through a rotation, the next
	// (decision 43 ruling 25). Empty when broker.tls_ca_bundle_file is not
	// set.
	BrokerCABundle string `json:"broker_ca_bundle,omitempty"`
	// BrokerCABundleRefused is set when broker.tls_ca_bundle_file is
	// configured and the broker refused it at start (its log says why): a
	// client keeps the CAs it holds, and does not read the missing bundle as
	// the broker sending none.
	BrokerCABundleRefused bool `json:"broker_ca_bundle_refused,omitempty"`
	// PerLoginMFA is set when this broker verifies at least one per-login
	// method (plan 9c; decision 45): the methods it verifies now.
	PerLoginMFA *MFAConfig `json:"per_login_mfa,omitempty"`
}

// OIDCProvider is one human OIDC verifier as GET /v1/config names it.
type OIDCProvider struct {
	Issuer   string   `json:"issuer"`
	ClientID string   `json:"client_id"`
	Scopes   []string `json:"scopes"`
}

// MintRequest is POST /v1/tokens: Devices by name, or a page of Scope's
// (spec §13 decision 42), continued after After. TTLSeconds is a request,
// not an instruction: the broker clamps it to the subject's token_ttl.
type MintRequest struct {
	Devices    []string `json:"devices,omitempty"`
	Scope      string   `json:"scope,omitempty"`
	After      string   `json:"after,omitempty"`
	Enable     bool     `json:"enable"`
	TTLSeconds int      `json:"ttl_seconds"`
	Purpose    string   `json:"purpose"`
	// PerLoginMFAChallenge names the challenge whose proof (POST /v1/mfa)
	// covers this request's items whose requirement accepts its method,
	// once (plan 9c; decision 45 ruling 14).
	PerLoginMFAChallenge string `json:"per_login_mfa_challenge,omitempty"`
}

// MintItem is one device's answer. Verdict and Reason use the decision log's
// closed vocabulary (spec §5.7), so the response and the audit record agree.
// An item the broker could not decide — a fault on the broker's side, not a
// refusal of the caller — carries Error and Detail instead of a Verdict, and
// has no decision record.
type MintItem struct {
	Device    string `json:"device"`
	Verdict   string `json:"verdict,omitempty"`
	Reason    string `json:"reason,omitempty"`
	Address   string `json:"address,omitempty"`
	Platform  string `json:"platform,omitempty"`
	Username  string `json:"username,omitempty"`
	Login     string `json:"login,omitempty"`
	Enable    string `json:"enable,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`
	Error     string `json:"error,omitempty"`
	Detail    string `json:"detail,omitempty"`
	// SessionExpiresAt is when a login with this token stops being
	// authorized: the connection's authentication plus the device's
	// max_session_age (spec §5.6). Empty when the roles say never.
	SessionExpiresAt string `json:"session_expires_at,omitempty"`
	// PerLoginMFA is the requirement this item is denied under
	// per_login_mfa_required (or unavailable), with the challenge to prove.
	PerLoginMFA *PerLoginMFA `json:"per_login_mfa,omitempty"`
	// Replayed is the broker's own, never on the wire: this permit is an
	// idempotent replay, which recorded no permit of its own.
	Replayed bool `json:"-"`
}

// String is the item with its tokens withheld, so that a %v anywhere — a
// test's failure message, a debug line — never prints one (plan 7b final
// review M-1). The wire form is JSON and is untouched.
func (it MintItem) String() string {
	type plain MintItem
	p := plain(it)
	p.Login, p.Enable = withheld(p.Login), withheld(p.Enable)
	return fmt.Sprintf("%+v", p)
}

// GoString is String, for %#v.
func (it MintItem) GoString() string { return it.String() }

// withheld stands in for a credential in printed output: whether there was
// one, never what it was.
func withheld(s string) string {
	if s == "" {
		return ""
	}
	return "<withheld>"
}

// MintResponse is POST /v1/tokens' 200: partial failure is per item, never at
// the top level (design §17).
type MintResponse struct {
	Principal string `json:"principal"`
	Subject   string `json:"subject,omitempty"`
	// Subjects is every subject the principal matched, when it matched
	// more than one; Subject is then absent (plan 7g).
	Subjects []string   `json:"subjects,omitempty"`
	Results  []MintItem `json:"results"`
	// Next is a sweep page's last device when more remain: the next page's
	// after. Absent at a sweep's end, and on a mint by name.
	Next string `json:"next,omitempty"`
}

// Error is every non-200 body.
type Error struct {
	Error  string `json:"error"`
	Detail string `json:"detail,omitempty"`
}
