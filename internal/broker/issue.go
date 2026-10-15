package broker

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/issuer"
	"github.com/rhwendt/port49/internal/oidc"
	"github.com/rhwendt/port49/internal/printsafe"
)

// issueFresh is how long after the provider authenticated the person a
// sign-in may be exchanged for a certificate: the sign-in's own wait
// (oidcclient.SignInWait), so a login is a fresh authentication (decision 43
// ruling 8; R3).
const issueFresh = 5 * time.Minute

// issueKey is a sign-in's once-only key: its ID token's SHA-256, so the
// store never holds a token.
func issueKey(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return "issue_token " + hex.EncodeToString(sum[:])
}

// certificateLifetime is broker.identity.issuance.certificate_lifetime,
// issuer.DefaultLifetime when unset.
func (b *Broker) certificateLifetime() time.Duration {
	if b.CertificateLifetime > 0 {
		return b.CertificateLifetime
	}
	return issuer.DefaultLifetime
}

// issue is POST /v1/certificate (plan 9b; spec §13 decision 43 rulings
// 8–10): a person's sign-in, its ID token the bearer, exchanged for a
// short-lived client certificate for the key the request's CSR proves and
// the token's nonce names. Each refusal is one issue deny record. A broker
// whose CA cannot issue says so and records nothing: the fault is its own,
// and its start said which.
func (b *Broker) issue(w http.ResponseWriter, r *http.Request) {
	if b.Issuer == nil {
		writeError(w, http.StatusNotFound, "not_issuing", "this broker issues no certificates "+
			"(broker.identity.issuance is not configured); log in with a certificate")
		return
	}
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		b.Metrics.CertificatesIssued.WithLabelValues("refused").Inc()
		b.emit(decision.Record{TS: b.Now(), Event: decision.EventIssue, Verdict: decision.VerdictDeny,
			Reason: decision.TrustDomainUnresolved, Auth: &decision.Auth{Method: "cert"}})
		writeError(w, http.StatusBadRequest, "bad_request", "a sign-in is exchanged with no client certificate: its "+
			"ID token is the one credential")
		return
	}
	raw, has, berr := bearerOf(r)
	if !has || berr != nil {
		b.Metrics.CertificatesIssued.WithLabelValues("refused").Inc()
		b.emit(decision.Record{TS: b.Now(), Event: decision.EventIssue, Verdict: decision.VerdictDeny,
			Reason: decision.TrustDomainUnresolved, Auth: &decision.Auth{Method: "oidc"}})
		writeError(w, http.StatusUnauthorized, string(decision.TrustDomainUnresolved),
			"a certificate is issued for a sign-in: send its ID token as the bearer (Authorization: Bearer)")
		return
	}
	// The token as any person's (decision 39 rulings 2–6), the marks and the
	// logouts; each refusal is recorded under issue.
	c, ok := b.bearerCaller(w, r, decision.EventIssue, "issued nothing", raw)
	if !ok {
		b.Metrics.CertificatesIssued.WithLabelValues("refused").Inc()
		return
	}
	now := b.Now()
	refuse := func(status int, code, detail string) {
		b.Metrics.CertificatesIssued.WithLabelValues("refused").Inc()
		b.emit(decision.Record{TS: now, Event: decision.EventIssue, Verdict: decision.VerdictDeny,
			Reason: decision.TrustDomainUnresolved, Principal: c.principal, Auth: c.auth()})
		writeError(w, status, code, detail)
	}
	if c.oidc.Domain != oidc.Humans {
		refuse(http.StatusBadRequest, "bad_request", "a machine is issued nothing: a workload presents its own "+
			"certificate or token")
		return
	}
	// Freshness on two clocks (R3): iat − auth_time is the provider's own, so
	// only it can say prompt=login was not honoured; now − iat is the
	// broker's against the provider's, a sign-in that took too long or two
	// clocks that differ, never blamed on the provider's prompt.
	skew, at := b.Identity.Timing.ClockSkew, c.oidc.AuthTime.UTC().Format(time.RFC3339)
	iat := c.oidc.IssuedAt.UTC().Format(time.RFC3339)
	switch {
	case c.oidc.AuthTime.After(c.oidc.IssuedAt.Add(skew)):
		refuse(http.StatusUnauthorized, "sign_in_not_fresh", fmt.Sprintf("your identity provider's token says you "+
			"authenticated at %s, after it issued the token at %s; such a token is no sign-in; run `port49 login` "+
			"again, and if it recurs tell the provider's operator", at, iat))
		return
	case c.oidc.IssuedAt.Sub(c.oidc.AuthTime) > issueFresh+skew:
		refuse(http.StatusUnauthorized, "sign_in_not_fresh", fmt.Sprintf("your identity provider last authenticated "+
			"you at %s, over %s before it issued this sign-in's token at %s: it did not ask you to sign in again "+
			"(prompt=login was not honoured); run `port49 login` again", at, issueFresh, iat))
		return
	case now.Sub(c.oidc.IssuedAt) > issueFresh+skew:
		refuse(http.StatusUnauthorized, "sign_in_not_fresh", fmt.Sprintf("your identity provider issued this "+
			"sign-in's token at %s, over %s before the broker's now (%s): the sign-in took too long, or the "+
			"provider's clock and the broker's differ by more than that; run `port49 login` again, and if it "+
			"recurs tell the broker's operator to check both clocks", iat, issueFresh, now.UTC().Format(time.RFC3339)))
		return
	}
	var req api.IssueRequest
	dec := json.NewDecoder(io.LimitReader(r.Body, 16<<10))
	dec.DisallowUnknownFields()
	if dec.Decode(&req) != nil {
		refuse(http.StatusBadRequest, "bad_request", `the body is not a certificate request: {"csr": base64url DER}`)
		return
	}
	der, err := base64.RawURLEncoding.DecodeString(req.CSR)
	var csr *x509.CertificateRequest
	if err == nil {
		csr, err = x509.ParseCertificateRequest(der)
	}
	if err == nil {
		err = csr.CheckSignature()
	}
	if err != nil {
		refuse(http.StatusBadRequest, "bad_request", "the CSR does not parse, or its signature is not its key's")
		return
	}
	if why := issuableKey(csr.PublicKey); why != "" {
		refuse(http.StatusBadRequest, "bad_request", why)
		return
	}
	if want, err := api.IssuanceNonce(csr.PublicKey); err != nil || c.oidc.Nonce != want {
		refuse(http.StatusUnauthorized, "sign_in_not_bound", "the sign-in's nonce does not name this request's key: "+
			"sign in again with the key you send (`port49 login`)")
		return
	}
	// Whether a certificate can be made, before the sign-in is spent: the
	// person's claims it cannot carry are the person's (a recorded refusal),
	// the CA's own faults the broker's (unrecorded), and either way the token
	// stays unspent.
	sign := issuer.SignIn{Principal: c.principal, Issuer: c.oidc.Issuer, Subject: c.oidc.Subject, Sid: c.oidc.Sid,
		AMR: c.oidc.AMR, ACR: c.oidc.ACR, AuthTime: c.oidc.AuthTime, IssuedAt: c.oidc.IssuedAt}
	if err := b.Issuer.CanIssue(sign, now, b.certificateLifetime()); err != nil {
		if errors.Is(err, issuer.ErrNotCertifiable) {
			refuse(http.StatusUnauthorized, "sign_in_not_certifiable", "your sign-in's principal or claims cannot be "+
				"carried in a certificate; tell the operator")
			return
		}
		b.Metrics.CertificatesIssued.WithLabelValues("unavailable").Inc()
		b.sayOnce("issuance_unavailable", sayEvery, "issuance: a sign-in of %s was not issued a certificate: %s",
			printsafe.Line(c.principal, 300), printsafe.Line(err.Error(), 300))
		w.Header().Set("Retry-After", "60")
		writeError(w, http.StatusServiceUnavailable, "issuance_unavailable", "this broker cannot issue certificates "+
			"now: its issuing CA is not usable; tell its operator (the broker's log says why)")
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), holdTimeout)
	defer cancel()
	storeError := func() {
		b.Metrics.CertificatesIssued.WithLabelValues("refused").Inc()
		b.emit(decision.Record{TS: now, Event: decision.EventIssue, Verdict: decision.VerdictDeny,
			Reason: decision.StoreUnavailable, Principal: c.principal, Auth: c.auth()})
		writeError(w, http.StatusServiceUnavailable, string(decision.StoreUnavailable),
			"the broker could not record your sign-in, so it issued nothing; run `port49 login` again")
	}
	switch first, err := b.Store.PutOnce(ctx, issueKey(raw), nil, b.Identity.Timing.MaxTokenAge); {
	case err != nil:
		storeError()
		return
	case !first:
		refuse(http.StatusUnauthorized, "sign_in_spent", "this sign-in was exchanged for a certificate already; run "+
			"`port49 login` to sign in again")
		return
	}
	// The owner record first, as a mint writes it (decision 39 ruling 11): a
	// logout that lands before the certificate's first mint finds the
	// principal by it.
	if err := b.noteOwner(ctx, *c.oidc); err != nil {
		storeError()
		return
	}
	b.issueTo(w, now, csr.PublicKey, sign, c.auth(), nil)
}

// issueTo signs pub a certificate over sign, records the issue permit with
// auth and extra (a directory sign-in's source), and answers it. On the CA's
// signing fault it answers 503 issuance_unavailable, unrecorded. The caller
// has called CanIssue, and spent whatever the sign-in spends.
func (b *Broker) issueTo(w http.ResponseWriter, now time.Time, pub crypto.PublicKey, sign issuer.SignIn,
	auth *decision.Auth, extra *decision.SignIn) bool {
	cert, err := b.Issuer.Issue(pub, sign, now, b.certificateLifetime())
	if err != nil {
		b.Metrics.CertificatesIssued.WithLabelValues("unavailable").Inc()
		b.say("issuance: a certificate for %s could not be signed: %s", printsafe.Line(sign.Principal, 300),
			printsafe.Line(err.Error(), 300))
		w.Header().Set("Retry-After", "60")
		writeError(w, http.StatusServiceUnavailable, "issuance_unavailable", "this broker could not sign your "+
			"certificate; tell its operator (the broker's log says why)")
		return false
	}
	serial, notAfter := cert.SerialNumber.Text(16), cert.NotAfter.UTC().Format(time.RFC3339)
	b.Metrics.CertificatesIssued.WithLabelValues("issued").Inc()
	b.emit(decision.Record{TS: now, Event: decision.EventIssue, Verdict: decision.VerdictPermit,
		Reason: decision.CertificateIssued, Principal: sign.Principal, Auth: auth, SignIn: extra,
		Certificate: &decision.Certificate{Serial: serial, Issuer: cert.Issuer.String(),
			Fingerprint: issuer.Fingerprint(cert), NotAfter: notAfter}})
	writeJSON(w, http.StatusOK, api.IssueResponse{Certificate: string(b.Issuer.PEM(cert)), Principal: sign.Principal,
		Serial: serial, NotAfter: notAfter})
	return true
}

// issuableKey is why pub cannot be issued a certificate, "" when it can: a
// key a refresh signature is made with (api.RefreshAlgorithm), at a strength
// the broker takes.
func issuableKey(pub any) string {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if k.Curve == elliptic.P256() || k.Curve == elliptic.P384() {
			return ""
		}
	case ed25519.PublicKey:
		return ""
	case *rsa.PublicKey:
		if n := k.N.BitLen(); n >= 2048 && n <= 8192 {
			return ""
		}
	}
	return "the key must be ECDSA P-256 or P-384, Ed25519, or RSA of 2048 to 8192 bits"
}
