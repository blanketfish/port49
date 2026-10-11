package broker

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/issuer"
	"github.com/rhwendt/port49/internal/oidc"
	"github.com/rhwendt/port49/internal/printsafe"
)

// personBearerText answers a person's ID token at a broker that issues
// certificates, anywhere but POST /v1/certificate (decision 43 ruling 13).
const personBearerText = "this broker takes a person's ID token at POST /v1/certificate alone, which exchanges it " +
	"for a short-lived certificate; run `port49 login` (spec §13 decision 43 ruling 13)"

// issuedCaller is CertCallerOf for a chain ending at the broker's own
// issuing CA (plan 9b; spec §13 decision 43 ruling 10): the certificate's
// validity and clientAuth as any certificate's (CertIdentity), then the
// sign-in it carries. The principal is the sign-in's, never mapped through
// the directory. The sign-in's issuer must still be one of this broker's
// human OIDC verifiers, for the principal's domain, so a provider removed
// from the configuration takes its people's certificates with it. The
// credential is the certificate's and the sign-in's both, so a mint indexes
// its contexts under the sid a logout names.
func (b *Broker) issuedCaller(cs *tls.ConnectionState, now time.Time) (CertCaller, error) {
	cred, leaf, err := CertIdentity(cs, now)
	cc := CertCaller{Domain: DomainHumans, Cred: cred, Leaf: leaf}
	if err != nil {
		return cc, err
	}
	s, err := issuer.ReadSignIn(leaf)
	if err != nil {
		return cc, fmt.Errorf("%w: a certificate this broker's issuing CA signed does not read as one it issues: %v",
			ErrUntrusted, err)
	}
	if b.Identity == nil || !slices.Contains(b.Identity.HumanDomains(s.Issuer), oidc.DomainOf(s.Principal)) {
		return cc, fmt.Errorf("%w: the sign-in this certificate was issued on (%s, for %s) is not one this broker's "+
			"human OIDC verifiers take now; run `port49 login --sign-in`", ErrUntrusted, printsafe.Line(s.Issuer, 200),
			printsafe.Line(s.Principal, 200))
	}
	a := oidc.Assertion{Domain: oidc.Humans, Principal: s.Principal, Issuer: s.Issuer, Subject: s.Subject, Sid: s.Sid,
		AMR: s.AMR, ACR: s.ACR, AuthTime: s.AuthTime, IssuedAt: s.IssuedAt}
	oc := a.Credential()
	cc.Cred.Iss, cc.Cred.Sub, cc.Cred.Sid, cc.Cred.AMR, cc.Cred.ACR = oc.Iss, oc.Sub, oc.Sid, oc.AMR, oc.ACR
	cc.Principal, cc.Issued = s.Principal, &a
	return cc, nil
}

// issuedLoggedOut answers a request made with a certificate this broker
// issued whose sign-in the provider has since ended (decision 43 ruling 16):
// the logout records decision 39 ruling 13 keeps, read as a bearer's are,
// the sign-in's iat the token's. It reports whether it answered. A logout
// closes the connection. nothing completes the logouts-unreadable answer.
func (b *Broker) issuedLoggedOut(w http.ResponseWriter, r *http.Request, event, nothing string, now time.Time,
	c caller) bool {
	ctx, cancel := context.WithTimeout(r.Context(), holdTimeout)
	l, out, err := b.loggedOut(ctx, *c.oidc)
	cancel()
	switch {
	case err != nil:
		b.emit(decision.Record{TS: now, Event: event, Verdict: decision.VerdictDeny,
			Reason: decision.StoreUnavailable, Principal: c.principal, Auth: c.auth()})
		writeError(w, http.StatusServiceUnavailable, string(decision.StoreUnavailable),
			"the broker could not read the logouts in force, so it "+nothing+"; try again")
		return true
	case out:
		b.emit(decision.Record{TS: now, Event: event, Verdict: decision.VerdictDeny,
			Reason: decision.CredentialRevoked, Principal: c.principal, Auth: c.auth()})
		w.Header().Set("Connection", "close")
		b.answerLoggedOut(w, l)
		return true
	}
	return false
}
