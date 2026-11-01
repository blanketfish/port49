package broker

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/blanketfish/port49/internal/broker/api"
	"github.com/blanketfish/port49/internal/decision"
	"github.com/blanketfish/port49/internal/issuer"
	"github.com/blanketfish/port49/internal/oidc"
	"github.com/blanketfish/port49/internal/printsafe"
	"github.com/blanketfish/port49/internal/store"
)

// caller is who a request is: from its connection's certificate, or from
// its bearer token (plan 7h; spec §13 decision 39). A record's principal
// and auth always describe one credential (decision 34).
type caller struct {
	principal string
	// legacy is a mapped certificate's pre-directory principal (pre-flight
	// I-16); "" on the OIDC path.
	legacy   string
	cred     store.Credential
	authTime time.Time
	// oidc is the verified token; nil on the certificate path.
	oidc *oidc.Assertion
	// signIn is the sign-in a certificate this broker issued carries, either
	// method; nil otherwise. oidc is set for the OIDC method alone.
	signIn *issuer.SignIn
}

// auth is a record's auth for c.
func (c caller) auth() *decision.Auth {
	a := &decision.Auth{Method: c.cred.Method, Fingerprint: c.cred.Fingerprint}
	switch {
	case c.oidc != nil && c.oidc.K8s != nil:
		a.K8s = k8sAuth(*c.oidc)
	case c.oidc != nil:
		a.OIDC = oidcAuth(*c.oidc)
	}
	if c.signIn != nil && c.signIn.Method == issuer.MethodDirectoryPassword {
		a.DirectoryPassword = directoryPasswordAuth(*c.signIn)
	}
	return a
}

// oidcAuth is auth.oidc (spec §5.7): the provider's own sid, not the
// issuer-qualified key.
func oidcAuth(a oidc.Assertion) *decision.OIDC {
	return &decision.OIDC{Issuer: a.Issuer, Sub: a.Subject, Sid: a.Sid, AMR: a.AMR, ACR: a.ACR,
		AuthTime: decision.FormatTime(a.AuthTime)}
}

// k8sAuth is auth.k8s (spec §5.7; decision 49 ruling 9).
func k8sAuth(a oidc.Assertion) *decision.K8s {
	return &decision.K8s{Cluster: a.K8s.Cluster, Issuer: a.Issuer, Sub: a.Subject, ServiceAccountUID: a.K8s.ServiceAccountUID,
		Pod: a.K8s.Pod, PodUID: a.K8s.PodUID, Node: a.K8s.Node, JTI: a.K8s.JTI}
}

// errBearer is an Authorization header that is not one Bearer token.
var errBearer = errors.New("broker: the Authorization header is not one Bearer token")

// bearerOf is r's bearer token: present is whether r has an Authorization
// header at all, and err says it is not one "Bearer <token>".
func bearerOf(r *http.Request) (string, bool, error) {
	vals := r.Header.Values("Authorization")
	if len(vals) == 0 {
		return "", false, nil
	}
	scheme, tok, ok := strings.Cut(vals[0], " ")
	if len(vals) != 1 || !ok || !strings.EqualFold(scheme, "Bearer") || tok == "" || strings.ContainsAny(tok, " \t,") {
		return "", true, errBearer
	}
	return tok, true, nil
}

// bearerCaller is authenticate on the OIDC path (Rulings 2–10, 13): the
// token verified by exactly one verifier, its auth_time within
// max_session_age, no mark on its principal, and no logout of its session
// or subject. A refusal is answered and recorded once under event, with
// no principal and no claim when the token did not verify.
func (b *Broker) bearerCaller(w http.ResponseWriter, r *http.Request, event, nothing, raw string) (caller, bool) {
	now := b.Now()
	// method is the record's: oidc until a verifier's refusal or a verified
	// token says k8s.
	method := "oidc"
	deny := func(reason decision.Reason, principal string, a *oidc.Assertion) {
		rec := decision.Record{TS: now, Event: event, Verdict: decision.VerdictDeny, Reason: reason,
			Principal: principal, Auth: &decision.Auth{Method: method}}
		if a != nil {
			rec.Auth = caller{oidc: a, cred: a.Credential()}.auth()
		}
		b.emit(rec)
	}
	if b.Identity == nil {
		deny(decision.TrustDomainUnresolved, "", nil)
		writeError(w, http.StatusUnauthorized, string(decision.TrustDomainUnresolved),
			"this broker accepts no OIDC or k8s token: no oidc or k8s verifier is configured under broker.identity")
		return caller{}, false
	}
	vctx, cancel := context.WithTimeout(r.Context(), holdTimeout)
	a, err := b.Identity.Verify(vctx, raw)
	cancel()
	if err != nil {
		method = oidc.MethodOf(err)
	}
	// said is the operator line's key prefix and noun: a cluster's refusals
	// are their own lines, not an oidc provider's.
	said, what := "oidc", "a bearer token"
	if method == oidc.KindK8s {
		said, what = "k8s", "a k8s token"
	}
	switch {
	case errors.Is(err, oidc.ErrUnavailable):
		deny(decision.TrustDomainUnresolved, "", nil)
		b.sayOnce(said+"_unavailable", sayEvery, "identity: %s was refused (identity_provider_unavailable): %s", what,
			printsafe.Line(err.Error(), 300))
		w.Header().Set("Retry-After", "30")
		writeError(w, http.StatusServiceUnavailable, "identity_provider_unavailable",
			"the broker cannot use your identity provider's keys right now, so it "+nothing+"; retry shortly")
		return caller{}, false
	case errors.Is(err, oidc.ErrUnmapped):
		deny(decision.IdentityUnmapped, "", nil)
		b.sayOnce(said+"_unmapped", sayEvery, "identity: %s was refused (identity_unmapped): %s", what,
			printsafe.Line(err.Error(), 300))
		why := "your token names no principal this broker can use; tell the operator"
		if method == oidc.KindK8s {
			// A k8s refusal names only the caller's own verified sub or
			// namespace and the configured issuer (decision 49 ruling 8).
			why = err.Error()
		}
		writeError(w, http.StatusUnauthorized, string(decision.IdentityUnmapped), why)
		return caller{}, false
	case err != nil:
		deny(decision.TrustDomainUnresolved, "", nil)
		b.sayOnce(said+"_invalid", sayEvery, "identity: %s was refused (trust_domain_unresolved): %s", what,
			printsafe.Line(err.Error(), 300))
		writeError(w, http.StatusUnauthorized, string(decision.TrustDomainUnresolved), err.Error())
		return caller{}, false
	}
	c := caller{principal: a.Principal, cred: a.Credential(), authTime: notAfter(a.AuthTime, now), oidc: &a}
	// The refresh's own requests are exempt (Ruling 9): a challenge grants
	// nothing, and the refresh's token is checked against its challenge.
	if event != decision.EventRefresh && b.MaxSessionAge > 0 && now.Sub(a.AuthTime) > b.MaxSessionAge {
		deny(decision.SessionExpired, a.Principal, &a)
		if a.Domain == oidc.Machines {
			writeError(w, http.StatusUnauthorized, string(decision.SessionExpired), fmt.Sprintf(
				"your token was issued at %s, more than max_session_age (%s) ago; a workload's platform renews its token",
				a.AuthTime.UTC().Format(time.RFC3339), b.MaxSessionAge))
			return caller{}, false
		}
		writeError(w, http.StatusUnauthorized, string(decision.SessionExpired), fmt.Sprintf(
			"your identity provider last authenticated you at %s, more than max_session_age (%s) ago; run "+
				"`port49 login` (it asks the provider to authenticate you again)",
			a.AuthTime.UTC().Format(time.RFC3339), b.MaxSessionAge))
		return caller{}, false
	}
	ctx, cancel := context.WithTimeout(r.Context(), holdTimeout)
	defer cancel()
	rv, revoked, err := b.revocation(ctx, a.Principal, c.cred)
	if err == nil && !revoked {
		var l logoutRefusal
		var out bool
		if l, out, err = b.loggedOut(ctx, a); err == nil && out {
			b.Metrics.OIDCTokens.WithLabelValues(a.Issuer, "logged_out").Inc()
			deny(decision.CredentialRevoked, a.Principal, &a)
			b.answerLoggedOut(w, l)
			return caller{}, false
		}
	}
	switch {
	case err != nil:
		deny(decision.StoreUnavailable, a.Principal, &a)
		writeError(w, http.StatusServiceUnavailable, string(decision.StoreUnavailable),
			"the broker could not read the revocations and logouts in force, so it "+nothing+"; try again")
		return caller{}, false
	case revoked:
		rec := revokedRecord(now, a.Principal, c.cred)
		rec.Event, rec.Auth = event, c.auth()
		b.emit(rec)
		answerRevoked(w, rv)
		return caller{}, false
	}
	return c, true
}

// notAfter is t, or now when t is later: an auth_time ahead of the broker's
// clock, within clock_skew, starts no session clock in the future
// (pre-flight M-18).
func notAfter(t, now time.Time) time.Time {
	if t.After(now) {
		return now
	}
	return t
}

// logoutRefusal is the logout refusing a session, and whether it was the
// sub's record that did.
type logoutRefusal struct {
	store.Logout
	bySub bool
}

// loggedOut is the logout refusing a: by its sub when it was issued at or
// before the sub's logout plus clock_skew, else by its sid (Ruling 13). The
// sub is read first: Keycloak's logout writes both records, and the sub's
// answer is the one that names when a login is taken. A machine has no
// session a provider logs out, so none refuses it (pre-flight M-16); port49
// revoke --principal app:<client> does.
func (b *Broker) loggedOut(ctx context.Context, a oidc.Assertion) (logoutRefusal, bool, error) {
	if a.Domain != oidc.Humans {
		return logoutRefusal{}, false, nil
	}
	l, err := b.Store.GetLogout(ctx, store.OIDCKey(store.OIDCSub, a.Issuer, a.Subject))
	switch {
	case err == nil:
		if !a.IssuedAt.After(l.At.Add(b.Identity.Timing.ClockSkew)) {
			return logoutRefusal{l, true}, true, nil
		}
	case !errors.Is(err, store.ErrNotFound):
		return logoutRefusal{}, false, err
	}
	if key := store.SidKey(a.Issuer, a.Sid); key != "" {
		l, err := b.Store.GetLogout(ctx, key)
		switch {
		case err == nil:
			return logoutRefusal{l, false}, true, nil
		case !errors.Is(err, store.ErrNotFound):
			return logoutRefusal{}, false, err
		}
	}
	return logoutRefusal{}, false, nil
}

// answerLoggedOut is the 401 credential_revoked a logged-out session's
// request is answered. A refusal by the sub's record, which refuses every
// login inside clock_skew of the logout (Ruling 13), names the time from
// which a login is taken: the first whole second after the logout plus
// clock_skew, since a token issued at the logout plus clock_skew is still
// refused; a time already past reads as now. A sid's record refuses only
// its own session, so a new login is never held by it.
func (b *Broker) answerLoggedOut(w http.ResponseWriter, l logoutRefusal) {
	detail := fmt.Sprintf("your identity provider ended this session at %s (back-channel logout); log in again",
		l.At.UTC().Format(time.RFC3339))
	if l.bySub {
		from := l.At.Add(b.Identity.Timing.ClockSkew).Truncate(time.Second).Add(time.Second)
		detail = fmt.Sprintf("your identity provider ended your sessions at %s (back-channel logout); "+
			"log in again from %s", l.At.UTC().Format(time.RFC3339), from.UTC().Format(time.RFC3339))
	}
	writeJSON(w, http.StatusUnauthorized, api.Error{Error: string(decision.CredentialRevoked), Detail: detail})
}

// ownerFresh is how long an owner record is left as it is before a mint
// writes it again (Ruling 11).
const ownerFresh = time.Hour

// ownerTTL is an owner record's life: as long as a context minted under it
// can be expected to live, at least a day.
func (b *Broker) ownerTTL() time.Duration { return max(b.MaxSessionAge, 24*time.Hour) }

// noteOwner records that a's principal mints under its sid and its sub,
// before the first token write (Ruling 11): a logout finds the tokens to
// delete through it. The record keeps every principal written to it
// (Ruling 24), so this adds a's beside any other; an entry for a's
// principal written within ownerFresh is left alone. A machine writes none
// (pre-flight M-16).
func (b *Broker) noteOwner(ctx context.Context, a oidc.Assertion) error {
	if a.Domain != oidc.Humans {
		return nil
	}
	for _, key := range []string{store.SidKey(a.Issuer, a.Sid), store.OIDCKey(store.OIDCSub, a.Issuer, a.Subject)} {
		if key == "" {
			continue
		}
		if o, err := b.Store.OIDCOwner(ctx, key); err == nil {
			if e, ok := o.Entry(a.Principal); ok && b.Now().Sub(e.WrittenAt) < ownerFresh {
				continue
			}
		}
		if err := b.Store.PutOIDCOwner(ctx, key, a.Principal, b.ownerTTL()); err != nil {
			return err
		}
	}
	return nil
}
