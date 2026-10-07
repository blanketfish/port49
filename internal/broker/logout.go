package broker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/oidc"
	"github.com/rhwendt/port49/internal/printsafe"
	"github.com/rhwendt/port49/internal/store"
)

// maxLogoutBody bounds a logout request: a logout token is a few hundred
// bytes (Ruling 12).
const maxLogoutBody = 16 << 10

// jtiKey is a logout token's once-only key.
func jtiKey(issuer, jti string) string { return "logout_jti " + store.OIDCKey("jti", issuer, jti) }

// logout is POST /v1/logout (Ruling 12; OpenID Connect Back-Channel Logout
// 1.0 §2.5–§2.8): no certificate and no api: right, the provider's
// signature on the token the only authentication.
func (b *Broker) logout(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	count := func(outcome string) { b.Metrics.OIDCLogouts.WithLabelValues(outcome).Inc() }
	bad := func(why string) {
		count("invalid")
		b.sayOnce("logout_invalid", sayEvery, "logout: a logout request was refused: %s", printsafe.Line(why, 300))
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": why})
	}
	retry := func(outcome, why string) {
		count(outcome)
		w.Header().Set("Retry-After", "30")
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "temporarily_unavailable",
			"error_description": why})
	}
	if b.Identity == nil || len(b.Identity.Humans()) == 0 {
		bad("this broker has no human OIDC verifier, so it takes no logout")
		return
	}
	mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	body, err := io.ReadAll(io.LimitReader(r.Body, maxLogoutBody+1))
	if mt != "application/x-www-form-urlencoded" || err != nil || len(body) > maxLogoutBody {
		bad("a logout is a form, application/x-www-form-urlencoded, of at most 16 KiB")
		return
	}
	form, err := url.ParseQuery(string(body))
	if err != nil || len(form["logout_token"]) != 1 {
		bad("a logout carries exactly one logout_token")
		return
	}
	vctx, vcancel := context.WithTimeout(r.Context(), holdTimeout)
	lt, err := b.Identity.VerifyLogout(vctx, form["logout_token"][0])
	vcancel()
	switch {
	case errors.Is(err, oidc.ErrUnavailable):
		retry("unavailable", "the broker cannot use the identity provider's keys right now")
		return
	case err != nil:
		bad(err.Error())
		return
	}
	ctx, cancel := b.detach(r.Context())
	defer cancel()
	skew := b.Identity.Timing.ClockSkew
	first, err := b.Store.PutOnce(ctx, jtiKey(lt.Issuer, lt.JTI), nil, oidc.MaxLogoutAge+2*skew)
	switch {
	case err != nil:
		// The write may have committed before the answer was lost; given
		// back, the provider's retry applies the logout instead of being
		// answered 200 "replayed" (best effort).
		_, _ = b.Store.TakeOnce(ctx, jtiKey(lt.Issuer, lt.JTI))
		retry("store_error", "the broker's store did not answer; the logout was not applied")
		return
	case !first:
		count("replayed")
		w.WriteHeader(http.StatusOK)
		return
	}
	rep, err := b.Logout(ctx, lt, "backchannel_logout "+lt.Issuer)
	if err != nil || rep.Err != nil {
		// Taken back so the provider's retry applies it again; every step
		// is safe to run twice.
		_, terr := b.Store.TakeOnce(ctx, jtiKey(lt.Issuer, lt.JTI))
		outcome := "store_error"
		if err == nil {
			outcome = "partial"
		}
		b.say("logout: a logout token from %s could not be applied: the store did not answer; answered 503 so the "+
			"provider may retry; if it does not, once the store returns: %s", lt.Issuer, b.logoutByHand(lt, rep, err == nil))
		if terr != nil && !errors.Is(terr, store.ErrNotFound) {
			// The provider's retry will be answered 200 "replayed" and do
			// nothing (pre-flight M-13): say how to end it by hand.
			what, byHand := "sub "+printsafe.Line(lt.Subject, 80), b.logoutByHand(lt, rep, err == nil)
			if lt.Sid != "" {
				what = "sid " + printsafe.Line(lt.Sid, 80)
			}
			b.say("logout: the logout of %s from %s could not be given back for a retry (%s): the provider's retry "+
				"will be answered 200 and do nothing; end it by hand with %s", what, lt.Issuer,
				printsafe.Line(terr.Error(), 200), byHand)
		}
		retry(outcome, "the broker's store did not answer; the logout may be partly applied: retry")
		return
	}
	if len(rep.Contexts) == 0 && rep.TokenKeys == 0 {
		count("nothing")
	} else {
		count("applied")
	}
	w.WriteHeader(http.StatusOK)
}

// logoutByHand is how an operator ends what a logout that could not be
// applied would have, never a bare port49 revoke (a logout is not a ban).
// For a sid it leads with the API call that runs the whole logout again.
// applied is whether Logout got as far as writing its record: when it did
// (a later step failed), logoutRecovery's form holds, its revoke record
// being in the log; when it did not, nothing was written, so the form is
// unconditional and lifts only once no held ID token could still mint.
func (b *Broker) logoutByHand(lt oidc.LogoutToken, rep RevokeReport, applied bool) string {
	who := []string{"<principal>"}
	lead := "for each principal the decision log's mint records name for this sub, and with its name for " +
		"<principal> below, "
	if lt.Sid != "" {
		lead = "for each principal the decision log's mint records name for this sid, and with its name for " +
			"<principal> below, "
	}
	if len(rep.Principals) > 0 {
		who, lead = rep.Principals, ""
	}
	var each []string
	for _, p := range who {
		if applied {
			each = append(each, b.logoutRecovery(p))
		} else {
			each = append(each, b.logoutUnapplied(p, b.Now().Add(b.Identity.Timing.MaxTokenAge+2*b.Identity.Timing.ClockSkew)))
		}
	}
	out := lead + strings.Join(each, "; and ")
	if lt.Sid != "" {
		out = fmt.Sprintf(`POST /v1/tokens/revoke {"sid": %q, "issuer": %q} (needs revoke_others), or %s`, lt.Sid, lt.Issuer, out)
	}
	return out
}

// logoutUnapplied is the recovery for a logout nothing of which was written:
// no logout record refuses the session's held ID token, so the contexts are
// ended and the mark is lifted only after lift, when that token has expired.
func (b *Broker) logoutUnapplied(principal string, lift time.Time) string {
	at := lift.UTC().Format(time.RFC3339)
	if b.AdminSocket == "" {
		return b.proc() + " has no admin_socket configured, so end " + principal + "'s contexts: remove " + principal +
			"'s grants from broker.policy_file (live within two watch intervals), and restore them only after " + at +
			", when no ID token the logout would have refused can still mint; or configure admin_socket and revoke there"
	}
	where := b.proc() + "'s admin socket (" + b.AdminSocket + ")"
	return "end " + principal + "'s contexts with `port49 revoke --principal " + principal + "` on " + where +
		", and lift it with `port49 revoke --principal " + principal + " --lift` there only after " + at +
		": no logout record refuses the session's held ID token until then; last check that `port49 revoke --list` " +
		"there shows no mark for " + principal
}

// RevokeSid ends one OIDC session as a back-channel logout by sid does, at
// the broker's now (Ruling 14), reaching only principals in the issuer's
// human verifiers' domains (Ruling 22).
func (b *Broker) RevokeSid(ctx context.Context, issuer, sid, origin string) (RevokeReport, error) {
	if b.Identity == nil {
		return RevokeReport{}, errors.New("broker: this broker has no human OIDC verifier, so it takes no logout")
	}
	return b.Logout(ctx, oidc.LogoutToken{Issuer: issuer, Sid: sid, IssuedAt: b.Now(),
		Domains: b.Identity.HumanDomains(issuer)}, origin)
}

// Logout is Ruling 13: the logout record first, then each owner principal's
// own unspent tokens, then the contexts twice, the receipts, and one revoke
// record. It leaves no standing mark. It reaches only owner principals in
// lt.Domains (Ruling 22), and every one of them (Ruling 24). The error is
// the logout record not written, when nothing was applied; a later step's
// is the report's Err, and the steps after it still run.
func (b *Broker) Logout(ctx context.Context, lt oidc.LogoutToken, origin string) (RevokeReport, error) {
	if b.Identity == nil {
		return RevokeReport{}, errors.New("broker: this broker has no human OIDC verifier, so it takes no logout")
	}
	ctx, cancel := b.detach(ctx)
	defer cancel()
	now := b.Now()
	t := b.Identity.Timing
	rep := RevokeReport{By: ByLogoutSub, OIDCIssuer: lt.Issuer, Sub: lt.Subject,
		Request: RevokeRequest{Origin: origin}, Mark: store.Revocation{At: now}}
	key := store.OIDCKey(store.OIDCSub, lt.Issuer, lt.Subject)
	if lt.Sid != "" {
		rep.By, rep.Sid, rep.Sub, key = ByLogoutSid, lt.Sid, "", store.SidKey(lt.Issuer, lt.Sid)
	}
	if err := b.Store.PutLogout(ctx, store.Logout{Key: key, At: lt.IssuedAt, Origin: origin},
		t.MaxTokenAge+2*t.ClockSkew); err != nil {
		return RevokeReport{}, err
	}
	note := func(err error) {
		if err != nil && rep.Err == nil {
			rep.Err = err
		}
	}
	owner, err := b.Store.OIDCOwner(ctx, key)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		note(err)
	}
	// Every owner principal (Ruling 24), within the provider's domains alone
	// (Ruling 22): an entry outside them, left from before a configuration
	// change, is said and not reached.
	for _, p := range owner.Names() {
		if !slices.Contains(lt.Domains, oidc.DomainOf(p)) {
			b.say("logout: %s: the owner record names %s, outside this verifier's principal_domains (%s); it is not "+
				"reached", lt.Issuer, p, strings.Join(lt.Domains, ", "))
			continue
		}
		rep.Principals = append(rep.Principals, p)
	}
	if len(rep.Principals) > 0 {
		rep.Request.Principal = rep.Principals[0]
	}
	for _, p := range rep.Principals {
		rep.TokenKeys += b.deleteOwnTokens(ctx, p, nil, note)
	}
	seen := map[store.ContextRef]bool{}
	for pass := 0; pass < 2; pass++ {
		var refs []store.ContextRef
		switch {
		case rep.By == ByLogoutSid && b.Sessions != nil:
			refs, err = b.Sessions.RevokeBySid(ctx, key)
			note(err)
		default:
			for _, p := range rep.Principals {
				all, err := b.Store.ContextsByPrincipal(ctx, p)
				note(err)
				for _, ref := range all {
					marked, err := b.revokeOwnContext(ctx, p, ref, now)
					note(err)
					if marked {
						refs = append(refs, ref)
					}
				}
			}
		}
		for _, ref := range refs {
			if !seen[ref] {
				seen[ref] = true
				rep.Contexts = append(rep.Contexts, ref)
			}
		}
	}
	if rep.By == ByLogoutSub {
		for _, p := range rep.Principals {
			_, err := b.Store.DeleteReceiptsByPrincipal(ctx, p)
			note(err)
		}
	}
	rep.Unreached = b.unreachedOf(rep.Contexts)
	outcome := "applied"
	if rep.Err != nil {
		outcome = "partial"
	}
	b.recordRevocation(now, rep, decision.VerdictDeny, decision.CredentialRevoked, outcome)
	b.say("%s", rep.logoutText(lt.IssuedAt.Add(t.ClockSkew), b.ownerTTL()))
	return rep, nil
}

// logoutText is Logout's line (What the operator sees).
func (r RevokeReport) logoutText(cutoff time.Time, ownerTTL time.Duration) string {
	who := strings.Join(r.Principals, ", ")
	var where []string
	for _, ref := range r.Contexts {
		where = append(where, ref.NAS+"/"+ref.Username)
	}
	switch {
	case r.By == ByLogoutSid && who != "":
		return fmt.Sprintf("logout: %s ended session sid %s of %s: %d contexts marked (%s), tokens on %d keys deleted",
			r.OIDCIssuer, printsafe.Line(r.Sid, 80), who, len(r.Contexts), strings.Join(where, ", "), r.TokenKeys)
	case r.By == ByLogoutSid:
		return fmt.Sprintf("logout: %s ended session sid %s, which no mint is on record for; %d contexts marked; "+
			"its tokens are refused from now on", r.OIDCIssuer, printsafe.Line(r.Sid, 80), len(r.Contexts))
	case who != "":
		return fmt.Sprintf("logout: %s ended every session of sub %s, %s: %d contexts marked (%s), tokens on %d keys "+
			"deleted", r.OIDCIssuer, printsafe.Line(r.Sub, 80), who, len(r.Contexts), strings.Join(where, ", "), r.TokenKeys)
	}
	return fmt.Sprintf("logout: %s ended every session of sub %s: no principal is on record for it (no mint in the "+
		"last %s); tokens it issued before %s are refused from now on; to end a person's sessions at once use "+
		"port49 revoke", r.OIDCIssuer, printsafe.Line(r.Sub, 80), ownerTTL, cutoff.UTC().Format(time.RFC3339))
}
