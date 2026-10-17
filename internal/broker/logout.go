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
	"github.com/rhwendt/port49/internal/issuer"
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
		// Nothing in the token can be said: it was not verified. The issuers
		// named are the configured ones. Keycloak sends a 503'd logout once, so
		// the refused ones are found in its log.
		var issuers []string
		for _, v := range b.Identity.Humans() {
			if !slices.Contains(issuers, v.Issuer) {
				issuers = append(issuers, v.Issuer)
			}
		}
		b.sayOnce("logout_unavailable", sayEvery, "logout: a logout request was refused with 503: the broker has no usable "+
			"keys for its human issuer(s) %s (stale past jwks_max_age, or the provider's keys cannot be fetched); the "+
			"provider may not retry, so the logouts refused meanwhile are in its own log (Keycloak: KC-SERVICES0057 "+
			"\"Logout ... failed\"); once its keys are back, end those people's sessions by hand with `port49 revoke "+
			"--principal <principal>` on %s's admin socket", strings.Join(issuers, ", "), b.proc())
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
		// The token verified, so its names are said; nothing was written.
		b.say("logout: a logout token from %s could not be applied: the store did not answer; answered 503 so the "+
			"provider may retry; if it does not, once the store returns: %s", lt.Issuer, b.logoutByHand(lt, RevokeReport{}, false))
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
		if err == nil || rep.Sid != "" {
			outcome = "partial"
		}
		b.say("logout: a logout token from %s could not be applied: the store did not answer; answered 503 so the "+
			"provider may retry; if it does not, once the store returns: %s", lt.Issuer, b.logoutByHand(lt, rep, err == nil))
		if terr != nil && !errors.Is(terr, store.ErrNotFound) {
			// The provider's retry will be answered 200 "replayed" and do
			// nothing (pre-flight M-13): say how to end it by hand.
			what, byHand := "sub "+printsafe.Line(lt.Subject, 80), b.logoutByHand(lt, rep, err == nil)
			switch {
			case lt.Sid != "" && lt.Subject != "":
				what = "sid " + printsafe.Line(lt.Sid, 80) + " and " + what
			case lt.Sid != "":
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

// logoutRecordTTL is how long a logout record stands: while a token issued
// before it could still be presented, and on a broker that issues
// certificates while one issued on a sign-in before it could (decision 43
// ruling 16): such a certificate carries no mark of its own, so the record
// is what refuses it. That is the longest lifetime any broker may issue,
// issuer.MaxLifetime, not this one's certificate_lifetime: a lifetime
// lowered since, or a replica configured otherwise, leaves certificates
// issued for longer. The recovery's lift time is the same quantity.
func (b *Broker) logoutRecordTTL() time.Duration {
	t := b.Identity.Timing
	held := t.MaxTokenAge
	if b.Issuer != nil {
		held = max(held, issuer.MaxLifetime)
	}
	return held + 2*t.ClockSkew
}

// logoutByHand is how an operator ends what a logout that could not be
// applied would have, never a bare port49 revoke (a logout is not a ban).
// For a sid alone it leads with the API call that runs the whole logout
// again; a token naming the sub as well gets the sub's form only, the API
// call ending one session (Ruling 13).
// applied is whether Logout got as far as writing its record: when it did
// (a later step failed), logoutRecovery's form holds, its revoke record
// being in the log; when it did not, nothing was written, so the form is
// unconditional and lifts only once no held ID token could still mint.
func (b *Broker) logoutByHand(lt oidc.LogoutToken, rep RevokeReport, applied bool) string {
	who := []string{"<principal>"}
	lead := "for each principal the decision log's mint records name for this sub, and with its name for " +
		"<principal> below, "
	sidOnly := lt.Sid != "" && lt.Subject == ""
	if sidOnly {
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
			each = append(each, b.logoutUnapplied(p, b.Now().Add(b.logoutRecordTTL())))
		}
	}
	out := lead + strings.Join(each, "; and ")
	if sidOnly {
		out = fmt.Sprintf(`POST /v1/tokens/revoke {"sid": %q, "issuer": %q} (needs revoke_others), or %s`, lt.Sid, lt.Issuer, out)
	}
	return out
}

// logoutUnapplied is the recovery for a logout nothing of which was written:
// no logout record refuses the session's held ID token, or the certificate
// issued on its sign-in, so the contexts are ended and the mark is lifted
// only after lift, when that token or certificate has expired. On a broker
// that issues, lift is a day off (issuer.MaxLifetime), so it also names the
// shorter path: each certificate the sign-in got revoked by serial, from its
// issue record, and the mark lifted once no ID token from before the logout
// can still be presented.
func (b *Broker) logoutUnapplied(principal string, lift time.Time) string {
	at := lift.UTC().Format(time.RFC3339)
	if b.AdminSocket == "" {
		return b.proc() + " has no admin_socket configured, so end " + principal + "'s contexts: remove " + principal +
			"'s grants from broker.policy_file (live within two watch intervals), and restore them only after " + at +
			", when no ID token or issued certificate the logout would have refused can still mint; or configure " +
			"admin_socket and revoke there"
	}
	where := b.proc() + "'s admin socket (" + b.AdminSocket + ")"
	return "end " + principal + "'s contexts with `port49 revoke --principal " + principal + "` on " + where +
		", and lift it with `port49 revoke --principal " + principal + " --lift` there only after " + at +
		": no logout record refuses the session's held ID token or issued certificate until then; last check that " +
		"`port49 revoke --list` there shows no mark for " + principal + b.revokeIssuedSooner(principal, where)
}

// revokeIssuedSooner is logoutUnapplied's shorter path on a broker that
// issues (decision 43 ruling 16), "" on one that does not.
func (b *Broker) revokeIssuedSooner(principal, where string) string {
	if b.Issuer == nil {
		return ""
	}
	t := b.Identity.Timing
	sooner := b.Now().Add(t.MaxTokenAge + 2*t.ClockSkew).UTC().Format(time.RFC3339)
	return "; or, sooner: revoke every certificate issued to " + principal + " before the logout, by every " +
		"broker on this store, each with `port49 revoke --cert-issuer DN --cert-serial HEX` on " + where +
		", the DN and serial from each broker's decision-log issue records for " + principal + ", and lift the " +
		"principal's mark after " + sooner + " instead, when no ID token from before the logout can still be " +
		"presented; if any broker's issue records cannot be read, wait out the first time"
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
// the logout record not written; a later step's is the report's Err, and
// the steps after it still run. A token carrying both sid and sub is a
// logout by the sid and then one by the sub, each as above (Ruling 13): a
// provider's "sign out user" names one session and the sub, and every
// session of the person ends. The sub half's record not written, after the
// sid half ran, is the error too, with a report naming no principal: no
// record refuses the person's other sessions, so the caller gives the
// unapplied recovery, and the sid half's own revoke record is not a sign
// the logout was done.
func (b *Broker) Logout(ctx context.Context, lt oidc.LogoutToken, origin string) (RevokeReport, error) {
	if b.Identity == nil {
		return RevokeReport{}, errors.New("broker: this broker has no human OIDC verifier, so it takes no logout")
	}
	ctx, cancel := b.detach(ctx)
	defer cancel()
	if lt.Sid == "" || lt.Subject == "" {
		return b.logoutOne(ctx, lt, origin)
	}
	bySub := lt
	bySub.Sid = ""
	rep, err := b.logoutOne(ctx, lt, origin)
	if err != nil {
		return RevokeReport{}, err
	}
	subRep, err := b.logoutOne(ctx, bySub, origin)
	if err != nil {
		return RevokeReport{By: ByLogoutSid, OIDCIssuer: lt.Issuer, Sid: lt.Sid, Sub: lt.Subject}, err
	}
	rep.Sub = lt.Subject
	for _, p := range subRep.Principals {
		if !slices.Contains(rep.Principals, p) {
			rep.Principals = append(rep.Principals, p)
		}
	}
	if len(rep.Principals) > 0 {
		rep.Request.Principal = rep.Principals[0]
	}
	for _, ref := range subRep.Contexts {
		if !slices.Contains(rep.Contexts, ref) {
			rep.Contexts = append(rep.Contexts, ref)
		}
	}
	rep.TokenKeys += subRep.TokenKeys
	rep.Unreached = b.unreachedOf(rep.Contexts)
	if rep.Err == nil {
		rep.Err = subRep.Err
	}
	return rep, nil
}

// logoutOne is one logout of one kind, by lt.Sid when it names one, else by
// lt.Subject: Logout's body, the same for either.
func (b *Broker) logoutOne(ctx context.Context, lt oidc.LogoutToken, origin string) (RevokeReport, error) {
	now := b.Now()
	t := b.Identity.Timing
	rep := RevokeReport{By: ByLogoutSub, OIDCIssuer: lt.Issuer, Sub: lt.Subject,
		Request: RevokeRequest{Origin: origin}, Mark: store.Revocation{At: now}}
	key := store.OIDCKey(store.OIDCSub, lt.Issuer, lt.Subject)
	if lt.Sid != "" {
		rep.By, rep.Sid, rep.Sub, key = ByLogoutSid, lt.Sid, "", store.SidKey(lt.Issuer, lt.Sid)
	}
	if err := b.Store.PutLogout(ctx, store.Logout{Key: key, At: lt.IssuedAt, Origin: origin},
		b.logoutRecordTTL()); err != nil {
		return RevokeReport{}, err
	}
	b.reachLogout(ctx, key, lt.Domains, &rep)
	rep.Unreached = b.unreachedOf(rep.Contexts)
	outcome := "applied"
	if rep.Err != nil {
		outcome = "partial"
	}
	b.recordRevocation(now, rep, decision.VerdictDeny, decision.CredentialRevoked, outcome)
	b.say("%s", rep.logoutText(lt.IssuedAt.Add(t.ClockSkew), b.ownerTTL(), b.revokeHow()))
	return rep, nil
}

// reachLogout is a logout's reach in this broker's session store, by key
// (spec §5.1.4; plan 7h Rulings 22, 24): the owners within domains, their
// tokens, and the contexts by sid, or by owner for a sub, and a sub's
// receipts. It fills rep.
func (b *Broker) reachLogout(ctx context.Context, key string, domains []string, rep *RevokeReport) {
	now := rep.Mark.At
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
		if !slices.Contains(domains, oidc.DomainOf(p)) {
			b.say("logout: %s: the owner record names %s, outside this verifier's principal_domains (%s); it is not "+
				"reached", rep.OIDCIssuer, p, strings.Join(domains, ", "))
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
}

// ReachLogout reaches, in this broker's session store, a logout another
// region ingested (plan 11a, R26): the runner calls it for each logout it
// follows. It writes no logout record and no revoke record; the region that
// ingested the logout recorded it. A key naming no verifier of this broker
// reaches nothing, said.
func (b *Broker) ReachLogout(ctx context.Context, l store.Logout) (RevokeReport, error) {
	kind, issuer, value, ok := store.ParseOIDCKey(l.Key)
	if !ok || b.Identity == nil {
		return RevokeReport{}, fmt.Errorf("broker: a followed logout's key does not name an OIDC session or subject")
	}
	domains := b.Identity.HumanDomains(issuer)
	if len(domains) == 0 {
		return RevokeReport{}, fmt.Errorf("broker: a followed logout names issuer %s, which no human verifier here "+
			"trusts; nothing reached", printsafe.Line(issuer, 200))
	}
	ctx, cancel := b.detach(ctx)
	defer cancel()
	rep := RevokeReport{By: ByLogoutSub, OIDCIssuer: issuer, Sub: value, Request: RevokeRequest{Origin: l.Origin},
		Mark: store.Revocation{At: b.Now()}}
	if kind == store.OIDCSid {
		rep.By, rep.Sid, rep.Sub = ByLogoutSid, value, ""
	}
	b.reachLogout(ctx, l.Key, domains, &rep)
	rep.Unreached = b.unreachedOf(rep.Contexts)
	return rep, rep.Err
}

// revokeHow is how an operator ends one person's sessions at once, as every
// recovery line says it: the revoke command on the admin socket.
func (b *Broker) revokeHow() string {
	if b.AdminSocket == "" {
		return b.proc() + " has no admin_socket configured: configure one and run `port49 revoke --principal " +
			"<principal>` there"
	}
	return "run `port49 revoke --principal <principal>` on " + b.proc() + "'s admin socket (" + b.AdminSocket + ")"
}

// logoutText is Logout's line (What the operator sees).
func (r RevokeReport) logoutText(cutoff time.Time, ownerTTL time.Duration, revokeHow string) string {
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
		"last %s); tokens it issued before %s are refused from now on; to end a person's sessions at once, %s",
		r.OIDCIssuer, printsafe.Line(r.Sub, 80), ownerTTL, cutoff.UTC().Format(time.RFC3339), revokeHow)
}
