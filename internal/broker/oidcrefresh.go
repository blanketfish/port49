package broker

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/directory"
	"github.com/rhwendt/port49/internal/oidc"
	"github.com/rhwendt/port49/internal/store"
)

// oidcChallengeTTL is how long an OIDC refresh challenge may be answered: a
// person entering their credentials and a second factor at the provider
// (Ruling 15).
const oidcChallengeTTL = 5 * time.Minute

// challengeKey is a challenge's once-only key: its SHA-256, so the store
// never holds a nonce that answers it.
func challengeKey(nonce string) string {
	sum := sha256.Sum256([]byte(nonce))
	return "refresh_challenge " + hex.EncodeToString(sum[:])
}

// paceKey paces a principal's challenges across replicas.
func paceKey(principal string) string { return "refresh_pace " + principal }

// challengeRec is what a challenge's once-only record holds.
type challengeRec struct {
	Principal string    `json:"principal"`
	Issuer    string    `json:"issuer"`
	IssuedAt  time.Time `json:"issued_at"`
}

// oidcChallenge is POST /v1/refresh/challenge with a bearer (Ruling 15):
// a nonce held in the store for oidcChallengeTTL, one per principal per
// refreshEvery.
func (b *Broker) oidcChallenge(w http.ResponseWriter, r *http.Request) {
	c, ok := b.authenticate(w, r, decision.EventRefresh, "issued no challenge")
	if !ok {
		return
	}
	if c.oidc.Domain != oidc.Humans {
		writeError(w, http.StatusBadRequest, "bad_request", "a machine has no session to refresh: fetch a new token")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), holdTimeout)
	defer cancel()
	now := b.Now()
	first, err := b.Store.PutOnce(ctx, paceKey(c.principal), nil, refreshEvery)
	switch {
	case err != nil:
		b.refreshStoreError(w, now, c.principal, c.cred, c.auth().OIDC, 0, "the broker could not issue a challenge; retry shortly")
		return
	case !first:
		b.Metrics.SessionRefreshes.WithLabelValues("too_soon").Inc()
		w.Header().Set("Retry-After", strconv.Itoa(int(refreshEvery/time.Second)))
		writeError(w, http.StatusTooManyRequests, "refresh_too_soon", "you asked for a challenge moments ago; wait and retry")
		return
	}
	raw := make([]byte, api.RefreshNonceLen)
	if _, err := rand.Read(raw); err != nil {
		writeError(w, http.StatusInternalServerError, "broker_error", "no randomness for a challenge")
		return
	}
	nonce := base64.RawURLEncoding.EncodeToString(raw)
	rec, _ := json.Marshal(challengeRec{Principal: c.principal, Issuer: c.oidc.Issuer, IssuedAt: now})
	if ok, err := b.Store.PutOnce(ctx, challengeKey(nonce), rec, oidcChallengeTTL); err != nil || !ok {
		b.refreshStoreError(w, now, c.principal, c.cred, c.auth().OIDC, 0, "the broker could not issue a challenge; retry shortly")
		return
	}
	writeJSON(w, http.StatusOK, api.RefreshChallenge{Nonce: nonce,
		ExpiresAt: now.Add(oidcChallengeTTL).UTC().Format(time.RFC3339)})
}

// oidcRefresh is POST /v1/refresh with a bearer (Ruling 15): the new ID
// token's nonce must be the caller's unspent challenge, and its auth_time
// no earlier than the challenge; then the caller's live sessions take the
// policy in force and are extended from that auth_time.
func (b *Broker) oidcRefresh(w http.ResponseWriter, r *http.Request) {
	c, ok := b.authenticate(w, r, decision.EventRefresh, "extended nothing")
	if !ok {
		return
	}
	now := b.Now()
	body, err := io.ReadAll(io.LimitReader(r.Body, 4<<10))
	if t := strings.TrimSpace(string(body)); err != nil || (t != "" && t != "{}") {
		writeError(w, http.StatusBadRequest, "bad_request", "an OIDC refresh's body is empty: the new ID token is "+
			"its bearer, and its nonce answers the challenge")
		return
	}
	if c.oidc.Domain != oidc.Humans {
		writeError(w, http.StatusBadRequest, "bad_request", "a machine has no session to refresh: fetch a new token")
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), holdTimeout)
	defer cancel()
	refuse := func(code, detail string) {
		b.Metrics.SessionRefreshes.WithLabelValues("refused").Inc()
		b.emit(decision.Record{TS: now, Event: decision.EventRefresh, Verdict: decision.VerdictDeny,
			Reason: decision.TrustDomainUnresolved, Principal: c.principal, Auth: c.auth()})
		writeError(w, http.StatusUnauthorized, code, detail)
	}
	if c.oidc.Nonce == "" {
		refuse("refresh_challenge_missing", "the token carries no nonce: ask for a challenge and send it as the "+
			"nonce of a prompt=login authentication")
		return
	}
	raw, err := b.Store.TakeOnce(ctx, challengeKey(c.oidc.Nonce))
	switch {
	case errors.Is(err, store.ErrNotFound):
		refuse("refresh_challenge_missing", "the token's nonce is no live challenge of this broker's: ask for one "+
			"and answer it within 5m, once")
		return
	case err != nil:
		b.refreshStoreError(w, now, c.principal, c.cred, c.auth().OIDC, refreshEvery, "the broker could not read your challenge; "+
			"ask for a new challenge (run `port49 refresh` again)")
		return
	}
	var ch challengeRec
	if json.Unmarshal(raw, &ch) != nil || ch.Principal != c.principal || ch.Issuer != c.oidc.Issuer {
		refuse("refresh_challenge_missing", "the token's nonce answers a challenge issued to someone else")
		return
	}
	if c.oidc.AuthTime.Before(ch.IssuedAt.Add(-b.Identity.Timing.ClockSkew)) {
		refuse("refresh_not_fresh", "your identity provider did not authenticate you again (prompt=login was not "+
			"honoured); the session was not extended")
		return
	}
	if err := b.noteOwner(ctx, *c.oidc); err != nil {
		b.refreshStoreError(w, now, c.principal, c.cred, c.auth().OIDC, refreshEvery, "the broker could not record your new "+
			"session for a logout to find, so it extended nothing; ask for a new challenge (run `port49 refresh` again)")
		return
	}
	dctx, dcancel := context.WithTimeout(r.Context(), b.memberBudget())
	m, answer, err := b.memberFor(dctx, c.principal)
	dcancel()
	if err != nil {
		dref := directoryRefusal(err)
		b.Metrics.SessionRefreshes.WithLabelValues("refused").Inc()
		b.emit(decision.Record{TS: now, Event: decision.EventRefresh, Verdict: decision.VerdictDeny, Reason: dref.Reason,
			Principal: c.principal, Auth: c.auth()})
		b.answerRefusal(w, r, dref)
		return
	}
	rep, err := b.RefreshSession(ctx, m, answer, c.cred, c.authTime, c.auth().OIDC)
	switch {
	case errors.Is(err, directory.ErrUsernameTaken):
		dref := directoryRefusal(err)
		b.Metrics.SessionRefreshes.WithLabelValues("refused").Inc()
		b.emit(decision.Record{TS: now, Event: decision.EventRefresh, Verdict: decision.VerdictDeny, Reason: dref.Reason,
			Principal: c.principal, Auth: c.auth()})
		b.answerRefusal(w, r, dref)
		return
	case err != nil:
		b.failedRefresh(ctx, w, now, c, rep)
		return
	}
	// The marks and the logouts again, after the extension's writes, as on
	// the certificate path.
	rv, revoked, err := b.revocation(ctx, c.principal, c.cred)
	var l logoutRefusal
	var out bool
	if err == nil && !revoked {
		l, out, err = b.loggedOut(ctx, *c.oidc)
	}
	switch {
	case err != nil:
		b.refreshStoreError(w, now, c.principal, c.cred, c.auth().OIDC, refreshEvery, oidcPartialRefreshText)
	case revoked:
		b.Metrics.SessionRefreshes.WithLabelValues("refused").Inc()
		b.refuseRevokedAs(w, decision.EventRefresh, b.Now(), c.principal, c.cred, rv)
	case out:
		b.markExtended(ctx, c, rep)
		b.Metrics.SessionRefreshes.WithLabelValues("refused").Inc()
		b.answerLoggedOut(w, l)
	default:
		writeJSON(w, http.StatusOK, rep.response(b.MaxSessionAge))
	}
}

// oidcPartialRefreshText answers a refresh whose challenge is spent and whose
// extension did not finish: a retry with the same token is refused, so the
// text asks for a new challenge, not a retry.
const oidcPartialRefreshText = "the broker could not finish extending your live sessions; some may have been " +
	"extended; ask for a new challenge (run `port49 refresh` again) after Retry-After and it reports them all"

// markExtended marks every context rep extended, context by context, after a
// logout landed during the refresh (pre-flight I-2). The logout's passes may
// have run before the new sid was indexed, and a logout leaves no standing
// mark (Ruling 13), so what this refresh extended is marked here. A sid-less
// token indexed nothing, and the loop does not need the index.
func (b *Broker) markExtended(ctx context.Context, c caller, rep SessionRefreshReport) {
	at := b.Now()
	var failed error
	for _, s := range rep.Sessions {
		if s.Outcome != "extended" {
			continue
		}
		if _, err := b.revokeOwnContext(ctx, c.principal, s.Ref, at); err != nil && failed == nil {
			failed = err
		}
	}
	if failed != nil {
		b.say("logout: a session %s's refresh extended could not be marked after a logout landed during it "+
			"(%v); %s", c.principal, failed, b.logoutRecovery(c.principal))
	}
}

// logoutRecovery is what an operator does about a session a logout may have
// left extended. A logout is not a ban: the person may log in again once
// clock_skew has passed after the logout (spec §5.1.4; the refusal names the
// time), so the tail ends their contexts and lifts the mark that does it
// (spec §5.1.4: a mark stands until an operator lifts it). With no admin
// socket there is no revoke to run: the cut is the grants, as unrecordedNote
// says.
func (b *Broker) logoutRecovery(principal string) string {
	const seen = "if the decision log has a revoke record with origin backchannel_logout for "
	if b.AdminSocket == "" {
		return seen + principal + " just before this line, " + b.proc() + " has no admin_socket configured, so " +
			"end its contexts: remove " + principal + "'s grants from broker.policy_file (live within two watch " +
			"intervals), and restore them once " + principal + "'s session ceiling has passed so they may log " +
			"in again; or configure admin_socket and revoke there"
	}
	where := b.proc() + "'s admin socket (" + b.AdminSocket + ")"
	return seen + principal +
		" just before this line, end its contexts with `port49 revoke --principal " + principal + "` on " + where +
		", then `port49 revoke --principal " + principal + " --lift` there so they may log in again; a lift can be lost across a " + b.proc() +
		" stop, so last check that `port49 revoke --list` there shows no mark for " + principal
}

// failedRefresh answers a refresh whose extension failed part way. The
// contexts already extended are checked against the logouts again as a
// finished refresh's are (pre-flight I-2): the provider was answered 200 for
// its logout and will not send it again.
func (b *Broker) failedRefresh(ctx context.Context, w http.ResponseWriter, now time.Time, c caller,
	rep SessionRefreshReport) {
	extended := false
	for _, s := range rep.Sessions {
		extended = extended || s.Outcome == "extended"
	}
	if extended {
		l, out, err := b.loggedOut(ctx, *c.oidc)
		switch {
		case err != nil:
			b.say("logout: the logouts could not be read again after a refresh of %s failed part way (%v); a session "+
				"it extended may have outlived a logout that landed during it; %s", c.principal, err,
				b.logoutRecovery(c.principal))
		case out:
			b.markExtended(ctx, c, rep)
			b.Metrics.SessionRefreshes.WithLabelValues("refused").Inc()
			b.answerLoggedOut(w, l)
			return
		}
	}
	b.refreshStoreError(w, now, c.principal, c.cred, c.auth().OIDC, refreshEvery, oidcPartialRefreshText)
}
