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
	"time"

	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/directory"
	"github.com/rhwendt/port49/internal/oidc"
	"github.com/rhwendt/port49/internal/policy"
	"github.com/rhwendt/port49/internal/store"
)

// oidcChallengeTTL is how long an OIDC refresh challenge may be answered: a
// person entering their credentials and a second factor at the provider
// (Ruling 15).
const oidcChallengeTTL = 5 * time.Minute

// refreshChallengeKey is a challenge's once-only key: its SHA-256, so the store
// never holds a nonce that answers it.
func refreshChallengeKey(nonce string) string {
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
	// Proved is the per-login proof the challenge request named, for the
	// refresh that answers this challenge (decision 45 ruling 16).
	Proved *provedRecord `json:"proved,omitempty"`
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
	var named api.RefreshChallengeRequest
	dec := json.NewDecoder(io.LimitReader(r.Body, 4<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&named); err != nil && !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "bad_request", "the body is not a refresh challenge request")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), holdTimeout)
	defer cancel()
	now := b.Now()
	// A challenge this caller proved exempts this one request from the
	// pacing and is kept with the nonce for the refresh that answers it
	// (decision 45 ruling 16), taken under the bearer's own binding: another
	// principal's challenge finds nothing, spends nothing, and is paced as
	// any request. A store error is paced, never an exemption. A second
	// exempt request by the same caller spends the first proof: one proof
	// exempts one request.
	var proved *provedChallenge
	if named.PerLoginMFAChallenge != "" {
		proved, _ = b.takeProved(ctx, c, "", named.PerLoginMFAChallenge)
	}
	if proved == nil {
		first, err := b.Store.PutOnce(ctx, paceKey(c.principal), nil, refreshEvery)
		switch {
		case err != nil:
			b.refreshStoreError(w, now, c.principal, c.cred, c.auth().OIDC, nil, 0, "the broker could not issue a challenge; retry shortly")
			return
		case !first:
			b.Metrics.SessionRefreshes.WithLabelValues("too_soon").Inc()
			w.Header().Set("Retry-After", strconv.Itoa(int(refreshEvery/time.Second)))
			writeError(w, http.StatusTooManyRequests, "refresh_too_soon", "you asked for a challenge moments ago; wait and retry")
			return
		}
	}
	raw := make([]byte, api.RefreshNonceLen)
	if _, err := rand.Read(raw); err != nil {
		writeError(w, http.StatusInternalServerError, "broker_error", "no randomness for a challenge")
		return
	}
	nonce := base64.RawURLEncoding.EncodeToString(raw)
	cr := challengeRec{Principal: c.principal, Issuer: c.oidc.Issuer, IssuedAt: now}
	if proved != nil {
		cr.Proved = &provedRecord{Method: string(proved.Method), At: proved.At}
	}
	rec, _ := json.Marshal(cr)
	if ok, err := b.Store.PutOnce(ctx, refreshChallengeKey(nonce), rec, oidcChallengeTTL); err != nil || !ok {
		b.refreshStoreError(w, now, c.principal, c.cred, c.auth().OIDC, nil, 0, "the broker could not issue a challenge; retry shortly")
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
	// The body is empty, or names the per-login proof (decision 45 ruling
	// 16): the new ID token is the bearer, and its nonce answers the challenge.
	var req struct {
		PerLoginMFAChallenge string `json:"per_login_mfa_challenge,omitempty"`
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, 4<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "bad_request", "an OIDC refresh's body is empty or names the "+
			"per_login_mfa_challenge you proved: the new ID token is its bearer, and its nonce answers the challenge")
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
	raw, err := b.Store.TakeOnce(ctx, refreshChallengeKey(c.oidc.Nonce))
	switch {
	case errors.Is(err, store.ErrNotFound):
		refuse("refresh_challenge_missing", "the token's nonce is no live challenge of this broker's: ask for one "+
			"and answer it within 5m, once")
		return
	case err != nil:
		b.refreshStoreError(w, now, c.principal, c.cred, c.auth().OIDC, nil, refreshEvery, "the broker could not read your challenge; "+
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
		b.refreshStoreError(w, now, c.principal, c.cred, c.auth().OIDC, nil, refreshEvery, "the broker could not record your new "+
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
	// The proof the challenge request kept, else the one the answer names,
	// taken under the bearer's own binding. It has no agent session, so it
	// covers this refresh once and is not kept for reuse (ruling 15).
	var proved *provedChallenge
	switch {
	case ch.Proved != nil:
		proved = &provedChallenge{Method: policy.MFAMethod(ch.Proved.Method), At: ch.Proved.At}
	case req.PerLoginMFAChallenge != "":
		p, err := b.takeProved(ctx, c, "", req.PerLoginMFAChallenge)
		if err != nil {
			b.refreshStoreError(w, now, c.principal, c.cred, c.auth().OIDC, nil, refreshEvery, "the broker could not read the "+
				"proof you named, so it extended nothing; ask for a new challenge (run `port49 refresh` again)")
			return
		}
		proved = p
	}
	rep, err := b.RefreshSession(ctx, m, answer, c.cred, c.authTime, c.auth().OIDC, nil, "", proved)
	switch {
	case errors.Is(err, directory.ErrUsernameTaken):
		dref := directoryRefusal(err)
		b.Metrics.SessionRefreshes.WithLabelValues("refused").Inc()
		b.emit(decision.Record{TS: now, Event: decision.EventRefresh, Verdict: decision.VerdictDeny, Reason: dref.Reason,
			Principal: c.principal, Auth: c.auth()})
		b.answerRefusal(w, r, dref)
		return
	case err != nil:
		b.failedRefresh(ctx, w, now, c, rep, oidcPartialRefreshText)
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
		b.refreshStoreError(w, now, c.principal, c.cred, c.auth().OIDC, nil, refreshEvery, oidcPartialRefreshText)
	case revoked:
		b.Metrics.SessionRefreshes.WithLabelValues("refused").Inc()
		b.refuseRevokedAuth(w, decision.EventRefresh, b.Now(), c.principal, c.cred, c.auth().OIDC, nil, rv)
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
// its logout and will not send it again. text is the 503's: the bearer path
// asks for a new challenge, the certificate path for a retry.
func (b *Broker) failedRefresh(ctx context.Context, w http.ResponseWriter, now time.Time, c caller,
	rep SessionRefreshReport, text string) {
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
	b.refreshStoreError(w, now, c.principal, c.cred, c.auth().OIDC, nil, refreshEvery, text)
}
