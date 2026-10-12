package broker

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/directory"
	"github.com/rhwendt/port49/internal/policy"
	"github.com/rhwendt/port49/internal/store"
)

// refreshNonceTTL is how long a challenge may be answered; refreshEvery
// paces one connection's refreshes (pre-flight M17).
const (
	refreshNonceTTL = 60 * time.Second
	refreshEvery    = 10 * time.Second
)

// refreshChallenge issues the nonce a refresh signs (spec §5.6; decision
// 33). It is held on this connection alone; a new one replaces it. A
// connection that refreshed within refreshEvery is told to wait.
func (b *Broker) refreshChallenge(w http.ResponseWriter, r *http.Request) {
	if _, ok, _ := bearerOf(r); ok {
		b.oidcChallenge(w, r)
		return
	}
	now := b.Now()
	principal, _, cred, _, err := b.callerOf(r, now)
	if err != nil {
		b.refuseCaller(w, r, now, principal, cred, err)
		return
	}
	h := heldOf(r)
	if h == nil {
		writeError(w, http.StatusBadRequest, "bad_request", "a refresh is made on the held connection")
		return
	}
	var named api.RefreshChallengeRequest
	dec := json.NewDecoder(io.LimitReader(r.Body, 4<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&named); err != nil && !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "bad_request", "the body is not a refresh challenge request")
		return
	}
	nonce := make([]byte, api.RefreshNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		writeError(w, http.StatusInternalServerError, "broker_error", "no randomness for a challenge")
		return
	}
	// A challenge this caller proved exempts this one request from the
	// pacing, and is taken here, under this caller's own binding: another
	// caller's challenge finds nothing, spends nothing, and is paced as any
	// request. A store error is paced, never an exemption.
	var proved *provedChallenge
	if named.PerLoginMFAChallenge != "" {
		tctx, tcancel := context.WithTimeout(r.Context(), holdTimeout)
		proved, _ = b.takeProved(tctx, caller{principal: principal, cred: cred}, agentKey(r), named.PerLoginMFAChallenge)
		tcancel()
	}
	h.mu.Lock()
	wait := h.lastRefresh.Add(refreshEvery).Sub(now)
	if proved != nil {
		wait = 0
	}
	if wait <= 0 {
		h.nonce, h.nonceExp, h.proved = nonce, now.Add(refreshNonceTTL), proved
	}
	h.mu.Unlock()
	if wait > 0 {
		b.Metrics.SessionRefreshes.WithLabelValues("too_soon").Inc()
		w.Header().Set("Retry-After", strconv.Itoa(int((wait+time.Second-1)/time.Second)))
		writeError(w, http.StatusTooManyRequests, "refresh_too_soon", "this connection refreshed moments ago; wait and retry")
		return
	}
	writeJSON(w, http.StatusOK, api.RefreshChallenge{Nonce: base64.RawURLEncoding.EncodeToString(nonce),
		ExpiresAt: now.Add(refreshNonceTTL).UTC().Format(time.RFC3339)})
}

// refresh verifies the signed challenge and extends the caller's live
// sessions (spec §5.6). The nonce is taken whatever the outcome: single use.
func (b *Broker) refresh(w http.ResponseWriter, r *http.Request) {
	if _, ok, _ := bearerOf(r); ok {
		b.oidcRefresh(w, r)
		return
	}
	now := b.Now()
	principal, legacy, cred, issued, err := b.callerOf(r, now)
	if err != nil {
		b.refuseCaller(w, r, now, principal, cred, err)
		return
	}
	// via is the sign-in a certificate this broker issued carries: every
	// record its refresh makes names it (decision 43 rulings 10, 11).
	var via *decision.OIDC
	if issued != nil {
		via = oidcAuth(*issued)
	}
	h := heldOf(r)
	if h == nil {
		writeError(w, http.StatusBadRequest, "bad_request", "a refresh is made on the held connection")
		return
	}
	var req api.RefreshRequest
	dec := json.NewDecoder(io.LimitReader(r.Body, 4<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "the body is not a refresh request")
		return
	}
	// A live nonce consumed is paced, whether its answer verifies or not: a
	// caller looping challenge and wrong nonce or bad signature is held to
	// one per refreshEvery as a good one is (pre-flight M17). An expired one
	// is not, so the agent's one retry after refresh_challenge_missing gets
	// its new challenge; it can come only once per refreshNonceTTL anyway.
	h.mu.Lock()
	nonce, exp := h.nonce, h.nonceExp
	proved := h.proved
	h.nonce, h.proved = nil, nil // one proof exempts once, whatever the outcome
	if nonce != nil && now.Before(exp) {
		h.lastRefresh = now
	} else {
		proved = nil // expired with its nonce
	}
	h.mu.Unlock()
	got, _ := base64.RawURLEncoding.DecodeString(req.Nonce)
	sig, _ := base64.RawURLEncoding.DecodeString(req.Signature)
	if nonce == nil || !now.Before(exp) || subtle.ConstantTimeCompare(nonce, got) != 1 {
		b.refuseRefresh(w, now, principal, cred, via, decision.TrustDomainUnresolved, "refresh_challenge_missing",
			"no live refresh challenge on this connection; ask for one and answer it within 60s")
		return
	}
	leaf := r.TLS.VerifiedChains[0][0] // Identity verified there is one
	ekm, err := r.TLS.ExportKeyingMaterial(api.RefreshExporterLabel, nil, 32)
	alg, ok := api.RefreshAlgorithm(leaf.PublicKey)
	if err != nil || !ok || leaf.CheckSignature(alg, api.RefreshMessage(nonce, ekm), sig) != nil {
		b.refuseRefresh(w, now, principal, cred, via, decision.TrustDomainUnresolved, string(decision.TrustDomainUnresolved),
			"the refresh challenge was not answered by this connection's key")
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), holdTimeout)
	defer cancel()
	rv, revoked, err := b.revocation(ctx, principal, cred, legacy)
	switch {
	case err != nil:
		b.refreshStoreError(w, now, principal, cred, via, refreshEvery,
			"the broker could not read the revocations in force, so it extended nothing; try again")
		return
	case revoked:
		b.Metrics.SessionRefreshes.WithLabelValues("refused").Inc()
		b.refuseRevokedAs(w, decision.EventRefresh, now, principal, cred, via, rv)
		return
	}
	// A certificate this broker issued answers to its sign-in's logouts
	// (decision 43 ruling 16).
	if issued != nil && b.issuedLoggedOut(w, r, decision.EventRefresh, "extended nothing", now,
		caller{principal: principal, cred: cred, oidc: issued}) {
		b.Metrics.SessionRefreshes.WithLabelValues("refused").Inc()
		return
	}
	// The certificate's status, beside the marks (spec §5.1.4): a revoked one
	// is answered credential_revoked and closed; one not established is 503,
	// to be retried, and ends nothing. Either is one refresh deny record.
	statusCtx, cancelStatus := context.WithTimeout(r.Context(), holdTimeout)
	ref := b.certRefusal(statusCtx, r.TLS, cred)
	cancelStatus()
	if ref != nil {
		b.Metrics.SessionRefreshes.WithLabelValues("refused").Inc()
		b.emit(decision.Record{TS: now, Event: decision.EventRefresh, Verdict: decision.VerdictDeny, Reason: ref.Reason,
			Principal: principal, Auth: &decision.Auth{Method: cred.Method, Fingerprint: cred.Fingerprint, OIDC: via}})
		b.answerRefusal(w, r, ref)
		return
	}
	// Group membership is read again here, as a mint reads it, before the
	// policy is held (Ruling 10): a refusal extends nothing, and a refresh
	// is a fresh authentication only as far as the directory verified it.
	dctx, dcancel := context.WithTimeout(r.Context(), b.memberBudget())
	m, answer, err := b.memberFor(dctx, principal)
	dcancel()
	if err != nil {
		dref := directoryRefusal(err)
		b.Metrics.SessionRefreshes.WithLabelValues("refused").Inc()
		b.emit(decision.Record{TS: now, Event: decision.EventRefresh, Verdict: decision.VerdictDeny, Reason: dref.Reason,
			Principal: principal, Auth: &decision.Auth{Method: cred.Method, Fingerprint: cred.Fingerprint, OIDC: via}})
		b.answerRefusal(w, r, dref)
		return
	}
	// A challenge named in the answer is taken here, once the signature has
	// verified, when the challenge request did not already take one.
	if proved == nil && req.PerLoginMFAChallenge != "" {
		tctx, tcancel := context.WithTimeout(r.Context(), holdTimeout)
		p, err := b.takeProved(tctx, caller{principal: principal, cred: cred}, agentKey(r), req.PerLoginMFAChallenge)
		tcancel()
		if err != nil {
			b.refreshStoreError(w, b.Now(), principal, cred, via, refreshEvery,
				"the broker could not read the proof you named, so it extended nothing; try again")
			return
		}
		proved = p
	}
	at := b.Now() // the broker's verification time: the one clock §5.6 gives it
	// The connection's clock moves before the extension, and stays moved if
	// the extension fails: the signature and the marks verified, so this was
	// a fresh authentication of the connection whatever the store does next.
	h.mu.Lock()
	h.at, h.lastRefresh = at, at
	h.mu.Unlock()
	rep, err := b.RefreshSession(ctx, m, answer, cred, at, via, agentKey(r), proved)
	if errors.Is(err, directory.ErrUsernameTaken) {
		dref := directoryRefusal(err)
		b.Metrics.SessionRefreshes.WithLabelValues("refused").Inc()
		b.emit(decision.Record{TS: at, Event: decision.EventRefresh, Verdict: decision.VerdictDeny, Reason: dref.Reason,
			Principal: principal, Auth: &decision.Auth{Method: cred.Method, Fingerprint: cred.Fingerprint, OIDC: via}})
		b.answerRefusal(w, r, dref)
		return
	}
	if err != nil {
		if issued != nil {
			// What the refresh extended before it failed answers to a logout
			// that landed meanwhile, as on the OIDC path (pre-flight I-2).
			b.failedRefresh(ctx, w, at, caller{principal: principal, cred: cred, oidc: issued}, rep, partialRefreshText)
			return
		}
		b.refreshStoreError(w, at, principal, cred, nil, refreshEvery, partialRefreshText) // fixed text (M5)
		return
	}
	// The marks again, after the extension's writes, as a mint reads them
	// after its last token write (revokedSince): a revocation that landed
	// while this refresh extended is answered, not reported as extended.
	switch rv, revoked, err := b.revocation(ctx, principal, cred, legacy); {
	case err != nil:
		b.refreshStoreError(w, at, principal, cred, via, refreshEvery, partialRefreshText)
		return
	case revoked:
		b.Metrics.SessionRefreshes.WithLabelValues("refused").Inc()
		b.refuseRevokedAs(w, decision.EventRefresh, b.Now(), principal, cred, via, rv)
		return
	}
	// The logouts again, after the extension's writes, as on the OIDC path:
	// what a logout that landed meanwhile would have missed is marked.
	if issued != nil {
		switch l, out, err := b.loggedOut(ctx, *issued); {
		case err != nil:
			b.refreshStoreError(w, at, principal, cred, via, refreshEvery, partialRefreshText)
			return
		case out:
			b.markExtended(ctx, caller{principal: principal, cred: cred, oidc: issued}, rep)
			b.Metrics.SessionRefreshes.WithLabelValues("refused").Inc()
			b.answerLoggedOut(w, l)
			return
		}
	}
	writeJSON(w, http.StatusOK, rep.response(b.MaxSessionAge))
}

// partialRefreshText answers a refresh whose signature verified but whose
// extension failed part way: the connection is renewed, and some sessions
// may already be extended.
const partialRefreshText = "the broker could not finish extending your live sessions; some may have been " +
	"extended; retry after Retry-After and the retry reports them all"

// refreshStoreError answers a refresh the store failed 503
// store_unavailable, with its one refresh deny record (spec §5.7), as a
// mint's store error is answered. A non-zero retry is sent as Retry-After:
// the connection's pacing, which a retry sooner would meet as a 429.
func (b *Broker) refreshStoreError(w http.ResponseWriter, now time.Time, principal string, cred store.Credential,
	via *decision.OIDC, retry time.Duration, text string) {
	b.Metrics.SessionRefreshes.WithLabelValues("store_error").Inc()
	b.emit(decision.Record{TS: now, Event: decision.EventRefresh, Verdict: decision.VerdictDeny,
		Reason: decision.StoreUnavailable, Principal: principal, Auth: &decision.Auth{Method: cred.Method, OIDC: via}})
	if retry > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(int(retry/time.Second)))
	}
	writeError(w, http.StatusServiceUnavailable, string(decision.StoreUnavailable), text)
}

// refuseCaller answers a refresh whose caller callerOf could not name: a
// connection with no pin is the directory not answering (503
// directory_unavailable, the session kept, as a mint is answered; spec
// §5.7); anything else is the certificate's own refusal.
func (b *Broker) refuseCaller(w http.ResponseWriter, r *http.Request, now time.Time, principal string,
	cred store.Credential, err error) {
	if !errors.Is(err, errNoPin) {
		// A workload naming no principal is identity_unmapped, as authenticate
		// records it (decision 40).
		reason := decision.TrustDomainUnresolved
		if errors.Is(err, ErrWorkloadUnmapped) {
			reason = decision.IdentityUnmapped
		}
		b.refuseRefresh(w, now, principal, cred, nil, reason, string(reason), err.Error())
		return
	}
	ref := directoryRefusal(directory.ErrUnavailable)
	b.Metrics.SessionRefreshes.WithLabelValues("refused").Inc()
	b.emit(decision.Record{TS: now, Event: decision.EventRefresh, Verdict: decision.VerdictDeny, Reason: ref.Reason,
		Principal: principal, Auth: &decision.Auth{Method: cred.Method, Fingerprint: cred.Fingerprint}})
	b.answerRefusal(w, r, ref)
}

// refuseRefresh answers a refresh that proved nothing, and records it
// without the nonce or the signature.
func (b *Broker) refuseRefresh(w http.ResponseWriter, now time.Time, principal string, cred store.Credential,
	via *decision.OIDC, reason decision.Reason, code, detail string) {
	b.Metrics.SessionRefreshes.WithLabelValues("refused").Inc()
	b.emit(decision.Record{TS: now, Event: decision.EventRefresh, Verdict: decision.VerdictDeny, Reason: reason,
		Principal: principal, Auth: &decision.Auth{Method: "cert", Fingerprint: cred.Fingerprint, OIDC: via}})
	writeError(w, http.StatusUnauthorized, code, detail)
}

// RefreshedContext is one context a session refresh visited.
type RefreshedContext struct {
	Ref            store.ContextRef
	Outcome        string // extended | revoked | past_grace | not_judged
	SessionExpires time.Time
	Unreached      bool
}

// SessionRefreshReport is what RefreshSession did.
type SessionRefreshReport struct {
	At       time.Time
	Sessions []RefreshedContext
	// Challenge is the one challenge to prove when any context needed a
	// proof (outcome per_login_mfa_required), nil otherwise.
	Challenge *api.PerLoginMFA
}

// errMFAStore is a per-login proof the store could not read: the refresh
// fails closed as store_unavailable, never as "not covered".
var errMFAStore = errors.New("broker: the store could not be read for a per-login proof")

// refreshAsk is one session refresh's per-login state: the request-wide
// proof and challenge (as a mint's), and the items it asked.
type refreshAsk struct {
	mf    mfaRequest
	items []*api.PerLoginMFA
}

// strictest is the item that asks the most: the fewest methods, then the
// shortest reuse. Its Device is cleared: the challenge is the refresh's.
func (a *refreshAsk) strictest() *api.PerLoginMFA {
	var best *api.PerLoginMFA
	for _, it := range a.items {
		if best == nil || len(it.Methods) < len(best.Methods) ||
			(len(it.Methods) == len(best.Methods) && it.ReuseForSeconds < best.ReuseForSeconds) {
			best = it
		}
	}
	if best == nil {
		return nil
	}
	out := *best
	out.Device = ""
	return &out
}

// RefreshSession carries a fresh authentication at at into every live
// context of principal (spec §5.6; decision 33). It holds the policy in
// force, as a mint does, and first judges each context exactly as a policy
// refresh would (refreshContext): a withdrawn grant is revoked there. Only
// a context that judgment kept (unchanged, or updated with its write
// landed) is extended, through store.RefreshContext bound to the revision
// just read, to the ceiling the policy gives from at; a context past its
// grace window is deleted, bound the same way (teardown row 3). Everything
// else is named, not extended (pre-flight I4).
//
// Every record it writes goes to a buffer, written to the log once it lets
// go of the policy and before the caller answers: a log sink that stalls
// must not hold a reload (plan 7e, Ruling 10). A policy refresh, the pass
// after a reload, holds no policy and writes at once.
func (b *Broker) RefreshSession(ctx context.Context, m policy.Member, answer *directory.Answer,
	cred store.Credential, at time.Time, via *decision.OIDC, agentSHA256 string,
	proved *provedChallenge) (SessionRefreshReport, error) {
	principal := m.Principal
	ask := &refreshAsk{mf: mfaRequest{agentSHA256: agentSHA256, proved: proved}}
	buf := newHeldLog()
	pol, hold := b.Policy.Hold()
	defer func() {
		hold()
		buf.Flush(b.Log, b.blobLanded)
	}()
	rep := SessionRefreshReport{At: at}
	// The member was read before the hold: a reload since may declare its
	// username (final review M-1). The caller answers username_collision.
	m, err := heldCollision(pol, m, answer)
	if err != nil {
		return rep, err
	}
	refs, err := b.Store.ContextsByPrincipal(ctx, principal)
	if err != nil {
		return rep, err
	}
	pass := RefreshReport{session: true, log: buf}
	quarantined := map[string]bool{}
	for _, ref := range refs {
		k := store.ContextKey{NAS: ref.NAS, Username: ref.Username}
		dev, known := pol.Device(ref.NAS)
		unreached := !known || dev.Platform == "" || sessionOnly(pol, dev.Platform)
		visit := RefreshedContext{Ref: ref, Unreached: unreached}
		outcome, err := b.refreshContext(ctx, pol, nil, at, m, ref, &pass, quarantined, false, time.Time{})
		switch {
		case err != nil && !errors.Is(err, store.ErrConflict):
			return rep, err
		case outcome == "revoked", outcome == "failed" && err == nil:
			// "failed" with no error is a context refreshContext revoked for
			// a fault: unopenable, or a policy that would not compile for it.
			visit.Outcome = "revoked"
		case err != nil || (outcome != "unchanged" && outcome != "updated"):
			if outcome == "skipped" && !b.livePrincipalContext(ctx, k, principal) {
				continue // gone, or another principal's now: not this caller's to report
			}
			visit.Outcome = "not_judged"
		}
		if visit.Outcome == "" {
			visit.Outcome, visit.SessionExpires, err = b.extend(ctx, buf, pol, m, answer, cred, ref, dev, at, unreached, via, ask)
			if err != nil {
				return rep, err
			}
			if visit.Outcome == "" {
				continue
			}
		}
		b.Metrics.SessionRefreshes.WithLabelValues(visit.Outcome).Inc()
		rep.Sessions = append(rep.Sessions, visit)
	}
	rep.Challenge = ask.strictest()
	return rep, nil
}

// extend reads the context the judgment kept and extends it, or deletes
// it past its grace window, both bound to the revision read, and writes its
// record to out, the refresh's buffer. It returns "" for a context gone or
// no longer the caller's.
func (b *Broker) extend(ctx context.Context, out decision.Emitter, pol *policy.Policy, m policy.Member,
	answer *directory.Answer, cred store.Credential, ref store.ContextRef, dev admission.Device, at time.Time,
	unreached bool, via *decision.OIDC, ask *refreshAsk) (string, time.Time, error) {
	principal := m.Principal
	k := store.ContextKey{NAS: ref.NAS, Username: ref.Username}
	c, err := b.Store.GetContext(ctx, k)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return "", time.Time{}, nil
	case err != nil:
		return "", time.Time{}, err
	case c.Principal != principal:
		return "", time.Time{}, nil
	case !c.RevokedAt.IsZero():
		return "revoked", time.Time{}, nil
	}
	rec := decision.Record{TS: at, Event: decision.EventRefresh, Principal: principal,
		Auth:    &decision.Auth{Method: cred.Method, Fingerprint: cred.Fingerprint, OIDC: via},
		Device:  &decision.Device{Name: ref.NAS, Platform: dev.Platform},
		Session: &decision.Session{CtxID: c.CtxID, Username: c.Username, Unreached: unreached}}
	if c.HasCeiling() && !at.Before(c.SessionExpires.Add(b.GraceWindow)) {
		switch err := b.Store.DeleteContextIf(ctx, k, c.Rev); {
		case errors.Is(err, store.ErrConflict), errors.Is(err, store.ErrNotFound):
			return "not_judged", time.Time{}, nil
		case err != nil:
			return "", time.Time{}, err
		}
		rec.Verdict, rec.Reason = decision.VerdictDeny, decision.SessionExpired
		b.emitTo(out, rec)
		return "past_grace", time.Time{}, nil
	}
	age := time.Duration(0)
	res, rerr := pol.ResolveMember(m, dev, at)
	if rerr == nil {
		age = res.SessionAge.Of(b.MaxSessionAge)
	} else {
		age = b.MaxSessionAge // a device with no platform: the default, as its mint would have
	}
	// A requirement is read here and only here: the extension needs a proof
	// that covers it, and a reload that added one revoked nothing (the policy
	// refresh never reads it). An unproved context is named, not extended.
	if rerr == nil && res.PerLoginMFA.Required() {
		v := b.judgeMFA(ctx, caller{principal: principal, cred: cred}, &ask.mf, ref.NAS, res.PerLoginMFA, at)
		rec.PerLoginMFA = v.rec
		switch {
		case v.reason == decision.StoreUnavailable:
			return "", time.Time{}, errMFAStore
		case v.reason != "":
			rec.Verdict, rec.Reason = decision.VerdictDeny, v.reason
			b.emitTo(out, rec)
			if v.item == nil { // unavailable: no method here to prove with
				return string(v.reason), time.Time{}, nil
			}
			ask.items = append(ask.items, v.item)
			return "per_login_mfa_required", time.Time{}, nil
		}
	}
	// The new sid is indexed before the extension (pre-flight I-2): a
	// logout's RevokeBySid that runs after this reaches the context whether
	// or not the extension has landed. An entry for a context the extension
	// then does not reach is harmless: it names a context of this person.
	sid := newSid(cred, c)
	if sid != "" && b.Sessions != nil {
		if err := b.Sessions.AddSid(ctx, principal, sid, ref); err != nil {
			return "", time.Time{}, err
		}
	}
	switch err := b.Store.RefreshContext(ctx, k, store.ContextRefresh{AuthTime: at, RefreshedAt: refreshedAt(answer, at),
		SessionAge: &age, GraceCutoff: at.Add(-b.GraceWindow), Sid: sid, ExpectRev: c.Rev}, b.ContextIdleTTL); {
	case errors.Is(err, store.ErrPastGrace):
		return "past_grace", time.Time{}, nil
	case errors.Is(err, store.ErrConflict), errors.Is(err, store.ErrNotFound):
		return "not_judged", time.Time{}, nil
	case err != nil:
		return "", time.Time{}, err
	}
	var expires time.Time
	if age > 0 {
		expires = at.Add(age)
		rec.Session.SessionExpires = decision.FormatTime(expires)
	}
	if c.BlobHash != "" {
		_ = b.Store.BumpBlob(ctx, c.BlobHash, max(b.ContextIdleTTL, age))
	}
	rec.Session.AuthTime = decision.FormatTime(at)
	rec.Verdict, rec.Reason = decision.VerdictPermit, decision.GrantsMatched
	b.emitTo(out, rec)
	return "extended", expires, nil
}

// newSid is the refresh's own sid when it differs from the context's: an
// OIDC refresh under a new provider session (Ruling 15); "" otherwise,
// and always on the certificate path, whose credential has none.
func newSid(cred store.Credential, c store.Context) string {
	if cred.Sid == "" || cred.Sid == c.Credential.Sid {
		return ""
	}
	return cred.Sid
}

// refreshedAt is the staleness clock a session refresh writes: the
// directory's last verification (the stored one under grace), never later
// than at, and at without a directory. A session refresh must not reset the
// clock past the directory's last answer (Ruling 11).
func refreshedAt(answer *directory.Answer, at time.Time) time.Time {
	if v := verifiedAt(answer); !v.IsZero() && v.Before(at) {
		return v
	}
	return at
}

// livePrincipalContext reports whether k still holds a live context of
// principal: a context refreshContext skipped for no blob is the caller's
// and is reported not judged; one gone or another's is not reported.
func (b *Broker) livePrincipalContext(ctx context.Context, k store.ContextKey, principal string) bool {
	c, err := b.Store.GetContext(ctx, k)
	return err == nil && c.Principal == principal && c.RevokedAt.IsZero()
}

// response is the wire form of rep; the connection's own session now ends
// connAge after rep.At.
func (rep SessionRefreshReport) response(connAge time.Duration) api.RefreshResponse {
	out := api.RefreshResponse{AuthTime: rep.At.UTC().Format(time.RFC3339),
		SessionEndsAt: rep.At.Add(connAge).UTC().Format(time.RFC3339), Sessions: []api.RefreshedSession{}}
	for _, v := range rep.Sessions {
		s := api.RefreshedSession{Device: v.Ref.NAS, Username: v.Ref.Username, Outcome: v.Outcome, Unreached: v.Unreached}
		if !v.SessionExpires.IsZero() {
			s.SessionExpires = v.SessionExpires.UTC().Format(time.RFC3339)
		}
		out.Sessions = append(out.Sessions, s)
	}
	out.PerLoginMFA = rep.Challenge
	return out
}
