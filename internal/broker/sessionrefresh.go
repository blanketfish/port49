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
	now := b.Now()
	principal, cred, err := Identity(r.TLS, now)
	if err != nil {
		b.refuseRefresh(w, now, principal, cred, decision.TrustDomainUnresolved, string(decision.TrustDomainUnresolved), err.Error())
		return
	}
	h := heldOf(r)
	if h == nil {
		writeError(w, http.StatusBadRequest, "bad_request", "a refresh is made on the held connection")
		return
	}
	nonce := make([]byte, api.RefreshNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		writeError(w, http.StatusInternalServerError, "broker_error", "no randomness for a challenge")
		return
	}
	h.mu.Lock()
	wait := h.lastRefresh.Add(refreshEvery).Sub(now)
	if wait <= 0 {
		h.nonce, h.nonceExp = nonce, now.Add(refreshNonceTTL)
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
	now := b.Now()
	principal, cred, err := Identity(r.TLS, now)
	if err != nil {
		b.refuseRefresh(w, now, principal, cred, decision.TrustDomainUnresolved, string(decision.TrustDomainUnresolved), err.Error())
		return
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
	// Every consumed nonce is paced, whether its answer verifies or not: a
	// caller looping challenge and bad answer is held to one per refreshEvery
	// as a good one is (pre-flight M17).
	h.mu.Lock()
	nonce, exp := h.nonce, h.nonceExp
	if nonce != nil {
		h.nonce, h.lastRefresh = nil, now
	}
	h.mu.Unlock()
	got, _ := base64.RawURLEncoding.DecodeString(req.Nonce)
	sig, _ := base64.RawURLEncoding.DecodeString(req.Signature)
	if nonce == nil || !now.Before(exp) || subtle.ConstantTimeCompare(nonce, got) != 1 {
		b.refuseRefresh(w, now, principal, cred, decision.TrustDomainUnresolved, "refresh_challenge_missing",
			"no live refresh challenge on this connection; ask for one and answer it within 60s")
		return
	}
	leaf := r.TLS.VerifiedChains[0][0] // Identity verified there is one
	ekm, err := r.TLS.ExportKeyingMaterial(api.RefreshExporterLabel, nil, 32)
	alg, ok := api.RefreshAlgorithm(leaf.PublicKey)
	if err != nil || !ok || leaf.CheckSignature(alg, api.RefreshMessage(nonce, ekm), sig) != nil {
		b.refuseRefresh(w, now, principal, cred, decision.TrustDomainUnresolved, string(decision.TrustDomainUnresolved),
			"the refresh challenge was not answered by this connection's key")
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), holdTimeout)
	defer cancel()
	rv, revoked, err := b.revocation(ctx, principal, cred)
	switch {
	case err != nil:
		b.refreshStoreError(w, now, principal, cred, 0,
			"the broker could not read the revocations in force, so it extended nothing; try again")
		return
	case revoked:
		b.Metrics.SessionRefreshes.WithLabelValues("refused").Inc()
		b.refuseRevokedAs(w, decision.EventRefresh, now, principal, cred, rv)
		return
	}
	// Certificate status (Task 10) is checked here, beside the marks.
	at := b.Now() // the broker's verification time: the one clock §5.6 gives it
	// The connection's clock moves before the extension, and stays moved if
	// the extension fails: the signature and the marks verified, so this was
	// a fresh authentication of the connection whatever the store does next.
	h.mu.Lock()
	h.at, h.lastRefresh = at, at
	h.mu.Unlock()
	rep, err := b.RefreshSession(ctx, principal, cred, at)
	if err != nil {
		b.refreshStoreError(w, at, principal, cred, refreshEvery, partialRefreshText) // fixed text (M5)
		return
	}
	// The marks again, after the extension's writes, as a mint reads them
	// after its last token write (revokedSince): a revocation that landed
	// while this refresh extended is answered, not reported as extended.
	switch rv, revoked, err := b.revocation(ctx, principal, cred); {
	case err != nil:
		b.refreshStoreError(w, at, principal, cred, refreshEvery, partialRefreshText)
		return
	case revoked:
		b.Metrics.SessionRefreshes.WithLabelValues("refused").Inc()
		b.refuseRevokedAs(w, decision.EventRefresh, b.Now(), principal, cred, rv)
		return
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
	retry time.Duration, text string) {
	b.Metrics.SessionRefreshes.WithLabelValues("store_error").Inc()
	b.emit(decision.Record{TS: now, Event: decision.EventRefresh, Verdict: decision.VerdictDeny,
		Reason: decision.StoreUnavailable, Principal: principal, Auth: &decision.Auth{Method: cred.Method}})
	if retry > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(int(retry/time.Second)))
	}
	writeError(w, http.StatusServiceUnavailable, string(decision.StoreUnavailable), text)
}

// refuseRefresh answers a refresh that proved nothing, and records it
// without the nonce or the signature.
func (b *Broker) refuseRefresh(w http.ResponseWriter, now time.Time, principal string, cred store.Credential,
	reason decision.Reason, code, detail string) {
	b.Metrics.SessionRefreshes.WithLabelValues("refused").Inc()
	b.emit(decision.Record{TS: now, Event: decision.EventRefresh, Verdict: decision.VerdictDeny, Reason: reason,
		Principal: principal, Auth: &decision.Auth{Method: "cert", Fingerprint: cred.Fingerprint}})
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
func (b *Broker) RefreshSession(ctx context.Context, principal string, cred store.Credential, at time.Time) (SessionRefreshReport, error) {
	pol, hold := b.Policy.Hold()
	defer hold()
	rep := SessionRefreshReport{At: at}
	refs, err := b.Store.ContextsByPrincipal(ctx, principal)
	if err != nil {
		return rep, err
	}
	var pass RefreshReport
	quarantined := map[string]bool{}
	for _, ref := range refs {
		k := store.ContextKey{NAS: ref.NAS, Username: ref.Username}
		dev, known := pol.Device(ref.NAS)
		unreached := !known || dev.Platform == "" || sessionOnly(pol, dev.Platform)
		visit := RefreshedContext{Ref: ref, Unreached: unreached}
		outcome, err := b.refreshContext(ctx, pol, nil, at, principal, ref, &pass, quarantined, false)
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
			visit.Outcome, visit.SessionExpires, err = b.extend(ctx, pol, principal, cred, ref, dev, at, unreached)
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
	return rep, nil
}

// extend reads the context the judgment kept and extends it, or deletes
// it past its grace window, both bound to the revision read. It returns ""
// for a context gone or no longer the caller's.
func (b *Broker) extend(ctx context.Context, pol *policy.Policy, principal string, cred store.Credential,
	ref store.ContextRef, dev admission.Device, at time.Time, unreached bool) (string, time.Time, error) {
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
		Auth:    &decision.Auth{Method: cred.Method, Fingerprint: cred.Fingerprint},
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
		b.emit(rec)
		return "past_grace", time.Time{}, nil
	}
	age := time.Duration(0)
	if res, err := pol.Resolve(principal, dev, at); err == nil {
		age = res.SessionAge.Of(b.MaxSessionAge)
	} else {
		age = b.MaxSessionAge // a device with no platform: the default, as its mint would have
	}
	switch err := b.Store.RefreshContext(ctx, k, store.ContextRefresh{AuthTime: at, RefreshedAt: at,
		SessionAge: &age, GraceCutoff: at.Add(-b.GraceWindow), ExpectRev: c.Rev}, b.ContextIdleTTL); {
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
	b.emit(rec)
	return "extended", expires, nil
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
	return out
}
