package broker

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"sort"
	"time"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/engine"
	"github.com/rhwendt/port49/internal/policy"
	"github.com/rhwendt/port49/internal/store"
)

// Prior is a policy that has been in force since the last complete refresh,
// and the span it minted in: from At — when the last complete refresh ran, or
// when it came into force if that was later — to Until, when it was replaced;
// zero for the policy still in force, whose span runs to the refresh. A token
// it minted carries its answer at the instant of the mint, and a resolution
// changes only at a grant's expiry, so its answers are read at At and at every
// expiry in the span (instants). The refresh that runs at each expiry would
// otherwise close the span there, but one the store stopped does not.
type Prior struct {
	Policy *policy.Policy
	At     time.Time
	Until  time.Time
}

// instants are the times at which pr's answers are read: At, and every grant
// expiry after it up to Until (now, for the policy still in force).
func (pr Prior) instants(now time.Time) []time.Time {
	until := pr.Until
	if until.IsZero() {
		until = now
	}
	out := []time.Time{pr.At}
	for t := pr.At; ; {
		next, ok := pr.Policy.NextChange(t)
		if !ok || next.After(until) {
			return out
		}
		out = append(out, next)
		t = next
	}
}

// RefreshReport counts what one refresh did, for the line port49d writes after
// it. The context counts are port49_context_refreshes_total's outcomes.
type RefreshReport struct {
	// TokenKeys is how many (device, username) keys had their unspent tokens
	// deleted as superseded.
	TokenKeys                                        int
	Updated, Unchanged, Revoked, Quarantined, Failed int
	// Unreached is how many of the contexts updated, revoked or failed are
	// on a platform that does not authorize commands (Junos, spec §13
	// decision 21): the context is written, for the next login and any
	// receipt replay, but the live session keeps what it had at login until
	// logout. It counts contexts the other counts already count.
	Unreached int
	// At is the instant the pass judged every token and context at. A caller
	// schedules the next grant expiry from it (policy.NextChange(At)), not
	// from its own clock after the pass, and runs another pass at once when
	// that expiry is already due: an expiry between At and the caller's clock
	// is one no context has been judged after.
	At time.Time
}

// Refresh carries the policy in force into everything the policies before it
// left behind (spec §5.1.3), and is what makes a policy edit reach a live
// session with no logout (plan 4b). It runs after every reload and at every
// grant expiry, and it can be run again: a pass that stopped part-way is
// finished by the next.
//
// First the contexts, because revoking a live session is the security
// priority and the token scan is the costlier half (principals × devices ×
// instants compiles; plan 12 measures it). Either order needs the settle pass
// for a redemption in flight, so nothing is lost by this one. Every live
// context of every active principal is
// re-resolved against the policy in force, for that principal on that device,
// and the answer is written into it by compare-and-set on the policy revision
// read (store.SetContextPolicy) — the blob, the ceiling (a held level above a
// lowered one comes down to it) and the enable mechanism. A principal left
// with no grant on the device has the context revoked instead, so its next
// command is denied `credential_revoked` (spec §5.6 row 2). A context the
// policy in force cannot be resolved or compiled for, or that cannot be
// opened, is revoked too, failing closed, and counted failed. Every
// revocation is written through store.SetRevokedAt, which writes the mark
// alone and keeps the later of two: it is right whoever the record belongs to
// by now, so no write racing it can hold a withdrawn grant in force. A context
// on a device quarantined now is left as it is: the daemon answers nothing
// from that device while it is quarantined, and the refresh at the reload or
// expiry that lifts the quarantine reaches it. Nobody is logged out: a
// narrowed rule denies the next command, a widened one permits it, and the
// session goes on — on a platform that authorizes commands. One that does not
// (Junos, spec §13 decision 21) never asks about a command, so its live
// session keeps what it had at login until logout: the context is still
// written, for the next login and any receipt replay, and it is counted
// Unreached and named in the process log.
//
// Then the tokens. A token carries its blob hash, ceiling and enable
// mechanism from the policy that minted it, and a redemption writes them into
// the context it creates or joins. So an unspent token minted under a prior
// policy whose answer the policy in force would not give is deleted, key by
// key; otherwise a grant removed at 10:00 comes back at 10:05 on a device where
// the operator had no context yet, from a token minted at 09:58. A token the
// policy in force would mint identically is left alone: a reload is not a
// reason to make everyone run `port49 token` again.
//
// Every context the refresh changes is one `refresh` decision record naming
// the context's ctx_id, so the record before a command's changed answer says
// why; a context left for a quarantine is recorded once per policy, not at
// every pass.
//
// A pass judges every token and context at one instant, RefreshReport.At. A
// grant that expires while it runs sends it round again at once, so the
// report's counts can sum more than one pass, and At is the last pass's.
//
// It is not meant to run concurrently with itself: port49d runs one pass at a
// time, and two at once could each forget the other's quarantine records and
// write one twice.
//
// It returns nil only when every live context is on the policy in force —
// written, unchanged, revoked, or left for a quarantine — which is what
// port49d clears port49_policy_refresh_pending on. A store error ends the pass
// and is returned with the report so far; nothing is half-written to any one
// context, and the caller runs it again. A context still changing after every
// attempt does not end it: it is counted failed and left for the retry, and
// the pass goes on and returns store.ErrConflict at the end so the caller
// runs it again. A cancelled ctx ends the pass at the next principal, in
// either half, and is returned: port49d is shutting down.
func (b *Broker) Refresh(ctx context.Context, priors []Prior) (RefreshReport, error) {
	cur := b.Policy.Load()
	var rep RefreshReport
	for {
		rep.At = b.Now()
		busy := b.refreshContexts(ctx, cur, rep.At, &rep)
		if busy != nil && !errors.Is(busy, store.ErrConflict) {
			return rep, fmt.Errorf("refreshing live contexts: %w", busy)
		}
		// A busy context is left for the retry, and the tokens are still
		// superseded: a key whose answer changed is cleared either way.
		if err := b.supersedeTokens(ctx, cur, rep.At, priors, &rep); err != nil {
			return rep, fmt.Errorf("deleting superseded tokens: %w", err)
		}
		if busy != nil {
			return rep, fmt.Errorf("refreshing live contexts: %w", busy)
		}
		// Every context was judged at At. A grant that expired while the
		// pass ran was judged before its expiry, and a caller scheduling from
		// its own clock would never come back for it, so the pass runs again
		// at once, over the span the policy in force has minted in since At.
		// Each pass passes at least one expiry, so this ends. A policy
		// swapped in meanwhile is the reload's own pass to carry.
		next, ok := cur.NextChange(rep.At)
		if !ok || next.After(b.Now()) || b.Policy.Load() != cur {
			return rep, nil
		}
		priors = []Prior{{Policy: cur, At: rep.At}}
	}
}

// minted is what a token for one principal on one device carries of its
// policy, the bundle aside: every policy file has its own bundle, so comparing
// it would supersede every token at every edit. ttl is the subject's
// token_ttl, the longest the token can live.
type minted struct {
	username string
	blob     []byte
	ceiling  uint8
	enable   string
	ttl      time.Duration
}

// mintedBy is what p would mint for principal on d at at, and false when it
// would mint nothing: no grant, a quarantine, or a refusal the broker makes as
// an item error (policy.MintCheck).
func mintedBy(p *policy.Policy, principal string, d admission.Device, at time.Time) (minted, bool) {
	res, err := p.Resolve(principal, d, at)
	if err != nil {
		return minted{}, false
	}
	if code, _ := policy.MintCheck(res, principal, d.Name); code != "" {
		return minted{}, false
	}
	blob := res.Blob
	blob.Bundle = "-" // Encode refuses an empty bundle; every real one is a sha256
	body, _, err := engine.Encode(blob)
	if err != nil {
		return minted{}, false
	}
	return minted{username: res.Username, blob: body, ceiling: res.MaxPrivilege, enable: res.Enable,
		ttl: res.TokenTTL}, true
}

// keeps reports whether a token m describes is one o would have minted: the
// same answer, and a life no longer than o allows. A shortened token_ttl — an
// incident's response, say — supersedes the tokens minted under the longer
// one; a lengthened one does not, since those tokens live less than allowed.
func (m minted) keeps(o minted) bool {
	return m.username == o.username && bytes.Equal(m.blob, o.blob) && m.ceiling == o.ceiling &&
		m.enable == o.enable && m.ttl <= o.ttl
}

// supersedeTokens deletes the unspent tokens of every (device, username) where
// a prior policy minted something, at any instant of its span, that the policy
// in force would not. A key is cleared whole: tokens are keyed by it, and
// every principal minting under one username is one subject, whose answer
// changed. That includes a token minted under the policy in force between the
// swap and this pass — the operator runs `port49 token` again, and the refresh
// runs straight after the swap to keep that window short.
func (b *Broker) supersedeTokens(ctx context.Context, cur *policy.Policy, now time.Time, priors []Prior,
	rep *RefreshReport) error {
	names := make([]string, 0, len(b.Devices))
	for name := range b.Devices {
		names = append(names, name)
	}
	sort.Strings(names)
	type answer struct {
		m  minted
		ok bool
	}
	current := map[[2]string]answer{} // the policy in force's, by (principal, device), computed once
	keys := map[store.TokenKey]bool{}
	for _, pr := range priors {
		instants := pr.instants(now)
		if pr.Policy == cur && len(instants) == 1 {
			// The policy in force, over a span with no expiry in it — a
			// settle pass, or a retry: every answer is the one it gives now.
			continue
		}
		for _, principal := range pr.Policy.Principals() {
			if err := ctx.Err(); err != nil {
				return err
			}
			for _, name := range names {
				d := b.Devices[name]
				for _, at := range instants {
					was, ok := mintedFor(pr.Policy, principal, d, at)
					if !ok {
						continue // nothing was minted then, so nothing is superseded
					}
					is, seen := current[[2]string{principal, name}]
					if !seen {
						is.m, is.ok = mintedFor(cur, principal, d, now)
						current[[2]string{principal, name}] = is
					}
					if is.ok && was.keeps(is.m) {
						continue
					}
					keys[store.TokenKey{NAS: name, Username: was.username}] = true
				}
			}
		}
	}
	ordered := make([]store.TokenKey, 0, len(keys))
	for k := range keys {
		ordered = append(ordered, k)
	}
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].NAS != ordered[j].NAS {
			return ordered[i].NAS < ordered[j].NAS
		}
		return ordered[i].Username < ordered[j].Username
	})
	for _, k := range ordered {
		// Read first only to count: a key whose tokens are all spent or
		// expired supersedes nothing an operator would notice.
		toks, err := b.Store.Candidates(ctx, k)
		if err != nil {
			return err
		}
		if err := b.Store.DeleteTokens(ctx, k); err != nil {
			return err
		}
		b.mu.Lock()
		if b.superseded == nil {
			b.superseded = map[store.TokenKey]time.Time{}
		}
		b.superseded[k] = b.Now()
		b.mu.Unlock()
		if len(toks) > 0 {
			rep.TokenKeys++
			b.Metrics.TokensSuperseded.Inc()
		}
	}
	return nil
}

// refreshContexts visits every live context through the indexes the daemon
// keeps for exactly this (spec §5.1.3): active_principals, then each one's
// contexts_by_principal. A store error ends the pass. A context still changing
// after every attempt does not: it is left for the retry, the pass goes on,
// and the conflict is returned at the end so the caller runs it again — one
// busy session must not hold every session after it on the superseded policy.
func (b *Broker) refreshContexts(ctx context.Context, cur *policy.Policy, now time.Time, rep *RefreshReport) error {
	principals, err := b.Store.ActivePrincipals(ctx)
	if err != nil {
		return err
	}
	quarantined := map[string]bool{} // the ctx_ids this pass left for a quarantine
	var busy error
	for _, principal := range principals {
		if err := ctx.Err(); err != nil {
			return err
		}
		refs, err := b.Store.ContextsByPrincipal(ctx, principal)
		if err != nil {
			return err
		}
		for _, ref := range refs {
			switch err := b.refreshContext(ctx, cur, now, principal, ref, rep, quarantined); {
			case errors.Is(err, store.ErrConflict):
				if busy == nil {
					busy = err
				}
			case err != nil:
				return err
			}
		}
	}
	// Every live context was visited, so a quarantine this pass did not see
	// is over, or its context is: forget it, and a context quarantined again
	// later is recorded again.
	b.mu.Lock()
	for id := range b.quarantineRecorded {
		if !quarantined[id] {
			delete(b.quarantineRecorded, id)
		}
	}
	b.mu.Unlock()
	return busy
}

// refreshContext re-resolves one context and writes the answer, reading again
// and deciding again when a write landed between its read and its own, up to
// store.MaxJoinAttempts times. quarantined collects the ctx_ids the pass
// leaves for a quarantine.
func (b *Broker) refreshContext(ctx context.Context, cur *policy.Policy, now time.Time, principal string,
	ref store.ContextRef, rep *RefreshReport, quarantined map[string]bool) error {
	k := store.ContextKey{NAS: ref.NAS, Username: ref.Username}
	for attempt := 0; attempt < store.MaxJoinAttempts; attempt++ {
		c, err := b.Store.GetContext(ctx, k)
		var unreadable *store.UnreadableContextError
		switch {
		case errors.Is(err, store.ErrNotFound):
			return nil // the index outlived the context; its own TTL reclaims it
		case errors.As(err, &unreadable):
			if !unreadable.RevokedAt.IsZero() {
				return nil // revoked already, and a refresh never lifts a mark
			}
			// Sealed under a key that has left the two-key window, or failing
			// authentication: whose it is and what it holds cannot be read,
			// so it cannot be judged against the policy in force, and it is
			// not left on the one before. It is revoked, as a compile fault
			// is; the authorizer cannot open it either, and the next login
			// replaces it. The record names what is authoritative, the
			// device and the username the key holds, and no principal: the
			// index entry that led here may be one another principal's
			// login has made stale, and whose the record is, is sealed.
			log.Printf("broker: refresh: the context for %q on %q, indexed under %s, will not open (%v); revoking it",
				ref.Username, ref.NAS, principal, err)
			rec := decision.Record{TS: now, Event: decision.EventRefresh, Verdict: decision.VerdictDeny,
				Reason:  decision.BlobUnavailable,
				Device:  &decision.Device{Name: ref.NAS, Platform: b.Devices[ref.NAS].Platform},
				Session: &decision.Session{Username: ref.Username},
				Policy:  &decision.Policy{Bundle: cur.Bundle}}
			return b.revoke(ctx, k, now, refreshStep{revoke: true, rec: rec, outcome: "failed",
				sessionOnly: sessionOnly(cur, b.Devices[ref.NAS].Platform)}, rep)
		case err != nil:
			return err
		}
		// Another principal's since the index was read (its own pass reaches
		// it), the lab's instrument's (no blob; it answers from config), or
		// revoked already (a refresh never lifts a mark, store.Store).
		if c.Principal != principal || c.BlobHash == "" || !c.RevokedAt.IsZero() {
			return nil
		}
		step := b.decideRefresh(cur, now, principal, ref, c)
		step.sessionOnly = sessionOnly(cur, b.Devices[ref.NAS].Platform)
		switch {
		case step.revoke:
			return b.revoke(ctx, k, now, step, rep)
		case step.outcome == "quarantined":
			quarantined[c.CtxID] = true
			if b.quarantineUnrecorded(c.CtxID, cur.Bundle) {
				b.emit(step.rec)
			}
			b.count(rep, step.outcome)
			return nil
		case step.write == nil:
			b.count(rep, step.outcome)
			return nil
		}
		// The blob is in the store, and in the log, before any context
		// names it: the daemon's next command reads it by that name.
		if err := b.putBlob(ctx, step.write.BlobHash, step.body); err != nil {
			return err
		}
		switch err := b.Store.SetContextPolicy(ctx, k, c.PolicyRev, *step.write); {
		case errors.Is(err, store.ErrConflict):
			continue
		case errors.Is(err, store.ErrNotFound):
			return nil
		case err != nil:
			return err
		}
		b.emit(step.rec)
		b.count(rep, step.outcome)
		b.unreached(step, rep)
		return nil
	}
	// Still changing after every attempt: a login or a privilege change
	// landing between every read and its write. A revocation never gets here
	// (it does not compare), so this context keeps a policy the one in force
	// would widen or narrow, and is left for the retry.
	log.Printf("broker: refresh: the context for %q on %q was still changing after %d attempts; left for the retry",
		ref.Username, ref.NAS, store.MaxJoinAttempts)
	b.count(rep, "failed")
	return fmt.Errorf("the context for %q on %q was still changing after %d attempts: %w", ref.Username, ref.NAS,
		store.MaxJoinAttempts, store.ErrConflict)
}

// revoke marks the context revoked at at through SetRevokedAt, the setter that
// writes the mark alone and keeps the later of two, and records and counts it.
// It does not compare: a revocation is right whoever the record belongs to by
// now, at the worst revoking a login another principal made a moment ago,
// whose owner logs in again (fail closed).
func (b *Broker) revoke(ctx context.Context, k store.ContextKey, at time.Time, step refreshStep,
	rep *RefreshReport) error {
	switch err := b.Store.SetRevokedAt(ctx, k, at); {
	case errors.Is(err, store.ErrNotFound):
		return nil
	case err != nil:
		return err
	}
	b.emit(step.rec)
	b.count(rep, step.outcome)
	b.unreached(step, rep)
	return nil
}

// sessionOnly reports whether a platform never asks about a command (spec §13
// decision 21), as explain judges it: a refresh cannot reach a live session
// there.
func sessionOnly(p *policy.Policy, platform string) bool {
	return !p.Dialect(platform).Authorizes("commands")
}

// unreached counts a context the refresh changed on a platform that never
// asks about a command, and names it in the process log: its live session
// keeps what it had at login until logout, and the operator who withdrew a
// grant must not read "revoked" and stop there.
func (b *Broker) unreached(step refreshStep, rep *RefreshReport) {
	if !step.sessionOnly {
		return
	}
	rep.Unreached++
	which := "ctx_id " + step.rec.Session.CtxID
	if step.rec.Session.CtxID == "" {
		which = fmt.Sprintf("username %q", step.rec.Session.Username)
	}
	log.Printf("broker: refresh: the context on %q (%s) was %s, but %s does not authorize commands: its live "+
		"session keeps what it had at login until logout (spec §13 decision 21)", step.rec.Device.Name, which,
		step.outcome, step.rec.Device.Platform)
}

// quarantineUnrecorded reports whether the context ctxID has no `refresh`
// record yet for its quarantine under bundle, and marks it recorded. The
// settle pass, the retries and the pass at every expiry would otherwise write
// the same line for the same context again and again.
func (b *Broker) quarantineUnrecorded(ctxID, bundle string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.quarantineRecorded[ctxID] == bundle {
		return false
	}
	if b.quarantineRecorded == nil {
		b.quarantineRecorded = map[string]string{}
	}
	b.quarantineRecorded[ctxID] = bundle
	return true
}

// refreshStep is one context's answer: a revocation, or the write when there
// is one (nil with no revocation leaves the context as it is), the blob it
// names, the decision record, and the outcome it is counted under.
type refreshStep struct {
	revoke  bool
	write   *store.ContextPolicy
	body    []byte
	rec     decision.Record
	outcome string
	// sessionOnly is a context on a platform that never asks about a
	// command: a change written to it does not reach its live session.
	sessionOnly bool
}

// decideRefresh is what the policy in force says about principal on the
// context's device now. It reads no store.
func (b *Broker) decideRefresh(cur *policy.Policy, now time.Time, principal string, ref store.ContextRef,
	c store.Context) refreshStep {
	rec := decision.Record{TS: now, Event: decision.EventRefresh, Principal: principal,
		Device:  &decision.Device{Name: ref.NAS},
		Session: &decision.Session{CtxID: c.CtxID, Username: c.Username, Privilege: c.PrivLvl},
		Policy:  &decision.Policy{Bundle: cur.Bundle}}
	rec.Policy.Subject, _ = cur.SubjectOf(principal)
	revoke := func() refreshStep {
		rec.Verdict, rec.Reason = decision.VerdictDeny, decision.NoGrantsMatched
		return refreshStep{revoke: true, rec: rec, outcome: "revoked"}
	}
	// fault is a policy in force that cannot be resolved or compiled for this
	// context. The load's joint checks compile every subject on every device
	// at every expiry and quarantine the ones that fail, so this is a broker
	// defect, as it is at mint. The context is revoked rather than left on a
	// policy that is no longer in force, and never silently: the record says
	// blob_unavailable, the process log names the ctx_id and the fault, and it
	// is counted failed (spec §5.1.3).
	fault := func(what string, err any) refreshStep {
		b.logf("broker: refresh: %s for %s on %q: %v; revoking the context (ctx_id %s)", what, principal,
			ref.NAS, err, c.CtxID)
		rec.Verdict, rec.Reason = decision.VerdictDeny, decision.BlobUnavailable
		return refreshStep{revoke: true, rec: rec, outcome: "failed"}
	}
	dev, ok := b.Devices[ref.NAS]
	if !ok {
		// Inventory is read once, at start, so a live context on a device it
		// does not name was written by a daemon reading another inventory.
		// Nothing can be minted for it here.
		return revoke()
	}
	rec.Device.Platform = dev.Platform
	res, err := resolveFor(cur, principal, dev, now)
	if err == nil {
		rec.Policy.Grants = res.Grants
	}
	switch {
	case errors.Is(err, policy.ErrNoGrants):
		return revoke()
	case errors.Is(err, policy.ErrDeviceQuarantined):
		rec.Verdict, rec.Reason = decision.VerdictDeny, decision.DeviceQuarantined
		return refreshStep{rec: rec, outcome: "quarantined"}
	case err != nil:
		return fault("resolving the policy in force", err)
	case res.Username != c.Username:
		// The subject's username changed: the principal can no longer mint
		// under the name this context is keyed by. No grant selects this
		// context's key, so the record names none.
		rec.Policy.Grants = nil
		return revoke()
	}
	body, hash, err := engine.Encode(res.Blob)
	if err != nil {
		return fault("the policy in force compiled to a blob the daemon would refuse", err)
	}
	switch code, detail := policy.MintCheck(res, principal, ref.NAS); code {
	case "":
	case "attribute_too_long", "attribute_unsafe":
		// The mint would refuse this principal a token here, as an item
		// error: the fault is in the data a placeholder fills in. The context
		// still takes the new rules — its commands are decided by the policy
		// in force — and the daemon refuses the session reply it cannot
		// build, blob_unavailable, as it would have for a token (spec §6).
		log.Printf("broker: refresh: the session reply for %s on %q will be refused (%s): %s", principal, ref.NAS,
			code, detail)
	default:
		return fault("the policy in force compiled to a blob the daemon would refuse", detail)
	}
	clamp := res.HasCeiling && c.PrivLvl > res.MaxPrivilege
	if hash == c.BlobHash && res.MaxPrivilege == c.MaxPrivilege && res.Enable == c.Enable && !clamp {
		return refreshStep{outcome: "unchanged"}
	}
	rec.Verdict, rec.Reason, rec.Policy.Blob = decision.VerdictPermit, decision.GrantsMatched, hash
	if clamp {
		rec.Session.PrivilegeClamped = &decision.PrivilegeClamp{From: c.PrivLvl, To: res.MaxPrivilege}
		rec.Session.Privilege = res.MaxPrivilege
	}
	return refreshStep{write: &store.ContextPolicy{BlobHash: hash, MaxPrivilege: res.MaxPrivilege, Enable: res.Enable},
		body: body, rec: rec, outcome: "updated"}
}

// count adds one context to the report and the metric.
func (b *Broker) count(rep *RefreshReport, outcome string) {
	switch outcome {
	case "updated":
		rep.Updated++
	case "unchanged":
		rep.Unchanged++
	case "revoked":
		rep.Revoked++
	case "quarantined":
		rep.Quarantined++
	case "failed":
		rep.Failed++
	}
	b.Metrics.ContextRefreshes.WithLabelValues(outcome).Inc()
}

// resolveFor is how the refresh resolves a context's principal, swapped in
// tests to stand in for a composition the load never compiled.
var resolveFor = (*policy.Policy).Resolve

// mintedFor is mintedBy for the token scan, swapped in tests to count what it
// compiles.
var mintedFor = mintedBy
