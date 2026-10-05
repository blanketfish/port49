package broker

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/directory"
	"github.com/rhwendt/port49/internal/engine"
	"github.com/rhwendt/port49/internal/policy"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/crypt"
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
	// Unverified is the contexts left unstamped: the directory did not
	// answer for their principal. UnverifiedPrincipals counts those
	// principals, and OldestUnverified is the least refreshed_at among the
	// contexts (zero with none).
	Unverified           int
	UnverifiedPrincipals int
	OldestUnverified     time.Time
	// Narrowed is the principals a pass revoked or narrowed a context of,
	// for token supersession.
	Narrowed []string
	// At is the instant the pass judged every token and context at. A caller
	// schedules the next grant expiry from it (policy.NextChange(At)), not
	// from its own clock after the pass, and runs another pass at once when
	// that expiry is already due: an expiry between At and the caller's clock
	// is one no context has been judged after.
	At time.Time
	// session is set on the judgment a session refresh makes
	// (RefreshSession). It is counted in port49_session_refreshes_total, not
	// in the policy refresh's port49_context_refreshes_total, and nothing
	// retries it: the operator runs `port49 refresh` again (final review
	// M-2).
	session bool
	// log is where the pass writes its records, nil for b.Log (passLog). A
	// session refresh holds the policy while it judges, so it passes its
	// buffer, written once it lets go (plan 7e, Ruling 10); a policy
	// refresh, after a reload, holds none and writes at once.
	log *heldLog
}

// passLog is where a pass writes its records: rep's buffer, or b.Log.
func (b *Broker) passLog(rep *RefreshReport) decision.Emitter {
	if rep.log != nil {
		return rep.log
	}
	return b.Log
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
// runs it again. So does a context under a key this port49d does not hold,
// and a principal whose contexts could not be looked up: each is left
// unjudged (re-review r-m1). A cancelled ctx ends the pass at the next principal, in
// either half, and is returned: port49d is shutting down.
func (b *Broker) Refresh(ctx context.Context, priors []Prior) (RefreshReport, error) {
	cur := b.Policy.Load()
	// sameSource is an inventory-only swap: every policy since the last
	// complete refresh was read from the file in force, so a context whose
	// blob differs from the new one only in the bundle it names is left as
	// it is (spec §5.1.3; plan 6a Decided 3).
	sameSource := true
	for _, pr := range priors {
		sameSource = sameSource && pr.Policy.Source == cur.Source
	}
	var rep RefreshReport
	for {
		rep.At = b.Now()
		busy := b.refreshContexts(ctx, cur, priors, rep.At, &rep, sameSource, passJudge{member: b.storedJudge})
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

// RefreshTokens is Refresh's token half alone (plan 7e, Ruling 6): every
// broker process runs it at its own reload, for the policies it minted
// under, and the runner runs Refresh, whose context half is the runner's
// alone. It deletes the unspent tokens priors minted that the policy in
// force would not, at every grant expiry in their spans, and judges no
// context. Like Refresh it runs again at once over an expiry the pass
// crossed.
func (b *Broker) RefreshTokens(ctx context.Context, priors []Prior) (RefreshReport, error) {
	cur := b.Policy.Load()
	var rep RefreshReport
	for {
		rep.At = b.Now()
		if err := b.supersedeTokens(ctx, cur, rep.At, priors, &rep); err != nil {
			return rep, fmt.Errorf("deleting superseded tokens: %w", err)
		}
		next, ok := cur.NextChange(rep.At)
		if !ok || next.After(b.Now()) || b.Policy.Load() != cur {
			return rep, nil
		}
		priors = []Prior{{Policy: cur, At: rep.At}}
	}
}

// RefreshAtStart carries the policy in force into every live context a
// persistent store kept across a restart (plan 7d; spec §13, decision
// 35). No policy those contexts were written under is one this port49d
// loaded, so none is the same source, and every context is judged against
// the policy in force; the tokens are already purged, so nothing is
// superseded here. port49d runs it before TACACS+ binds.
//
// What it leaves unjudged is an ErrConflict, and port49d does a different
// thing with each (decision 35, a start on etcd, step 6):
//   - ErrPrincipalUnvisited, a principal whose contexts could not be
//     looked up: those contexts would open unjudged, so it holds the start
//     as an outage does, and port49d runs it again (Ruling T12-c);
//   - any other ErrConflict, a context still changing after every
//     attempt: another writer is changing it, so the start goes on, and
//     port49d runs a refresh pass at once after the listeners open
//     (Ruling T12-d);
//   - ErrLeftUnderUnheldKey, a context sealed under a key this port49d
//     does not hold: every path denies it, so the start goes on, and the
//     next pass judges it (Ruling T12-a).
//
// The last two keep port49_policy_refresh_pending at 1 (re-review r-m1).
// refreshContexts returns the first of these that the pass met at all, in
// that order. A store error is returned as it is, and holds the start.
func (b *Broker) RefreshAtStart(ctx context.Context) (RefreshReport, error) {
	var rep RefreshReport
	rep.At = b.Now()
	err := b.refreshContexts(ctx, b.Policy.Load(), nil, rep.At, &rep, false, passJudge{member: b.storedJudge})
	return rep, err
}

// Contexts is how many live contexts the pass judged.
func (r RefreshReport) Contexts() int {
	return r.Updated + r.Unchanged + r.Revoked + r.Quarantined + r.Failed
}

// ApplyMarksAtStart runs 7a's two context passes for every standing mark
// (plan 7d; pre-flight C1). On the memory store a restart lost every
// context, so a mark never had a kept context to miss. On a store that
// persists, a start keeps contexts a revocation never reached: a mark
// added to broker.revocations_file with port49d stopped, or a revocation
// whose passes an outage cut short. It touches no token (the start purges
// them) and no connection (none is held yet). It reports how many
// contexts it marked, and its first outage, for the caller to run it
// again; a mark it could not apply is still denied by the daemon's marks.
//
// Only an outage is returned (re-check R-I3). A context that will not
// open, sealed under a key this window lacks, is still marked (session.mark
// marks what it cannot read, since a revocation needs no key), and is
// denied as unreadable anyway; returned, it would fail every start until
// that context's TTL ran out. Any other error is said and skipped for the
// same reason: the daemon's marks deny that context on every request.
func (b *Broker) ApplyMarksAtStart(ctx context.Context, marks []store.Revocation) (int, error) {
	if b.Sessions == nil {
		return 0, errors.New("broker: revocation is not wired (no session manager); the standing marks were not applied")
	}
	reached := map[store.ContextRef]bool{}
	var first error
	var kind string
	note := func(err error) {
		var unreadable *store.UnreadableContextError
		switch {
		case err == nil, errors.Is(err, store.ErrNotFound), errors.As(err, &unreadable):
		case errors.Is(err, store.ErrUnavailable):
			if first == nil {
				first = err
			}
		default:
			b.logf("broker: a standing %s revocation was not applied to every kept context (%v); the daemon's marks "+
				"deny those contexts on every request regardless", kind, err)
		}
	}
	for _, r := range marks {
		kind = r.Kind
		for pass := 0; pass < 2; pass++ {
			var refs []store.ContextRef
			var err error
			switch r.Kind {
			case store.RevocationPrincipal:
				refs, err = b.Sessions.RevokeByPrincipal(ctx, r.Key)
			case store.RevocationCert:
				i := strings.LastIndexByte(r.Key, '|')
				if i < 0 {
					continue // CheckRevocation refused such a key; nothing names it
				}
				refs, err = b.Sessions.RevokeByCert(ctx, r.Key[:i], r.Key[i+1:])
			}
			note(err)
			for _, ref := range refs {
				reached[ref] = true
			}
		}
	}
	return len(reached), first
}

// minted is what a token for one principal on one device carries of its
// policy, the bundle aside: every policy file has its own bundle, so comparing
// it would supersede every token at every edit. ttl is the subject's
// token_ttl, the longest the token can live; age is the device's
// max_session_age, zero for never.
type minted struct {
	username string
	blob     []byte
	ceiling  uint8
	enable   string
	ttl      time.Duration
	age      time.Duration
}

// mintedBy is what p would mint for m on d at at, and false when it
// would mint nothing: no grant, a quarantine, or a refusal the broker makes as
// an item error (policy.MintCheck). def is port49d's max_session_age.
func mintedBy(p *policy.Policy, m policy.Member, d admission.Device, at time.Time,
	def time.Duration) (minted, bool) {
	res, err := p.ResolveMember(m, d, at)
	if err != nil {
		return minted{}, false
	}
	if code, _ := policy.MintCheck(res, m.Principal, d.Name); code != "" {
		return minted{}, false
	}
	blob := res.Blob
	blob.Bundle = "-" // Encode refuses an empty bundle; every real one is a sha256
	body, _, err := engine.Encode(blob)
	if err != nil {
		return minted{}, false
	}
	return minted{username: res.Username, blob: body, ceiling: res.MaxPrivilege, enable: res.Enable,
		ttl: res.TokenTTL, age: res.SessionAge.Of(def)}, true
}

// keeps reports whether a token m describes is one o would have minted: the
// same answer, and a life no longer than o allows. A shortened token_ttl or
// max_session_age — an incident's response, say — supersedes the tokens
// minted under the longer one; a lengthened one does not, since those tokens
// live less than allowed.
func (m minted) keeps(o minted) bool {
	return m.username == o.username && bytes.Equal(m.blob, o.blob) && m.ceiling == o.ceiling &&
		m.enable == o.enable && m.ttl <= o.ttl && !longerAge(m.age, o.age)
}

// longerAge reports whether a ceiling of a outlasts one of b, zero being
// never: a token minted under a longer ceiling than the policy in force
// allows is superseded, as a longer token_ttl is (decision 33).
func longerAge(a, b time.Duration) bool {
	return b != 0 && (a == 0 || a > b)
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
	seen := map[string]bool{}
	for _, d := range cur.Devices() {
		seen[d.Name] = true
	}
	for _, pr := range priors {
		for _, d := range pr.Policy.Devices() {
			seen[d.Name] = true
		}
	}
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	type answer struct {
		m  minted
		ok bool
	}
	current := map[[2]string]answer{} // the policy in force's, by (principal, device), computed once
	keys := map[store.TokenKey]bool{}
	// A group member is named by no identity subject, so the principals the
	// scan judges are those a prior declares and those the store holds a
	// membership for (pre-flight I-13); read once per pass, and only under a
	// directory.
	var held []string
	if b.Directory != nil {
		var err error
		if held, err = b.Store.MembershipPrincipals(ctx); err != nil {
			return err
		}
	}
	members := map[string]policy.Member{}
	memberOf := func(principal string) (policy.Member, error) {
		if m, ok := members[principal]; ok {
			return m, nil
		}
		m, err := b.storedMember(ctx, principal)
		if err == nil {
			members[principal] = m
		}
		return m, err
	}
	for _, pr := range priors {
		instants := pr.instants(now)
		if pr.Policy == cur && len(instants) == 1 {
			// The policy in force, over a span with no expiry in it — a
			// settle pass, or a retry: every answer is the one it gives now.
			continue
		}
		principals := pr.Policy.Principals()
		if len(held) > 0 {
			principals = append(slices.Clone(principals), held...)
			sort.Strings(principals)
			principals = slices.Compact(principals)
		}
		for _, principal := range principals {
			if err := ctx.Err(); err != nil {
				return err
			}
			m, err := memberOf(principal)
			if err != nil {
				return err
			}
			for _, name := range names {
				d, known := pr.Policy.Device(name)
				if !known {
					continue // the prior did not know it, so it minted nothing for it
				}
				for _, at := range instants {
					was, ok := mintedFor(pr.Policy, m, d, at, b.MaxSessionAge)
					if !ok {
						continue // nothing was minted then, so nothing is superseded
					}
					is, computed := current[[2]string{principal, name}]
					if !computed {
						// A device the inventory in force no longer names mints
						// nothing now, so every token for it is superseded.
						if nd, ok := cur.Device(name); ok {
							is.m, is.ok = mintedFor(cur, m, nd, now, b.MaxSessionAge)
						}
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
		b.supersede(ctx, k, b.Now())
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
// Nor does one principal's lookup failing for any reason but the store being
// unavailable: it is said, counted failed and left for the next pass, and the
// pass returns ErrPrincipalUnvisited, an ErrConflict, so it is not taken as
// complete (re-review r-m1).
//
// What it left is returned by what a start does with it (RefreshAtStart):
// ErrPrincipalUnvisited over a context still changing, and that over
// ErrLeftUnderUnheldKey, whatever order the pass met them in.
func (b *Broker) refreshContexts(ctx context.Context, cur *policy.Policy, priors []Prior, now time.Time,
	rep *RefreshReport, sameSource bool, judge passJudge) error {
	principals, err := b.Store.ActivePrincipals(ctx)
	if err != nil {
		return err
	}
	quarantined := map[string]bool{} // the ctx_ids this pass left for a quarantine
	unvisited := false               // a principal whose contexts this pass could not look up
	var busy, unheld error
	for _, principal := range principals {
		if err := ctx.Err(); err != nil {
			return err
		}
		refs, err := b.Store.ContextsByPrincipal(ctx, principal)
		switch {
		case errors.Is(err, store.ErrUnavailable), errors.Is(err, context.Canceled),
			errors.Is(err, context.DeadlineExceeded):
			return err
		case err != nil:
			// One principal's lookup failing for any other reason (a
			// record a store writer planted) must not leave every
			// principal after it on the superseded policy: said, counted
			// failed, and left for the next pass (final review I-1).
			log.Printf("broker: refresh: the contexts of %q could not be looked up (%v); left for the next pass",
				principal, err)
			b.count(rep, "failed")
			unvisited = true
			continue
		}
		m, stamp, jerr := judge.member(ctx, principal)
		switch {
		case errors.Is(jerr, directory.ErrUnavailable), errors.Is(jerr, context.DeadlineExceeded):
			if err := ctx.Err(); err != nil {
				return err // the pass's own deadline or cancel: not the directory's silence
			}
			// The directory did not answer for this principal: its contexts
			// are left as they are and unstamped, and context_stale takes
			// over at the ceiling (Ruling 12).
			rep.UnverifiedPrincipals++
			for _, ref := range refs {
				b.count(rep, "unverified")
				rep.Unverified++
				if c, err := b.Store.GetContext(ctx, store.ContextKey{NAS: ref.NAS, Username: ref.Username}); err == nil &&
					(rep.OldestUnverified.IsZero() || c.RefreshedAt.Before(rep.OldestUnverified)) {
					rep.OldestUnverified = c.RefreshedAt
				}
			}
			continue
		case errors.Is(jerr, directory.ErrUnmapped), errors.Is(jerr, directory.ErrAmbiguous),
			errors.Is(jerr, directory.ErrUsernameTaken):
			// The directory answered no: every context of the principal is
			// revoked under that reason, and its tokens superseded.
			for _, ref := range refs {
				if err := b.revokeFor(ctx, principal, ref, refusalReason(jerr), now, rep); err != nil {
					return err
				}
			}
			rep.Narrowed = append(rep.Narrowed, principal)
			continue
		case jerr != nil:
			return jerr
		}
		pol, release := cur, func() {}
		if judge.hold != nil {
			pol, release = judge.hold()
		}
		for _, ref := range refs {
			_, err := b.refreshContext(ctx, pol, priors, now, m, ref, rep, quarantined, sameSource, stamp)
			switch {
			case errors.Is(err, ErrLeftUnderUnheldKey):
				unheld = err
			case errors.Is(err, store.ErrConflict):
				if busy == nil {
					busy = err
				}
			case err != nil:
				release()
				return err
			}
		}
		release()
	}
	// Every live context was visited, so a quarantine this pass did not see
	// is over, or its context is: forget it, and a context quarantined again
	// later is recorded again. A principal left unvisited may hold one still.
	if unvisited {
		return ErrPrincipalUnvisited
	}
	b.mu.Lock()
	for id := range b.quarantineRecorded {
		if !quarantined[id] {
			delete(b.quarantineRecorded, id)
		}
	}
	b.mu.Unlock()
	if busy != nil {
		return busy
	}
	return unheld
}

// refreshContext re-resolves one context and writes the answer, reading again
// and deciding again when a write landed between its read and its own, up to
// store.MaxJoinAttempts times. quarantined collects the ctx_ids the pass
// leaves for a quarantine. sameSource is an inventory-only swap (Refresh).
// outcome is what it counted the context, "skipped" for one it left without
// judging (gone, another principal's, the lab's, or revoked already), and ""
// with a store error.
func (b *Broker) refreshContext(ctx context.Context, cur *policy.Policy, priors []Prior, now time.Time,
	m policy.Member, ref store.ContextRef, rep *RefreshReport, quarantined map[string]bool,
	sameSource bool, stamp time.Time) (outcome string, err error) {
	principal := m.Principal
	k := store.ContextKey{NAS: ref.NAS, Username: ref.Username}
	known, plat := knownPlatform(cur, priors, ref.NAS)
	for attempt := 0; attempt < store.MaxJoinAttempts; attempt++ {
		c, err := b.Store.GetContext(ctx, k)
		var unreadable *store.UnreadableContextError
		switch {
		case errors.Is(err, store.ErrNotFound):
			return "skipped", nil // the index outlived the context; its own TTL reclaims it
		case errors.As(err, &unreadable):
			outcome, err := b.revokeUnopened(ctx, cur, priors, now, "indexed under "+principal, ref, unreadable, rep)
			if errors.Is(err, errReadAgain) {
				continue
			}
			if errors.Is(err, errKeyNotHeld) {
				log.Printf("broker: refresh: the context for %q on %q, indexed under %s: %v; left for the next pass",
					ref.Username, ref.NAS, principal, err)
				b.count(rep, "failed")
				return "failed", ErrLeftUnderUnheldKey
			}
			return outcome, err
		case err != nil:
			return "", err
		}
		// Another principal's since the index was read (its own pass reaches
		// it), the lab's instrument's (no blob; it answers from config), or
		// revoked already (a refresh never lifts a mark, store.Store).
		if c.Principal != principal || c.BlobHash == "" || !c.RevokedAt.IsZero() {
			return "skipped", nil
		}
		step := b.decideRefresh(cur, now, m, ref, c)
		step.sessionOnly = sessionOnly(known, plat)
		if step.rec.Session != nil { // an unchanged step carries no record (pre-flight I13)
			step.rec.Session.Unreached = step.sessionOnly
		}
		if step.rec.Device != nil && step.rec.Device.Platform == "" {
			step.rec.Device.Platform = plat
		}
		if sameSource && step.write != nil && step.rec.Session.PrivilegeClamped == nil && !step.shortens &&
			step.write.MaxPrivilege == c.MaxPrivilege && step.write.Enable == c.Enable &&
			b.sameButBundle(ctx, c.BlobHash, step.write.BlobHash, step.body) {
			// An inventory-only swap that left this context's answer as it
			// was: nothing is written and nothing recorded, and it goes on
			// naming the bundle that compiled it, which is still true.
			switch err := b.stamp(ctx, k, c.PolicyRev, stamp); {
			case errors.Is(err, store.ErrConflict):
				continue
			case errors.Is(err, store.ErrNotFound):
				return "skipped", nil
			case err != nil:
				return "", err
			}
			b.count(rep, "unchanged")
			return "unchanged", nil
		}
		switch {
		case step.revoke:
			rep.Narrowed = append(rep.Narrowed, principal)
			return b.revoke(ctx, k, c.Rev, now, step, rep)
		case step.outcome == "quarantined":
			quarantined[c.CtxID] = true
			if b.quarantineUnrecorded(c.CtxID, cur.Bundle) {
				b.emitTo(b.passLog(rep), step.rec)
			}
			b.count(rep, step.outcome)
			return step.outcome, nil
		case step.write == nil:
			if step.outcome == "unchanged" {
				switch err := b.stamp(ctx, k, c.PolicyRev, stamp); {
				case errors.Is(err, store.ErrConflict):
					continue
				case errors.Is(err, store.ErrNotFound):
					return "skipped", nil
				case err != nil:
					return "", err
				}
			}
			b.count(rep, step.outcome)
			return step.outcome, nil
		}
		step.write.RefreshedAt = stamp
		// The blob is in the store before any context names it: the
		// daemon's next command reads it by that name. It is kept as long
		// as the context can live, as at mint: an idle context outliving
		// its blob would be denied blob_unavailable for nothing (final
		// review M-4).
		ttl := blobTTL(max(step.age, b.ContextIdleTTL), b.MaxSessionAge)
		// Its blob record reaches the log before this context is written,
		// except under a session refresh, which buffers it ahead of this
		// context's record and writes both once it lets go of the policy
		// (plan 7e, Ruling 10). A port49d that dies between this context's
		// write and that flush leaves a context naming a blob its log never
		// carried. Nothing running misreads that: the daemon reads the
		// store, and replay holds a record until its blob appears. The gap
		// closes on the hash's next use, since the hash is marked emitted
		// only when its record lands (blobLanded), so the next mint or
		// refresh that writes it writes its record again.
		if rep.log != nil {
			err = b.putBlob(ctx, rep.log, step.write.BlobHash, step.body, ttl)
		} else {
			one := newHeldLog()
			err = b.putBlob(ctx, one, step.write.BlobHash, step.body, ttl)
			one.Flush(b.Log, b.blobLanded)
		}
		if err != nil {
			return "", err
		}
		switch err := b.Store.SetContextPolicy(ctx, k, c.PolicyRev, *step.write); {
		case errors.Is(err, store.ErrConflict):
			continue
		case errors.Is(err, store.ErrNotFound):
			return "skipped", nil
		case err != nil:
			return "", err
		}
		rep.Narrowed = append(rep.Narrowed, principal)
		b.emitTo(b.passLog(rep), step.rec)
		b.count(rep, step.outcome)
		b.unreached(step, rep)
		return step.outcome, nil
	}
	// Still changing after every attempt: a login or a privilege change
	// landing between every read and its write. A revocation never gets here
	// (it does not compare), so this context keeps a policy the one in force
	// would widen or narrow, and is left for the retry.
	next := "left for the retry"
	if rep.session {
		next = "not extended; run 'port49 refresh' again"
	}
	log.Printf("broker: refresh: the context for %q on %q was still changing after %d attempts; %s",
		ref.Username, ref.NAS, store.MaxJoinAttempts, next)
	b.count(rep, "failed")
	return "failed", fmt.Errorf("the context for %q on %q was still changing after %d attempts: %w", ref.Username,
		ref.NAS, store.MaxJoinAttempts, store.ErrConflict)
}

// stamp is StampRefreshed for a pass that verified the directory; a zero at
// stamps nothing.
func (b *Broker) stamp(ctx context.Context, k store.ContextKey, policyRev uint64, at time.Time) error {
	if at.IsZero() {
		return nil
	}
	return b.Store.StampRefreshed(ctx, k, policyRev, at)
}

// revokeFor revokes one context of principal under reason, as a refresh's
// revoking step does: the directory answered no for the principal, so none
// of its contexts stands. A context gone, revoked already, or another
// principal's now is left.
func (b *Broker) revokeFor(ctx context.Context, principal string, ref store.ContextRef, reason decision.Reason,
	now time.Time, rep *RefreshReport) error {
	k := store.ContextKey{NAS: ref.NAS, Username: ref.Username}
	c, err := b.Store.GetContext(ctx, k)
	var unreadable *store.UnreadableContextError
	switch {
	case errors.Is(err, store.ErrNotFound), errors.As(err, &unreadable):
		return nil // gone, or unopenable: its own judgment revokes it
	case err != nil:
		return err
	case c.Principal != principal || !c.RevokedAt.IsZero():
		return nil
	}
	rec := decision.Record{TS: now, Event: decision.EventRefresh, Verdict: decision.VerdictDeny, Reason: reason,
		Principal: principal, Device: &decision.Device{Name: ref.NAS},
		Session: &decision.Session{CtxID: c.CtxID, Username: c.Username, Privilege: c.PrivLvl}}
	_, err = b.revoke(ctx, k, c.Rev, now, refreshStep{revoke: true, rec: rec, outcome: "revoked"}, rep)
	return err
}

// refusalReason is the reason a directory refusal is recorded under.
func refusalReason(err error) decision.Reason {
	switch {
	case errors.Is(err, directory.ErrAmbiguous):
		return decision.IdentityAmbiguous
	case errors.Is(err, directory.ErrUsernameTaken):
		return decision.UsernameCollision
	}
	return decision.IdentityUnmapped
}

// passJudge is how a pass learns each principal's member, and under which
// policy it judges it.
type passJudge struct {
	// member is principal's member and the stamp's time; a zero time stamps nothing.
	member func(ctx context.Context, principal string) (policy.Member, time.Time, error)
	// hold, when set, is the policy each principal is judged under: taken
	// after member answers, released once that principal's contexts are
	// written (pre-flight I-11). Unset, cur judges every principal.
	hold func() (*policy.Policy, func())
}

// storedJudge is a policy pass's member: the stored membership, no stamp.
func (b *Broker) storedJudge(ctx context.Context, principal string) (policy.Member, time.Time, error) {
	m, err := b.storedMember(ctx, principal)
	if err != nil {
		// A store read failing is a failed pass, never the directory's
		// silence: the chain is cut so no deadline reads as unverified.
		return policy.Member{}, time.Time{}, fmt.Errorf("reading the stored membership of %s: %v", principal, err)
	}
	return m, time.Time{}, nil
}

// storedMember is the membership a policy pass judges principal by: the
// store's, if it is unrefused and verified within directory.grace; else no
// groups (Ruling 12; pre-flight I-14). A machine principal is MemberOf.
func (b *Broker) storedMember(ctx context.Context, principal string) (policy.Member, error) {
	if b.Directory == nil || !directory.IsUser(principal) {
		return policy.MemberOf(principal), nil // a machine principal has no entry (pre-flight I-10)
	}
	sm, ok, err := b.Directory.Stored(ctx, principal)
	switch {
	case err != nil:
		return policy.Member{}, err
	case !ok, sm.Refused:
		// None stored, or the directory's refusal: no groups and no username,
		// so nothing the principal holds stands (pre-flight C-1).
		return policy.Member{Principal: principal, Directory: true}, nil
	case b.Now().Sub(sm.VerifiedAt) > b.Directory.Cfg.Grace:
		// Older than grace: no groups, which can only narrow. A reload during
		// a long outage never widens a context on a membership nobody has
		// verified for longer than grace (pre-flight I-14), but the username
		// it last verified still keys the principal's contexts, so an
		// outage revokes none (spec §5.1.3; context_stale takes over).
		return policy.Member{Principal: principal, Directory: true, Username: sm.Username}, nil
	}
	return member(directory.Answer{Membership: sm}), nil
}

// sameButBundle reports whether the blob a context names is the new one but
// for the bundle, read from the store. A blob the store cannot give is not:
// the context takes the new one, failing toward the write.
func (b *Broker) sameButBundle(ctx context.Context, oldHash, newHash string, newBody []byte) bool {
	raw, err := b.Store.GetBlob(ctx, oldHash)
	if err != nil {
		return false
	}
	old, err := engine.Decode(oldHash, raw)
	if err != nil {
		return false
	}
	nb, err := engine.Decode(newHash, newBody)
	if err != nil {
		return false
	}
	old.Bundle = nb.Bundle
	_, h, err := engine.Encode(old)
	return err == nil && h == newHash
}

// knownPlatform is a device's platform, and the policy that names it: the
// policy in force, or, for a device its inventory no longer names, the latest
// prior that did (Task 11 M3). A context on a device an inventory reload
// removed is then judged reached or not by what the device was, not counted
// out of reach for want of a platform; one no policy names is (cur, "").
func knownPlatform(cur *policy.Policy, priors []Prior, name string) (*policy.Policy, string) {
	if d, ok := cur.Device(name); ok {
		return cur, d.Platform
	}
	for i := len(priors) - 1; i >= 0; i-- {
		if d, ok := priors[i].Policy.Device(name); ok {
			return priors[i].Policy, d.Platform
		}
	}
	return cur, ""
}

// revokeUnopened revokes a context that will not open, found by via (the
// index entry that led here, or the re-index), and records and counts it
// failed. One revoked already is "skipped": a refresh never lifts a mark.
//
// Sealed under a key that has left the two-key window, or failing
// authentication: whose it is and what it holds cannot be read, so it
// cannot be judged against the policy in force, and it is not left on the
// one before. It is revoked, as a compile fault is; the authorizer cannot
// open it either, and the next login replaces it. The record names what is
// authoritative, the device and the username the key holds, and no
// principal: the index entry that led here may be one another principal's
// login has made stale, and whose the record is, is sealed.
//
// Sealed under a key this port49d does not hold (crypt.ErrUnknownKey), it
// is not revoked: that is a mis-set or rotated-out PORT49_ENC_V1, and
// revoking would end every session on the fleet for a key mistake that
// fixing the key undoes (crypt.openErr; final review I-2). It returns
// errKeyNotHeld, and the caller says it, counts it a failure and leaves it
// for the next pass. No login can open it meanwhile, so it is denied
// anyway. One that fails authentication, or opens and is sealed below the
// newest write known at its key (crypt.ErrNotLastWritten), is tampered,
// and revoked.
// The ledger's denial is read once more first: revoked only when the read
// again is still denied at the same revision, since one the store now
// answers, or holds at another, raced a write of its own and is
// errReadAgain, for the caller to judge afresh (Task 13b review I-1). A
// record put back, or restored under a running port49d, is still denied
// there, and revoked (Ruling T13b-a).
func (b *Broker) revokeUnopened(ctx context.Context, cur *policy.Policy, priors []Prior, now time.Time, via string,
	ref store.ContextRef, unreadable *store.UnreadableContextError, rep *RefreshReport) (string, error) {
	if !unreadable.RevokedAt.IsZero() {
		return "skipped", nil
	}
	if errors.Is(unreadable, crypt.ErrUnknownKey) {
		return "", fmt.Errorf("%w (%v)", errKeyNotHeld, unreadable)
	}
	if errors.Is(unreadable, crypt.ErrNotLastWritten) {
		var again *store.UnreadableContextError
		switch _, err := b.Store.GetContext(ctx, store.ContextKey{NAS: ref.NAS, Username: ref.Username}); {
		case errors.As(err, &again) && errors.Is(again, crypt.ErrNotLastWritten) && again.Rev == unreadable.Rev:
		case errors.Is(err, store.ErrNotFound):
			return "skipped", nil
		case err == nil, errors.As(err, &again):
			return "", errReadAgain
		default:
			return "", err
		}
	}
	known, plat := knownPlatform(cur, priors, ref.NAS)
	log.Printf("broker: refresh: the context for %q on %q, %s, will not open (%v); revoking it",
		ref.Username, ref.NAS, via, unreadable)
	rec := decision.Record{TS: now, Event: decision.EventRefresh, Verdict: decision.VerdictDeny,
		Reason:  decision.BlobUnavailable,
		Device:  &decision.Device{Name: ref.NAS, Platform: plat},
		Session: &decision.Session{Username: ref.Username, Unreached: sessionOnly(known, plat)},
		Policy:  &decision.Policy{Bundle: cur.Bundle}}
	step := refreshStep{revoke: true, rec: rec, outcome: "failed", sessionOnly: sessionOnly(known, plat)}
	return b.revoke(ctx, store.ContextKey{NAS: ref.NAS, Username: ref.Username}, unreadable.Rev, now, step, rep)
}

// errReadAgain is a context the ledger denied that revokeUnopened, reading
// it again, found written since: a read that raced a write, judged afresh.
var errReadAgain = fmt.Errorf("broker: the context was written again since it was read: %w", store.ErrConflict)

// errKeyNotHeld is a context revokeUnopened left because it is sealed under
// a key this port49d does not hold.
var errKeyNotHeld = errors.New("broker: sealed under a key this port49d does not hold; not revoked")

// ErrLeftUnderUnheldKey and ErrPrincipalUnvisited are what a pass left
// unjudged. Each is store.ErrConflict, as a busy context is: the pass goes
// on, the tokens are still superseded, and Refresh returns it, so port49d
// keeps port49_policy_refresh_pending at 1 and runs the pass again, never
// taking the pass for one that reached every live context (re-review r-m1).
var (
	ErrLeftUnderUnheldKey = fmt.Errorf("broker: a context under an unheld key was left unjudged: %w", store.ErrConflict)
	ErrPrincipalUnvisited = fmt.Errorf("broker: a principal could not be looked up, so its contexts were left "+
		"unjudged: %w", store.ErrConflict)
)

// revoke marks the context revoked at at through SetRevokedAt, the setter that
// writes the mark alone and keeps the later of two, and records and counts it.
// It does not compare: a revocation is right whoever the record belongs to by
// now, at the worst revoking a login another principal made a moment ago,
// whose owner logs in again (fail closed). It returns the step's outcome, or
// "skipped" for a context already gone. One the store cannot revoke is
// deleted at rev, the revision it was read at (revokeOrDelete).
func (b *Broker) revoke(ctx context.Context, k store.ContextKey, rev uint64, at time.Time, step refreshStep,
	rep *RefreshReport) (string, error) {
	switch gone, err := b.revokeOrDelete(ctx, k, rev, at); {
	case err != nil:
		return "", err
	case gone:
		return "skipped", nil
	}
	b.emitTo(b.passLog(rep), step.rec)
	b.count(rep, step.outcome)
	b.unreached(step, rep)
	return step.outcome, nil
}

// revokeOrDelete marks the context at k revoked at at, which needs no key.
// One the store cannot mark because it does not decode (an etcd record a
// store writer garbled) is deleted at rev, the revision it was read at:
// nothing can use it, and left in place it would stop every refresh pass
// that reaches it, for every principal after it (Task 7 review K-1; Task
// 7b review I-1). gone reports one gone already, or written again since
// that read, which the next pass reads afresh.
func (b *Broker) revokeOrDelete(ctx context.Context, k store.ContextKey, rev uint64, at time.Time) (gone bool,
	err error) {
	var bad *store.UnreadableContextError
	switch err := b.Store.SetRevokedAt(ctx, k, at); {
	case errors.Is(err, store.ErrNotFound):
		return true, nil
	case errors.As(err, &bad):
		switch err := b.Store.DeleteContextIf(ctx, k, rev); {
		case errors.Is(err, store.ErrNotFound), errors.Is(err, store.ErrConflict):
			return true, nil
		case err != nil:
			return false, err
		}
		log.Printf("broker: the context for %q on %q could not be revoked (%v); deleted it at the revision read",
			k.Username, k.NAS, bad)
		return false, nil
	case err != nil:
		return false, err
	}
	return false, nil
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
	if step.rec.Device.Platform == "" {
		// A device the inventory in force no longer names, or names with no
		// platform: its live session is assumed out of reach, as the
		// operator must hear for one that is.
		log.Printf("broker: refresh: the context on %q (%s) was %s, but the inventory in force gives the device "+
			"no platform, so whether it authorizes commands is not known: its live session may keep what it had "+
			"at login until logout (spec §13 decision 21)", step.rec.Device.Name, which, step.outcome)
		return
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
	// age is the policy in force's ceiling for the context, zero for never,
	// and shortens is that ceiling moving the context's earlier.
	age      time.Duration
	shortens bool
}

// decideRefresh is what the policy in force says about principal on the
// context's device now. It reads no store.
func (b *Broker) decideRefresh(cur *policy.Policy, now time.Time, m policy.Member, ref store.ContextRef,
	c store.Context) refreshStep {
	principal := m.Principal
	rec := decision.Record{TS: now, Event: decision.EventRefresh, Principal: principal,
		Device:  &decision.Device{Name: ref.NAS},
		Session: &decision.Session{CtxID: c.CtxID, Username: c.Username, Privilege: c.PrivLvl},
		Policy:  &decision.Policy{Bundle: cur.Bundle}}
	rec.Policy.Subject, rec.Policy.Subjects = subjectNames(cur, m)
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
	dev, ok := cur.Device(ref.NAS)
	if !ok {
		// A context on a device the inventory in force no longer names:
		// nothing can be minted for it, so it is revoked (plan 4b's hand-off:
		// a device leaving inventory is a narrowing like any other).
		return revoke()
	}
	rec.Device.Platform = dev.Platform
	res, err := resolveFor(cur, m, dev, now)
	if err == nil {
		rec.Policy.Grants = res.Grants
	}
	switch {
	case errors.Is(err, policy.ErrNoGrants):
		return revoke()
	case errors.Is(err, policy.ErrDeviceQuarantined):
		rec.Verdict, rec.Reason = decision.VerdictDeny, decision.DeviceQuarantined
		return refreshStep{rec: rec, outcome: "quarantined"}
	case errors.Is(err, policy.ErrDeviceRefused):
		// Not live (spec §5.7, device_unknown): the device cannot reach
		// port49d, so the context is revoked as for a removed device.
		rec.Verdict, rec.Reason = decision.VerdictDeny, decision.DeviceUnknown
		return refreshStep{revoke: true, rec: rec, outcome: "revoked"}
	case errors.Is(err, policy.ErrNoUsername):
		// The directory gave this principal no username (none stored, or the
		// membership is refused or past grace): the context is revoked, as a
		// mint would refuse it (spec §2, decision 38).
		rec.Policy.Grants = nil
		rec.Verdict, rec.Reason = decision.VerdictDeny, decision.IdentityUnmapped
		return refreshStep{revoke: true, rec: rec, outcome: "revoked"}
	case errors.Is(err, policy.ErrCompositionRefused):
		b.logf("broker: refresh: %v; revoking the context (ctx_id %s)", err, c.CtxID)
		rec.Verdict, rec.Reason = decision.VerdictDeny, decision.CompositionRefused
		return refreshStep{revoke: true, rec: rec, outcome: "revoked"}
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
	// shortens is a ceiling the policy in force puts earlier than the
	// context's, or on a context with none: a policy edit shortens a live
	// session, and only a fresh authentication lengthens one (decision 33).
	// A context with no AuthTime is written too, and the store gives it a
	// ceiling in the distant past, failing it closed (store.ContextPolicy).
	age := res.SessionAge.Of(b.MaxSessionAge)
	shortens := age > 0 && (c.SessionExpires.IsZero() || c.AuthTime.Add(age).Before(c.SessionExpires))
	if hash == c.BlobHash && res.MaxPrivilege == c.MaxPrivilege && res.Enable == c.Enable && !clamp && !shortens {
		return refreshStep{outcome: "unchanged", age: age}
	}
	rec.Verdict, rec.Reason, rec.Policy.Blob = decision.VerdictPermit, decision.GrantsMatched, hash
	if clamp {
		rec.Session.PrivilegeClamped = &decision.PrivilegeClamp{From: c.PrivLvl, To: res.MaxPrivilege}
		rec.Session.Privilege = res.MaxPrivilege
	}
	if shortens {
		rec.Session.SessionExpires = decision.FormatTime(c.AuthTime.Add(age))
	}
	return refreshStep{write: &store.ContextPolicy{BlobHash: hash, MaxPrivilege: res.MaxPrivilege, Enable: res.Enable,
		MaxSessionAge: age}, body: body, rec: rec, outcome: "updated", age: age, shortens: shortens}
}

// count adds one context to the report, and to the policy refresh's metric
// unless the judgment is a session refresh's.
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
	// "unverified" is counted by its caller in the report's own fields.
	if !rep.session {
		b.Metrics.ContextRefreshes.WithLabelValues(outcome).Inc()
	}
}

// resolveFor is how the refresh resolves a context's principal, swapped in
// tests to stand in for a composition the load never compiled.
var resolveFor = (*policy.Policy).ResolveMember

// mintedFor is mintedBy for the token scan, swapped in tests to count what it
// compiles.
var mintedFor = mintedBy
