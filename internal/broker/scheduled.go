package broker

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/blanketfish/port49/internal/directory"
	"github.com/blanketfish/port49/internal/policy"
	"github.com/blanketfish/port49/internal/printsafe"
	"github.com/blanketfish/port49/internal/store"
)

// RefreshDirectory is the scheduled refresh (spec §5.1.3; plan 7g Ruling
// 12): every principal in active_principals verified against the
// directory, from a server and never from grace, its contexts judged on
// that membership and stamped with its verification time. A principal the
// directory does not answer for is left and unstamped; its contexts
// deny context_stale past session.staleness_ceiling. A workload
// under the mapping is verified as a person is (decision 41 ruling 6); any
// other machine principal, and every principal without a directory, is judged
// on the policy alone and stamped with the pass's instant.
//
// Each principal is verified first, with no policy held, then judged and
// written under b.Policy.Hold, so a reload between two principals is the
// policy the next is judged by, and a reload never waits on a directory
// query (pre-flight I-11). Records go to a held log flushed after each
// release, as RefreshSession's do (plan 7e, Ruling 10).
//
// A directory refusal (entry gone, two entries, a username a subject
// declares) revokes the principal's contexts under its reason and is never
// stamped; only the directory's silence (directory.ErrUnavailable, a
// deadline) leaves a context unstamped and unrevoked.
//
// It writes contexts, so it is the runner's alone, as the policy pass's
// context half is (plan 7e, Ruling 6).
func (b *Broker) RefreshDirectory(ctx context.Context) (RefreshReport, error) {
	var rep RefreshReport
	rep.At = b.Now()
	// The series exists from the first pass, at 0 until one verifies every principal, so an alert
	// on its age sees a runner whose passes never complete; a process that runs no pass has none.
	b.Metrics.DirectoryRefreshLastComplete.WithLabelValues()
	var first error // the first principal the directory failed for in a way that is no outage and no refusal
	judge := passJudge{
		member: func(ctx context.Context, principal string) (policy.Member, time.Time, error) {
			switch {
			case b.Directory != nil && directory.IsUser(principal):
				a, err := b.Directory.Verify(ctx, principal)
				if err != nil {
					return policy.Member{}, time.Time{}, b.verifyFailed(ctx, principal, err, &first)
				}
				// A declaration made by a reload since the answer was written is
				// the resolver's collision too (pre-flight M-11).
				if who, ok := b.Directory.DeclaredBy(a.Username); ok {
					return policy.Member{}, time.Time{}, fmt.Errorf("%w: the directory derives username %q for %s, "+
						"which subject %q declares", directory.ErrUsernameTaken, a.Username, principal, who)
				}
				return member(a), a.VerifiedAt, nil
			case b.workloadMapped(principal):
				// A mapped workload is verified and stamped as a person is
				// (decision 41 ruling 6); its username is settled under the
				// policy in force.
				a, err := b.Directory.VerifyWorkload(ctx, principal)
				if err != nil {
					return policy.Member{}, time.Time{}, b.verifyFailed(ctx, principal, err, &first)
				}
				m, err := workloadMember(b.Policy.Load(), a)
				if err != nil {
					return policy.Member{}, time.Time{}, err
				}
				return m, a.VerifiedAt, nil
			}
			return policy.MemberOf(principal), rep.At, nil
		},
		hold: func() (*policy.Policy, func()) {
			buf := newHeldLog()
			rep.log = buf
			pol, release := b.Policy.Hold()
			return pol, func() {
				release()
				rep.log = nil
				buf.Flush(b.Log, b.blobLanded)
			}
		},
	}
	// sameSource: this pass is membership and the stamp. A change of policy
	// source is the policy pass's, at the reload; a context differing only in
	// the bundle it names is stamped and left, so an inventory swap is never a
	// fleet-wide rewrite here (plan 6a Decided 3).
	err := b.refreshContexts(ctx, b.Policy.Load(), nil, rep.At, &rep, true, judge)
	if err != nil && !errors.Is(err, store.ErrConflict) {
		// A conflict (a busy context, an unvisited principal, an unheld
		// key) is left for the next pass; the rest ends this one.
		err = fmt.Errorf("the scheduled refresh: %w", err)
	}
	// Tokens are superseded whatever ended the pass: a context already
	// written narrower is unchanged at the next pass, which would never name
	// its principal again.
	if serr := b.supersedeNarrowed(ctx, &rep); serr != nil {
		if err == nil {
			err = fmt.Errorf("deleting superseded tokens: %w", serr)
		} else {
			b.logf("broker: refresh: deleting superseded tokens failed (%v) after the pass ended (%v)", serr, err)
		}
	}
	if err == nil && first != nil {
		err = fmt.Errorf("the scheduled refresh: %w", first)
	}
	if rep.UnverifiedPrincipals == 0 && err == nil {
		b.Metrics.DirectoryRefreshLastComplete.WithLabelValues().Set(float64(rep.At.Unix()))
	}
	if rep.UnverifiedPrincipals > 0 {
		b.sayOnce("refresh-unverified", time.Hour, "broker: refresh: the directory did not answer for %d principals; "+
			"their %d contexts keep their last verification (oldest %s ago) and deny context_stale past port49d's "+
			"session.staleness_ceiling", rep.UnverifiedPrincipals, rep.Unverified,
			rep.At.Sub(rep.OldestUnverified).Round(time.Minute))
	}
	if b.PasswordSignIn != nil {
		b.enrollmentPass(ctx)
	}
	b.pinPass(ctx)
	return rep, err
}

// enrollmentPass is the directory-password sign-in's share of the scheduled
// pass (plan 9e, D7): a look at the enrollment store, which clears or sets its
// lost state, and, the store not lost, the re-seal of what opened under the
// previous encryption key. Neither error fails the pass; each is said once an
// hour.
func (b *Broker) enrollmentPass(ctx context.Context) {
	if err := b.CheckEnrollmentStore(ctx); err != nil {
		b.sayOnce("sign_in_enrollment_check", time.Hour, "sign-in: the enrollment store was not checked: %s; password "+
			"sign-in keeps the state it had, and the next pass looks again", printsafe.Line(err.Error(), 300))
		return
	}
	if b.EnrollmentStoreLost() != "" {
		return
	}
	if _, err := b.ResealSecondFactors(ctx); err != nil {
		b.sayOnce("sign_in_reseal_pass", time.Hour, "sign-in: the re-seal of second factors stopped: %s; the next pass "+
			"starts again", printsafe.Line(err.Error(), 300))
	}
}

// pinResealer is the store whose directory pins the scheduled pass seals
// again: placement's, on a directory store of its own (decision 57).
type pinResealer interface {
	ResealPins(ctx context.Context, unopened func(principal string, err error)) (store.PinReseal, bool, error)
}

// pinLinesNamed is how many unopenable pins one pass names: a lost key
// strands every pin, and the count's line says the rest.
const pinLinesNamed = 20

// pinPass is the directory pins' share of the scheduled pass (decision
// 57): the re-seal, its gauges set from a pass that completed on a store
// that holds pins and left as they were by one that stopped, each line said
// at most once an hour. A shared store keeps no pin without a lease and
// has none of it.
func (b *Broker) pinPass(ctx context.Context) {
	r, ok := b.Store.(pinResealer)
	if !ok {
		return
	}
	named := 0
	rep, held, err := r.ResealPins(ctx, func(principal string, err error) {
		if named++; named > pinLinesNamed {
			return
		}
		b.sayOnce("pin_reseal "+principal, time.Hour, "directory store: %s's pin does not open (%s): it is left as "+
			"it is; put the key that sealed it back as encryption.previous and restart, or run `port49 directory "+
			"forget %s`", printsafe.Line(principal, 300), printsafe.Line(err.Error(), 300), printsafe.Line(principal, 300))
	})
	switch {
	case !held, ctx.Err() != nil:
		return
	case err != nil:
		b.sayOnce("pin_reseal_pass", time.Hour, "directory store: the re-seal of pins stopped: %s; the next pass "+
			"starts again", printsafe.Line(err.Error(), 300))
		return
	}
	b.Metrics.DirectoryPinsSealedPrevious.WithLabelValues().Set(float64(rep.Previous))
	b.Metrics.DirectoryPinsUnopenable.WithLabelValues().Set(float64(rep.Unopened))
	b.Metrics.DirectoryPinsResealLastComplete.WithLabelValues().Set(float64(b.Now().Unix()))
	if rep.Sealed > 0 {
		b.logf("directory store: the re-seal sealed %d pins under the current key; %d are left under "+
			"encryption.previous", rep.Sealed, rep.Previous)
	}
	if rep.Unopened > 0 {
		more := ""
		if n := rep.Unopened - pinLinesNamed; n > 0 {
			more = fmt.Sprintf("; %d more are not named", n)
		}
		b.sayOnce("pin_reseal_unopened", time.Hour, "directory store: %d pins open under neither encryption key; "+
			"their principals cannot bind, mint or refresh until the key is back as encryption.previous or each "+
			"is forgotten%s", rep.Unopened, more)
	}
}

// verifyFailed is how the pass takes a Verify error. A refusal, the pass's
// own cancel or deadline, a store failure and the directory's silence are as
// refreshContexts reads them. Any other error (an LDAP 50 on a protected
// account, a referral, a size limit) is one principal's: it is counted as the
// directory not answering for them, so the pass goes on and every principal
// after is verified and stamped; theirs reaches context_stale at the ceiling
// as in an outage. The first is kept for the pass to return, and it is said
// once an hour per principal, never with a group.
func (b *Broker) verifyFailed(ctx context.Context, principal string, err error, first *error) error {
	switch {
	case errors.Is(err, directory.ErrUnavailable), errors.Is(err, directory.ErrUnmapped),
		errors.Is(err, directory.ErrAmbiguous), errors.Is(err, directory.ErrUsernameTaken),
		errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled),
		errors.Is(err, store.ErrUnavailable), ctx.Err() != nil:
		return err
	}
	if *first == nil {
		*first = fmt.Errorf("verifying %s: %w", principal, err)
	}
	b.sayOnce("refresh-verify:"+principal, time.Hour, "broker: refresh: the directory failed for %s (%s); its "+
		"contexts are left unstamped and unrevoked, and the pass goes on", principal, printsafe.Line(err.Error(), 300))
	return fmt.Errorf("%w: %v", directory.ErrUnavailable, printsafe.Line(err.Error(), 300))
}

// supersedeNarrowed deletes the unspent tokens of every principal the pass
// revoked or changed a context of (pre-flight I-13): a token minted on the
// membership the pass just withdrew must not be redeemable after it. A
// key is cleared whole, as supersedeTokens clears one.
func (b *Broker) supersedeNarrowed(ctx context.Context, rep *RefreshReport) error {
	slices.Sort(rep.Narrowed)
	for _, principal := range slices.Compact(rep.Narrowed) {
		keys, err := b.Store.TokensByPrincipal(ctx, principal)
		if err != nil {
			return err
		}
		for _, k := range keys {
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
	}
	return nil
}
