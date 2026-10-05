package broker

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/rhwendt/port49/internal/directory"
	"github.com/rhwendt/port49/internal/policy"
	"github.com/rhwendt/port49/internal/store"
)

// RefreshDirectory is the scheduled refresh (spec §5.1.3; plan 7g Ruling
// 12): every principal in active_principals verified against the
// directory, from a server and never from grace, its contexts judged on
// that membership and stamped with its verification time. A principal the
// directory does not answer for is left and unstamped; its contexts
// deny context_stale past session.staleness_ceiling. A machine principal,
// and every principal without a directory, is judged on the policy alone
// and stamped with the pass's instant.
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
	judge := passJudge{
		member: func(ctx context.Context, principal string) (policy.Member, time.Time, error) {
			if b.Directory == nil || !directory.IsUser(principal) {
				return policy.MemberOf(principal), rep.At, nil
			}
			a, err := b.Directory.Verify(ctx, principal)
			if err != nil {
				return policy.Member{}, time.Time{}, err
			}
			// A declaration made by a reload since the answer was written is
			// the resolver's collision too (pre-flight M-11).
			if who, ok := b.Directory.DeclaredBy(a.Username); ok {
				return policy.Member{}, time.Time{}, fmt.Errorf("%w: the directory derives username %q for %s, "+
					"which subject %q declares", directory.ErrUsernameTaken, a.Username, principal, who)
			}
			return member(a), a.VerifiedAt, nil
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
	err := b.refreshContexts(ctx, b.Policy.Load(), nil, rep.At, &rep, false, judge)
	if err != nil && !errors.Is(err, store.ErrConflict) {
		// A conflict (a busy context, an unvisited principal, an unheld
		// key) is left for the next pass; the rest ends this one.
		err = fmt.Errorf("the scheduled refresh: %w", err)
	}
	// Tokens are superseded whatever ended the pass: a context already
	// written narrower is unchanged at the next pass, which would never name
	// its principal again.
	if serr := b.supersedeNarrowed(ctx, &rep); serr != nil && err == nil {
		err = fmt.Errorf("deleting superseded tokens: %w", serr)
	}
	if rep.UnverifiedPrincipals == 0 && err == nil {
		b.Metrics.DirectoryRefreshLastComplete.Set(float64(rep.At.Unix()))
	}
	if rep.UnverifiedPrincipals > 0 {
		b.sayOnce("refresh-unverified", time.Hour, "broker: refresh: the directory did not answer for %d principals; "+
			"their %d contexts keep their last verification (oldest %s ago) and deny context_stale past port49d's "+
			"session.staleness_ceiling", rep.UnverifiedPrincipals, rep.Unverified,
			rep.At.Sub(rep.OldestUnverified).Round(time.Minute))
	}
	return rep, err
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
