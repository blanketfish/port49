package broker

import (
	"context"
	"errors"
	"slices"

	"github.com/rhwendt/port49/internal/policy"
	"github.com/rhwendt/port49/internal/store"
)

// ReindexContexts is what port49d does with the contexts
// (*etcd.Store).Unindexed names (plan 7d; Ruling 6; re-check IA2): each
// one that opens and whose index record does not list its own principal
// and certificate, read sealed, or lists no sid while it has one, is
// indexed again under its own principal, sid and certificate, and judged
// at once against the policy in force, since a refresh that ran while it
// was hidden never reached it. A record rewritten to list another
// principal hides the context as a deleted one does, so the compare is
// with the sealed principal, never with any principal listed (re-check
// I2). A sid is compared only by its absence: a session refresh rotates
// the sid in the index and not on the record (session.Manager.Refresh).
//
// One that will not open, and that no live principal lists, cannot be
// indexed, and no refresh would visit it, so it is revoked, which needs no
// key; one the store cannot revoke because it does not decode is deleted
// at its own revision, since nothing can use it (Task 7 review K-1). One
// listed live is left to the refresh, which revokes it. One gone since the
// scan is skipped. Each re-indexed or revoked is counted
// (port49_contexts_reindexed_total), and the total said: any is an index
// record deleted or rewritten in the store.
//
// One context that fails is said, by its device and username alone, and
// counted (port49_contexts_reindex_failures_total), and the pass goes on:
// one bad record must not stop the start or the re-index of every other
// (re-check I3). It returns how many it found, and the store being
// unavailable or ctx ending, for the caller to run it again.
func (b *Broker) ReindexContexts(ctx context.Context, refs []store.IndexedRef) (int, error) {
	if b.Sessions == nil {
		return 0, errors.New("broker: revocation is not wired (no session manager); the unindexed contexts were not re-indexed")
	}
	var rep RefreshReport
	rep.At = b.Now()
	cur := b.Policy.Load()
	n := 0
	defer func() {
		if n > 0 {
			b.logf("broker: %d live context(s) were missing from the index (an index record deleted or rewritten "+
				"in the store?); re-indexed and judged against the policy in force, or revoked when they would not open", n)
		}
	}()
	for _, r := range refs {
		if err := ctx.Err(); err != nil {
			return n, err
		}
		found, err := b.reindexContext(ctx, cur, r, &rep)
		if found {
			n++
			b.Metrics.ContextsReindexed.Inc()
		}
		switch {
		case errors.Is(err, store.ErrUnavailable), errors.Is(err, context.Canceled),
			errors.Is(err, context.DeadlineExceeded):
			return n, err
		case err != nil:
			b.logf("broker: re-index: the context for %q on %q: %v; left for the next pass", r.Username, r.NAS, err)
			b.Metrics.ContextsReindexFailures.Inc()
		}
	}
	return n, nil
}

// reindexContext is ReindexContexts for one ref: found reports a context
// it re-indexed or revoked, and is true with the error of a judging that
// failed after the re-index landed. A judging that lost every race is no
// failure: the context is indexed now, so the next refresh reaches it.
func (b *Broker) reindexContext(ctx context.Context, cur *policy.Policy, r store.IndexedRef,
	rep *RefreshReport) (found bool, err error) {
	k := store.ContextKey{NAS: r.NAS, Username: r.Username}
	c, err := b.Store.GetContext(ctx, k)
	var unreadable *store.UnreadableContextError
	switch {
	case errors.Is(err, store.ErrNotFound):
		return false, nil
	case errors.As(err, &unreadable):
		if len(r.Principals) > 0 || !unreadable.RevokedAt.IsZero() {
			return false, nil // the refresh reaches it, or it is revoked already
		}
		var bad *store.UnreadableContextError
		switch err := b.Store.SetRevokedAt(ctx, k, rep.At); {
		case errors.As(err, &bad):
			if err := b.Store.DeleteContextIf(ctx, k, unreadable.Rev); err != nil &&
				!errors.Is(err, store.ErrNotFound) {
				return false, err
			}
		case err != nil && !errors.Is(err, store.ErrNotFound):
			return false, err
		}
		return true, nil
	case err != nil:
		return false, err
	}
	ck := store.CertKey(c.Credential.Issuer, c.Credential.Serial)
	if slices.Contains(r.Principals, c.Principal) && (c.Credential.Sid == "" || len(r.Sids) > 0) &&
		(store.BlankCertKey(ck) || slices.Contains(r.Certs, ck)) {
		return false, nil
	}
	if err := b.Sessions.Reindex(ctx, r.ContextRef, c); err != nil {
		return false, err
	}
	if _, err := b.refreshContext(ctx, cur, nil, rep.At, c.Principal, r.ContextRef, rep, map[string]bool{},
		false); err != nil && !errors.Is(err, store.ErrConflict) {
		return true, err
	}
	return true, nil
}
