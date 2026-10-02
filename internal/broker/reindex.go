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
// One that a standing mark revokes (store.Marks) is marked instead of
// judged: the revocation walked the index, and missed it.
//
// One that will not open cannot be indexed, and no refresh may visit it,
// so it is revoked, which needs no key, as the refresh revokes one, with
// its blob_unavailable record; one the store cannot revoke because it does
// not decode is deleted at its own revision, since nothing can use it
// (revokeOrDelete; Task 7 review K-1). One gone since the scan is skipped.
// Each re-indexed or revoked is said by its device and username, and
// counted (port49_contexts_reindexed_total), and the total said: any is
// an index record deleted or rewritten in the store.
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
		// Revoked whether or not a principal lists it: a listing may name
		// only one whose lookup entry is gone, which no refresh walks
		// (Task 7b review m-2), and the refresh would revoke it anyway.
		outcome, err := b.revokeUnopened(ctx, cur, nil, rep.At, "found by the re-index", r.ContextRef, unreadable, rep)
		return outcome != "skipped" && err == nil, err
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
	b.logf("broker: re-index: the context for %q on %q was missing from the index under its own principal, "+
		"certificate or sid; re-indexed", r.Username, r.NAS)
	// A mark set while it was hidden missed it, since a revocation walks
	// the index. The daemon denies by the mark anyway; the record is
	// marked too, so it reads as revoked (Task 7b review m-1).
	if at := b.Marks.RevokedAt(c); c.RevokedAt.IsZero() && !at.IsZero() {
		if _, err := b.revokeOrDelete(ctx, k, c.Rev, at); err != nil {
			return true, err
		}
		b.logf("broker: re-index: the context for %q on %q stands revoked by a mark; marked it", r.Username, r.NAS)
		return true, nil
	}
	if _, err := b.refreshContext(ctx, cur, nil, rep.At, c.Principal, r.ContextRef, rep, map[string]bool{},
		false); err != nil && !errors.Is(err, store.ErrConflict) {
		return true, err
	}
	return true, nil
}
