package broker

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/store"
)

// ownRevokeTries bounds how often a self-revocation reads a context again
// after its compare-and-set lost to another write.
const ownRevokeTries = 3

// RevokeOwn ends principal's own live sessions and deletes its own unspent
// tokens, everywhere or on the one key only names, and leaves no mark:
// nothing stands against principal after it, and a token minted later joins
// the revoked context and lifts it (spec §5.1.4, §5.6; decisions 15, 34).
// It is what a principal may do to itself with no api: right.
//
// It never reaches another principal's, even under a shared (device,
// username): tokens are deleted one by one by ID, only those the caller
// minted (DeleteToken), and a context is marked by compare-and-set on the
// policy revision read, only while it is the caller's (revokeOwnContext).
// As Revoke does, tokens go before contexts and contexts are marked twice,
// so a redemption in flight is caught; then the caller's receipts are
// deleted, everywhere, even when only names one key: the store holds no
// finer cut, so a retransmission in flight on another device is answered
// token_not_found (spec §5.6; pre-flight M9). It closes no held connection:
// with no mark the agent reconnects, and the request arrives on one.
//
// It runs to the end on a context detached from the caller and bounded by
// RevokeTimeout, as Revoke does once it holds its slot, so a dropped
// request never leaves it half done. A store error is the report's Err,
// and the steps after it still run. One revoke record is written.
func (b *Broker) RevokeOwn(ctx context.Context, principal string, only *store.TokenKey, origin string) RevokeReport {
	ctx, cancel := b.detach(ctx)
	defer cancel()
	now := b.Now()
	rep := RevokeReport{By: ByOwn, Request: RevokeRequest{Principal: principal, Origin: origin},
		Mark: store.Revocation{At: now}}
	note := func(err error) {
		if err != nil && rep.Err == nil {
			rep.Err = err
		}
	}
	var keys []store.TokenKey
	if only != nil {
		rep.Key, keys = *only, []store.TokenKey{*only}
	} else {
		var err error
		keys, err = b.Store.TokensByPrincipal(ctx, principal)
		note(err)
	}
	for _, k := range keys {
		toks, err := b.Store.Candidates(ctx, k)
		if err != nil {
			note(err)
			continue
		}
		deleted := false
		for _, t := range toks {
			if t.Principal != principal {
				continue
			}
			switch err := b.Store.DeleteToken(ctx, k, t.ID); {
			case err == nil:
				deleted = true
			case !errors.Is(err, store.ErrNotFound): // gone since: spent, or expired
				note(err)
			}
		}
		if deleted {
			// An idempotent retry of a mint from before now is minted
			// afresh, not answered with a token that no longer exists.
			// The supersede is per key, so another principal holding this
			// (device, username) pays for it too: its retry is minted fresh
			// beside the token it still holds, nearer the outstanding cap.
			b.supersede(k, b.Now())
			rep.TokenKeys++
		}
	}
	seen := map[store.ContextRef]bool{}
	for pass := 0; pass < 2; pass++ {
		var refs []store.ContextRef
		if only != nil {
			refs = []store.ContextRef{{NAS: only.NAS, Username: only.Username}}
		} else {
			var err error
			refs, err = b.Store.ContextsByPrincipal(ctx, principal)
			note(err)
		}
		for _, ref := range refs {
			marked, err := b.revokeOwnContext(ctx, principal, ref, now)
			note(err)
			if marked && !seen[ref] {
				seen[ref] = true
				rep.Contexts = append(rep.Contexts, ref)
			}
		}
	}
	if _, err := b.Store.DeleteReceiptsByPrincipal(ctx, principal); err != nil {
		note(err)
	}
	rep.Unreached = b.unreachedOf(rep.Contexts)
	outcome := "applied"
	if rep.Err != nil {
		outcome = "partial"
	}
	b.recordRevocation(now, rep, decision.VerdictDeny, decision.CredentialRevoked, outcome)
	return rep
}

// revokeOwnContext marks the context at ref revoked at at while it is
// principal's, by compare-and-set on the policy revision it read
// (SetContextPolicy with RevokedAt alone), so a context another principal's
// login replaced in between is read again and left (decision 34). marked is
// true when it is principal's and revoked at at or later. A context that
// will not open is left, since whose it is cannot be read; its error is
// returned.
func (b *Broker) revokeOwnContext(ctx context.Context, principal string, ref store.ContextRef, at time.Time) (bool, error) {
	k := store.ContextKey{NAS: ref.NAS, Username: ref.Username}
	for try := 0; try < ownRevokeTries; try++ {
		c, err := b.Store.GetContext(ctx, k)
		switch {
		case errors.Is(err, store.ErrNotFound):
			return false, nil
		case err != nil:
			return false, err
		case c.Principal != principal:
			return false, nil
		case !c.RevokedAt.IsZero() && !c.RevokedAt.Before(at):
			return true, nil
		}
		switch err := b.Store.SetContextPolicy(ctx, k, c.PolicyRev, store.ContextPolicy{RevokedAt: at}); {
		case err == nil:
			return true, nil
		case errors.Is(err, store.ErrConflict):
			continue // written since it was read: read again, decide again
		case errors.Is(err, store.ErrNotFound):
			return false, nil
		default:
			return false, err
		}
	}
	return false, fmt.Errorf("broker: the context on %s (%s) kept changing; run the revocation again", ref.NAS,
		ref.Username)
}

// RevokeKey ends whatever holds one (device, username), whoever's it is:
// every unspent token under it, its live context marked twice, and the
// owner's receipts deleted, with no mark (spec §5.1.4; decision 34). It is
// revoke_others' key form and checks no right itself: the endpoint calls it
// only for a caller holding revoke_others, and nothing else may. A context
// that will not open is still marked, as a revocation by certificate marks
// it (session.Manager): SetRevokedAt needs no key. The owner's receipts are
// deleted everywhere, the store holding no finer cut, which errs toward
// denying (session.Manager's mark); when the two passes read different
// owners, a login having replaced the context in between, both owners' are.
func (b *Broker) RevokeKey(ctx context.Context, k store.TokenKey, origin string) RevokeReport {
	ctx, cancel := b.detach(ctx)
	defer cancel()
	now := b.Now()
	rep := RevokeReport{By: ByKey, Key: k, Request: RevokeRequest{Origin: origin}, Mark: store.Revocation{At: now}}
	note := func(err error) {
		if err != nil && rep.Err == nil {
			rep.Err = err
		}
	}
	toks, cerr := b.Store.Candidates(ctx, k)
	if err := b.Store.DeleteTokens(ctx, k); err != nil {
		note(err)
	} else {
		b.supersede(k, b.Now())
		if cerr != nil || len(toks) > 0 {
			rep.TokenKeys = 1
		}
	}
	ck := store.ContextKey{NAS: k.NAS, Username: k.Username}
	var owners []string
	for pass := 0; pass < 2; pass++ {
		c, err := b.Store.GetContext(ctx, ck)
		switch {
		case errors.Is(err, store.ErrNotFound):
			continue
		case err != nil:
			note(err)
		case c.Principal != "":
			rep.Request.Principal = c.Principal
			if len(owners) == 0 || owners[len(owners)-1] != c.Principal {
				owners = append(owners, c.Principal)
			}
		}
		switch err := b.Store.SetRevokedAt(ctx, ck, now); {
		case err == nil:
			if len(rep.Contexts) == 0 {
				rep.Contexts = []store.ContextRef{{NAS: k.NAS, Username: k.Username}}
			}
		case !errors.Is(err, store.ErrNotFound):
			note(err)
		}
	}
	for _, p := range owners {
		if _, err := b.Store.DeleteReceiptsByPrincipal(ctx, p); err != nil {
			note(err)
		}
	}
	rep.Unreached = b.unreachedOf(rep.Contexts)
	outcome := "applied"
	if rep.Err != nil {
		outcome = "partial"
	}
	b.recordRevocation(now, rep, decision.VerdictDeny, decision.CredentialRevoked, outcome)
	return rep
}
