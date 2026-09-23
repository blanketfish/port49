// Package session holds the broker-side operations on live login context:
// refresh (spec §5.1.3, §5.6) and revocation (spec §5.6 row 2). It imports the
// store and nothing else of port49 — in particular not the daemon, which never
// calls any of it. Plan 7's broker puts these behind /v1/refresh, /v1/logout
// and /v1/tokens/revoke.
//
// Both operations write through the store's narrow setters rather than by
// reading a context, editing the copy and putting it back. That is not a
// style preference: the writers a broker operation races are accounting's
// annotation, the enable path's privilege raise, and revocation itself, and a
// re-put of a copy read at the top of the request silently discards whichever
// of them landed in between (store.Store's comment on TouchContext).
//
// What revocation here does NOT do: it does not delete the principal's
// unredeemed tokens. Design §1182 puts that on the broker — "broker deletes on
// revoke by principal, sid, or (device, username)" — and until the broker does
// it, a revoked principal's unredeemed token still redeems. On a device where
// the revoked context is still live the damage is contained: the token was
// minted before the revocation, so the login is refused `credential_revoked`
// and the token spent (package authen; spec §5.6). On a device with no live
// context there is nothing to join, and the redemption writes a fresh context
// with no revoked_at on it. The operator sees a revocation that marked every
// context and deleted every receipt, and then a PERMIT on a device they
// thought they had closed, with no log line connecting the two. Plan 7 owns
// closing this.
//
// Which of the refs returned here is unreachable at the device — a
// session-only platform, spec §13 decision 21 — is the caller's question, not
// this package's: it is answered with the adapter set from plan 5. Every ref
// touched is returned. On Junos in particular a revocation reaches a context
// nobody will read again: `authorization-time-interval` re-authorizes, and a
// DENIED re-authorization does not end the live session
// (tests/lab/results/L17-juniper_vsrx.md).
package session

import (
	"context"
	"errors"
	"time"

	"github.com/rhwendt/port49/internal/store"
)

// Manager is the broker's handle on live context. It is safe for concurrent
// use to exactly the extent the store it wraps is.
type Manager struct {
	store          store.Store
	now            func() time.Time
	contextIdleTTL time.Duration
	indexTTL       time.Duration
}

// New returns a Manager over s. contextIdleTTL is the expiry a refreshed
// context is extended to; indexTTL stamps a re-indexed sid. Revocation uses
// neither: a marked context ages out on the clock it was already on (spec §5.6
// row 6).
func New(s store.Store, now func() time.Time, contextIdleTTL, indexTTL time.Duration) *Manager {
	return &Manager{store: s, now: now, contextIdleTTL: contextIdleTTL, indexTTL: indexTTL}
}

// Refresh carries a scheduled group re-resolution (spec §5.1.3) into every
// live context of principal: auth_time moves to authTime, the session ceiling
// moves with it keeping the window it described, refreshed_at is stamped, and
// newBlobHash is installed when it is non-empty. It returns how many contexts
// were touched.
//
// It does not clear a revocation. A refresh re-resolves a directory; it does
// not re-verify a credential, and it runs on every principal with a live
// context every few minutes — so lifting the mark here would un-revoke every
// revoked principal within one interval, on the very path §5.1.3 names as how
// a policy-driven revocation reaches live sessions. Spec §5.6 row 6 is what
// ends a revocation. See store.Store's RefreshContext.
//
// A rotated sid (newSid different from oldSid, both non-empty in practice)
// moves in the index, not on the record: Credential is sealed, so the sid is
// the one thing a narrow setter cannot write (store.Store's RefreshContext).
// Nothing reads the sid off a context to make a decision — revocation by sid
// reads the index — so the index is the copy that has to be right. For the
// same reason oldSid must be the sid the caller's own session record holds,
// never one read off a stored context: a context's recorded sid is not updated
// by a rotation, so passing it on a second rotation removes nothing and leaves
// the intermediate sid indexed against a live ref. That direction is
// over-revocation, so it is safe, but it accumulates dangling entries.
//
// An index entry whose context is already gone is skipped rather than treated
// as an error: the index has its own TTL and reclaims it. The other direction
// — a context outliving the entries that name it — is the dangerous one and is
// not this package's to police: every store writer that moves a context's
// expiry moves its index entries with it (design §12).
func (m *Manager) Refresh(ctx context.Context, principal string, authTime time.Time, newBlobHash, oldSid, newSid string) (int, error) {
	refs, err := m.store.ContextsByPrincipal(ctx, principal)
	if err != nil {
		return 0, err
	}
	r := store.ContextRefresh{AuthTime: authTime, RefreshedAt: m.now(), BlobHash: newBlobHash}
	rotating := newSid != "" && newSid != oldSid
	n := 0
	for _, ref := range refs {
		switch err := m.store.RefreshContext(ctx, keyOf(ref), r, m.contextIdleTTL); {
		case errors.Is(err, store.ErrNotFound):
			continue
		case err != nil:
			// The count is what was actually refreshed before the store
			// failed, not zero: the broker has to know the operation was
			// partial to decide whether to retry it.
			return n, err
		}
		n++
		if rotating {
			if err := m.store.ReindexSid(ctx, oldSid, newSid, ref, m.indexTTL); err != nil {
				return n, err
			}
		}
	}
	return n, nil
}

// ErrBlankRevocation is a revocation by an empty sid, or by a certificate
// with no issuer or no serial. Every certificate login has sid "" and every
// OIDC login a certificate with neither, so a revocation by a blank names
// every such operator on the fleet at once; it is refused and marks nothing
// (ruling P8). The store never indexes a blank either, so this is the guard
// on the broker's side of the same rule.
var ErrBlankRevocation = errors.New("session: revocation by an empty sid or certificate")

// RevokeBySid marks every context authorized by this OIDC session id and
// deletes the receipts of the principals behind them. It never deletes a
// context. An empty sid is ErrBlankRevocation.
func (m *Manager) RevokeBySid(ctx context.Context, sid string) ([]store.ContextRef, error) {
	if sid == "" {
		return nil, ErrBlankRevocation
	}
	refs, err := m.store.ContextsBySid(ctx, sid)
	if err != nil {
		return nil, err
	}
	return m.mark(ctx, refs, "")
}

// RevokeByPrincipal marks every live context of principal and deletes its
// receipts. The receipts are deleted whether or not a live context was found:
// a receipt outlives the token that wrote it (store.Receipt) and a context has
// its own idle TTL, so a principal with nothing left to mark can still have a
// spent token answering replays.
func (m *Manager) RevokeByPrincipal(ctx context.Context, principal string) ([]store.ContextRef, error) {
	refs, err := m.store.ContextsByPrincipal(ctx, principal)
	if err != nil {
		return nil, err
	}
	return m.mark(ctx, refs, principal)
}

// RevokeByCert marks every context authorized by this certificate — the index
// key a CRL or OCSP response names (spec §5.1.4) — and deletes the receipts of
// the principals behind them. An empty issuer or serial is
// ErrBlankRevocation.
func (m *Manager) RevokeByCert(ctx context.Context, issuer, serial string) ([]store.ContextRef, error) {
	if issuer == "" || serial == "" {
		return nil, ErrBlankRevocation
	}
	refs, err := m.store.ContextsByCert(ctx, store.CertKey(issuer, serial))
	if err != nil {
		return nil, err
	}
	return m.mark(ctx, refs, "")
}

// mark sets revoked_at on every ref and deletes the receipts of every
// principal behind them, returning the refs it touched.
//
// Deleting the receipts is the half of revocation that closes the replay
// window: a receipt left behind lets the revoked credential keep being
// answered PASS `receipt_replayed` for up to receipt_max_age (spec §13,
// decision 15). RevokeByPrincipal already knows whose receipts those are and
// passes it as knownPrincipal; revocation by sid or by certificate does not,
// and reads it off each context before marking.
//
// That deletion is deliberately over-broad on the by-sid and by-cert paths: a
// back-channel logout for one sid deletes the principal's receipts everywhere,
// including a concurrent session under another sid on another device, whose
// device retry inside the receipt window then finds neither token nor receipt
// and is denied though nobody revoked it. The store offers no finer cut — a
// Receipt carries no sid and receipts_by_principal is the only index
// (store.Receipt) — so this is a shape limit, and it errs toward denying a
// session nobody revoked rather than permitting one somebody did.
//
// It does not delete tokens; see the package comment.
//
// That read is the only place this package needs a context's sealed body, and
// it is deliberately not allowed to stop the marking. A record that will not
// open — sealed under a retired key — is still marked, because SetRevokedAt
// needs no key at all (crypt): a revocation that cannot read the record can
// still deny it. The error is returned so the caller learns the receipts were
// not reached, alongside the refs that were.
func (m *Manager) mark(ctx context.Context, refs []store.ContextRef, knownPrincipal string) ([]store.ContextRef, error) {
	at := m.now()
	principals := map[string]bool{}
	if knownPrincipal != "" {
		principals[knownPrincipal] = true
	}
	var touched []store.ContextRef
	var firstErr error
	for _, ref := range refs {
		k := keyOf(ref)
		if knownPrincipal == "" {
			// Read before the mark, while the context is still whole.
			c, err := m.store.GetContext(ctx, k)
			switch {
			case errors.Is(err, store.ErrNotFound):
				// The index entry outlived its context; the index TTL
				// reclaims it, and there is nothing left to mark.
				continue
			case err != nil:
				if firstErr == nil {
					firstErr = err
				}
			default:
				if c.Principal != "" {
					principals[c.Principal] = true
				}
			}
		}
		switch err := m.store.SetRevokedAt(ctx, k, at); {
		case errors.Is(err, store.ErrNotFound):
			continue
		case err != nil:
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		touched = append(touched, ref)
	}
	for p := range principals {
		if _, err := m.store.DeleteReceiptsByPrincipal(ctx, p); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return touched, firstErr
}

// keyOf is the whole of the ref-to-key conversion: the indexes hold the
// context key and nothing more (store.ContextRef).
func keyOf(ref store.ContextRef) store.ContextKey {
	return store.ContextKey{NAS: ref.NAS, Username: ref.Username}
}
