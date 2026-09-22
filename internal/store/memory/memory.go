// Package memory is the in-process store.Store. It exists so the daemon can be
// integration-tested as a single binary (design §12) and as the lab store.
package memory

import (
	"bytes"
	"context"
	"sync"
	"time"

	"github.com/rhwendt/port49/internal/store"
)

type Store struct {
	now      func() time.Time
	mu       sync.Mutex
	tokens   map[store.TokenKey][]store.Token
	receipts map[store.ReceiptKey]store.Receipt
	// receiptsByPrincipal is the revocation index: principal to the receipt
	// keys written under it, each with its own expiry so the sweep can reclaim
	// an index entry whose record is already gone. It is plaintext by design —
	// the records it points at are sealed, the index is not (store.ReceiptWrite).
	receiptsByPrincipal map[string]map[store.ReceiptKey]time.Time
	contexts            map[store.ContextKey]ctxEntry
	writes              int // incremented on every write; triggers sweep at sweepEvery
}

type ctxEntry struct {
	c   store.Context
	exp time.Time
}

func New(now func() time.Time) *Store {
	return &Store{
		now:                 now,
		tokens:              make(map[store.TokenKey][]store.Token),
		receipts:            make(map[store.ReceiptKey]store.Receipt),
		receiptsByPrincipal: make(map[string]map[store.ReceiptKey]time.Time),
		contexts:            make(map[store.ContextKey]ctxEntry),
	}
}

func (s *Store) live(k store.TokenKey) []store.Token {
	now := s.now()
	set := s.tokens[k]
	out := set[:0]
	for _, t := range set {
		if t.ExpiresAt.After(now) {
			out = append(out, t)
		}
	}
	clearTail(set, len(out))
	if len(out) == 0 {
		delete(s.tokens, k)
	} else {
		s.tokens[k] = out
	}
	return out
}

// clearTail zeroes what in-place compaction left past the new length. The
// entries there are Token values for tokens that have been evicted, still
// holding their Secret headers, unreachable through the map but alive for as
// long as the backing array is.
//
// It clears the entries, never the secret bytes they point at: a surviving
// token copied down during compaction leaves a duplicate of itself in the
// tail, so wiping the bytes would destroy a live token's secret.
func clearTail(set []store.Token, n int) {
	for i := n; i < len(set); i++ {
		set[i] = store.Token{}
	}
}

const sweepEvery = 1024

func (s *Store) sweepLocked() {
	now := s.now()

	// Sweep tokens: delete TokenKey entries whose live set is empty
	for k := range s.tokens {
		set := s.tokens[k]
		live := set[:0]
		for _, t := range set {
			if t.ExpiresAt.After(now) {
				live = append(live, t)
			}
		}
		clearTail(set, len(live))
		if len(live) == 0 {
			delete(s.tokens, k)
		} else {
			s.tokens[k] = live
		}
	}

	// Sweep receipts: delete receipts past their retention. RetainUntil, not
	// IdleExpiresAt: a receipt whose sliding bound has passed is still the
	// difference between `token_spent` and `token_not_found` (store.Receipt).
	for k, r := range s.receipts {
		if !r.RetainUntil.After(now) {
			delete(s.receipts, k)
		}
	}

	// Sweep the revocation index. Its entries expire on their own IndexTTL and
	// a principal whose last entry is gone drops out entirely, so a daemon that
	// runs for weeks does not keep one map entry per principal it ever saw.
	for p, set := range s.receiptsByPrincipal {
		for k, exp := range set {
			if !exp.After(now) {
				delete(set, k)
			}
		}
		if len(set) == 0 {
			delete(s.receiptsByPrincipal, p)
		}
	}

	// Sweep contexts: delete expired contexts
	for k, e := range s.contexts {
		if !e.exp.After(now) {
			delete(s.contexts, k)
		}
	}
}

func (s *Store) PutToken(_ context.Context, k store.TokenKey, t store.Token) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.live(k)
	// Copy Secret to prevent aliasing
	t.Secret = bytes.Clone(t.Secret)
	s.tokens[k] = append(s.tokens[k], t)
	s.writes++
	if s.writes%sweepEvery == 0 {
		s.sweepLocked()
	}
	return len(s.tokens[k]), nil
}

func (s *Store) Candidates(_ context.Context, k store.TokenKey) ([]store.Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	live := s.live(k)
	// Return a copy of each Token's Secret to prevent aliasing
	result := make([]store.Token, len(live))
	for i, t := range live {
		result[i] = t
		result[i].Secret = bytes.Clone(t.Secret)
	}
	return result, nil
}

func (s *Store) RedeemAndReceipt(_ context.Context, k store.TokenKey, tokenID string, w store.ReceiptWrite) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	set := s.live(k)
	for i, t := range set {
		// `==`, not crypto/subtle: the ID is a handle the daemon chose for
		// itself and never puts on the wire, so nothing an attacker can
		// influence reaches this comparison (store.Token).
		if t.ID != tokenID {
			continue
		}
		s.tokens[k] = append(set[:i:i], set[i+1:]...)
		if len(s.tokens[k]) == 0 {
			delete(s.tokens, k)
		}
		// Receipt and index in the same critical section as the removal: that
		// is what makes this the atomic remove-and-write of design §12, and
		// what lets exactly one racing redeemer win.
		s.receipts[w.Key] = w.Receipt
		if w.Principal != "" {
			byP := s.receiptsByPrincipal[w.Principal]
			if byP == nil {
				byP = make(map[store.ReceiptKey]time.Time)
				s.receiptsByPrincipal[w.Principal] = byP
			}
			byP[w.Key] = now.Add(w.IndexTTL)
		}
		s.writes++
		if s.writes%sweepEvery == 0 {
			s.sweepLocked()
		}
		return nil
	}
	return store.ErrNotFound
}

// DeleteTokens drops every token under this key, spent or not. Revocation and
// the §5.6 teardown rows both need it: a principal whose authorization was
// withdrawn must not be able to redeem a token minted before the withdrawal.
func (s *Store) DeleteTokens(_ context.Context, k store.TokenKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if set, ok := s.tokens[k]; ok {
		clearTail(set, 0)
		delete(s.tokens, k)
	}
	return nil
}

func (s *Store) GetReceipt(_ context.Context, rk store.ReceiptKey) (store.Receipt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.receipts[rk]
	// RetainUntil, not IdleExpiresAt: a presentation past the sliding bound has
	// to find this record in order to be answered `token_spent` rather than
	// `token_not_found` (store.Receipt). Deciding which of the two bounds a
	// found receipt has passed is the caller's job, not the store's.
	if !ok || !r.RetainUntil.After(s.now()) {
		delete(s.receipts, rk)
		return store.Receipt{}, store.ErrNotFound
	}
	return r, nil
}

// ExtendReceipt pushes IdleExpiresAt out and touches nothing else, so neither
// FirstRedeemedAt's absolute anchor nor the store's own retention can be slid.
func (s *Store) ExtendReceipt(_ context.Context, rk store.ReceiptKey, idleExpiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.receipts[rk]
	if !ok || !r.RetainUntil.After(s.now()) {
		delete(s.receipts, rk)
		return store.ErrNotFound
	}
	r.IdleExpiresAt = idleExpiresAt
	s.receipts[rk] = r
	return nil
}

// DeleteReceiptsByPrincipal removes every live receipt this principal wrote and
// reports how many. It is the half of revocation that closes the replay window:
// deleting the tokens alone leaves a spent token's receipt answering a replay
// with the decision made before the principal lost its authorization.
//
// The count is of records actually deleted, so an index entry whose receipt has
// already aged out does not inflate what the operator is told.
func (s *Store) DeleteReceiptsByPrincipal(_ context.Context, principal string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	n := 0
	for rk := range s.receiptsByPrincipal[principal] {
		r, ok := s.receipts[rk]
		if ok && r.RetainUntil.After(now) {
			n++
		}
		delete(s.receipts, rk)
	}
	delete(s.receiptsByPrincipal, principal)
	return n, nil
}

func (s *Store) PutContext(_ context.Context, k store.ContextKey, c store.Context, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	// The write is an extension too, so it stamps the same clock TouchContext
	// does (store.Context). Leaving it to the caller would hand Task 10's
	// half-TTL rule a zero on every freshly written context, and a rule that
	// reads zero extends on every command — the write this exists to avoid.
	c.LastTouchedAt = now
	s.contexts[k] = ctxEntry{c: c, exp: now.Add(ttl)}
	s.writes++
	if s.writes%sweepEvery == 0 {
		s.sweepLocked()
	}
	return nil
}

func (s *Store) GetContext(_ context.Context, k store.ContextKey) (store.Context, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.contexts[k]
	if !ok || !e.exp.After(s.now()) {
		delete(s.contexts, k)
		return store.Context{}, store.ErrNotFound
	}
	return e.c, nil
}

// TouchContext is the read-modify-write inside the lock that the handler cannot
// do for itself; store.Store's comment on it is the argument for why.
func (s *Store) TouchContext(_ context.Context, k store.ContextKey, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	e, ok := s.contexts[k]
	if !ok || !e.exp.After(now) {
		delete(s.contexts, k)
		return store.ErrNotFound
	}
	// Only the expiry and its own stamp. Every other field is left exactly
	// as whoever wrote it last left it, which is the property the caller
	// cannot get by re-putting a record it read a moment ago.
	e.exp = now.Add(ttl)
	e.c.LastTouchedAt = now
	s.contexts[k] = e
	return nil
}

func (s *Store) DeleteContext(_ context.Context, k store.ContextKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.contexts, k)
	return nil
}

var _ store.Store = (*Store)(nil)
