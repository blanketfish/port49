// Package memory is the in-process store.Store. It exists so the daemon can be
// integration-tested as a single binary (design §12) and as the lab store.
package memory

import (
	"bytes"
	"context"
	"crypto/subtle"
	"sync"
	"time"

	"github.com/rhwendt/port49/internal/store"
)

type Store struct {
	now      func() time.Time
	mu       sync.Mutex
	tokens   map[store.TokenKey][]store.Token
	receipts map[store.ReceiptKey]store.Receipt
	contexts map[store.ContextKey]ctxEntry
	writes   int // incremented on every write; triggers sweep at sweepEvery
}

type ctxEntry struct {
	c   store.Context
	exp time.Time
}

func New(now func() time.Time) *Store {
	return &Store{
		now:      now,
		tokens:   make(map[store.TokenKey][]store.Token),
		receipts: make(map[store.ReceiptKey]store.Receipt),
		contexts: make(map[store.ContextKey]ctxEntry),
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

	// Sweep receipts: delete expired receipts
	for k, r := range s.receipts {
		if !r.ExpiresAt.After(now) {
			delete(s.receipts, k)
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

func (s *Store) RedeemAndReceipt(_ context.Context, k store.TokenKey, secret []byte, rk store.ReceiptKey, r store.Receipt) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	set := s.live(k)
	for i, t := range set {
		if subtle.ConstantTimeCompare(t.Secret, secret) == 1 {
			if !t.Reusable {
				s.tokens[k] = append(set[:i:i], set[i+1:]...)
				if len(s.tokens[k]) == 0 {
					delete(s.tokens, k)
				}
			}
			s.receipts[rk] = r
			s.writes++
			if s.writes%sweepEvery == 0 {
				s.sweepLocked()
			}
			return nil
		}
	}
	return store.ErrNotFound
}

func (s *Store) GetReceipt(_ context.Context, rk store.ReceiptKey) (store.Receipt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.receipts[rk]
	if !ok || !r.ExpiresAt.After(s.now()) {
		delete(s.receipts, rk)
		return store.Receipt{}, store.ErrNotFound
	}
	return r, nil
}

func (s *Store) PutContext(_ context.Context, k store.ContextKey, c store.Context, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.contexts[k] = ctxEntry{c: c, exp: s.now().Add(ttl)}
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

func (s *Store) DeleteContext(_ context.Context, k store.ContextKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.contexts, k)
	return nil
}

var _ store.Store = (*Store)(nil)
