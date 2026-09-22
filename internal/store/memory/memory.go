// Package memory is the in-process store.Store. It exists so the daemon can be
// integration-tested as a single binary (design §12) and as the lab store.
package memory

import (
	"bytes"
	"context"
	"sort"
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
	blobs               map[string]blobEntry

	// byPrincipal, bySid, and byCert are the context indexes (design §12):
	// each maps its key to the set of ContextRefs live under it, with each
	// ref's own expiry so the sweep can reclaim an index entry whose context
	// is already gone.
	byPrincipal map[string]map[store.ContextRef]time.Time
	bySid       map[string]map[store.ContextRef]time.Time
	byCert      map[string]map[store.ContextRef]time.Time
	idem        map[string]store.Idempotency

	writes int // incremented on every write; triggers sweep at sweepEvery
}

type ctxEntry struct {
	c   store.Context
	exp time.Time
}

type blobEntry struct {
	body []byte
	exp  time.Time
}

func New(now func() time.Time) *Store {
	return &Store{
		now:                 now,
		tokens:              make(map[store.TokenKey][]store.Token),
		receipts:            make(map[store.ReceiptKey]store.Receipt),
		receiptsByPrincipal: make(map[string]map[store.ReceiptKey]time.Time),
		contexts:            make(map[store.ContextKey]ctxEntry),
		blobs:               make(map[string]blobEntry),
		byPrincipal:         make(map[string]map[store.ContextRef]time.Time),
		bySid:               make(map[string]map[store.ContextRef]time.Time),
		byCert:              make(map[string]map[store.ContextRef]time.Time),
		idem:                make(map[string]store.Idempotency),
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

	// Sweep blobs: delete blobs past their expiry.
	for h, b := range s.blobs {
		if !b.exp.After(now) {
			delete(s.blobs, h)
		}
	}

	// Sweep idempotency records: delete past ExpiresAt.
	for k, r := range s.idem {
		if !r.ExpiresAt.After(now) {
			delete(s.idem, k)
		}
	}

	// Sweep the context indexes: an entry expires on its own TTL, and a key
	// whose last entry is gone drops out entirely — the same shape as
	// receiptsByPrincipal, and for the same reason.
	sweepIndex(s.byPrincipal, now)
	sweepIndex(s.bySid, now)
	sweepIndex(s.byCert, now)
}

func sweepIndex(idx map[string]map[store.ContextRef]time.Time, now time.Time) {
	for k, set := range idx {
		for ref, exp := range set {
			if !exp.After(now) {
				delete(set, ref)
			}
		}
		if len(set) == 0 {
			delete(idx, k)
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
		// The append clips the capacity to i, so when the spent token is the
		// last member nothing reallocates and its entry — Secret pointer
		// included — stays reachable from the allocation the map still holds.
		// clearTail zeroes the entries past i in the old array and never the
		// secret bytes they point at, so the tokens copied down into the new
		// array in the reallocating case keep their secrets (clearTail).
		clearTail(set, i)
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

func (s *Store) SetPrivilege(_ context.Context, k store.ContextKey, level uint8) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.contexts[k]
	if !ok || !e.exp.After(s.now()) {
		delete(s.contexts, k)
		return store.ErrNotFound
	}
	// Only the level. The expiry and its stamp belong to TouchContext, and
	// every other field is left exactly as whoever wrote it last left it --
	// which is the property the caller cannot get by re-putting a record it
	// read a moment ago (store.Store).
	e.c.PrivLvl = level
	s.contexts[k] = e
	return nil
}

func (s *Store) DeleteContext(_ context.Context, k store.ContextKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.contexts, k)
	return nil
}

// PutBlob writes body under hash, keeping the later of the existing and the
// new expiry: a re-put must not shorten a blob another context still
// references.
func (s *Store) PutBlob(_ context.Context, hash string, body []byte, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	exp := s.now().Add(ttl)
	if existing, ok := s.blobs[hash]; ok && existing.exp.After(exp) {
		exp = existing.exp
	}
	s.blobs[hash] = blobEntry{body: bytes.Clone(body), exp: exp}
	s.writes++
	if s.writes%sweepEvery == 0 {
		s.sweepLocked()
	}
	return nil
}

// GetBlob returns a copy of the blob's body, or ErrNotFound if it is absent
// or has expired.
func (s *Store) GetBlob(_ context.Context, hash string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.blobs[hash]
	if !ok || !b.exp.After(s.now()) {
		delete(s.blobs, hash)
		return nil, store.ErrNotFound
	}
	return bytes.Clone(b.body), nil
}

// BumpBlob extends a blob to at least now+ttl and never shortens it.
func (s *Store) BumpBlob(_ context.Context, hash string, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.blobs[hash]
	if !ok || !b.exp.After(s.now()) {
		delete(s.blobs, hash)
		return store.ErrNotFound
	}
	if newExp := s.now().Add(ttl); newExp.After(b.exp) {
		b.exp = newExp
		s.blobs[hash] = b
	}
	return nil
}

// addRef adds ref to idx[key] with the given expiry. An empty key is a
// caller opting out of that index — IndexContext passes "" for a sid or cert
// it does not have — and is a no-op rather than an entry under the empty
// string.
func addRef(idx map[string]map[store.ContextRef]time.Time, key string, ref store.ContextRef, exp time.Time) {
	if key == "" {
		return
	}
	set := idx[key]
	if set == nil {
		set = make(map[store.ContextRef]time.Time)
		idx[key] = set
	}
	set[ref] = exp
}

// removeRef removes ref from idx[key] and drops the key entirely once its
// last ref is gone, the same shape as receiptsByPrincipal.
func removeRef(idx map[string]map[store.ContextRef]time.Time, key string, ref store.ContextRef) {
	if key == "" {
		return
	}
	set := idx[key]
	if set == nil {
		return
	}
	delete(set, ref)
	if len(set) == 0 {
		delete(idx, key)
	}
}

// listRefs returns the live refs under idx[key], sorted on NAS+"\x00"+Username,
// dropping expired entries as it walks.
func listRefs(idx map[string]map[store.ContextRef]time.Time, key string, now time.Time) []store.ContextRef {
	set := idx[key]
	if set == nil {
		return nil
	}
	out := make([]store.ContextRef, 0, len(set))
	for ref, exp := range set {
		if exp.After(now) {
			out = append(out, ref)
		} else {
			delete(set, ref)
		}
	}
	if len(set) == 0 {
		delete(idx, key)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].NAS+"\x00"+out[i].Username < out[j].NAS+"\x00"+out[j].Username
	})
	return out
}

// IndexContext adds ref to each non-empty index — principal, sid, and cert —
// sharing the one ttl. A caller with no sid or cert passes "" to skip that
// index (store.ContextRef alone is not enough to reconstruct the context).
func (s *Store) IndexContext(_ context.Context, principal, sid, certKey string, ref store.ContextRef, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	exp := s.now().Add(ttl)
	addRef(s.byPrincipal, principal, ref, exp)
	addRef(s.bySid, sid, ref, exp)
	addRef(s.byCert, certKey, ref, exp)
	s.writes++
	if s.writes%sweepEvery == 0 {
		s.sweepLocked()
	}
	return nil
}

// UnindexContext removes ref from each of the three indexes it was written
// under.
func (s *Store) UnindexContext(_ context.Context, principal, sid, certKey string, ref store.ContextRef) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	removeRef(s.byPrincipal, principal, ref)
	removeRef(s.bySid, sid, ref)
	removeRef(s.byCert, certKey, ref)
	return nil
}

// ContextsByPrincipal returns the live context refs indexed under principal.
func (s *Store) ContextsByPrincipal(_ context.Context, principal string) ([]store.ContextRef, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return listRefs(s.byPrincipal, principal, s.now()), nil
}

// ContextsBySid returns the live context refs indexed under sid.
func (s *Store) ContextsBySid(_ context.Context, sid string) ([]store.ContextRef, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return listRefs(s.bySid, sid, s.now()), nil
}

// ContextsByCert returns the live context refs indexed under certKey.
func (s *Store) ContextsByCert(_ context.Context, certKey string) ([]store.ContextRef, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return listRefs(s.byCert, certKey, s.now()), nil
}

// ReindexSid moves ref from oldSid's index entry to newSid's, re-stamping its
// expiry from ttl. A session ID that changes mid-session (spec §5.8) must not
// leave the ref answering lookups under a sid the device no longer uses.
func (s *Store) ReindexSid(_ context.Context, oldSid, newSid string, ref store.ContextRef, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	removeRef(s.bySid, oldSid, ref)
	addRef(s.bySid, newSid, ref, s.now().Add(ttl))
	s.writes++
	if s.writes%sweepEvery == 0 {
		s.sweepLocked()
	}
	return nil
}

// ActivePrincipals returns, sorted, every principal with at least one live
// context ref, dropping expired refs as it walks.
func (s *Store) ActivePrincipals(_ context.Context) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	var out []string
	for p, set := range s.byPrincipal {
		live := false
		for ref, exp := range set {
			if exp.After(now) {
				live = true
			} else {
				delete(set, ref)
			}
		}
		if len(set) == 0 {
			delete(s.byPrincipal, p)
		}
		if live {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out, nil
}

// idemKey joins principal and key so idempotency is scoped per principal:
// one principal's replay must not answer another's request.
func idemKey(principal, key string) string {
	return principal + "\x00" + key
}

// PutIdempotency records rec under (principal, key), expiring on rec.ExpiresAt.
func (s *Store) PutIdempotency(_ context.Context, principal, key string, rec store.Idempotency) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.idem[idemKey(principal, key)] = rec
	s.writes++
	if s.writes%sweepEvery == 0 {
		s.sweepLocked()
	}
	return nil
}

// GetIdempotency returns the record written under (principal, key), or
// ErrNotFound if it is absent, expired, or was written under a different
// principal.
func (s *Store) GetIdempotency(_ context.Context, principal, key string) (store.Idempotency, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := idemKey(principal, key)
	r, ok := s.idem[k]
	if !ok || !r.ExpiresAt.After(s.now()) {
		delete(s.idem, k)
		return store.Idempotency{}, store.ErrNotFound
	}
	return r, nil
}

var _ store.Store = (*Store)(nil)
