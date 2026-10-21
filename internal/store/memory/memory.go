// Package memory is the in-process store.Store. It exists so the daemon can be
// integration-tested as a single binary (design §12) and as the lab store.
package memory

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"sort"
	"strings"
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
	// indexedAs is the reverse of those three: the keys each ref was indexed
	// under. It exists so an extension of a context can carry its index
	// entries with it, which design §12 requires — an index entry "carries
	// the context's TTL". Without it the dangerous direction opens up: a
	// session kept alive by activity for 8 to 16 hours outlives the entries
	// that name it, and then RevokeByPrincipal and RevokeByCert find zero
	// refs on a context that is still live and still authorizing, while the
	// operator is told "0 touched" — which reads as "already gone", not as "I
	// could not find it".
	indexedAs map[store.ContextRef]indexKeys
	idem      map[string]store.Idempotency

	// once, owners and logout are plan 7h's records: the once-only keys, the
	// principals minting under an OIDC sid or sub, and back-channel logouts.
	once   map[string]onceEntry
	owners map[string]map[string]store.OwnerPrincipal // key, then principal
	logout map[string]logoutEntry
	// mfaProof is plan 9c's kept per-login proofs.
	mfaProof map[string]mfaProofEntry
	// attempts is plan 9e's sign-in attempt counts.
	attempts map[string]memAttempts

	// tokensByPrincipal and tokensByCert are the token indexes (plan 7a):
	// each key's set of TokenKeys, each with the expiry of the longest token
	// indexed under it. Plaintext, as the context indexes are.
	tokensByPrincipal map[string]map[store.TokenKey]time.Time
	tokensByCert      map[string]map[store.TokenKey]time.Time

	// revocations are the standing marks (plan 7a), by (Kind, Key). The
	// sweep never touches them: only DeleteRevocation lifts one.
	revocations map[[2]string]store.Revocation

	// superseded is, by key, when its unspent tokens were last superseded,
	// and supersededAll the same for every key (plan 7e, Ruling 9). Each is
	// kept SupersededFor from its last write, and the sweep drops it then.
	superseded    map[store.TokenKey]supersededEntry
	supersededAll supersededEntry

	// memberships and memberKeys are the directory's (plan 7g): a record by
	// principal, or the tombstone a forget left, and the principal a
	// mapping key resolved to. Each is judged live against its own expiry.
	memberships map[string]membershipEntry
	memberKeys  map[string]memberKeyEntry

	memberVer uint64 // the last membership version handed out
	writes    int    // incremented on every write; triggers sweep at sweepEvery
	// revs is the last context revision handed out. It is store-wide rather
	// than per key so a context that is deleted and written again never
	// repeats a revision an earlier reader holds.
	revs uint64
}

type ctxEntry struct {
	c   store.Context
	exp time.Time
	rev uint64 // store.Context.Rev; see nextRevLocked
	// policyRev is store.Context.PolicyRev: it takes a revision from the same
	// counter as rev, but only on a write to what a policy refresh decides.
	policyRev uint64
}

// nextRevLocked returns a revision no context has held. Every write to a
// context takes one, which is what makes SwapContext's comparison mean "no one
// wrote this record since you read it" (store.Context.Rev).
func (s *Store) nextRevLocked() uint64 {
	s.revs++
	return s.revs
}

// indexKeys is the set of index keys one ref was written under. An empty
// principal means that index was never written for this ref — the same "" that
// IndexContext reads as "skip this index".
//
// sids and certKeys are lists, not single values, because a context is
// joined: a second login by the same principal on the same device merges into
// the live context (spec §5.6), and each login is indexed under its own sid
// and certificate. Revocation by either has to keep reaching the context for
// as long as it lives, so an extension re-stamps every one of them.
//
// The lists are deliberately uncapped. They hold one entry per distinct
// credential that logged into this one context on this one device, each
// behind a token the broker minted. Another principal's replace, or an
// unreadable one, clears them (UnindexRef), and the sweep drops an entry once
// its index entry is gone. Dropping an entry to hold a cap would silently cost
// revocation its reach into a context that is still live and authorizing —
// the fail-open direction — and no cap could tell which entry was safe to
// lose.
type indexKeys struct {
	principal string
	sids      []string
	certKeys  []string
}

func (r indexKeys) empty() bool { return r.principal == "" && len(r.sids) == 0 && len(r.certKeys) == 0 }

// withKey appends key if it is non-empty and not already present. It copies,
// for the reason addDiscriminator does.
func withKey(keys []string, key string) []string {
	if key == "" {
		return keys
	}
	for _, k := range keys {
		if k == key {
			return keys
		}
	}
	return append(append([]string(nil), keys...), key)
}

// withoutKey drops key, copying.
func withoutKey(keys []string, key string) []string {
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		if k != key {
			out = append(out, k)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
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
		indexedAs:           make(map[store.ContextRef]indexKeys),
		idem:                make(map[string]store.Idempotency),
		once:                make(map[string]onceEntry),
		owners:              make(map[string]map[string]store.OwnerPrincipal),
		logout:              make(map[string]logoutEntry),
		mfaProof:            make(map[string]mfaProofEntry),
		attempts:            make(map[string]memAttempts),
		tokensByPrincipal:   make(map[string]map[store.TokenKey]time.Time),
		tokensByCert:        make(map[string]map[store.TokenKey]time.Time),
		revocations:         make(map[[2]string]store.Revocation),
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

type supersededEntry struct{ at, until time.Time }

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

	// Sweep the once-only, owner and logout records past their expiry; an
	// owner key whose every entry lapsed goes whole.
	for k, e := range s.once {
		if !now.Before(e.exp) {
			delete(s.once, k)
		}
	}
	for k, set := range s.owners {
		for p, e := range set {
			if !now.Before(e.ExpiresAt) {
				delete(set, p)
			}
		}
		if len(set) == 0 {
			delete(s.owners, k)
		}
	}
	for k, e := range s.logout {
		if !now.Before(e.exp) {
			delete(s.logout, k)
		}
	}
	for k, e := range s.mfaProof {
		if !now.Before(e.exp) {
			delete(s.mfaProof, k)
		}
	}
	for k, a := range s.attempts {
		if !now.Before(a.end) {
			delete(s.attempts, k)
		}
	}

	// Sweep superseded instants past SupersededFor.
	for k, e := range s.superseded {
		if !now.Before(e.until) {
			delete(s.superseded, k)
		}
	}
	if !now.Before(s.supersededAll.until) {
		s.supersededAll = supersededEntry{}
	}

	// Sweep the directory's records and keys past their expiry.
	for p, e := range s.memberships {
		if !alive(e.exp, now) {
			delete(s.memberships, p)
		}
	}
	for k, e := range s.memberKeys {
		if !alive(e.expires, now) {
			delete(s.memberKeys, k)
		}
	}

	// Sweep the context indexes: an entry expires on its own TTL, and a key
	// whose last entry is gone drops out entirely — the same shape as
	// receiptsByPrincipal, and for the same reason.
	sweepIndex(s.byPrincipal, now)
	sweepIndex(s.bySid, now)
	sweepIndex(s.byCert, now)
	sweepTokenIndex(s.tokensByPrincipal, now)
	sweepTokenIndex(s.tokensByCert, now)

	// Sweep the reverse record last, once the three indexes above have
	// dropped what expired: a ref no index still names has nothing left to
	// extend, so keeping its entry would be one map entry per ref the daemon
	// ever saw.
	for ref, rec := range s.indexedAs {
		if !indexed(s.byPrincipal, rec.principal, ref) {
			rec.principal = ""
		}
		rec.sids = stillIndexed(s.bySid, rec.sids, ref)
		rec.certKeys = stillIndexed(s.byCert, rec.certKeys, ref)
		if rec.empty() {
			delete(s.indexedAs, ref)
		} else {
			s.indexedAs[ref] = rec
		}
	}
}

// stillIndexed keeps the keys under which idx still holds ref.
func stillIndexed(idx map[string]map[store.ContextRef]time.Time, keys []string, ref store.ContextRef) []string {
	var out []string
	for _, k := range keys {
		if indexed(idx, k, ref) {
			out = append(out, k)
		}
	}
	return out
}

// indexed reports whether idx[key] still holds ref.
func indexed(idx map[string]map[store.ContextRef]time.Time, key string, ref store.ContextRef) bool {
	if key == "" {
		return false
	}
	_, ok := idx[key][ref]
	return ok
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

// TokenIDs is the ID of every live token under k.
func (s *Store) TokenIDs(_ context.Context, k store.TokenKey) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	live := s.live(k)
	ids := make([]string, len(live))
	for i, t := range live {
		ids[i] = t.ID
	}
	return ids, nil
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

// DeleteToken removes the live token with this ID under k, compacting the
// set as RedeemAndReceipt does, so the removed entry's Secret is not left
// reachable from the backing array (clearTail).
func (s *Store) DeleteToken(_ context.Context, k store.TokenKey, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	set := s.live(k)
	for i, t := range set {
		if t.ID != id {
			continue
		}
		s.tokens[k] = append(set[:i:i], set[i+1:]...)
		clearTail(set, i)
		if len(s.tokens[k]) == 0 {
			delete(s.tokens, k)
		}
		return nil
	}
	return store.ErrNotFound
}

// PurgeTokens drops every token, clearing each set's entries so no
// secret stays reachable from a backing array (clearTail), and counts
// the live ones.
func (s *Store) PurgeTokens(context.Context) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	n := 0
	for k, set := range s.tokens {
		for _, t := range set {
			if t.ExpiresAt.After(now) {
				n++
			}
		}
		clearTail(set, 0)
		delete(s.tokens, k)
	}
	return n, nil
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

// FailReceipt sets Failed under the lock and touches nothing else, so a
// concurrent extend and this mark cannot erase each other.
func (s *Store) FailReceipt(_ context.Context, rk store.ReceiptKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.receipts[rk]
	if !ok || !r.RetainUntil.After(s.now()) {
		delete(s.receipts, rk)
		return store.ErrNotFound
	}
	r.Failed = true
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

func (s *Store) PutContext(ctx context.Context, k store.ContextKey, c store.Context, ttl time.Duration) error {
	_, err := s.PutContextRev(ctx, k, c, ttl)
	return err
}

// PutContextRev is PutContext, returning the revision it committed at
// (store.RevStore).
func (s *Store) PutContextRev(_ context.Context, k store.ContextKey, c store.Context, ttl time.Duration) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	// The write is an extension too, so it stamps the same clock TouchContext
	// does (store.Context). Leaving it to the caller would hand Task 10's
	// half-TTL rule a zero on every freshly written context, and a rule that
	// reads zero extends on every command — the write this exists to avoid.
	return s.writeContextLocked(k, c, now, ttl), nil
}

// writeContextLocked is the whole-record write PutContext and SwapContext
// share once SwapContext's precondition has held. It returns the revision
// the write took.
func (s *Store) writeContextLocked(k store.ContextKey, c store.Context, now time.Time, ttl time.Duration) uint64 {
	c.LastTouchedAt = now
	c.Rev, c.PolicyRev = 0, 0 // the entry holds the revisions; the record's copies are GetContext's to fill
	exp := now.Add(ttl)
	rev := s.nextRevLocked()
	s.contexts[k] = ctxEntry{c: c, exp: exp, rev: rev, policyRev: rev}
	// A re-put is an extension too, so the index entries come with it
	// (design §12). At a first login this is a no-op — the context is written
	// before it is indexed — and it matters when a second login joins or
	// replaces a live context.
	s.extendIndexesLocked(store.ContextRef{NAS: k.NAS, Username: k.Username}, exp)
	s.writes++
	if s.writes%sweepEvery == 0 {
		s.sweepLocked()
	}
	return rev
}

func (s *Store) GetContext(_ context.Context, k store.ContextKey) (store.Context, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.contexts[k]
	if !ok || !e.exp.After(s.now()) {
		delete(s.contexts, k)
		return store.Context{}, store.ErrNotFound
	}
	c := e.c
	c.Rev, c.PolicyRev = e.rev, e.policyRev
	return c, nil
}

// SwapContext is SwapLogin with no index change and no mark to check.
func (s *Store) SwapContext(ctx context.Context, k store.ContextKey, rev uint64, c store.Context, ttl time.Duration) error {
	return s.SwapLogin(ctx, k, rev, c, ttl, store.LoginWrite{})
}

// SwapContextRev is SwapContext, returning the revision it committed at
// (store.RevStore).
func (s *Store) SwapContextRev(ctx context.Context, k store.ContextKey, rev uint64, c store.Context,
	ttl time.Duration) (uint64, error) {
	return s.SwapLoginRev(ctx, k, rev, c, ttl, store.LoginWrite{})
}

// SwapLogin writes c only if the record at k still carries revision rev
// (for rev zero, only if there is no live record) and every mark in
// w.Marks is still as read; then the index change, all under the one
// lock, which is what makes the three one step (store.Store).
func (s *Store) SwapLogin(ctx context.Context, k store.ContextKey, rev uint64, c store.Context, ttl time.Duration,
	w store.LoginWrite) error {
	_, err := s.SwapLoginRev(ctx, k, rev, c, ttl, w)
	return err
}

// SwapLoginRev is SwapLogin, returning the revision it committed at
// (store.RevStore).
func (s *Store) SwapLoginRev(_ context.Context, k store.ContextKey, rev uint64, c store.Context, ttl time.Duration,
	w store.LoginWrite) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	e, ok := s.contexts[k]
	live := ok && e.exp.After(now)
	if live && e.rev != rev || !live && rev != 0 {
		return 0, store.ErrConflict
	}
	for _, m := range w.Marks {
		cur, ok := s.revocations[[2]string{m.Kind, m.Key}]
		if ok == m.At.IsZero() || ok && !cur.At.Equal(m.At) {
			return 0, store.ErrConflict
		}
	}
	committed := s.writeContextLocked(k, c, now, ttl)
	ref := store.ContextRef{NAS: k.NAS, Username: k.Username}
	if w.ClearRef {
		s.unindexRefLocked(ref)
	}
	if w.DropSid != "" || w.DropCertKey != "" {
		s.unindexLocked("", w.DropSid, w.DropCertKey, ref)
	}
	if w.Principal != "" || w.Sid != "" || w.CertKey != "" {
		s.indexLocked(w.Principal, w.Sid, w.CertKey, ref, w.IndexTTL)
	}
	return committed, nil
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
	e.rev = s.nextRevLocked()
	s.contexts[k] = e
	// The index entries go with the expiry, or a session kept alive by
	// activity outlives the entries a revocation reads (extendIndexesLocked).
	s.extendIndexesLocked(store.ContextRef{NAS: k.NAS, Username: k.Username}, e.exp)
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
	//
	// The rule under this lock: the ceiling read is the one on the record
	// now, which a join may have moved since the caller read it (spec §5.3).
	moved := store.ApplyPrivilege(&e.c, level)
	e.rev = s.nextRevLocked()
	// A level that moved is a write to what the refresh decides; a grant of
	// the level already held, which a device repeats, is not, or a session
	// authorizing often could keep the refresh losing (store.Context.PolicyRev).
	if moved {
		e.policyRev = e.rev
	}
	s.contexts[k] = e
	return nil
}

// AnnotateContext is the accounting path's setter, and it is TouchContext's
// and SetPrivilege's sibling: the read-modify-write happens inside this lock
// so that a revocation racing it is not overwritten by a copy of the record
// accounting read at the top of its request (store.Store).
//
// It writes at most two fields and deliberately moves neither the expiry nor
// LastTouchedAt: accounting is not activity for the idle TTL (spec §5.8).
func (s *Store) AnnotateContext(_ context.Context, k store.ContextKey, discHash, state string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.contexts[k]
	if !ok || !e.exp.After(s.now()) {
		delete(s.contexts, k)
		return store.ErrNotFound
	}
	if discHash != "" {
		e.c.SessionDiscriminators = addDiscriminator(e.c.SessionDiscriminators, discHash)
	}
	if state != "" {
		e.c.AccountingState = state
	}
	e.rev = s.nextRevLocked()
	s.contexts[k] = e
	return nil
}

// addDiscriminator appends h if it is not already present, evicting from the
// front once the set is full. The copy is not an accident: the slice header in
// the map may share its array with one a caller read out through GetContext,
// and appending in place would edit that caller's copy under it.
func addDiscriminator(set []string, h string) []string {
	for _, existing := range set {
		if existing == h {
			return set
		}
	}
	out := make([]string, 0, store.MaxSessionDiscriminators)
	if len(set) >= store.MaxSessionDiscriminators {
		set = set[len(set)-store.MaxSessionDiscriminators+1:]
	}
	out = append(out, set...)
	return append(out, h)
}

// RefreshContext is the broker's setter, and the fourth of the siblings: the
// read-modify-write happens inside this lock so that the annotation, the
// privilege raise, or the revocation that landed since the broker read the
// record is not carried away by a copy of it (store.Store).
//
// Unlike AnnotateContext it does extend the expiry and stamp LastTouchedAt. A
// refresh is a fresh authentication event; an accounting record is not.
func (s *Store) RefreshContext(_ context.Context, k store.ContextKey, r store.ContextRefresh, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	e, ok := s.contexts[k]
	if !ok || !e.exp.After(now) {
		delete(s.contexts, k)
		return store.ErrNotFound
	}
	// Both refusals are made here, under the lock, before anything is
	// written: a revision checked outside it could move before the write, and
	// a ceiling checked outside it could be the one a racing refresh replaced.
	if r.ExpectRev != 0 && e.rev != r.ExpectRev {
		return store.ErrConflict
	}
	// The window is read here, under the lock, from the pair this call is
	// about to overwrite. A caller computing it from a copy it read earlier
	// would compute it from a pair another refresh may already have moved.
	// The rule refuses past the grace window with nothing written.
	blobMoved, err := store.ApplyRefresh(&e.c, r)
	if err != nil {
		return err
	}
	e.exp = now.Add(ttl)
	e.c.LastTouchedAt = now
	e.rev = s.nextRevLocked()
	// The clocks and the expiry are not what a policy refresh decides; a new
	// blob hash is (store.Context.PolicyRev).
	if blobMoved {
		e.policyRev = e.rev
	}
	s.contexts[k] = e
	s.extendIndexesLocked(store.ContextRef{NAS: k.NAS, Username: k.Username}, e.exp)
	return nil
}

// SetRevokedAt marks and never deletes, so the next command is denied
// `credential_revoked` rather than answered as a session port49 never saw
// (store.Store; spec §5.6 row 2). It moves neither the expiry nor
// LastTouchedAt: row 6 reclaims the record on the idle TTL it was already on.
// It keeps the later of the mark it holds and the one it is given.
func (s *Store) SetRevokedAt(_ context.Context, k store.ContextKey, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.contexts[k]
	if !ok || !e.exp.After(s.now()) {
		delete(s.contexts, k)
		return store.ErrNotFound
	}
	store.ApplyRevokedAt(&e.c, at)
	e.rev = s.nextRevLocked()
	e.policyRev = e.rev
	s.contexts[k] = e
	return nil
}

// SetContextPolicy is the refresher's setter: the compare, the write and the
// clamps are one critical section (store.Store). It compares the policy
// revision, moves both revisions, and nothing about the expiry: a policy edit
// is not activity. The session ceiling only ever moves earlier here.
func (s *Store) SetContextPolicy(_ context.Context, k store.ContextKey, policyRev uint64, p store.ContextPolicy) error {
	if err := store.CheckContextPolicy(p); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.contexts[k]
	if !ok || !e.exp.After(s.now()) {
		delete(s.contexts, k)
		return store.ErrNotFound
	}
	if e.policyRev != policyRev {
		return store.ErrConflict
	}
	store.ApplyContextPolicy(&e.c, p)
	e.rev = s.nextRevLocked()
	e.policyRev = e.rev
	s.contexts[k] = e
	return nil
}

// StampRefreshed is the scheduled refresh's stamp under the one lock: it
// compares the policy revision and moves only Rev (store.Store).
func (s *Store) StampRefreshed(_ context.Context, k store.ContextKey, policyRev uint64, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.contexts[k]
	if !ok || !e.exp.After(s.now()) {
		delete(s.contexts, k)
		return store.ErrNotFound
	}
	if e.policyRev != policyRev {
		return store.ErrConflict
	}
	store.ApplyStamp(&e.c, at)
	e.rev = s.nextRevLocked()
	s.contexts[k] = e
	return nil
}

// RewriteContext writes c over the live record at k only while its
// revision is rev, under the one lock (store.Store): the sealing layer's
// narrow setter.
func (s *Store) RewriteContext(ctx context.Context, k store.ContextKey, rev uint64, c store.Context, ttl time.Duration,
	policyMoved bool) error {
	_, err := s.RewriteContextRev(ctx, k, rev, c, ttl, policyMoved)
	return err
}

// RewriteContextRev is RewriteContext, returning the revision it committed
// at (store.RevStore).
func (s *Store) RewriteContextRev(_ context.Context, k store.ContextKey, rev uint64, c store.Context, ttl time.Duration,
	policyMoved bool) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	e, ok := s.contexts[k]
	if !ok || !e.exp.After(now) {
		delete(s.contexts, k)
		return 0, store.ErrNotFound
	}
	if e.rev != rev {
		return 0, store.ErrConflict
	}
	c.Rev, c.PolicyRev = 0, 0 // the entry holds the revisions
	c.LastTouchedAt = e.c.LastTouchedAt
	if ttl > 0 {
		e.exp, c.LastTouchedAt = now.Add(ttl), now
	}
	e.c = c
	e.rev = s.nextRevLocked()
	if policyMoved {
		e.policyRev = e.rev
	}
	s.contexts[k] = e
	if ttl > 0 {
		s.extendIndexesLocked(store.ContextRef{NAS: k.NAS, Username: k.Username}, e.exp)
	}
	return e.rev, nil
}

func (s *Store) DeleteContext(_ context.Context, k store.ContextKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.contexts, k)
	return nil
}

// DeleteContextIf is DeleteContext as a compare-and-set on Rev (store.Store):
// the grace window's sweep never deletes a context a login wrote since it was
// read.
func (s *Store) DeleteContextIf(_ context.Context, k store.ContextKey, rev uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.contexts[k]
	if !ok || !e.exp.After(s.now()) {
		delete(s.contexts, k)
		return store.ErrNotFound
	}
	if e.rev != rev {
		return store.ErrConflict
	}
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

// extendIndexesLocked re-stamps every index entry naming ref so it lives at
// least as long as the context does (design §12). It is a no-op for a ref
// that has not been indexed, which is the ordering at login: the caller writes
// the context first and indexes it after.
func (s *Store) extendIndexesLocked(ref store.ContextRef, exp time.Time) {
	rec, ok := s.indexedAs[ref]
	if !ok {
		return
	}
	restamp(s.byPrincipal, rec.principal, ref, exp)
	for _, sid := range rec.sids {
		restamp(s.bySid, sid, ref, exp)
	}
	for _, certKey := range rec.certKeys {
		restamp(s.byCert, certKey, ref, exp)
	}
}

// restamp pushes an existing entry's expiry out, and does two things it might
// not look like it does. It never creates an entry: a ref the index no longer
// holds was unindexed or swept, and an extension must not resurrect it. And it
// never shortens one, matching PutBlob — a context written with a short TTL
// must not pull in the reach of a revocation that the index was given longer
// to answer.
func restamp(idx map[string]map[store.ContextRef]time.Time, key string, ref store.ContextRef, exp time.Time) {
	if key == "" {
		return
	}
	set := idx[key]
	if set == nil {
		return
	}
	if existing, ok := set[ref]; ok && exp.After(existing) {
		set[ref] = exp
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

// blankCertKey is store.BlankCertKey.
func blankCertKey(certKey string) bool {
	return store.BlankCertKey(certKey)
}

// IndexContext adds ref to each non-empty index — principal, sid, and cert —
// sharing the one ttl. A caller with no sid or cert passes "" to skip that
// index (store.ContextRef alone is not enough to reconstruct the context). A
// certificate key with no issuer or no serial is skipped the same way
// (blankCertKey).
func (s *Store) IndexContext(_ context.Context, principal, sid, certKey string, ref store.ContextRef, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.indexLocked(principal, sid, certKey, ref, ttl)
	return nil
}

func (s *Store) indexLocked(principal, sid, certKey string, ref store.ContextRef, ttl time.Duration) {
	if blankCertKey(certKey) {
		certKey = ""
	}
	exp := s.now().Add(ttl)
	addRef(s.byPrincipal, principal, ref, exp)
	addRef(s.bySid, sid, ref, exp)
	addRef(s.byCert, certKey, ref, exp)
	// Record where this ref now answers from, so an extension of its context
	// can carry these entries with it (extendIndexesLocked). A sid or cert is
	// added to what was recorded, never swapped for it: a joined context
	// answers under every login's credential (indexKeys). An empty key leaves
	// the record alone, matching the "" this method already reads as "skip
	// this index".
	rec := s.indexedAs[ref]
	if principal != "" {
		rec.principal = principal
	}
	rec.sids = withKey(rec.sids, sid)
	rec.certKeys = withKey(rec.certKeys, certKey)
	s.indexedAs[ref] = rec
	s.writes++
	if s.writes%sweepEvery == 0 {
		s.sweepLocked()
	}
}

// UnindexContext removes ref from each of the three indexes it was written
// under. A blank certificate key was never indexed and is skipped, as "" is.
func (s *Store) UnindexContext(_ context.Context, principal, sid, certKey string, ref store.ContextRef) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.unindexLocked(principal, sid, certKey, ref)
	return nil
}

func (s *Store) unindexLocked(principal, sid, certKey string, ref store.ContextRef) {
	if blankCertKey(certKey) {
		certKey = ""
	}
	removeRef(s.byPrincipal, principal, ref)
	removeRef(s.bySid, sid, ref)
	removeRef(s.byCert, certKey, ref)
	// Forget only the keys this call actually removed. A ref unindexed from
	// one index of three still answers from the others, and an extension has
	// to keep reaching them.
	if rec, ok := s.indexedAs[ref]; ok {
		if rec.principal == principal {
			rec.principal = ""
		}
		rec.sids = withoutKey(rec.sids, sid)
		rec.certKeys = withoutKey(rec.certKeys, certKey)
		if rec.empty() {
			delete(s.indexedAs, ref)
		} else {
			s.indexedAs[ref] = rec
		}
	}
}

// UnindexRef removes ref from every entry recorded for it in indexedAs — its
// principal and every sid and certificate a login was indexed under — and
// forgets the record, so no extension re-stamps any of them.
func (s *Store) UnindexRef(_ context.Context, ref store.ContextRef) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.unindexRefLocked(ref)
	return nil
}

func (s *Store) unindexRefLocked(ref store.ContextRef) {
	rec, ok := s.indexedAs[ref]
	if !ok {
		return
	}
	removeRef(s.byPrincipal, rec.principal, ref)
	for _, sid := range rec.sids {
		removeRef(s.bySid, sid, ref)
	}
	for _, certKey := range rec.certKeys {
		removeRef(s.byCert, certKey, ref)
	}
	delete(s.indexedAs, ref)
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
	// The reverse record follows the move, or the next extension of this
	// context would re-stamp the sid entry the rotation just removed and
	// leave the live one to expire underneath it.
	if rec, ok := s.indexedAs[ref]; ok || newSid != "" {
		rec.sids = withKey(withoutKey(rec.sids, oldSid), newSid)
		if rec.empty() {
			delete(s.indexedAs, ref)
		} else {
			s.indexedAs[ref] = rec
		}
	}
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

// IndexToken adds k under principal and certKey, each skipped when empty,
// and a certificate key with no issuer or no serial the same way
// (blankCertKey).
func (s *Store) IndexToken(_ context.Context, principal, certKey string, k store.TokenKey, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if blankCertKey(certKey) {
		certKey = ""
	}
	exp := s.now().Add(ttl)
	for _, idx := range []struct {
		m   map[string]map[store.TokenKey]time.Time
		key string
	}{{s.tokensByPrincipal, principal}, {s.tokensByCert, certKey}} {
		if idx.key == "" {
			continue
		}
		set := idx.m[idx.key]
		if set == nil {
			set = make(map[store.TokenKey]time.Time)
			idx.m[idx.key] = set
		}
		if exp.After(set[k]) {
			set[k] = exp
		}
	}
	s.wroteLocked()
	return nil
}

func (s *Store) TokensByPrincipal(_ context.Context, principal string) ([]store.TokenKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return liveTokenKeys(s.tokensByPrincipal[principal], s.now()), nil
}

func (s *Store) TokensByCert(_ context.Context, certKey string) ([]store.TokenKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return liveTokenKeys(s.tokensByCert[certKey], s.now()), nil
}

// liveTokenKeys is set's unexpired keys, sorted by (NAS, Username).
func liveTokenKeys(set map[store.TokenKey]time.Time, now time.Time) []store.TokenKey {
	var out []store.TokenKey
	for k, exp := range set {
		if exp.After(now) {
			out = append(out, k)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].NAS != out[j].NAS {
			return out[i].NAS < out[j].NAS
		}
		return out[i].Username < out[j].Username
	})
	return out
}

// sweepTokenIndex is sweepIndex for the token indexes.
func sweepTokenIndex(idx map[string]map[store.TokenKey]time.Time, now time.Time) {
	for k, set := range idx {
		for tk, exp := range set {
			if !exp.After(now) {
				delete(set, tk)
			}
		}
		if len(set) == 0 {
			delete(idx, k)
		}
	}
}

// idemKey joins principal and key so idempotency is scoped per principal:
// one principal's replay must not answer another's request.
func idemKey(principal, key string) string {
	return principal + "\x00" + key
}

// liveIdemLocked is the live record under k, deleting one past its expiry.
func (s *Store) liveIdemLocked(k string) (store.Idempotency, bool) {
	r, ok := s.idem[k]
	if !ok {
		return store.Idempotency{}, false
	}
	if !r.ExpiresAt.After(s.now()) {
		delete(s.idem, k)
		return store.Idempotency{}, false
	}
	return r, true
}

// errNoHolder refuses an idempotency record without a holder: the empty
// holder is one any request can name, so it would hand a reservation's
// rights to everyone.
var errNoHolder = errors.New("store: an idempotency record must name its holder")

// ReserveIdempotency is design §17's put-if-absent: under the one lock, a
// live record is returned untouched and only its absence is written.
func (s *Store) ReserveIdempotency(_ context.Context, principal, key string, rec store.Idempotency) (store.Idempotency, bool, error) {
	if rec.Holder == "" {
		return store.Idempotency{}, false, errNoHolder
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	k := idemKey(principal, key)
	if cur, ok := s.liveIdemLocked(k); ok {
		return cur, false, nil
	}
	s.idem[k] = rec
	s.wroteLocked()
	return store.Idempotency{}, true, nil
}

// CompleteIdempotency writes rec over the live record only while that
// record's holder is expect. Nobody holds the empty holder.
func (s *Store) CompleteIdempotency(_ context.Context, principal, key, expect string, rec store.Idempotency) error {
	if rec.Holder == "" {
		return errNoHolder
	}
	if expect == "" {
		return store.ErrConflict
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	k := idemKey(principal, key)
	if cur, ok := s.liveIdemLocked(k); !ok || cur.Holder != expect {
		return store.ErrConflict
	}
	s.idem[k] = rec
	s.wroteLocked()
	return nil
}

// ReleaseIdempotency deletes holder's own pending reservation and nothing
// else.
func (s *Store) ReleaseIdempotency(_ context.Context, principal, key, holder string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := idemKey(principal, key)
	if cur, ok := s.liveIdemLocked(k); ok && cur.Pending && cur.Holder == holder {
		delete(s.idem, k)
	}
	return nil
}

// PutRevocation writes r unless a mark for its key already stands.
func (s *Store) PutRevocation(_ context.Context, r store.Revocation) error {
	if err := store.CheckRevocation(r); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	k := [2]string{r.Kind, r.Key}
	if _, ok := s.revocations[k]; !ok {
		s.revocations[k] = r
	}
	s.wroteLocked()
	return nil
}

func (s *Store) GetRevocation(_ context.Context, kind, key string) (store.Revocation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r, ok := s.revocations[[2]string{kind, key}]; ok {
		return r, nil
	}
	return store.Revocation{}, store.ErrNotFound
}

// DeleteRevocation lifts the mark, and keeps no lift record: the memory
// store is one process's, whose marks feed is the store itself, so no mark
// can land over a lift its writer had not seen, and none is flagged
// (decision 51; final check F-M1).
func (s *Store) DeleteRevocation(_ context.Context, kind, key string, _ store.Lift) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.revocations, [2]string{kind, key})
	return nil
}

// GetLift is always ErrNotFound: the memory store keeps no lift record.
func (s *Store) GetLift(context.Context, string, string) (store.Lift, error) {
	return store.Lift{}, store.ErrNotFound
}

func (s *Store) ListRevocations(_ context.Context) ([]store.Revocation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]store.Revocation, 0, len(s.revocations))
	for _, r := range s.revocations {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Key < out[j].Key
	})
	return out, nil
}

// wroteLocked counts a write and sweeps every sweepEvery writes, as every
// writer here does.
func (s *Store) wroteLocked() {
	s.writes++
	if s.writes%sweepEvery == 0 {
		s.sweepLocked()
	}
}

var _ store.RevStore = (*Store)(nil)

// Seen is the store's revision counter: no write has a higher one.
func (s *Store) Seen() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.revs
}

// Ping answers at once: the store is in the process.
func (s *Store) Ping(context.Context) error { return nil }

// SupersedeTokens keeps the later instant at k, for SupersededFor from now.
func (s *Store) SupersedeTokens(_ context.Context, k store.TokenKey, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.superseded == nil {
		s.superseded = map[store.TokenKey]supersededEntry{}
	}
	s.superseded[k] = s.superseded[k].with(at, s.now())
	return nil
}

// SupersedeAll keeps the later all-keys instant, for SupersededFor.
func (s *Store) SupersedeAll(_ context.Context, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.supersededAll = s.supersededAll.with(at, s.now())
	return nil
}

// with is e after at was written at now: the later of at and e's own
// instant while e is live, kept for SupersededFor from now.
func (e supersededEntry) with(at, now time.Time) supersededEntry {
	if now.Before(e.until) && e.at.After(at) {
		at = e.at
	}
	return supersededEntry{at: at, until: now.Add(store.SupersededFor)}
}

// SupersededAt is the later live instant of k's and every key's.
func (s *Store) SupersededAt(_ context.Context, k store.TokenKey) (time.Time, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	var at time.Time
	for _, e := range []supersededEntry{s.superseded[k], s.supersededAll} {
		if now.Before(e.until) && e.at.After(at) {
			at = e.at
		}
	}
	return at, nil
}

// membershipEntry is one principal's record and its expiry, or, with
// forgottenAt set, the tombstone a forget left: no record, only the time a
// write must not be verified before.
type membershipEntry struct {
	m           store.Membership
	exp         time.Time
	forgottenAt time.Time
	ver         uint64 // the record's version: PutPin compares it
}

// memberKeyEntry is one mapping key's index entry: every principal that
// registered a claim to it, and when it was last refused. It holds no
// pointer: MembershipByKey answers the one claimant whose live record lists
// the key, and a claimant that stopped listing it, or whose record is gone,
// is filtered there, so a stale claimant only ever denies. It lives as long
// as the longest record that registered.
type memberKeyEntry struct {
	claimants []string
	refusedAt time.Time
	expires   time.Time
}

func cloneMembership(m store.Membership) store.Membership {
	m.GroupDNs, m.GroupNames, m.MapKeys = slices.Clone(m.GroupDNs), slices.Clone(m.GroupNames), slices.Clone(m.MapKeys)
	m.Sealed = bytes.Clone(m.Sealed)
	return m
}

// liveMembershipLocked is principal's record, not a tombstone and not past
// its expiry; one past it is dropped.
func (s *Store) liveMembershipLocked(principal string) (membershipEntry, bool) {
	e, ok := s.memberships[principal]
	if !ok {
		return membershipEntry{}, false
	}
	if !alive(e.exp, s.now()) {
		delete(s.memberships, principal)
		return membershipEntry{}, false
	}
	return e, true
}

// PutMembership registers m's principal on each of its keys, then keeps
// the later verification at principal, dropping one from before the
// principal's forget. The registration comes first, as in etcd, where the
// two are separate writes: a write torn between them leaves a claimant with
// no record, which only denies, never a record that lists a key its index
// does not know.
func (s *Store) PutMembership(_ context.Context, m store.Membership, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.putMembershipLocked(m, ttl, nil)
}

// PutPin is PutMembership with no lease, written only when the record
// stands as expect says (store.Store).
func (s *Store) PutPin(_ context.Context, m store.Membership, expect store.PinExpect) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.putMembershipLocked(m, store.NoExpiry, &expect)
}

// initMembersLocked makes the membership maps, each only if it is missing.
func (s *Store) initMembersLocked() {
	if s.memberships == nil {
		s.memberships = map[string]membershipEntry{}
	}
	if s.memberKeys == nil {
		s.memberKeys = map[string]memberKeyEntry{}
	}
}

// stands reports whether e, a live record or none, is the state expect names.
func (e membershipEntry) stands(live bool, expect store.PinExpect) bool {
	switch {
	case expect.Absent:
		return !live
	case expect.Forgotten:
		return live && !e.forgottenAt.IsZero()
	}
	return live && e.forgottenAt.IsZero() && expect.Version != 0 && e.ver == expect.Version
}

func (s *Store) putMembershipLocked(m store.Membership, ttl time.Duration, expect *store.PinExpect) error {
	s.initMembersLocked()
	if expect != nil {
		cur, live := s.liveMembershipLocked(m.Principal)
		if !cur.stands(live, *expect) {
			return store.ErrConflict
		}
	}
	exp := expiry(s.now(), ttl)
	for _, key := range m.MapKeys {
		e, found := s.liveKeyLocked(key)
		if !slices.Contains(e.claimants, m.Principal) {
			e.claimants = append(slices.Clone(e.claimants), m.Principal)
			sort.Strings(e.claimants)
		}
		if found {
			e.expires = laterExp(e.expires, exp)
		} else {
			e.expires = exp
		}
		s.memberKeys[key] = e
	}
	if e, ok := s.liveMembershipLocked(m.Principal); ok {
		if !e.forgottenAt.IsZero() {
			if m.VerifiedAt.Before(e.forgottenAt) {
				return nil
			}
		} else if e.m.VerifiedAt.After(m.VerifiedAt) ||
			(e.m.VerifiedAt.Equal(m.VerifiedAt) && e.m.Refused && !m.Refused) {
			return nil // a refusal outranks a grant verified at its instant
		}
	}
	s.memberVer++
	s.memberships[m.Principal] = membershipEntry{m: cloneMembership(m), exp: exp, ver: s.memberVer}
	s.touchLocked()
	return nil
}

// liveKeyLocked is key's entry, or an empty one and false when it is absent
// or past its expiry.
func (s *Store) liveKeyLocked(key string) (memberKeyEntry, bool) {
	e, ok := s.memberKeys[key]
	if !ok || !alive(e.expires, s.now()) {
		return memberKeyEntry{}, false
	}
	return e, true
}

// claimsKeyLocked is whether principal has a live, unrefused record that
// lists key.
func (s *Store) claimsKeyLocked(principal, key string) bool {
	e, live := s.liveMembershipLocked(principal)
	return live && e.forgottenAt.IsZero() && !e.m.Refused && slices.Contains(e.m.MapKeys, key)
}

// expiry is ttl's expiry from now: none, the zero time, for
// store.NoExpiry (plan 11a, R13).
func expiry(now time.Time, ttl time.Duration) time.Time {
	if ttl == store.NoExpiry {
		return time.Time{}
	}
	return now.Add(ttl)
}

// alive reports whether a record expiring at exp stands at now: one with no
// expiry always does.
func alive(exp, now time.Time) bool { return exp.IsZero() || exp.After(now) }

// laterExp is the later of two expiries of records that exist, no expiry
// being the latest.
func laterExp(a, b time.Time) time.Time {
	if a.IsZero() || b.IsZero() {
		return time.Time{}
	}
	return laterOf(a, b)
}

func laterOf(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

// RefuseMapKeys marks each key refused as of at: a record verified after it
// answers the key again, one verified at or before it does not.
func (s *Store) RefuseMapKeys(_ context.Context, mapKeys []string, at time.Time, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.initMembersLocked()
	exp := expiry(s.now(), ttl)
	for _, key := range mapKeys {
		e, found := s.liveKeyLocked(key)
		e.refusedAt = laterOf(e.refusedAt, at)
		if found {
			e.expires = laterExp(e.expires, exp)
		} else {
			e.expires = exp
		}
		s.memberKeys[key] = e
	}
	s.touchLocked()
	return nil
}

func (s *Store) GetMembership(_ context.Context, principal string) (store.Membership, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.liveMembershipLocked(principal)
	if ok && !e.forgottenAt.IsZero() {
		return store.Membership{}, store.ErrForgotten
	}
	if !ok {
		return store.Membership{}, store.ErrNotFound
	}
	out := cloneMembership(e.m)
	out.Version = e.ver
	return out, nil
}

// MembershipByKey answers the one claimant whose live, unrefused record
// lists the key, when the key was not refused after that record's
// verification; none, or more than one, is ErrNotFound.
func (s *Store) MembershipByKey(_ context.Context, mapKey string) (store.Membership, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, _ := s.liveKeyLocked(mapKey)
	principal := ""
	for _, c := range k.claimants {
		if s.claimsKeyLocked(c, mapKey) {
			if principal != "" {
				return store.Membership{}, store.ErrNotFound
			}
			principal = c
		}
	}
	if principal == "" {
		return store.Membership{}, store.ErrNotFound
	}
	e, _ := s.liveMembershipLocked(principal)
	if !k.refusedAt.IsZero() && !e.m.VerifiedAt.After(k.refusedAt) {
		return store.Membership{}, store.ErrNotFound
	}
	return cloneMembership(e.m), nil
}

func (s *Store) MembershipPrincipals(context.Context) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for p := range s.memberships {
		if e, ok := s.liveMembershipLocked(p); ok && e.forgottenAt.IsZero() {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out, nil
}

// DeleteMembership replaces the record with a tombstone of the forget's
// time, kept for what the record had left. memberKeys is left alone, as
// etcd leaves mk/.
func (s *Store) DeleteMembership(_ context.Context, principal string) (store.Membership, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.liveMembershipLocked(principal)
	if ok && !e.forgottenAt.IsZero() {
		return store.Membership{}, store.ErrNotFound
	}
	now := s.now()
	s.initMembersLocked()
	s.memberVer++
	if !ok { // nothing held: the tombstone has no lease, so no copy elsewhere can outlive it
		s.memberships[principal] = membershipEntry{forgottenAt: now, ver: s.memberVer}
		s.touchLocked()
		return store.Membership{}, store.ErrNotFound
	}
	s.memberships[principal] = membershipEntry{forgottenAt: now, exp: laterExp(e.exp, now.Add(store.TombstoneFloor)),
		ver: s.memberVer}
	s.touchLocked()
	return cloneMembership(e.m), nil
}

// touchLocked counts a write, and sweeps every sweepEvery of them.
func (s *Store) touchLocked() {
	s.writes++
	if s.writes%sweepEvery == 0 {
		s.sweepLocked()
	}
}

type onceEntry struct {
	value []byte
	exp   time.Time
}

type logoutEntry struct {
	l   store.Logout
	exp time.Time
}

func (s *Store) PutOnce(_ context.Context, key string, value []byte, ttl time.Duration) (bool, error) {
	if key == "" {
		return false, store.ErrNoKey
	}
	if ttl <= 0 {
		return false, store.ErrBadTTL
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if e, ok := s.once[key]; ok && now.Before(e.exp) {
		return false, nil
	}
	s.once[key] = onceEntry{value: append([]byte(nil), value...), exp: now.Add(ttl)}
	s.wroteLocked()
	return true, nil
}

func (s *Store) TakeOnce(_ context.Context, key string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.once[key]
	delete(s.once, key)
	if !ok || !s.now().Before(e.exp) {
		return nil, store.ErrNotFound
	}
	s.wroteLocked()
	return e.value, nil
}

func (s *Store) PutOIDCOwner(_ context.Context, key, principal string, ttl time.Duration) error {
	if key == "" {
		return store.ErrNoKey
	}
	if principal == "" {
		return store.ErrNoPrincipal
	}
	if ttl <= 0 {
		return store.ErrBadTTL
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	set := s.owners[key]
	if set == nil {
		set = map[string]store.OwnerPrincipal{}
		s.owners[key] = set
	}
	for p, e := range set {
		if !now.Before(e.ExpiresAt) {
			delete(set, p)
		}
	}
	exp := now.Add(ttl)
	if e, ok := set[principal]; ok && e.ExpiresAt.After(exp) {
		exp = e.ExpiresAt
	}
	set[principal] = store.OwnerPrincipal{Principal: principal, WrittenAt: now, ExpiresAt: exp}
	s.wroteLocked()
	return nil
}

func (s *Store) OIDCOwner(_ context.Context, key string) (store.OIDCOwner, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	var o store.OIDCOwner
	for _, e := range s.owners[key] {
		if now.Before(e.ExpiresAt) {
			o.Principals = append(o.Principals, e)
		}
	}
	if len(o.Principals) == 0 {
		return store.OIDCOwner{}, store.ErrNotFound
	}
	slices.SortFunc(o.Principals, func(a, b store.OwnerPrincipal) int { return strings.Compare(a.Principal, b.Principal) })
	return o, nil
}

func (s *Store) PutLogout(_ context.Context, l store.Logout, ttl time.Duration) error {
	if l.Key == "" {
		return store.ErrNoKey
	}
	if ttl <= 0 {
		return store.ErrBadTTL
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	next := logoutEntry{l: l, exp: now.Add(ttl)}
	if e, ok := s.logout[l.Key]; ok && now.Before(e.exp) {
		if e.l.At.After(l.At) {
			next.l = e.l
		}
		if e.exp.After(next.exp) {
			next.exp = e.exp
		}
	}
	s.logout[l.Key] = next
	s.wroteLocked()
	return nil
}

func (s *Store) GetLogout(_ context.Context, key string) (store.Logout, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.logout[key]
	if !ok || !s.now().Before(e.exp) {
		return store.Logout{}, store.ErrNotFound
	}
	return e.l, nil
}

type mfaProofEntry struct {
	p   store.MFAProof
	exp time.Time
}

func (s *Store) PutMFAProof(_ context.Context, p store.MFAProof, ttl time.Duration) error {
	if p.Key == "" {
		return store.ErrNoKey
	}
	if ttl <= 0 {
		return store.ErrBadTTL
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	next := mfaProofEntry{p: p, exp: now.Add(ttl)}
	if e, ok := s.mfaProof[p.Key]; ok && now.Before(e.exp) {
		if e.p.At.After(p.At) {
			next.p = e.p
		}
		if e.exp.After(next.exp) {
			next.exp = e.exp
		}
	}
	s.mfaProof[p.Key] = next
	s.wroteLocked()
	return nil
}

func (s *Store) GetMFAProof(_ context.Context, key string) (store.MFAProof, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.mfaProof[key]
	if !ok || !s.now().Before(e.exp) {
		return store.MFAProof{}, store.ErrNotFound
	}
	return e.p, nil
}

// memAttempts is a sign-in attempt count and the end of its window.
type memAttempts struct {
	n   int
	end time.Time
}

func (s *Store) NoteSignInAttempt(_ context.Context, key string, window time.Duration) (int, time.Time, error) {
	if key == "" {
		return 0, time.Time{}, store.ErrNoKey
	}
	if window <= 0 {
		return 0, time.Time{}, store.ErrBadTTL
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	a := s.attempts[key]
	if !now.Before(a.end) {
		a = memAttempts{end: now.Add(window)}
	}
	a.n++
	s.attempts[key] = a
	s.wroteLocked()
	return a.n, a.end, nil
}

func (s *Store) UndoSignInAttempt(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if a, ok := s.attempts[key]; ok && s.now().Before(a.end) && a.n > 0 {
		a.n--
		s.attempts[key] = a
	}
	return nil
}

func (s *Store) ClearSignInAttempts(_ context.Context, key string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.attempts[key]
	delete(s.attempts, key)
	if !ok || !s.now().Before(a.end) {
		return 0, nil
	}
	return a.n, nil
}
