package crypt

import (
	"errors"
	"sync"
	"time"

	"github.com/rhwendt/port49/internal/store"
)

// ErrNotLastWritten is a context that opens at its key but is sealed below
// the highest write sequence this process knows there: another login's
// record, or an earlier version of the same context, written back by
// whoever can write the store (plan 7d, Ruling 17; plan 7e, Ruling 3).
// GetContext returns it inside an UnreadableContextError, so every handler
// treats it as a record that will not open.
var ErrNotLastWritten = errors.New("crypt: sealed below the newest write this port49d knows at its key")

// DefaultLedgerKeep is how long past the latest sealed ceiling seen at a
// key its mark is kept, at least: longer than any grace window a context
// is kept past its ceiling, so a record put back is past its ceiling, and
// denied by it, before its mark goes.
const DefaultLedgerKeep = 24 * time.Hour

// Ledger is, per context key, the highest write sequence this process
// knows there (plan 7e, Ruling 3; decision 36). Every context seal carries
// a sequence above the revision its write compares on, above every store
// revision the writing process has seen (store.RevStore.Seen), and above
// the key's mark here: so every write that lands at a key is sealed above
// every earlier one, whichever process made it, and no store writer can
// forge it.
//
// The rule, in full:
//   - A write at k compared on rev seals seq = max(rev, inner.Seen(),
//     next(k)). next(k) is the mark plus one, or the base for a key with
//     no mark.
//   - A read admits a record whose sealed seq is at or above the key's
//     mark, or at or above the base when the key has none, and then
//     Observes it.
//   - Below that, a record whose revision is below the mark's revision was
//     served before the write that set the mark committed (stale), and is
//     read again, up to twice. Anything else is ErrNotLastWritten.
//   - A write that lands Observes its own seq at the revision it committed
//     at.
//   - A write that fails needs nothing. A conflict wrote nothing. A
//     deadline or an outage may have committed it, and if it did, the next
//     read finds the higher sequence and admits it.
//   - Deletes forget nothing: a record put back after a delete is still
//     below the mark.
//
// A record below the mark is another login's, or an earlier version of
// the same context, written back. The base is the revision just past the
// start's scan of the contexts, which saw every record then at a key.
//
// The mark is fed by this process's own writes that land, its reads, the
// store's context feed (FollowContexts) and, at a start, the ledger record
// (LoadLedger, Seed). Each only raises. A write of unknown outcome needs
// nothing: if it landed, its sequence is the higher and the next read
// admits it; if not, the store holds the record the mark names. A delete
// forgets nothing.
//
// A revocation whose plaintext mark landed and whose seal did not is the
// key's revocation floor (final review 7d-2 I-1): GetContext takes the
// latest of the sealed time, the plaintext time and the floor. The floor
// is set by this process's own revocation (revoked), held through the
// mark and every sequence sealed before the revocation landed, and by any
// record it reads or the feed brings at the mark's sequence with a
// plaintext revoked_at; only a later sequence clears it.
//
// A mark is kept until keep past the latest sealed ceiling seen at its
// key; one that saw a context with no ceiling (max_session_age: never) is
// kept for good (Prune).
//
// One Ledger is shared by every Wrap in a process (WithLedger). It is safe
// for concurrent use.
type Ledger struct {
	mu    sync.Mutex
	m     map[store.ContextKey]*ledgerEntry
	base  uint64
	keep  time.Duration
	dirty map[store.ContextKey]bool
}

type ledgerEntry struct {
	hw       uint64    // the highest sequence known at the key
	rev      uint64    // the revision the record at hw was read or written at; zero when unknown
	floor    time.Time // a revocation's plaintext time, held while hw <= floorSeq
	floorSeq uint64    // the highest sequence the floor holds through
	ceiling  time.Time // the latest sealed ceiling seen at the key
	never    bool      // a context with no ceiling was seen at the key
}

// NewLedger is an empty ledger with a base of zero and the default keep.
func NewLedger() *Ledger {
	return &Ledger{m: map[store.ContextKey]*ledgerEntry{}, keep: DefaultLedgerKeep,
		dirty: map[store.ContextKey]bool{}}
}

// SetBase raises the base to rev: a key with no mark admits only a record
// sealed at or above it. port49d sets it just past its start's scan.
func (l *Ledger) SetBase(rev uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if rev > l.base {
		l.base = rev
	}
}

// Base is the base.
func (l *Ledger) Base() uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.base
}

// SetKeep sets how long past the latest ceiling a mark is kept, never
// below DefaultLedgerKeep.
func (l *Ledger) SetKeep(d time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.keep = max(d, DefaultLedgerKeep)
}

func (l *Ledger) entry(k store.ContextKey) *ledgerEntry {
	e := l.m[k]
	if e == nil {
		e = &ledgerEntry{}
		l.m[k] = e
	}
	return e
}

// Observe is a record known at k: sealed at seq, read or written at rev,
// with its plaintext revocation and its sealed ceiling (zero: never). It
// raises k's mark and never lowers it.
func (l *Ledger) Observe(k store.ContextKey, seq, rev uint64, plainRevokedAt, ceiling time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.observe(k, seq, rev, plainRevokedAt, ceiling)
}

func (l *Ledger) observe(k store.ContextKey, seq, rev uint64, plainRevokedAt, ceiling time.Time) {
	e := l.entry(k)
	changed := false
	switch {
	case seq > e.hw:
		e.hw, e.rev, changed = seq, rev, true
		if seq > e.floorSeq {
			e.floor, e.floorSeq = time.Time{}, 0
		}
	case seq == e.hw && rev > e.rev:
		e.rev = rev
	}
	if seq == e.hw && !plainRevokedAt.IsZero() && plainRevokedAt.After(e.floor) {
		e.floor, e.floorSeq, changed = plainRevokedAt, max(e.floorSeq, seq), true
	}
	switch {
	case ceiling.IsZero() && seq >= e.hw && !e.never:
		e.never, changed = true, true
	case ceiling.After(e.ceiling):
		e.ceiling, changed = ceiling, true
	}
	if changed {
		l.dirty[k] = true
	}
}

// Seed is Observe from the ledger record (plan 7e, Ruling 4).
func (l *Ledger) Seed(m store.LedgerMark) {
	ceiling := time.Time{}
	if !m.Until.IsZero() {
		ceiling = m.Until.Add(-l.keepFor())
	}
	l.Observe(m.Key, m.Seq, 0, m.RevokedAt, ceiling)
}

func (l *Ledger) keepFor() time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.keep
}

// admits reports whether a record sealed at seq may be read at k.
func (l *Ledger) admits(k store.ContextKey, seq uint64) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if e, ok := l.m[k]; ok && e.hw > 0 {
		return seq >= e.hw
	}
	return seq >= l.base
}

// next is the least sequence a write at k may seal: above the mark, or
// the base for a key with none.
func (l *Ledger) next(k store.ContextKey) uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	if e, ok := l.m[k]; ok && e.hw > 0 {
		return e.hw + 1
	}
	return max(l.base, 1)
}

// stale reports whether a record read at k at rev was served before the
// write that set the mark committed.
func (l *Ledger) stale(k store.ContextKey, rev uint64) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.m[k]
	return ok && e.rev > 0 && rev < e.rev
}

// wrote is a write of this process's that landed at k: sealed at seq,
// committed at committed (zero when the store did not say).
func (l *Ledger) wrote(k store.ContextKey, seq, committed uint64, ceiling time.Time) {
	l.Observe(k, seq, committed, time.Time{}, ceiling)
}

// revoked records at as k's revocation floor once this process's
// revocation's plaintext mark has landed there; seen is the store revision
// this process had seen once it landed (store.RevStore.Seen). The floor
// holds through the mark and every sequence below seen, which the record
// the plaintext mark landed on, and any record put back from before it,
// were sealed at; every write this process sends after it seals at seen
// or above the mark (seqFor), and clears it. So a login that replaces a
// revoked record this process could not open, at a key it has no mark
// for, is not read as revoked: at the 7e upgrade the start's refresh
// revokes every form-3 context, and each user's next login replaces one.
func (l *Ledger) revoked(k store.ContextKey, at time.Time, seen uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.entry(k)
	if at.After(e.floor) {
		e.floor = at
	}
	e.floorSeq = max(e.floorSeq, e.hw)
	if seen > 0 {
		e.floorSeq = max(e.floorSeq, seen-1)
	}
	l.dirty[k] = true
}

// floor is k's revocation floor, zero when it has none.
func (l *Ledger) floor(k store.ContextKey) time.Time {
	l.mu.Lock()
	defer l.mu.Unlock()
	if e, ok := l.m[k]; ok {
		return e.floor
	}
	return time.Time{}
}

// Dirty is every mark raised since the last call, which it clears, for
// the ledger record's keeper (Task 10).
func (l *Ledger) Dirty() []store.LedgerMark {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]store.LedgerMark, 0, len(l.dirty))
	for k := range l.dirty {
		e := l.m[k]
		if e == nil {
			continue
		}
		m := store.LedgerMark{Key: k, Seq: e.hw, RevokedAt: e.floor}
		if !e.never && !e.ceiling.IsZero() {
			m.Until = e.ceiling.Add(l.keep)
		}
		out = append(out, m)
	}
	clear(l.dirty)
	return out
}

// Redirty marks ms owed again: the keeper's write of them failed.
func (l *Ledger) Redirty(ms []store.LedgerMark) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, m := range ms {
		l.dirty[m.Key] = true
	}
}

// Pending is how many marks are owed to the ledger record.
func (l *Ledger) Pending() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.dirty)
}

// Prune drops every mark past its keep after the latest ceiling seen at
// its key, and returns how many. A mark that saw a never context stays.
func (l *Ledger) Prune(now time.Time) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for k, e := range l.m {
		if !e.never && !e.ceiling.IsZero() && now.After(e.ceiling.Add(l.keep)) {
			delete(l.m, k)
			delete(l.dirty, k)
			n++
		}
	}
	return n
}

// Len is how many keys the ledger holds a mark for.
func (l *Ledger) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.m)
}
