package crypt

import (
	"errors"
	"sync"

	"github.com/rhwendt/port49/internal/store"
)

// ErrNotLastWritten is a context that opens at its key but is not the
// write this process last made there, or first read there: another
// login's record, or an earlier version of the same context, written back
// by whoever can write the store (plan 7d; Ruling 17; re-check IA1;
// Ruling T12-g). GetContext returns it inside an
// UnreadableContextError, so every handler treats it as a record that
// will not open.
var ErrNotLastWritten = errors.New("crypt: not the context this port49d last wrote at its key")

// Ledger is, per context key, the write this process last made there,
// or first read there (plan 7d; Ruling 17; re-check IA1). A sealed
// context is bound to its key, not to the login that wrote it, so
// without the ledger a record of Alice's saved from leaf-01/netops and
// written back over Bob's there would authorize Bob's session as Alice.
// Each write is named by the write ID sealed into it, fresh on every seal
// (contextSecret), not by its ctx_id, which a join, a refresh or a
// revocation keeps: so an earlier version of the same context, written
// back, is denied too, and cannot undo a self revocation or a policy
// narrowing (Ruling T12-g).
//
// A write is told before it is sent (begin) and when it ends (end): in
// flight it is admitted beside the last, landed it replaces the last,
// refused (ErrConflict, ErrNotFound) it wrote nothing, and with any other
// error it may have committed (spec §5.6), so it stays admitted until a
// later write lands, or a read finds it, which proves it landed (re-check
// 2 M-B1).
//
// Until Seal, a key with no entry takes the first record read there, so
// a start's reads seed it before any listener binds. After Seal, a key
// with no entry admits nothing but what this process writes there itself
// (re-check 2 I1): port49d seals the ledger once the start has read every
// kept context, so a record put back at a key no one here has read is
// never taken as that key's. A record put back before the start's first
// read of its key is the residual.
//
// Two writes that both landed can end in either order, and the store
// holds the one it committed last, not the one that ended last (Task 4b
// defect: a login that read another's write in flight and swapped on it;
// Task 6b: two first logins racing on an empty key). So each write that
// lands reports the revision it committed at (store.RevStore), and
// replaces the last only when that is above the last's. Revisions never
// repeat at a key and only grow (store.Context.Rev), so a write that
// compared on a revision below the last's committed before it, if it
// landed at all; one whose outcome is unknown is not admitted then
// (earlier). A landed write whose revision the store did not report is
// not placed, and the key admits nothing but writes in flight until
// another lands, which fails closed. A read sets the last at no revision:
// any write that lands replaces it (Task 4b fix 2 review I1, N1).
//
// Revisions go back when etcd is restored from a snapshot under a running
// port49d (store.Context.Rev). A write sent after the last ended committed
// after it, so one that reports a revision below the last's is the
// store's revisions going back, and it is placed as the last, with its
// revision (Task 6b review C1): a login after the restore is admitted,
// and the stale last, replayed, is denied. A key no write lands at after
// the restore keeps its old last. A context written since the snapshot
// is restored to an earlier write, so it is denied, as any rollback is,
// until a login replaces it, which fails closed; the broker's refresh
// revokes it as altered meanwhile, and a restart before that seeds the
// key with it again (the restart residual). A write whose outcome is
// unknown, sent after the restore on a low revision, is taken as earlier
// and not admitted until the next write lands there, which fails closed.
// The runbook's restore bumps the revision instead (--bump-revision;
// design §12): a restored record keeps its revision, below the last's,
// and the store's jumps past every one it gave, so a login after it
// compares below the last and commits above it, and is placed as the last
// too (Task 15, measured: tests/lab/results/L35-restore-arista_eos.md).
//
// A read racing a write can return the record it replaced after it
// landed. Its revision is below the last's (stale), so GetContext reads
// again, up to twice, and judges that read; one still denied after it is
// denied, which fails closed (Task 13b review I-1).
// It holds one entry per key this process has read or written, until a
// delete of the key lands, or after Seal a read finds it empty, with no
// write to it sent since the delete or the read was (forget); after Seal
// a forgotten key admits only what this process writes there, so
// forgetting fails closed (Task 4b review M5). One Ledger is shared by every Wrap in a process
// (WithLedger). It is safe for concurrent use.
type Ledger struct {
	mu     sync.Mutex
	m      map[store.ContextKey]*ledgerEntry
	sealed bool
	seq    uint64 // counts begin, so forget can tell a write sent after its call was
}

type ledgerEntry struct {
	last     string          // the write ID of the last write that landed, or of the first read
	known    bool            // last is set: false for a key whose first write is in flight
	lastRev  uint64          // the revision the write that set last committed at; zero when a read did
	lastEnd  uint64          // seq when the write that set last ended
	inFlight map[string]int  // writes sent and not yet ended, by write ID; nil until one is
	unknown  map[string]bool // writes that ended with neither a landing nor a refusal; nil until one does
	began    uint64          // seq at the last write sent
}

// ledgerWrite is a write the ledger was told of (begin), for end: its
// key, its write ID, the revision it compares (zero for none, or for no
// record), and seq when it was sent.
type ledgerWrite struct {
	k   store.ContextKey
	id  string
	rev uint64
	seq uint64
}

// earlier reports whether w, had it landed, committed before the write
// that set last, so the store does not hold w (Ledger).
func (e *ledgerEntry) earlier(w ledgerWrite) bool {
	return e.known && w.rev > 0 && w.rev < e.lastRev
}

// settle makes id, read back, the last.
func (e *ledgerEntry) settle(id string) {
	e.last, e.known, e.lastRev = id, true, 0
}

// NewLedger is an empty ledger, not yet sealed.
func NewLedger() *Ledger { return &Ledger{m: map[store.ContextKey]*ledgerEntry{}} }

// Seal ends the first-read rule: from now on a key this process has
// neither read nor written admits nothing it did not write itself.
func (l *Ledger) Seal() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sealed = true
}

func (l *Ledger) entry(k store.ContextKey) *ledgerEntry {
	e := l.m[k]
	if e == nil {
		e = &ledgerEntry{}
		l.m[k] = e
	}
	return e
}

// mark is where the write sequence stands, taken before a delete or a read
// is sent, for forget.
func (l *Ledger) mark() uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.seq
}

// forget drops k's entry once the store holds no record there: a delete
// that landed, or after Seal a read that found none (sealedOnly). It keeps
// the entry while a write to k is in flight, or when one was sent after at
// (mark), since that write may be what the store holds now.
func (l *Ledger) forget(k store.ContextKey, at uint64, sealedOnly bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.m[k]
	if !ok || (sealedOnly && !l.sealed) || len(e.inFlight) > 0 || e.began > at {
		return
	}
	delete(l.m, k)
}

// admits reports whether a record sealed under the write ID id may be
// read at k.
func (l *Ledger) admits(k store.ContextKey, id string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.m[k]
	if !ok {
		if l.sealed {
			return false // and seeds nothing: the next read is denied too
		}
		l.entry(k).settle(id)
		return true
	}
	switch {
	case e.known && id == e.last, e.inFlight[id] > 0:
		return true
	case e.unknown[id]:
		// Read back, so it landed: it is the last now, and the writes it
		// replaced are not admitted again.
		e.settle(id)
		clear(e.unknown)
		return true
	}
	return false
}

// stale reports whether a record read at k at rev was served before the
// last write there committed: its revision is below the last's. A read
// that raced a write of the same context is one; a record put back is
// not, since it commits after the last (Task 13b review I-1). After a
// restore every revision is below the last's, so each read there is
// stale, and still denied once read again (Ruling T13b-a).
func (l *Ledger) stale(k store.ContextKey, rev uint64) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.m[k]
	return ok && e.known && e.lastRev > 0 && rev < e.lastRev
}

// begin is told of the write id at k, compared on rev, before it is
// sent; its return is end's.
func (l *Ledger) begin(k store.ContextKey, id string, rev uint64) ledgerWrite {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.entry(k)
	if e.inFlight == nil {
		e.inFlight = map[string]int{}
	}
	e.inFlight[id]++
	l.seq++
	e.began = l.seq
	return ledgerWrite{k: k, id: id, rev: rev, seq: l.seq}
}

// end is told that w ended with err, and, when it landed, the revision it
// committed at (zero when the store did not report one).
func (l *Ledger) end(w ledgerWrite, committed uint64, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.entry(w.k)
	if e.inFlight[w.id]--; e.inFlight[w.id] <= 0 {
		delete(e.inFlight, w.id)
	}
	switch {
	case err == nil && e.known && committed != 0 && committed < e.lastRev && w.seq > e.lastEnd:
		// Sent after the last ended, so committed after it: the store's
		// revisions went back (a restore), and it holds this write. Before
		// earlier, which takes its low compare revision as an earlier write.
		e.last, e.lastRev, e.lastEnd = w.id, committed, l.seq
		clear(e.unknown)
	case err == nil && e.earlier(w) && committed > e.lastRev:
		// Compared below the last and committed above it: a restore with
		// --bump-revision, whose records keep their revisions while the
		// store's jumps past every one it gave. It holds this write. Before
		// earlier, which takes the low compare revision as an earlier write.
		e.last, e.lastRev, e.lastEnd = w.id, committed, l.seq
		clear(e.unknown)
	case e.earlier(w), err == nil && e.known && committed != 0 && committed < e.lastRev:
		// Landed and replaced since, or never landed: the store holds the
		// last, whatever the error.
	case err == nil && committed == 0:
		// Landed at a revision unknown: it or the last is the store's, and
		// neither is admitted.
		e.last, e.known, e.lastRev = "", false, 0
		clear(e.unknown)
	case err == nil:
		e.last, e.known, e.lastRev, e.lastEnd = w.id, true, committed, l.seq
		clear(e.unknown)
	case errors.Is(err, store.ErrConflict), errors.Is(err, store.ErrNotFound):
	default:
		if e.unknown == nil {
			e.unknown = map[string]bool{}
		}
		e.unknown[w.id] = true
	}
}
