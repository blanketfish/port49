package crypt

import (
	"errors"
	"sync"

	"github.com/rhwendt/port49/internal/store"
)

// ErrNotLastWritten is a context that opens at its key but is not the
// one this process last wrote there, or first read there: another
// login's record, written back by whoever can write the store (plan 7d;
// Ruling 17; re-check IA1). GetContext returns it inside an
// UnreadableContextError, so every handler treats it as a record that
// will not open.
var ErrNotLastWritten = errors.New("crypt: not the context this port49d last wrote at its key")

// Ledger is, per context key, the ctx_id this process last wrote there,
// or first read there (plan 7d; Ruling 17; re-check IA1). A sealed
// context is bound to its key, not to the login that wrote it, so
// without the ledger a record of Alice's saved from leaf-01/netops and
// written back over Bob's there would authorize Bob's session as Alice.
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
// A read racing a login's replace can return the replaced record after
// the replace landed; that one request is denied, which fails closed.
// It holds one entry per key this process has read or written, kept
// while it runs. One Ledger is shared by every Wrap in a process
// (WithLedger). It is safe for concurrent use.
type Ledger struct {
	mu     sync.Mutex
	m      map[store.ContextKey]*ledgerEntry
	sealed bool
}

type ledgerEntry struct {
	last     string          // the last write that landed, or the first read
	known    bool            // last is set: false for a key whose first write is in flight
	inFlight map[string]int  // writes sent and not yet ended, by ctx_id
	unknown  map[string]bool // writes that ended with neither a landing nor a refusal
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
		e = &ledgerEntry{inFlight: map[string]int{}, unknown: map[string]bool{}}
		l.m[k] = e
	}
	return e
}

// admits reports whether a record holding id may be read at k.
func (l *Ledger) admits(k store.ContextKey, id string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.m[k]
	if !ok {
		if l.sealed {
			return false // and seeds nothing: the next read is denied too
		}
		e = l.entry(k)
		e.last, e.known = id, true
		return true
	}
	switch {
	case e.known && id == e.last, e.inFlight[id] > 0:
		return true
	case e.unknown[id]:
		// Read back, so it landed: it is the last now, and the writes it
		// replaced are not admitted again.
		e.last, e.known = id, true
		clear(e.unknown)
		return true
	}
	return false
}

func (l *Ledger) begin(k store.ContextKey, id string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entry(k).inFlight[id]++
}

func (l *Ledger) end(k store.ContextKey, id string, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.entry(k)
	if e.inFlight[id]--; e.inFlight[id] <= 0 {
		delete(e.inFlight, id)
	}
	switch {
	case err == nil:
		e.last, e.known = id, true
		clear(e.unknown)
	case errors.Is(err, store.ErrConflict), errors.Is(err, store.ErrNotFound):
	default:
		e.unknown[id] = true
	}
}
