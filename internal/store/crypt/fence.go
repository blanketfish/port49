package crypt

import (
	"context"
	"fmt"
	"sync"

	"github.com/blanketfish/port49/internal/store"
)

// ErrFeedBehind is a context read whose record this process's context feed
// had not delivered by the read's deadline (plan 7e, pre-flight C1). It is
// store.ErrUnavailable: the guard counts it, a handler denies
// store_unavailable, and the refresh leaves the context for its next pass.
var ErrFeedBehind = fmt.Errorf("%w: this process's context feed has not delivered the record's revision",
	store.ErrUnavailable)

// Fence is how far this process's context feed has delivered the store's
// changes (plan 7e, Ruling 3). A read judges no record its feed has not
// passed: a put-back commits above the write it hides, so once the feed has
// passed the put-back it has raised the key's mark past it, and while it
// has not, the read cannot tell a put-back from another process's login.
// With no feed attached (memory, a fixture, the offline revocation) every
// revision passes. It is safe for concurrent use.
type Fence struct {
	mu      sync.Mutex
	on      bool
	at      uint64
	up      bool
	waiting int // reads in Wait behind the feed
	wake    chan struct{}
	asks    chan struct{}
	// timedOut is told each ErrFeedBehind (OnTimeout).
	timedOut func()
	// behind is the highest revision a Wait has waited on, from the moment it
	// starts waiting, not only once it gives up; Behind is true while
	// the feed has not passed it.
	behind uint64
}

func newFence() *Fence { return &Fence{wake: make(chan struct{}), asks: make(chan struct{}, 1)} }

// Attach is a feed following the store from at: from now on a read waits
// for it. It only raises, so after an etcd restore without
// --bump-revision, when revisions repeat, a record below the old mark
// passes unwaited (re-check R3's family); the runbook's restart of every
// process, which builds a new fence, clears it as it clears R3.
func (f *Fence) Attach(at uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.on = true
	f.raise(at)
}

// Followed is every change through rev delivered. It only raises.
func (f *Fence) Followed(rev uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.raise(rev)
}

func (f *Fence) raise(rev uint64) {
	if rev > f.at {
		f.at = rev
		close(f.wake)
		f.wake = make(chan struct{})
	}
}

// OnTimeout has fn told each read Wait gives up on, ErrFeedBehind:
// port49_store_fence_timeouts_total, which tells a feed behind from an
// etcd failure (final review 7e-1 M-4). fn must not call back into f.
func (f *Fence) OnTimeout(fn func()) { f.mu.Lock(); f.timedOut = fn; f.mu.Unlock() }

// SetUp records whether the feed's watch runs; Up reads it.
func (f *Fence) SetUp(up bool) { f.mu.Lock(); f.up = up; f.mu.Unlock() }
func (f *Fence) Up() bool      { f.mu.Lock(); defer f.mu.Unlock(); return f.up }

// Behind reports a read Wait gave up on that the feed has not yet passed: etcd
// answered with a record this process cannot vouch for, so a failure that does
// not say so (an open circuit, saturated slots) is no outage (plan 7f, review
// I-1). It clears itself once the feed passes that revision.
func (f *Fence) Behind() bool { f.mu.Lock(); defer f.mu.Unlock(); return f.behind > f.at }

// At is the revision the feed has delivered through.
func (f *Fence) At() uint64 { f.mu.Lock(); defer f.mu.Unlock(); return f.at }

// Asks is where a waiting read asks the feed for a progress notification.
func (f *Fence) Asks() <-chan struct{} { return f.asks }

// askAgain asks once more for any read still waiting, before a watch
// starts: an ask the last watch took and failed before answering is lost
// with it, and Wait asks again only on a wake (review 8a M-4).
func (f *Fence) askAgain() {
	f.mu.Lock()
	waiting := f.waiting > 0
	f.mu.Unlock()
	if waiting {
		select {
		case f.asks <- struct{}{}:
		default: // an ask is already pending
		}
	}
}

// Wait returns once the feed has delivered every change through rev, or at
// once with no feed attached. While it is behind, it asks the feed for its
// progress, again after each wake that leaves it behind, and returns
// ErrFeedBehind when ctx ends first. ctx carries the guard's call deadline.
func (f *Fence) Wait(ctx context.Context, rev uint64) error {
	counted := false
	defer func() {
		if counted {
			f.mu.Lock()
			f.waiting--
			f.mu.Unlock()
		}
	}()
	for {
		f.mu.Lock()
		if !f.on || f.at >= rev {
			f.mu.Unlock()
			return nil
		}
		if !counted {
			f.waiting++
			counted = true
			f.behind = max(f.behind, rev) // etcd has answered with a record the feed has not reached
		}
		wake, at := f.wake, f.at
		f.mu.Unlock()
		select {
		case f.asks <- struct{}{}:
		default: // an ask is already pending
		}
		select {
		case <-wake:
		case <-ctx.Done():
			f.mu.Lock()
			timedOut := f.timedOut
			f.mu.Unlock()
			if timedOut != nil {
				timedOut()
			}
			return fmt.Errorf("%w (the feed at revision %d, the record at %d)", ErrFeedBehind, at, rev)
		}
	}
}

// Fenced is inner with each context read held until l's feed has passed
// the record's revision (plan 7e, pre-flight C1). port49d puts it under the
// guard, so the wait is bounded by call_timeout and a feed that never
// arrives is a counted failure. A record at the revision l last knew at
// its key needs no wait: the store holding that revision there holds that
// record and nothing written after it. Ping waits for the revision the
// ping itself read at, so a probe fails while the feed is behind.
func Fenced(inner store.RevStore, l *Ledger) store.RevStore { return fenced{RevStore: inner, l: l} }

type fenced struct {
	store.RevStore
	l *Ledger
}

func (f fenced) GetContext(ctx context.Context, k store.ContextKey) (store.Context, error) {
	c, err := f.RevStore.GetContext(ctx, k)
	if err != nil || f.l.knownAt(k, c.Rev) {
		return c, err
	}
	if err := f.l.Fence().Wait(ctx, c.Rev); err != nil {
		return store.Context{}, err
	}
	return c, nil
}

func (f fenced) Ping(ctx context.Context) error {
	if err := f.RevStore.Ping(ctx); err != nil {
		return err
	}
	return f.l.Fence().Wait(ctx, f.RevStore.Seen())
}
