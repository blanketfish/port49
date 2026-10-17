// Package placement is the fixed placement of records between port49's
// two stores (plan 11a; spec §13 decision 51): a store.Store over the
// session store whose revocation marks are the directory store's, and whose
// read of a mark is the process's copy of them.
//
// Directory membership is split by write rate (R13): the directory holds
// the pin, with no lease; the session store the freshness record.
//
// It is used where the two stores are two: a shared store keeps decision
// 35's atomic login check, and no router.
package placement

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/rhwendt/port49/internal/printsafe"
	"github.com/rhwendt/port49/internal/store"
)

// Directory is the directory store's revocation half, as the router writes,
// lists, and with no copy reads it.
type Directory interface {
	PutRevocation(ctx context.Context, r store.Revocation) error
	GetRevocation(ctx context.Context, kind, key string) (store.Revocation, error)
	DeleteRevocation(ctx context.Context, kind, key string) error
	ListRevocations(ctx context.Context) ([]store.Revocation, error)
}

// Members is the directory store's membership half (R13): the pin, the map
// keys, refusals and the forget's tombstone, sealed as the session store's.
type Members interface {
	PutPin(ctx context.Context, m store.Membership, expect store.PinExpect) error
	GetMembership(ctx context.Context, principal string) (store.Membership, error)
	MembershipByKey(ctx context.Context, mapKey string) (store.Membership, error)
	RefuseMapKeys(ctx context.Context, mapKeys []string, at time.Time, ttl time.Duration) error
	DeleteMembership(ctx context.Context, principal string) (store.Membership, error)
}

// Config is Wrap's.
type Config struct {
	// Session is the session store, sealed and guarded: every method but
	// the revocations'.
	Session store.Store
	// Directory is where the marks are written and listed.
	Directory Directory
	// Marks is the process's copy of the directory's marks, which
	// GetRevocation answers from. Nil reads Directory: the offline
	// revocation, which follows no feed.
	Marks *store.Marks
	// CallTimeout bounds each put, delete and read of Directory, and
	// BulkTimeout its list: a directory that does not answer within one is
	// store.ErrUnavailable. Zero is 500ms and 30s.
	CallTimeout, BulkTimeout time.Duration
	// Members is the directory's membership half; nil keeps membership
	// wholly in the session store (the daemon, which holds none).
	Members Members
	// Reachable is false while the directory is known not to answer: a
	// membership read then serves the session store's copy at once rather
	// than wait CallTimeout. Nil always tries.
	Reachable func() bool
	// Say is told once per principal per 10 minutes that a cached pin was
	// served, and each pin put back from this region's record; nil says
	// nothing.
	Say func(format string, args ...any)
}

type placed struct {
	store.Store
	c Config

	mu    sync.Mutex
	said  map[string]time.Time
	pins  map[string]pinEntry
	gens  map[string]uint64
	epoch uint64
}

// Wrap is c.Session with the revocation marks placed in c.Directory.
func Wrap(c Config) store.Store {
	if c.CallTimeout <= 0 {
		c.CallTimeout = 500 * time.Millisecond
	}
	if c.BulkTimeout <= 0 {
		c.BulkTimeout = 30 * time.Second
	}
	return &placed{Store: c.Session, c: c, said: map[string]time.Time{}, pins: map[string]pinEntry{},
		gens: map[string]uint64{}}
}

func (p *placed) PutRevocation(ctx context.Context, r store.Revocation) error {
	return bounded(ctx, p.c.CallTimeout, func(ctx context.Context) error { return p.c.Directory.PutRevocation(ctx, r) })
}

func (p *placed) DeleteRevocation(ctx context.Context, kind, key string) error {
	return bounded(ctx, p.c.CallTimeout, func(ctx context.Context) error {
		return p.c.Directory.DeleteRevocation(ctx, kind, key)
	})
}

func (p *placed) ListRevocations(ctx context.Context) (rs []store.Revocation, err error) {
	err = bounded(ctx, p.c.BulkTimeout, func(ctx context.Context) (x error) {
		rs, x = p.c.Directory.ListRevocations(ctx)
		return
	})
	return rs, err
}

// GetRevocation is the copy's mark, or ErrNotFound: a login's and a mint's
// check never waits on the directory (R4). With no copy it reads the
// directory.
func (p *placed) GetRevocation(ctx context.Context, kind, key string) (store.Revocation, error) {
	if p.c.Marks == nil {
		var r store.Revocation
		err := bounded(ctx, p.c.CallTimeout, func(ctx context.Context) (x error) {
			r, x = p.c.Directory.GetRevocation(ctx, kind, key)
			return
		})
		return r, err
	}
	if r, ok := p.c.Marks.Get(kind, key); ok {
		return r, nil
	}
	return store.Revocation{}, store.ErrNotFound
}

// SwapLogin compares no mark: the session store holds none, and the marks a
// login read came from the copy, which it has carried into the context
// already (JoinContext; decision 51). Every request is denied by the copy
// whatever the context says.
func (p *placed) SwapLogin(ctx context.Context, k store.ContextKey, rev uint64, c store.Context, ttl time.Duration,
	w store.LoginWrite) error {
	w.Marks = nil
	return p.Store.SwapLogin(ctx, k, rev, c, ttl, w)
}

// bounded runs f under d, and names a directory that did not answer within
// it store.ErrUnavailable; a caller that gave up keeps its own error.
func bounded(ctx context.Context, d time.Duration, f func(context.Context) error) error {
	cctx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	err := f(cctx)
	if err != nil && ctx.Err() == nil && cctx.Err() != nil && !errors.Is(err, store.ErrUnavailable) {
		return fmt.Errorf("%w: the directory store did not answer within %v", store.ErrUnavailable, d)
	}
	return err
}

// pinOf is the part of m the directory keeps: the pin, the map keys, the
// refusal and when it was verified, which the tombstone rule compares.
func pinOf(m store.Membership) store.Membership {
	return store.Membership{Principal: m.Principal, EntryID: m.EntryID, MapKeys: m.MapKeys, Refused: m.Refused,
		VerifiedAt: m.VerifiedAt}
}

// pinOnly is a pin with none of its verification's freshness: no groups,
// and no verification time unless it is a refusal, whose time grace names.
// Grace serves nothing from it; Resolver.pinned holds the next
// verification to its entry (I2).
func pinOnly(pin store.Membership) store.Membership {
	out := store.Membership{Principal: pin.Principal, EntryID: pin.EntryID, MapKeys: pin.MapKeys, Refused: pin.Refused}
	if pin.Refused {
		out.VerifiedAt = pin.VerifiedAt
	}
	return out
}

// samePin reports whether a and b hold one pin.
func samePin(a, b store.Membership) bool {
	return a.EntryID == b.EntryID && a.Refused == b.Refused && slices.Equal(a.MapKeys, b.MapKeys)
}

func (p *placed) reachable() bool { return p.c.Reachable == nil || p.c.Reachable() }

// pinState is what the directory says of a principal's pin.
type pinState int

const (
	pinUnknown   pinState = iota // the directory did not answer, and nothing is cached
	pinHeld                      // pinned: pin holds it
	pinForgotten                 // a forget's tombstone: the principal is free
	pinAbsent                    // never pinned
)

// dirPin is the directory's pin for principal: the cache's, else a bounded
// read, filled when no change came between (I3). fresh skips the cache: a
// write whose compare failed decides again on the directory's own answer.
// An error is a directory answer other than none or a cut.
func (p *placed) dirPin(ctx context.Context, principal string, fresh bool) (store.Membership, pinState, error) {
	if e, ok := p.cached(principal); ok && !fresh {
		return e.pin, e.state, nil
	}
	if !p.reachable() {
		return store.Membership{}, pinUnknown, nil
	}
	gen := p.genOf(principal)
	var pin store.Membership
	err := bounded(ctx, p.c.CallTimeout, func(ctx context.Context) (x error) {
		pin, x = p.c.Members.GetMembership(ctx, principal)
		return
	})
	var st pinState
	switch {
	case err == nil:
		st = pinHeld
	case errors.Is(err, store.ErrForgotten):
		st = pinForgotten
	case errors.Is(err, store.ErrNotFound):
		st = pinAbsent
	case errors.Is(err, store.ErrUnavailable):
		return store.Membership{}, pinUnknown, nil
	default:
		return store.Membership{}, pinUnknown, err
	}
	p.fillPin(principal, gen, pinEntry{pin: pin, state: st})
	return pin, st, nil
}

// putPin writes m's pin to the directory with no lease, bounded, failing
// closed, only if the directory's record still stands as the read that
// decided the write saw it (expect); store.ErrConflict when it does not. It
// drops the cached entry: the next read takes the directory's, which the
// tombstone rule may have kept.
func (p *placed) putPin(ctx context.Context, m store.Membership, expect store.PinExpect) error {
	if !p.reachable() {
		return fmt.Errorf("%w: the directory store does not answer, so %s cannot be pinned", store.ErrUnavailable,
			printsafe.Line(m.Principal, 300))
	}
	err := bounded(ctx, p.c.CallTimeout, func(ctx context.Context) error {
		return p.c.Members.PutPin(ctx, pinOf(m), expect)
	})
	p.dropPin(m.Principal)
	return err
}

// PutPin is the directory's compare-and-set pin write, which only the router
// itself makes; with no directory it is the session store's.
func (p *placed) PutPin(ctx context.Context, m store.Membership, expect store.PinExpect) error {
	if p.c.Members == nil {
		return p.Store.PutPin(ctx, m, expect)
	}
	return p.putPin(ctx, m, expect)
}

// PutMembership writes the session's record always, and the directory's
// pin when the directory's own differs: a first bind, a re-pin (the same
// entry after a forget included), a changed map key or a refusal. The pin
// write is a compare-and-set on the directory record the deciding read saw,
// so a stale cache or a lagging feed never overwrites another region's pin:
// on a conflict the decision is made again on a read of the directory itself.
// A pin held for another entry is never moved here, whatever the read said
// of it: only a forget frees a principal (Ruling 3). With the directory not
// answering and the pin not cached, the session copy is compared instead:
// only a pinned member's refresh is taken.
func (p *placed) PutMembership(ctx context.Context, m store.Membership, ttl time.Duration) error {
	if p.c.Members == nil {
		return p.Store.PutMembership(ctx, m, ttl)
	}
	for attempt := 0; ; attempt++ {
		pin, st, err := p.dirPin(ctx, m.Principal, attempt > 0)
		if err != nil {
			return err
		}
		var expect store.PinExpect
		switch {
		case st == pinHeld && samePin(pin, m):
			return p.Store.PutMembership(ctx, m, ttl)
		case st == pinHeld && pin.EntryID != "" && pin.EntryID != m.EntryID:
			return fmt.Errorf("%w: %s is pinned to entry %s, not %s; only `port49 directory forget` moves a pin",
				store.ErrPinHeld, printsafe.Line(m.Principal, 300), printsafe.Line(pin.EntryID, 120),
				printsafe.Line(m.EntryID, 120))
		case st == pinHeld:
			expect = store.PinExpect{Version: pin.Version}
		case st == pinAbsent:
			expect = store.PinExpect{Absent: true}
		case st == pinForgotten:
			expect = store.PinExpect{Forgotten: true}
		default: // pinUnknown
			held, herr := p.Store.GetMembership(ctx, m.Principal)
			if herr != nil || !samePin(held, m) {
				return fmt.Errorf("%w: the directory store does not answer, so %s cannot be pinned", store.ErrUnavailable,
					printsafe.Line(m.Principal, 300))
			}
			return p.Store.PutMembership(ctx, m, ttl)
		}
		err = p.putPin(ctx, m, expect)
		if errors.Is(err, store.ErrConflict) {
			if attempt < 2 {
				continue // another region wrote the pin since the read; decide again on a fresh one
			}
			return fmt.Errorf("%w: the directory pin for %s kept changing; try again", store.ErrUnavailable,
				printsafe.Line(m.Principal, 300))
		}
		if err != nil {
			return err
		}
		return p.Store.PutMembership(ctx, m, ttl)
	}
}

// GetMembership is the directory's pin with this region's freshness under
// it (R13). The pin comes from the cache FollowPins keeps (R4): a hit never
// waits on the directory. Forgotten is ErrForgotten, wherever it was
// forgotten. Absent, while this region's record holds a pin, is a pin the
// directory lost: it is put back from the record and the record served. A
// pin to another entry than this region's record answers the pin alone.
// With the directory not answering on a miss, the session's copy is served,
// and said.
func (p *placed) GetMembership(ctx context.Context, principal string) (store.Membership, error) {
	if p.c.Members == nil {
		return p.Store.GetMembership(ctx, principal)
	}
	return p.getMembership(ctx, principal, false)
}

func (p *placed) getMembership(ctx context.Context, principal string, again bool) (store.Membership, error) {
	local, lerr := p.Store.GetMembership(ctx, principal)
	if lerr != nil && !errors.Is(lerr, store.ErrNotFound) {
		return store.Membership{}, lerr
	}
	pin, st, err := p.dirPin(ctx, principal, again)
	if err != nil {
		return store.Membership{}, err
	}
	local.Version = 0
	switch st {
	case pinForgotten:
		return store.Membership{}, store.ErrForgotten
	case pinAbsent:
		if lerr != nil {
			return store.Membership{}, store.ErrNotFound
		}
		perr := p.putPin(ctx, local, store.PinExpect{Absent: true})
		if errors.Is(perr, store.ErrConflict) {
			if !again {
				return p.getMembership(ctx, principal, true) // the directory changed since the read: decide on its answer
			}
			return store.Membership{}, fmt.Errorf("%w: the directory store's pin for %s keeps changing", store.ErrUnavailable,
				printsafe.Line(principal, 300))
		}
		if perr == nil && p.c.Say != nil {
			p.c.Say("directory store: %s's pin (entry %s) was missing from the directory and is put back from this "+
				"region's record", printsafe.Line(principal, 300), printsafe.Line(local.EntryID, 120))
		}
		return local, nil // pinned by this region's record whether or not the put-back landed
	case pinHeld:
		if lerr == nil && local.EntryID == pin.EntryID {
			local.MapKeys, local.Refused = pin.MapKeys, pin.Refused
			return local, nil
		}
		return pinOnly(pin), nil // pinned elsewhere, or re-pinned to another entry (I2)
	}
	if lerr != nil {
		// The directory does not answer and nothing is cached or held here: whether
		// the principal is pinned is unknown, never "unpinned", which would let
		// a bind take it (Ruling 3; review of 8a, C1).
		return store.Membership{}, fmt.Errorf("%w: the directory store does not answer and no pin is held here for %s",
			store.ErrUnavailable, printsafe.Line(principal, 300))
	}
	p.sayCached(principal)
	return local, nil
}

// pinEntry is the router's cached answer for one principal: the
// directory's pin record and its state. FollowPins drops an entry at each
// change, so a hit is never older than the feed's delivery.
type pinEntry struct {
	pin   store.Membership
	state pinState
}

// pinGen is a principal's cache generation: the cache's epoch, which
// dropPins moves, and the principal's own count, which dropPin moves.
type pinGen struct{ epoch, n uint64 }

func (p *placed) cached(principal string) (pinEntry, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	e, ok := p.pins[principal]
	return e, ok
}

func (p *placed) genOf(principal string) pinGen {
	p.mu.Lock()
	defer p.mu.Unlock()
	return pinGen{p.epoch, p.gens[principal]}
}

// fillPin caches e for principal unless a change came since gen was read
// (I3): a fill read before a drop never outlives it.
func (p *placed) fillPin(principal string, gen pinGen, e pinEntry) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if gen != (pinGen{p.epoch, p.gens[principal]}) {
		return
	}
	if len(p.pins) >= maxPins {
		clear(p.pins) // a miss refills; bounded memory over a directory of any size
	}
	p.pins[principal] = e
}

// dropPin drops principal's entry and moves its generation.
func (p *placed) dropPin(principal string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.pins, principal)
	if len(p.gens) >= maxPins {
		clear(p.gens)
		p.epoch++ // every fill in flight is dropped; none is wrongly kept
	}
	p.gens[principal]++
}

// dropPins drops every entry, and every fill in flight.
func (p *placed) dropPins() {
	p.mu.Lock()
	defer p.mu.Unlock()
	clear(p.pins)
	clear(p.gens)
	p.epoch++
}

func (p *placed) cachedPin(principal string) bool {
	_, ok := p.cached(principal)
	return ok
}

// maxPins bounds the pin cache and its generations.
const maxPins = 1 << 16

// PinFeed is the directory's membership family as a stream of changes
// (*etcd.Store).
type PinFeed interface {
	Revision(ctx context.Context) (uint64, error)
	WatchMemberships(ctx context.Context, after uint64, fn func(principal string, rev uint64),
		progress func(rev uint64)) error
}

// FollowPins keeps s's pin cache current from feed until ctx ends (R4,
// R13): each change drops its principal's entry. A watch that fails is
// tried again every second from the last revision delivered, the cache
// served meanwhile (a cut); a compacted one, which only a reachable
// directory can say, drops every entry, and misses refill them. up is told
// whether the watch runs. s not a router (a shared store) returns at once.
func FollowPins(ctx context.Context, s store.Store, feed PinFeed, up func(bool), logf func(string, ...any)) error {
	p, ok := s.(*placed)
	if !ok || p.c.Members == nil {
		return nil
	}
	var from uint64
	failing := false
	for {
		var err error
		if from == 0 {
			var rev uint64
			if rev, err = feed.Revision(ctx); err == nil {
				p.dropPins() // what changed before the watch began is read afresh
				from = rev
			}
		}
		if from != 0 {
			up(true)
			err = feed.WatchMemberships(ctx, from, func(principal string, rev uint64) {
				p.dropPin(principal)
				from = max(from, rev)
			}, func(rev uint64) { from = max(from, rev) })
			up(false)
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if errors.Is(err, store.ErrCompacted) {
			from = 0 // reloads: Revision, then every entry dropped
			continue
		}
		if !failing {
			logf("directory store: the membership pins feed stopped (%v); serving the cached pins, trying again every second", err)
			failing = true
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

// MembershipByKey is the directory's answer, which knows every region's
// claims and refusals; the session's while the directory does not answer.
func (p *placed) MembershipByKey(ctx context.Context, mapKey string) (store.Membership, error) {
	if p.c.Members == nil || !p.reachable() {
		return p.Store.MembershipByKey(ctx, mapKey)
	}
	var m store.Membership
	err := bounded(ctx, p.c.CallTimeout, func(ctx context.Context) (x error) {
		m, x = p.c.Members.MembershipByKey(ctx, mapKey)
		return
	})
	if errors.Is(err, store.ErrUnavailable) {
		return p.Store.MembershipByKey(ctx, mapKey)
	}
	if err != nil {
		return store.Membership{}, err
	}
	return p.GetMembership(ctx, m.Principal)
}

// RefuseMapKeys is a refusal: the directory's, with no lease, failing
// closed, then the session's.
func (p *placed) RefuseMapKeys(ctx context.Context, mapKeys []string, at time.Time, ttl time.Duration) error {
	if p.c.Members != nil {
		if !p.reachable() {
			return fmt.Errorf("%w: the directory store does not answer, so the refusal is not recorded",
				store.ErrUnavailable)
		}
		if err := bounded(ctx, p.c.CallTimeout, func(ctx context.Context) error {
			return p.c.Members.RefuseMapKeys(ctx, mapKeys, at, store.NoExpiry)
		}); err != nil {
			return err
		}
	}
	return p.Store.RefuseMapKeys(ctx, mapKeys, at, ttl)
}

// DeleteMembership is port49 directory forget: the directory first, failing
// closed, so every region reads the pin forgotten; then this region's copy.
func (p *placed) DeleteMembership(ctx context.Context, principal string) (store.Membership, error) {
	if p.c.Members == nil {
		return p.Store.DeleteMembership(ctx, principal)
	}
	if !p.reachable() {
		return store.Membership{}, fmt.Errorf("%w: the directory store does not answer, so nothing was forgotten",
			store.ErrUnavailable)
	}
	var held store.Membership
	derr := bounded(ctx, p.c.CallTimeout, func(ctx context.Context) (x error) {
		held, x = p.c.Members.DeleteMembership(ctx, principal)
		return
	})
	// ErrNotFound is a directory that held nothing and now holds the
	// tombstone all the same: this region's copy goes too, so it cannot put
	// the pin back (review of 8a, I2).
	if derr != nil && !errors.Is(derr, store.ErrNotFound) {
		return store.Membership{}, derr
	}
	p.dropPin(principal)
	// This region's copy goes if it holds one; none is made for a principal
	// it holds nothing for, since the directory's tombstone is the authority.
	if _, gerr := p.Store.GetMembership(ctx, principal); gerr == nil {
		if local, err := p.Store.DeleteMembership(ctx, principal); err == nil {
			return local, nil // the region's record names more than the pin
		}
	}
	return held, derr
}

// sayCached says, once per principal per 10 minutes, that a cut directory's
// cached pin was served (R13: a region keeps serving a pinned member, and
// says so).
func (p *placed) sayCached(principal string) {
	if p.c.Say == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if t, ok := p.said[principal]; ok && time.Since(t) < 10*time.Minute {
		return
	}
	if len(p.said) > 1024 {
		clear(p.said)
	}
	p.said[principal] = time.Now()
	p.c.Say("directory store: not answering: serving %s's cached directory membership (its pin as this region "+
		"last read it); a forget made elsewhere reaches this region when the directory answers",
		printsafe.Line(principal, 300))
}
