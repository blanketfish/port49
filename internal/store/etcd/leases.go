package etcd

import (
	"context"
	"math"
	"sync"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
)

// leaseBucket is the width of one lease's expiry bucket: every record
// dying in the same minute shares a lease, so leases are granted at most
// one a minute of expiries, not one a record (design D1's cost).
const leaseBucket = time.Minute

// maxAttachesPerLease is how many records ride one lease before the next
// For grants a fresh lease for the same bucket. etcd checks put permission
// for every key already on a lease, on each put that names it, whenever the
// caller is not root (apply_auth.go, checkLeasePutsKeys), so a put's cost
// grows with the keys already attached. At 170 logins/s one lease a minute
// saturated etcd's apply loop; 100 a lease took the mint's p50 from 540 ms
// to 2 ms (plan 12c load run 1). A replaced lease still expires on its own
// TTL, and nothing revokes it early.
const maxAttachesPerLease = 100

// grantFallbackTimeout bounds a grant whose first caller carried no deadline.
const grantFallbackTimeout = 5 * time.Second

// leases hands out the lease a record is put on. A lease only reclaims:
// the record's own expiry, read against now, decides whether it is live
// (plan 7d, Ruling 3). So a lease is always the bucket ending at least
// grace after the record's expiry, and its TTL is a duration on etcd's
// clock, which skew between port49d and etcd cannot shorten.
type leases struct {
	cli   *clientv3.Client
	now   func() time.Time
	grace time.Duration
	mu    sync.Mutex
	// held is, by bucket end (unix seconds of now's clock), the lease
	// granted for it and until when it lives on the wall clock.
	held map[int64]heldLease
	// saw, when set, sees each grant's revision (Store.Seen).
	saw func(rev int64)
	// grant makes a lease; the client's Grant, but for a test's.
	grant func(ctx context.Context, ttl int64) (*clientv3.LeaseGrantResponse, error)
	// flight is, by bucket end, the grant in flight for it: callers that
	// find the bucket's lease full or gone wait on it and never grant their
	// own (a slow etcd would otherwise turn each rollover into a herd).
	flight map[int64]*grantFlight
}

// grantFlight is one grant in flight: done closes when it ends, err says how.
type grantFlight struct {
	done chan struct{}
	err  error
}

type heldLease struct {
	id      clientv3.LeaseID
	attach  int       // records handed this lease, capped at maxAttachesPerLease
	granted time.Time // wall clock, no monotonic reading
	until   time.Time // wall clock, no monotonic reading
}

func newLeases(cli *clientv3.Client, now func() time.Time, grace time.Duration) *leases {
	return &leases{cli: cli, now: now, grace: grace, held: map[int64]heldLease{}, flight: map[int64]*grantFlight{},
		grant: func(ctx context.Context, ttl int64) (*clientv3.LeaseGrantResponse, error) { return cli.Grant(ctx, ttl) }}
}

// wall is the wall clock with its monotonic reading stripped. The
// monotonic clock stops while the host is suspended and etcd's lease
// clock does not, so a lease judged by it would look alive past its
// death on etcd, and a reused one could reclaim a record early: a tp/
// entry gone before its token, which a `port49 revoke --mine` then
// misses (pre-flight M22).
func wall() time.Time { return time.Now().Round(0) }

// For returns a lease that lives at least until exp plus grace, measured
// from now on now's clock. An expiry already past gets the shortest such
// lease: the record is never read as live, and is reclaimed soon (7c M-2).
// A cached lease is reused only within one bucket of its grant, judged by
// the wall clock: past that it is granted afresh, so a suspend costs a
// grant, never a short lease.
func (l *leases) For(ctx context.Context, exp time.Time) (clientv3.LeaseID, error) {
	now := l.now()
	end := exp.Add(l.grace).Truncate(leaseBucket).Add(leaseBucket)
	need := end.Sub(now)
	if need < l.grace {
		need = l.grace
	}
	key := end.Unix()
	for {
		w := wall()
		l.mu.Lock()
		if h, ok := l.held[key]; ok && !h.until.Before(w.Add(need)) && w.Sub(h.granted) < leaseBucket && h.attach < maxAttachesPerLease {
			h.attach++
			l.held[key] = h
			l.mu.Unlock()
			return h.id, nil
		}
		f, ok := l.flight[key]
		if !ok {
			f = &grantFlight{done: make(chan struct{})}
			l.flight[key] = f
			// The grant is the bucket's, not this caller's: it runs on a
			// context its caller's cancel cannot reach, bounded by the
			// caller's own deadline (the store's call timeout), so one caller
			// that gives up does not fail the waiters.
			gctx := context.WithoutCancel(ctx)
			cancel := func() {}
			if dl, has := ctx.Deadline(); has {
				gctx, cancel = context.WithDeadline(gctx, dl)
			} else {
				gctx, cancel = context.WithTimeout(gctx, grantFallbackTimeout)
			}
			go func() {
				defer cancel()
				err := l.grantFor(gctx, key, need)
				l.mu.Lock()
				delete(l.flight, key)
				l.mu.Unlock()
				f.err = err
				close(f.done)
			}()
		}
		l.mu.Unlock()
		// Whoever started it, a caller waits on the grant under its own ctx,
		// then looks for the lease again. A failed grant is every waiter's error.
		select {
		case <-f.done:
		case <-ctx.Done():
			return 0, ctx.Err()
		}
		if f.err != nil {
			return 0, f.err
		}
	}
}

// grantFor grants the lease for the bucket at key and caches it with no
// attach taken: every caller, the one that started it too, takes its own.
func (l *leases) grantFor(ctx context.Context, key int64, need time.Duration) error {
	// A bucket's worth more, so records of the same bucket put later still
	// fit on it.
	ttl := int64(math.Ceil((need + leaseBucket).Seconds()))
	resp, err := l.grant(ctx, ttl)
	if err != nil {
		return err
	}
	if l.saw != nil {
		l.saw(resp.ResponseHeader.GetRevision())
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	w := wall()
	l.held[key] = heldLease{id: resp.ID, granted: w, until: w.Add(time.Duration(resp.TTL) * time.Second)}
	for b, h := range l.held {
		if h.until.Before(w) || w.Sub(h.granted) >= leaseBucket {
			delete(l.held, b)
		}
	}
	return nil
}

// Reset forgets every lease, after etcd said it no longer knows one.
func (l *leases) Reset() {
	l.mu.Lock()
	l.held = map[int64]heldLease{}
	l.mu.Unlock()
}
