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
}

type heldLease struct {
	id      clientv3.LeaseID
	granted time.Time // wall clock, no monotonic reading
	until   time.Time // wall clock, no monotonic reading
}

func newLeases(cli *clientv3.Client, now func() time.Time, grace time.Duration) *leases {
	return &leases{cli: cli, now: now, grace: grace, held: map[int64]heldLease{}}
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
	w := wall()
	l.mu.Lock()
	if h, ok := l.held[end.Unix()]; ok && !h.until.Before(w.Add(need)) && w.Sub(h.granted) < leaseBucket {
		l.mu.Unlock()
		return h.id, nil
	}
	l.mu.Unlock()
	// A bucket's worth more, so records of the same bucket put later still
	// fit on it.
	ttl := int64(math.Ceil((need + leaseBucket).Seconds()))
	resp, err := l.cli.Grant(ctx, ttl)
	if err != nil {
		return 0, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	w = wall()
	l.held[end.Unix()] = heldLease{id: resp.ID, granted: w, until: w.Add(time.Duration(resp.TTL) * time.Second)}
	for b, h := range l.held {
		if h.until.Before(w) || w.Sub(h.granted) >= leaseBucket {
			delete(l.held, b)
		}
	}
	return resp.ID, nil
}

// Reset forgets every lease, after etcd said it no longer knows one.
func (l *leases) Reset() {
	l.mu.Lock()
	l.held = map[int64]heldLease{}
	l.mu.Unlock()
}
