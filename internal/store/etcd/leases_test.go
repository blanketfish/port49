package etcd

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"

	"github.com/blanketfish/port49/internal/store/etcd/etcdtest"
)

// The 101st record of one expiry bucket gets a lease of its own, so no lease
// carries more than maxAttachesPerLease keys (etcd's checkLeasePutsKeys costs a
// put by the keys already on its lease); another bucket is unaffected.
func TestALeaseTakesAtMostMaxAttachesPerLease(t *testing.T) {
	ctx := context.Background()
	l := newLeases(etcdtest.Client(t), func() time.Time { return t0 }, 5*time.Minute)
	exp := t0.Add(10 * time.Minute)
	first, err := l.For(ctx, exp)
	if err != nil {
		t.Fatal(err)
	}
	for i := 2; i <= maxAttachesPerLease; i++ {
		id, err := l.For(ctx, exp)
		if err != nil || id != first {
			t.Fatalf("attach %d: lease %v, want the first %v (%v)", i, id, first, err)
		}
	}
	next, err := l.For(ctx, exp)
	if err != nil || next == first {
		t.Fatalf("attach %d: lease %v, want a fresh one (%v)", maxAttachesPerLease+1, next, err)
	}
	if again, err := l.For(ctx, exp); err != nil || again != next {
		t.Fatalf("attach %d: lease %v, want the fresh %v (%v)", maxAttachesPerLease+2, again, next, err)
	}
	other, err := l.For(ctx, exp.Add(2*leaseBucket))
	if err != nil || other == first || other == next {
		t.Fatalf("another bucket: lease %v (%v)", other, err)
	}
	if again, err := l.For(ctx, exp.Add(2*leaseBucket)); err != nil || again != other {
		t.Fatalf("another bucket's second attach: %v, want %v (%v)", again, other, err)
	}
}

// countingGrants wraps l's granter: it counts grants and holds each for hold,
// as a slow etcd does; fail, when set, makes the next grants fail.
type countingGrants struct {
	n    atomic.Int64
	fail atomic.Bool
}

func (c *countingGrants) wrap(l *leases, hold time.Duration) {
	inner := l.grant
	l.grant = func(ctx context.Context, ttl int64) (*clientv3.LeaseGrantResponse, error) {
		c.n.Add(1)
		time.Sleep(hold)
		if c.fail.Load() {
			return nil, errors.New("etcd is down")
		}
		return inner(ctx, ttl)
	}
}

// Callers that find a bucket's lease full together make one grant between
// them: the rest wait on it and all land on the one fresh lease. A slow etcd
// would otherwise see a herd of grants at every rollover.
func TestACallerOfAFullLeaseWaitsOnTheGrantInFlight(t *testing.T) {
	ctx := context.Background()
	l := newLeases(etcdtest.Client(t), func() time.Time { return t0 }, 5*time.Minute)
	var c countingGrants
	c.wrap(l, 200*time.Millisecond)
	exp := t0.Add(10 * time.Minute)
	first, err := l.For(ctx, exp)
	if err != nil {
		t.Fatal(err)
	}
	for i := 2; i <= maxAttachesPerLease; i++ {
		if _, err := l.For(ctx, exp); err != nil {
			t.Fatal(err)
		}
	}
	before := c.n.Load()
	const callers = 50
	ids := make([]clientv3.LeaseID, callers)
	var wg sync.WaitGroup
	for i := range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			id, err := l.For(ctx, exp)
			if err != nil {
				t.Error(err)
			}
			ids[i] = id
		}()
	}
	wg.Wait()
	if got := c.n.Load() - before; got != 1 {
		t.Fatalf("%d grants for %d callers of a full bucket, want 1", got, callers)
	}
	for i, id := range ids {
		if id == first || id != ids[0] {
			t.Fatalf("caller %d got lease %v (first %v, caller 0 %v), want the one fresh lease", i, id, first, ids[0])
		}
	}
}

// A failed grant wakes every waiter with its error and leaves nothing half
// done: the next caller grants again, and nothing was put on the full lease.
func TestAFailedGrantFailsItsWaitersAndTheNextCallerTriesAgain(t *testing.T) {
	ctx := context.Background()
	l := newLeases(etcdtest.Client(t), func() time.Time { return t0 }, 5*time.Minute)
	var c countingGrants
	c.wrap(l, 100*time.Millisecond)
	c.fail.Store(true)
	exp := t0.Add(10 * time.Minute)
	const callers = 10
	errs := make([]error, callers)
	var wg sync.WaitGroup
	for i := range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = l.For(ctx, exp)
		}()
	}
	wg.Wait()
	if got := c.n.Load(); got != 1 {
		t.Fatalf("%d grants for %d callers, want 1", got, callers)
	}
	for i, err := range errs {
		if err == nil {
			t.Fatalf("caller %d: no error from a failed grant", i)
		}
	}
	c.fail.Store(false)
	if id, err := l.For(ctx, exp); err != nil || id == 0 || c.n.Load() != 2 {
		t.Fatalf("the next caller: lease %v, %d grants, %v", id, c.n.Load(), err)
	}
}
