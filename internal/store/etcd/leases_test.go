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
	l := newLeases(etcdtest.Client(t), func() time.Time { return t0 }, 5*time.Minute, 0)
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
		if err := ctx.Err(); err != nil {
			return nil, err // as the client's Grant answers a cancelled call
		}
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
	l := newLeases(etcdtest.Client(t), func() time.Time { return t0 }, 5*time.Minute, 0)
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
	l := newLeases(etcdtest.Client(t), func() time.Time { return t0 }, 5*time.Minute, 0)
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

// One caller that gives up mid-grant does not fail the others: the grant runs on
// a context its caller's cancel cannot reach, so the waiters still get the lease.
func TestACallerThatCancelsMidGrantDoesNotFailTheWaiters(t *testing.T) {
	l := newLeases(etcdtest.Client(t), func() time.Time { return t0 }, 5*time.Minute, 0)
	var c countingGrants
	c.wrap(l, 300*time.Millisecond)
	exp := t0.Add(10 * time.Minute)
	gctx, cancel := context.WithCancel(context.Background())
	granter := make(chan error, 1)
	go func() {
		_, err := l.For(gctx, exp)
		granter <- err
	}()
	time.Sleep(50 * time.Millisecond) // the granter's grant is under way
	const waiters = 5
	ids := make([]clientv3.LeaseID, waiters)
	errs := make([]error, waiters)
	var wg sync.WaitGroup
	for i := range waiters {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ids[i], errs[i] = l.For(context.Background(), exp)
		}()
	}
	time.Sleep(50 * time.Millisecond)
	cancel() // the granter gives up mid-grant
	wg.Wait()
	if err := <-granter; !errors.Is(err, context.Canceled) {
		t.Fatalf("the granter that cancelled: %v, want context.Canceled", err)
	}
	for i := range waiters {
		if errs[i] != nil || ids[i] == 0 || ids[i] != ids[0] {
			t.Fatalf("waiter %d: lease %v, %v; want the one lease", i, ids[i], errs[i])
		}
	}
	if n := c.n.Load(); n != 1 {
		t.Fatalf("%d grants, want 1", n)
	}
}

// A starter with almost no budget left does not fail the waiters: the grant
// runs for a full call timeout from when it starts, not for the starter's.
func TestAStartersShortDeadlineDoesNotFailTheWaiters(t *testing.T) {
	l := newLeases(etcdtest.Client(t), func() time.Time { return t0 }, 5*time.Minute, 2*time.Second)
	var c countingGrants
	c.wrap(l, 100*time.Millisecond)
	exp := t0.Add(10 * time.Minute)
	sctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	starter := make(chan error, 1)
	go func() {
		_, err := l.For(sctx, exp)
		starter <- err
	}()
	time.Sleep(5 * time.Millisecond)
	const waiters = 5
	ids := make([]clientv3.LeaseID, waiters)
	errs := make([]error, waiters)
	var wg sync.WaitGroup
	for i := range waiters {
		wg.Add(1)
		go func() {
			defer wg.Done()
			wctx, wcancel := context.WithTimeout(context.Background(), time.Second)
			defer wcancel()
			ids[i], errs[i] = l.For(wctx, exp)
		}()
	}
	wg.Wait()
	if err := <-starter; !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("the starter: %v, want its own deadline", err)
	}
	for i := range waiters {
		if errs[i] != nil || ids[i] == 0 {
			t.Fatalf("waiter %d: lease %v, %v; want a lease", i, ids[i], errs[i])
		}
	}
}

// The grant's own bound is honoured: a grant that never answers ends at the
// call timeout, whatever the caller's ctx; and a waiter whose ctx is live then
// starts the next grant instead of taking the first one's timeout as its error.
func TestAGrantEndsAtTheCallTimeoutAndAWaiterGrantsNext(t *testing.T) {
	l := newLeases(etcdtest.Client(t), func() time.Time { return t0 }, 5*time.Minute, 100*time.Millisecond)
	inner := l.grant
	var calls atomic.Int64
	var bound atomic.Int64 // ms between the first grant's start and its ctx ending
	l.grant = func(ctx context.Context, ttl int64) (*clientv3.LeaseGrantResponse, error) {
		if calls.Add(1) == 1 {
			start := time.Now()
			<-ctx.Done() // a member that never answers
			bound.Store(time.Since(start).Milliseconds())
			return nil, ctx.Err()
		}
		return inner(ctx, ttl)
	}
	exp := t0.Add(10 * time.Minute)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	id, err := l.For(ctx, exp)
	if err != nil || id == 0 {
		t.Fatalf("a caller with a live ctx: lease %v, %v; want the next grant's lease", id, err)
	}
	if calls.Load() != 2 {
		t.Fatalf("%d grants, want 2", calls.Load())
	}
	if ms := bound.Load(); ms < 80 || ms > 1000 {
		t.Fatalf("the first grant ended after %d ms, want about its 100 ms bound", ms)
	}
}

// A lease's TTL is a duration worked out on the minting clock alone: the
// expiry and the now it is measured from are both the broker's, and etcd counts
// the TTL down on its own clock. So a broker whose clock is skewed asks for the
// same TTL as one in step, and a token from a broker ahead is reclaimed no
// later than ttl + lease_grace + one bucket after it was minted, whatever the
// skew (design 8; audit F8-1).
func TestALeaseTTLIsTheSameWhateverTheMintingClockSays(t *testing.T) {
	const grace, ttl = 5 * time.Minute, 30 * time.Second
	asked := func(skew time.Duration) int64 {
		t.Helper()
		// Near the real clock: a lease is asked for from the clock that mints it.
		now := time.Now().Truncate(time.Minute).Add(10 * time.Second).Add(skew)
		l := newLeases(etcdtest.Client(t), func() time.Time { return now }, grace, 0)
		var got atomic.Int64
		l.grant = func(ctx context.Context, ttl int64) (*clientv3.LeaseGrantResponse, error) {
			got.Store(ttl)
			return &clientv3.LeaseGrantResponse{ID: 1, TTL: ttl}, nil
		}
		if _, err := l.For(context.Background(), now.Add(ttl)); err != nil {
			t.Fatal(err)
		}
		return got.Load()
	}
	inStep := asked(0)
	for _, skew := range []time.Duration{-2 * time.Minute, 2 * time.Minute, time.Hour} {
		if got := asked(skew); got != inStep {
			t.Errorf("a clock %v off asks for a %ds lease, in step asks %ds", skew, got, inStep)
		}
	}
	// The bound the docs state: token_ttl + lease_grace plus up to a bucket, and the
	// bucket the grant keeps spare for later records.
	if max := int64((ttl + grace + 2*leaseBucket).Seconds()); inStep > max {
		t.Errorf("a %ds lease for a %v token, want at most %ds", inStep, ttl, max)
	}
}
