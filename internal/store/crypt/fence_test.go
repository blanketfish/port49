package crypt

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/blanketfish/port49/internal/store"
	"github.com/blanketfish/port49/internal/store/guard"
	"github.com/blanketfish/port49/internal/store/memory"
)

// fencedPair is twoProcesses with b's layer fenced, its feed attached at
// the store's revision and delivering nothing until the test says.
func fencedPair(t *testing.T) (*memory.Store, store.Store, store.Store, *Ledger) {
	t.Helper()
	inner, a, _, _, lb := twoProcesses(t)
	lb.Fence().Attach(inner.Seen())
	return inner, a, Wrap(Fenced(inner, lb), keys(), nil, WithLedger(lb)), lb
}

// feedUpTo stands in for b's feed delivering every change through the
// store's revision: each record at k is observed as FollowContexts would,
// and the fence moves.
func feedUpTo(t *testing.T, inner *memory.Store, l *Ledger, recs ...store.Context) {
	t.Helper()
	for _, c := range recs {
		observe(l, keys(), ka, c, false)
	}
	l.Fence().Followed(inner.Seen())
}

func within(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}

// While b's feed lags, a store writer puts back alice's context over the
// later login a made: b never admits it. It waits and is unavailable, and
// once the feed delivers the later write, it is denied (pre-flight C1).
// Without the fence b admitted it: alice's seq is b's high-water.
func TestAPutBackIsDeniedWhileTheFeedLags(t *testing.T) {
	inner, a, b, lb := fencedPair(t)
	login(t, a, "ctx-alice", "user:alice")
	alice, _ := inner.GetContext(context.Background(), ka)
	feedUpTo(t, inner, lb, alice)
	if c, err := b.GetContext(context.Background(), ka); err != nil || c.CtxID != "ctx-alice" {
		t.Fatalf("b's read of alice's: %v %v", c.CtxID, err)
	}
	login(t, a, "ctx-bob", "user:bob") // the later write b's feed has not delivered
	bob, _ := inner.GetContext(context.Background(), ka)
	if err := inner.PutContext(context.Background(), ka, alice, time.Hour); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := within(150 * time.Millisecond)
	defer cancel()
	c, err := b.GetContext(ctx, ka)
	if err == nil || !errors.Is(err, store.ErrUnavailable) || !errors.Is(err, ErrFeedBehind) {
		t.Fatalf("with the feed behind, b read %q: %v", c.CtxID, err)
	}
	back, _ := inner.GetContext(context.Background(), ka)
	feedUpTo(t, inner, lb, bob, back)
	if _, err := b.GetContext(context.Background(), ka); !errors.Is(err, ErrNotLastWritten) {
		t.Fatalf("once the feed delivered the later write: %v", err)
	}
}

// a revokes alice: its plaintext mark lands and its seal does not (the
// revocation floor's case). A store writer then puts back the record from
// before, revoked_at zeroed. With b's feed down, b never answers it as
// live; once the feed delivers the mark, the record put back is answered
// revoked, from the floor (pre-flight C1).
func TestARevocationFromAnotherProcessHoldsWhileTheFeedIsDown(t *testing.T) {
	inner, a, b, lb := fencedPair(t)
	login(t, a, "ctx-alice", "user:alice")
	before, _ := inner.GetContext(context.Background(), ka)
	feedUpTo(t, inner, lb, before)
	if _, err := b.GetContext(context.Background(), ka); err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC().Truncate(time.Second)
	if err := inner.SetRevokedAt(context.Background(), ka, at); err != nil { // the plaintext mark alone
		t.Fatal(err)
	}
	marked, _ := inner.GetContext(context.Background(), ka)
	before.RevokedAt = time.Time{}
	if err := inner.PutContext(context.Background(), ka, before, time.Hour); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := within(150 * time.Millisecond)
	defer cancel()
	if c, err := b.GetContext(ctx, ka); err == nil {
		t.Fatalf("with the feed down, b answered the put-back, revoked_at %v", c.RevokedAt)
	} else if !errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("with the feed down: %v", err)
	}
	back, _ := inner.GetContext(context.Background(), ka)
	feedUpTo(t, inner, lb, marked, back)
	c, err := b.GetContext(context.Background(), ka)
	if err != nil || !c.RevokedAt.Equal(at) {
		t.Fatalf("once the feed delivered the mark: revoked_at %v, %v", c.RevokedAt, err)
	}
}

// A login on a, read on b before b's feed has delivered it, is admitted
// once the feed does, within the read's wait (Review Focus 1).
func TestAnotherProcesssWriteIsAdmittedOnceTheFeedDeliversIt(t *testing.T) {
	inner, a, b, lb := fencedPair(t)
	feed := &feedOf{changes: make(chan store.ContextChange, 1), compact: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go FollowContexts(ctx, feed, nil, keys(), lb, inner.Seen(), func(bool) {}, func() {}, t.Logf)
	login(t, a, "ctx-alice", "user:alice")
	alice, _ := inner.GetContext(context.Background(), ka)
	go func() {
		time.Sleep(50 * time.Millisecond)
		feed.changes <- store.ContextChange{Key: ka, Context: alice, Rev: alice.Rev}
	}()
	rctx, rcancel := within(2 * time.Second)
	defer rcancel()
	if c, err := b.GetContext(rctx, ka); err != nil || c.CtxID != "ctx-alice" {
		t.Fatalf("b's read once its feed delivered a's login: %v %v", c.CtxID, err)
	}
}

// A read waiting on a feed with nothing to deliver asks it for its
// progress, and the answer lets it through (an idle family; etcd's
// RequestProgress).
func TestAWaitingReadAsksTheFeedForItsProgress(t *testing.T) {
	inner, a, b, lb := fencedPair(t)
	login(t, a, "ctx-alice", "user:alice")
	feed := &answeringFeed{now: inner.Seen}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go FollowContexts(ctx, feed, nil, keys(), lb, inner.Seen(), func(bool) {}, func() {}, t.Logf)
	rctx, rcancel := within(2 * time.Second)
	defer rcancel()
	if _, err := b.GetContext(rctx, ka); err != nil {
		t.Fatalf("a read the feed's progress answer should let through: %v", err)
	}
	if feed.asked.Load() == 0 {
		t.Fatal("the read never asked the feed")
	}
}

// answeringFeed delivers no change, and answers every ask with progress
// at the store's revision.
type answeringFeed struct {
	now   func() uint64
	asked atomic.Int32
}

func (f *answeringFeed) ScanContexts(context.Context, func(store.ContextKey, store.Context)) (uint64, error) {
	return f.now(), nil
}

func (f *answeringFeed) WatchContexts(ctx context.Context, _ uint64, _ func(store.ContextChange),
	progress func(uint64), asks <-chan struct{}) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-asks:
			f.asked.Add(1)
			progress(f.now())
		}
	}
}

// A ping through the fence fails while the feed is behind the revision
// the ping read at, so an idle port49d's probe takes it dark when its
// feed has stopped (Ruling 11).
func TestAPingFailsWhileTheFeedIsBehind(t *testing.T) {
	inner, a, _, lb := fencedPair(t)
	login(t, a, "ctx-alice", "user:alice") // the store moves past the fence
	f := Fenced(inner, lb)
	ctx, cancel := within(100 * time.Millisecond)
	defer cancel()
	if err := f.Ping(ctx); !errors.Is(err, ErrFeedBehind) {
		t.Fatalf("a ping with the feed behind: %v", err)
	}
	lb.Fence().Followed(inner.Seen())
	if err := f.Ping(context.Background()); err != nil {
		t.Fatalf("a ping with the feed caught up: %v", err)
	}
}

// Under the guard, a read the feed never lets through is the guard's
// timeout, counted in the context pool: a dead feed opens the circuit as
// a dead store does.
func TestAFeedThatNeverArrivesIsCountedByTheGuard(t *testing.T) {
	inner, a, _, lb := fencedPair(t)
	login(t, a, "ctx-alice", "user:alice")
	calls := prometheus.NewCounterVec(prometheus.CounterOpts{Name: "calls"}, []string{"component", "pool", "outcome"})
	g := guard.WrapRev(Fenced(inner, lb), guard.Config{Component: "daemon", CallTimeout: 100 * time.Millisecond,
		BulkTimeout: time.Second, Now: time.Now, Metrics: guard.Metrics{Calls: calls}})
	if _, err := g.GetContext(context.Background(), ka); !errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("%v", err)
	}
	if n := testutil.ToFloat64(calls.WithLabelValues("daemon", "context", "timeout")); n != 1 {
		t.Fatalf("the guard counted %v timeouts", n)
	}
}

// A fence no feed is attached to holds nothing: memory, a fixture and the
// offline revocation read at once, even with ctx already ended.
func TestAFenceWithNoFeedAttachedNeverWaits(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := newFence().Wait(ctx, 99); err != nil {
		t.Fatalf("a wait with no feed attached: %v", err)
	}
}

// A process reads its own landed write without waiting for its feed: the
// login's next packet on the same process is neither slowed nor, with the
// feed down, denied.
func TestAProcesssOwnWriteIsReadWithoutWaitingForTheFeed(t *testing.T) {
	_, _, b, _ := fencedPair(t)
	login(t, b, "ctx-alice", "user:alice")
	ctx, cancel := within(100 * time.Millisecond)
	defer cancel()
	if c, err := b.GetContext(ctx, ka); err != nil || c.CtxID != "ctx-alice" {
		t.Fatalf("b's read of its own write with its feed delivering nothing: %v %v", c.CtxID, err)
	}
}

// A watch that takes a read's ask and fails before answering it loses
// the ask; the next watch is asked again, so the read is let through
// rather than waiting out its deadline (review 8a M-4).
func TestAnAskAFailedWatchTookIsAskedAgain(t *testing.T) {
	inner, a, b, lb := fencedPair(t)
	login(t, a, "ctx-alice", "user:alice")
	feed := &losingFeed{answeringFeed: answeringFeed{now: inner.Seen}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go FollowContexts(ctx, feed, nil, keys(), lb, inner.Seen(), func(bool) {}, func() {}, t.Logf)
	rctx, rcancel := within(3 * time.Second)
	defer rcancel()
	if _, err := b.GetContext(rctx, ka); err != nil {
		t.Fatalf("a read whose ask the first watch lost: %v", err)
	}
	if feed.watches.Load() < 2 {
		t.Fatalf("let through by %d watch(es)", feed.watches.Load())
	}
}

// losingFeed's first watch takes one ask and fails without answering it;
// every later watch is an answeringFeed's.
type losingFeed struct {
	answeringFeed
	watches atomic.Int32
}

func (f *losingFeed) WatchContexts(ctx context.Context, after uint64, fn func(store.ContextChange),
	progress func(uint64), asks <-chan struct{}) error {
	if f.watches.Add(1) == 1 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-asks:
			return store.ErrUnavailable
		}
	}
	return f.answeringFeed.WatchContexts(ctx, after, fn, progress, asks)
}

// The fence only rises: a later Followed or Attach below it lowers
// nothing, so a read it held is never let through by a stale revision.
func TestTheFenceNeverLowers(t *testing.T) {
	f := newFence()
	f.Attach(10)
	f.Followed(5)
	if f.At() != 10 {
		t.Fatalf("Followed(5) after Attach(10) left the fence at %d", f.At())
	}
	f.Attach(3)
	if f.At() != 10 {
		t.Fatalf("Attach(3) left the fence at %d", f.At())
	}
}

// A read the feed has not passed by its deadline is told to the fence's
// timeout hook (port49_store_fence_timeouts_total; final review 7e-1
// M-4); a read the feed has passed is not.
func TestAFenceTimeoutIsTold(t *testing.T) {
	f := newFence()
	var timeouts atomic.Int32
	f.OnTimeout(func() { timeouts.Add(1) })
	f.Attach(5)
	if err := f.Wait(context.Background(), 5); err != nil || timeouts.Load() != 0 {
		t.Fatalf("a read the feed has passed: %v, %d timeouts", err, timeouts.Load())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := f.Wait(ctx, 9); !errors.Is(err, ErrFeedBehind) || timeouts.Load() != 1 {
		t.Fatalf("a read the feed has not passed: %v, %d timeouts", err, timeouts.Load())
	}
}
