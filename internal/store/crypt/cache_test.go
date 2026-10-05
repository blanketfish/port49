package crypt

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/memory"
)

// backing is the store under a cache in these tests: a memory store
// whose GetContext answers what the test says, counting reads.
type backing struct {
	store.Store
	mu    sync.Mutex
	c     store.Context
	err   error
	reads int
	hook  func() // run inside each read, before it answers
}

func (b *backing) GetContext(_ context.Context, _ store.ContextKey) (store.Context, error) {
	b.mu.Lock()
	b.reads++
	c, err, hook := b.c, b.err, b.hook
	b.mu.Unlock()
	if hook != nil {
		hook()
	}
	return c, err
}

func (b *backing) set(c store.Context, err error) { b.mu.Lock(); b.c, b.err = c, err; b.mu.Unlock() }
func (b *backing) count() int                     { b.mu.Lock(); defer b.mu.Unlock(); return b.reads }

// cacheRig is a cache over a backing whose context at ka the ledger knows
// at revision 7, with the feed up and a clock the test moves.
func cacheRig(t *testing.T) (*backing, store.Store, *Ledger, *time.Time, *prometheus.CounterVec) {
	t.Helper()
	now := time.Unix(1_800_000_000, 0)
	b := &backing{Store: memory.New(time.Now), c: store.Context{CtxID: "c1", Username: "alice", Rev: 7, LastTouchedAt: now}}
	l := NewLedger()
	l.Observe(ka, 7, 7, time.Time{}, time.Time{})
	l.Fence().SetUp(true)
	lookups := prometheus.NewCounterVec(prometheus.CounterOpts{Name: "t"}, []string{"outcome"})
	c := Cached(b, l, CacheConfig{TTL: 2 * time.Second, Max: 4, IdleTTL: time.Hour,
		Now: func() time.Time { return now }, Lookups: lookups})
	return b, c, l, &now, lookups
}

func get(t *testing.T, c store.Store) (store.Context, error) {
	t.Helper()
	return c.GetContext(context.Background(), ka)
}

func TestACachedContextIsServedWithoutAStoreRead(t *testing.T) {
	b, c, _, _, lookups := cacheRig(t)
	for i := 0; i < 3; i++ {
		if got, err := get(t, c); err != nil || got.CtxID != "c1" {
			t.Fatalf("%v %v", got, err)
		}
	}
	if b.count() != 1 || testutil.ToFloat64(lookups.WithLabelValues("hit")) != 2 {
		t.Fatalf("reads %d, hits %v", b.count(), testutil.ToFloat64(lookups.WithLabelValues("hit")))
	}
}

func TestAnEntryPastItsTTLIsReadAgain(t *testing.T) {
	b, c, _, now, _ := cacheRig(t)
	get(t, c)
	*now = now.Add(2 * time.Second)
	get(t, c)
	if b.count() != 2 {
		t.Fatalf("reads %d, want 2", b.count())
	}
}

func TestAWriteAtTheKeyEvictsIt(t *testing.T) {
	b, c, _, _, _ := cacheRig(t)
	get(t, c)
	if err := c.TouchContext(context.Background(), ka, time.Hour); err != nil && !errors.Is(err, store.ErrNotFound) {
		t.Fatal(err)
	}
	get(t, c)
	if b.count() != 2 {
		t.Fatalf("reads %d: a write did not evict", b.count())
	}
}

// Review Focus 3: every change the feed brings evicts, a delete included.
func TestAFeedChangeEvictsTheKey(t *testing.T) {
	b, c, l, _, _ := cacheRig(t)
	get(t, c)
	l.changed(ka)
	get(t, c)
	if b.count() != 2 {
		t.Fatalf("reads %d: a feed change did not evict", b.count())
	}
}

func TestARescanClearsTheCache(t *testing.T) {
	b, c, l, _, _ := cacheRig(t)
	get(t, c)
	l.rescanned()
	get(t, c)
	if b.count() != 2 {
		t.Fatalf("reads %d: a rescan did not clear", b.count())
	}
}

// A later record the ledger knows (this process's own write, or one the
// feed raised) makes the entry no hit, before any eviction lands.
func TestALaterRecordTheLedgerKnowsIsReadNotServed(t *testing.T) {
	b, c, l, _, _ := cacheRig(t)
	get(t, c)
	l.Observe(ka, 9, 9, time.Time{}, time.Time{})
	get(t, c)
	if b.count() != 2 {
		t.Fatalf("reads %d: a superseded entry was a hit", b.count())
	}
}

func TestNoHitWhileTheFeedIsDown(t *testing.T) {
	b, c, l, _, _ := cacheRig(t)
	get(t, c)
	l.Fence().SetUp(false)
	get(t, c)
	if b.count() != 2 {
		t.Fatalf("reads %d: a hit with the feed down", b.count())
	}
}

// Review Focus 3: a read that raced an eviction is not cached, so the
// change it raced is not hidden behind it.
func TestAReadThatRacedAnEvictionIsNotCached(t *testing.T) {
	b, c, l, _, _ := cacheRig(t)
	b.hook = func() { l.changed(ka) } // the change lands while the read is in flight
	get(t, c)
	b.hook = nil
	get(t, c)
	if b.count() != 2 {
		t.Fatalf("reads %d: a read that raced an eviction was cached", b.count())
	}
}

// Through an outage an entry past its TTL is served, counted and told
// (design §12).
func TestAnOutageServesTheEntryPastItsTTL(t *testing.T) {
	b, c, _, now, lookups := cacheRig(t)
	get(t, c)
	*now = now.Add(5 * time.Second)
	b.set(store.Context{}, store.ErrUnavailable)
	got, err := get(t, c)
	if err != nil || got.CtxID != "c1" || testutil.ToFloat64(lookups.WithLabelValues("stale")) != 1 {
		t.Fatalf("%v %v stale %v", got, err, testutil.ToFloat64(lookups.WithLabelValues("stale")))
	}
}

// Review Focus 3: never stale once a later record is known, nor past the
// context's own idle TTL, nor on not found.
func TestASupersededEntryIsNeverServedStale(t *testing.T) {
	for _, c := range []struct {
		name string
		edit func(b *backing, l *Ledger, now *time.Time)
		want error
	}{
		{"a later record known", func(b *backing, l *Ledger, _ *time.Time) {
			l.Observe(ka, 9, 9, time.Time{}, time.Time{})
			b.set(store.Context{}, store.ErrUnavailable)
		}, store.ErrUnavailable},
		{"past its idle TTL", func(b *backing, _ *Ledger, now *time.Time) {
			*now = now.Add(2 * time.Hour)
			b.set(store.Context{}, store.ErrUnavailable)
		}, store.ErrUnavailable},
		{"not found", func(b *backing, _ *Ledger, now *time.Time) {
			*now = now.Add(5 * time.Second)
			b.set(store.Context{}, store.ErrNotFound)
		}, store.ErrNotFound},
	} {
		b, cc, l, now, _ := cacheRig(t)
		get(t, cc)
		c.edit(b, l, now)
		if _, err := get(t, cc); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", c.name, err, c.want)
		}
	}
}

// A fence timeout is never served stale (plan 7f, I-2). crypt.Fenced waits
// only when the store's record carries a different revision than the
// ledger's, so a read that failed in the fence wait means etcd answered with
// a later record than the cached one, possibly a revocation (SetRevokedAt):
// that is not an outage. The guard keeps the fence's error inside its own
// ErrUnavailable, and the cache refuses to serve on it, and evicts the entry.
func TestAFenceTimeoutIsNeverServedStale(t *testing.T) {
	b, c, _, now, lookups := cacheRig(t)
	get(t, c)
	*now = now.Add(5 * time.Second) // past the TTL, within the idle TTL
	b.set(store.Context{}, fmt.Errorf("%w: no answer (%w)", store.ErrUnavailable, ErrFeedBehind))
	got, err := get(t, c)
	if err == nil || got.CtxID != "" {
		t.Fatalf("a fence timeout served %q, %v", got.CtxID, err)
	}
	if !errors.Is(err, store.ErrUnavailable) || !errors.Is(err, ErrFeedBehind) {
		t.Fatalf("the error lost its meaning: %v", err)
	}
	if n := testutil.ToFloat64(lookups.WithLabelValues("stale")); n != 0 {
		t.Fatalf("stale serves counted: %v", n)
	}
	if n := len(c.(*cache).m); n != 0 {
		t.Fatalf("%d entries: the superseded one was kept", n)
	}
}

// A hit hands out a copy: the entry's SessionDiscriminators slice is shared
// with no caller (store.Context is returned by value, its slice is not).
func TestAHitIsACopy(t *testing.T) {
	b, c, _, _, _ := cacheRig(t)
	b.c.SessionDiscriminators = []string{"d1", "d2"}
	first, _ := get(t, c)
	first.SessionDiscriminators[0] = "edited"
	second, _ := get(t, c) // a hit
	if second.SessionDiscriminators[0] != "d1" {
		t.Fatalf("a caller's edit reached the cached entry: %v", second.SessionDiscriminators)
	}
}

func TestTheCacheIsBounded(t *testing.T) {
	b, c, l, _, _ := cacheRig(t)
	for i := 0; i < 6; i++ {
		k := store.ContextKey{NAS: "leaf", Username: string(rune('a' + i))}
		l.Observe(k, 7, 7, time.Time{}, time.Time{})
		c.GetContext(context.Background(), k)
	}
	if n := len(c.(*cache).m); n > 4 {
		t.Fatalf("%d entries, Max 4", n)
	}
	_ = b
}

// A read the fence timed out leaves the feed behind: until it catches up, an
// ErrUnavailable that is not itself ErrFeedBehind (an open circuit, saturated
// slots) is no outage either, and no entry is served stale (plan 7f, review
// I-1). A true outage, with the feed not behind, still serves.
func TestNoStaleServeWhileTheFeedIsBehindATimedOutRead(t *testing.T) {
	b, c, l, now, lookups := cacheRig(t)
	get(t, c)
	l.Fence().Attach(5)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := l.Fence().Wait(ctx, 99); !errors.Is(err, ErrFeedBehind) {
		t.Fatal(err)
	}
	*now = now.Add(5 * time.Second)
	b.set(store.Context{}, fmt.Errorf("%w: the context pool's circuit is open", store.ErrUnavailable))
	if _, err := get(t, c); !errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("served while the feed was behind: %v", err)
	}
	if n := testutil.ToFloat64(lookups.WithLabelValues("stale")); n != 0 {
		t.Fatalf("stale serves counted: %v", n)
	}
	// The feed catches up: the entry was refused, not evicted, and an outage serves again.
	l.Fence().Followed(99)
	b.set(store.Context{}, store.ErrUnavailable)
	if got, err := get(t, c); err != nil || got.CtxID != "c1" {
		t.Fatalf("an outage with the feed caught up: %v %v", got, err)
	}
}

func TestCachedBoundsAreTrustedNoFurtherThanTheirDefaults(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	b := &backing{Store: memory.New(time.Now), c: store.Context{CtxID: "c1", Rev: 7, LastTouchedAt: now}}
	l := NewLedger()
	l.Observe(ka, 7, 7, time.Time{}, time.Time{})
	l.Fence().SetUp(true)
	c := Cached(b, l, CacheConfig{TTL: time.Second, Max: 0, IdleTTL: time.Hour, Now: func() time.Time { return now }})
	kb := store.ContextKey{NAS: "leaf-02", Username: "bob"}
	l.Observe(kb, 7, 7, time.Time{}, time.Time{})
	for _, k := range []store.ContextKey{ka, kb, ka, kb} {
		c.GetContext(context.Background(), k)
	}
	if b.count() != 2 {
		t.Fatalf("reads %d: Max 0 kept fewer than two entries", b.count())
	}
	// TTL 0: nothing is a hit and nothing is ever served stale.
	b2 := &backing{Store: memory.New(time.Now), c: store.Context{CtxID: "c1", Rev: 7, LastTouchedAt: now}}
	c2 := Cached(b2, l, CacheConfig{TTL: 0, Max: 4, IdleTTL: time.Hour, Now: func() time.Time { return now }})
	get(t, c2)
	get(t, c2)
	if b2.count() != 2 {
		t.Fatalf("reads %d: TTL 0 served a hit", b2.count())
	}
	b2.set(store.Context{}, store.ErrUnavailable)
	if _, err := get(t, c2); !errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("TTL 0 served stale: %v", err)
	}
}

// A read still waiting on the fence, not yet timed out, is the store having
// answered with a record the feed has not reached: an open circuit or
// saturated slots meanwhile are no outage either (plan 7f, review m-1).
func TestNoStaleServeWhileAReadWaitsOnTheFence(t *testing.T) {
	b, c, l, now, lookups := cacheRig(t)
	get(t, c)
	l.Fence().Attach(5)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go l.Fence().Wait(ctx, 99)
	eventually(t, func() bool { return l.Fence().Behind() })
	*now = now.Add(5 * time.Second)
	b.set(store.Context{}, fmt.Errorf("%w: the context pool's circuit is open", store.ErrUnavailable))
	if _, err := get(t, c); !errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("served while a read waited on the fence: %v", err)
	}
	if n := testutil.ToFloat64(lookups.WithLabelValues("stale")); n != 0 {
		t.Fatalf("stale serves counted: %v", n)
	}
}

// A cached key is no hit while a read waits on the fence: the feed is behind
// a read, so the entry may predate a change the store already holds (plan 7f,
// final review I-3). The read goes through to the store.
func TestNoHitWhileTheFeedIsBehindARead(t *testing.T) {
	b, c, l, _, lookups := cacheRig(t)
	get(t, c)
	l.Fence().Attach(5)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go l.Fence().Wait(ctx, 99)
	eventually(t, func() bool { return l.Fence().Behind() })
	if _, err := get(t, c); err != nil {
		t.Fatal(err)
	}
	if b.count() != 2 {
		t.Fatalf("the backing was read %d times, want 2 (the second a read-through)", b.count())
	}
	if n := testutil.ToFloat64(lookups.WithLabelValues("hit")); n != 0 {
		t.Fatalf("hits counted while the feed was behind a read: %v", n)
	}
}

// A change the feed brings while a read is in flight evicts the entry; the
// read then failing as unavailable must not serve that evicted entry stale
// (plan 7f, final review M-1). A delete does not move the ledger, so knownAt
// alone would not refuse it.
func TestAnEntryEvictedDuringTheReadIsNotServedStale(t *testing.T) {
	b, c, l, now, _ := cacheRig(t)
	get(t, c)
	*now = now.Add(5 * time.Second) // past the TTL, so the read goes to the store
	b.mu.Lock()
	b.hook = func() { l.changed(ka) }
	b.mu.Unlock()
	b.set(store.Context{}, store.ErrUnavailable)
	if got, err := get(t, c); !errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("served an entry the feed evicted mid-read: %v %v", got, err)
	}
}
