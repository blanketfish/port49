package crypt

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/memory"
)

// feedOf is a ContextFeed over a memory store for these tests: a scan of
// what the test planted, and a watch that delivers what the test sends.
type feedOf struct {
	mu      sync.Mutex
	scanned map[store.ContextKey]store.Context
	rev     uint64
	changes chan store.ContextChange
	compact chan struct{}
}

func (f *feedOf) ScanContexts(_ context.Context, fn func(store.ContextKey, store.Context)) (uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for k, c := range f.scanned {
		fn(k, c)
	}
	return f.rev, nil
}

func (f *feedOf) WatchContexts(ctx context.Context, _ uint64, fn func(store.ContextChange),
	progress func(uint64), _ <-chan struct{}) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case c := <-f.changes:
			fn(c)
			progress(c.Rev)
		case <-f.compact:
			return store.ErrCompacted
		}
	}
}

// setScanned replaces what the next scan finds, under the feed's lock: a
// rescan runs on FollowContexts's goroutine (pre-flight M4, the race).
func (f *feedOf) setScanned(m map[store.ContextKey]store.Context, rev uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.scanned, f.rev = m, rev
}

type marksOf []store.LedgerMark

func (m marksOf) LedgerMarks(context.Context) (uint64, []store.LedgerMark, error) { return 1, m, nil }

// until polls cond every 5ms for up to d, and reports whether it held.
func until(cond func() bool, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for !cond() {
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(5 * time.Millisecond)
	}
	return true
}

// eventually fails t unless cond holds within 10s. It is called on the
// test's goroutine only; a goroutine of the test's own uses until.
func eventually(t *testing.T, cond func() bool) {
	t.Helper()
	if !until(cond, 10*time.Second) {
		t.Fatal("never held")
	}
}

// seqOf is the sequence c, read at ka, is sealed at.
func seqOf(t *testing.T, c store.Context) uint64 {
	t.Helper()
	_, seq, err := openContextWith(keys(), ka, c)
	if err != nil {
		t.Fatal(err)
	}
	return seq
}

// sealedAt is a context for k sealed with the test keys at seq, as the
// backend holds it.
func sealedAt(t *testing.T, k store.ContextKey, seq uint64) store.Context {
	t.Helper()
	c, err := (&wrapped{keys: keys()}).sealContext(k, store.Context{CtxID: "ctx-" + k.Username,
		Principal: "user:" + k.Username, Username: k.Username}, seq)
	if err != nil {
		t.Fatal(err)
	}
	c.Rev = seq
	return c
}

// A process's feed brings another process's later write: the mark rises,
// so a record put back below it is denied even if this process never
// read the later one (Review Focus 2; Ruling 3).
func TestTheFeedRaisesTheHighWaterSoAPutBackIsDenied(t *testing.T) {
	inner, a, _, _, lb := twoProcesses(t)
	login(t, a, "ctx-alice", "user:alice")
	saved, _ := inner.GetContext(context.Background(), ka)
	b := Wrap(inner, keys(), nil, WithLedger(lb))
	if _, err := b.GetContext(context.Background(), ka); err != nil {
		t.Fatal(err) // b knows alice's
	}
	login(t, a, "ctx-bob", "user:bob")
	later, _ := inner.GetContext(context.Background(), ka)
	feed := &feedOf{changes: make(chan store.ContextChange, 1), compact: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go FollowContexts(ctx, feed, nil, keys(), lb, 0, func(bool) {}, func() {}, t.Logf)
	feed.changes <- store.ContextChange{Key: ka, Context: later, Rev: later.Rev}
	eventually(t, func() bool { return lb.next(ka) > 0 && !lb.admits(ka, seqOf(t, saved)) })
	inner.PutContext(context.Background(), ka, saved, time.Hour)
	if _, err := b.GetContext(context.Background(), ka); !errors.Is(err, ErrNotLastWritten) {
		t.Fatalf("a put-back below a mark the feed raised was admitted: %v", err)
	}
}

// A start's ledger: the record's marks first, then the scan; a scanned
// record below its key's recorded mark is a put-back and raises nothing;
// the base is just past the scan (Ruling 4).
func TestLoadLedgerTakesTheRecordOverAPutBack(t *testing.T) {
	inner, a, _, _, _ := twoProcesses(t)
	login(t, a, "ctx-alice", "user:alice")
	saved, _ := inner.GetContext(context.Background(), ka)
	login(t, a, "ctx-bob", "user:bob")
	later, _ := inner.GetContext(context.Background(), ka)
	feed := &feedOf{scanned: map[store.ContextKey]store.Context{ka: saved}, rev: inner.Seen()}
	l := NewLedger()
	rev, known, recorded, err := LoadLedger(context.Background(), feed, marksOf{{Key: ka, Seq: seqOf(t, later)}}, keys(), l)
	if err != nil || rev != feed.rev || known != 1 || recorded != 1 || l.Base() != rev+1 {
		t.Fatalf("rev %d known %d recorded %d base %d: %v", rev, known, recorded, l.Base(), err)
	}
	if l.admits(ka, seqOf(t, saved)) {
		t.Fatal("a scanned record below the recorded mark was admitted")
	}
}

// A compacted watch scans again, counts the rescan, and goes on. The rescan
// raises a mark below a record it finds, never lowers one above it, and
// makes an entry only for a record at or above the base: nothing the
// earlier scan would have denied is admitted (pre-flight M4: each half can
// fail; I1).
func TestACompactedFeedScansAgainAndOnlyRaises(t *testing.T) {
	kb := store.ContextKey{NAS: "leaf-02", Username: "bob"}
	kc := store.ContextKey{NAS: "leaf-03", Username: "carol"}
	kd := store.ContextKey{NAS: "leaf-04", Username: "dave"}
	l := NewLedger()
	l.SetBase(150)
	l.Observe(ka, 100, 100, time.Time{}, time.Time{})
	l.Observe(kb, 10, 10, time.Time{}, time.Time{})
	feed := &feedOf{changes: make(chan store.ContextChange), compact: make(chan struct{}, 1)}
	feed.setScanned(map[store.ContextKey]store.Context{
		ka: sealedAt(t, ka, 50),  // below ka's mark: must not lower it
		kb: sealedAt(t, kb, 300), // above kb's mark: must raise it
		kc: sealedAt(t, kc, 60),  // unseen, below the base: a put-back, no entry
		kd: sealedAt(t, kd, 400), // unseen, above the base: an entry
	}, 500)
	feed.compact <- struct{}{}
	var rescans atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		until(func() bool { return rescans.Load() > 0 && l.next(kd) == 401 }, 10*time.Second)
		cancel()
	}()
	FollowContexts(ctx, feed, nil, keys(), l, 150, func(bool) {}, func() { rescans.Add(1) }, t.Logf)
	if rescans.Load() != 1 || l.next(kd) != 401 {
		t.Fatalf("rescans %d, next at an unseen key above the base %d", rescans.Load(), l.next(kd))
	}
	if l.next(ka) != 101 {
		t.Fatalf("a rescan lowered the mark: next %d", l.next(ka))
	}
	if l.next(kb) != 301 {
		t.Fatalf("a rescan did not raise the mark: next %d", l.next(kb))
	}
	if l.admits(kc, 60) {
		t.Fatal("a rescan made an entry from a record below the base")
	}
}

// A put-back at a key this process never saw, brought by the feed, makes
// no entry: the read still judges it against the base, and denies it
// (pre-flight I1). Before ObserveFollowed, the event made hw = its own
// sequence and the read admitted it.
func TestAFedPutBackAtAnUnseenKeyIsDenied(t *testing.T) {
	inner, a, _, _, _ := twoProcesses(t)
	login(t, a, "ctx-alice", "user:alice")
	saved, _ := inner.GetContext(context.Background(), ka)
	if err := inner.DeleteContext(context.Background(), ka); err != nil {
		t.Fatal(err)
	}
	late := NewLedger()
	late.SetBase(inner.Seen() + 1) // started after the delete: ka is not in its scan
	c := Wrap(inner, keys(), nil, WithLedger(late))
	if err := inner.PutContext(context.Background(), ka, saved, time.Hour); err != nil {
		t.Fatal(err)
	}
	back, _ := inner.GetContext(context.Background(), ka)
	feed := &feedOf{changes: make(chan store.ContextChange, 1), compact: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	delivered := make(chan struct{})
	go FollowContexts(ctx, &tapFeed{feedOf: feed, after: func() { close(delivered) }}, nil, keys(), late,
		late.Base()-1, func(bool) {}, func() {}, t.Logf)
	feed.changes <- store.ContextChange{Key: ka, Context: back, Rev: back.Rev}
	<-delivered
	if _, err := c.GetContext(context.Background(), ka); !errors.Is(err, ErrNotLastWritten) {
		t.Fatalf("a put-back the feed brought at an unseen key was admitted: %v", err)
	}
}

// A compacted watch seeds from the ledger record before it scans again
// (re-check R1). b knows alice's record; while b's watch is down, a logs
// bob in and a store writer puts alice's back over it. The rescan sees
// only alice's, so without the seed it raises nothing, and alice's is
// admitted at b's high-water. The record holds bob's mark, and it is
// denied.
func TestACompactedRescanSeedsFromTheLedgerRecord(t *testing.T) {
	inner, a, _, _, lb := twoProcesses(t)
	login(t, a, "ctx-alice", "user:alice")
	alice, _ := inner.GetContext(context.Background(), ka)
	b := Wrap(inner, keys(), nil, WithLedger(lb))
	if _, err := b.GetContext(context.Background(), ka); err != nil {
		t.Fatal(err) // b's high-water at ka is alice's
	}
	login(t, a, "ctx-bob", "user:bob") // in the gap: b's watch delivers nothing
	bob, _ := inner.GetContext(context.Background(), ka)
	if err := inner.PutContext(context.Background(), ka, alice, time.Hour); err != nil {
		t.Fatal(err)
	}
	back, _ := inner.GetContext(context.Background(), ka)
	feed := &feedOf{changes: make(chan store.ContextChange), compact: make(chan struct{}, 1)}
	feed.setScanned(map[store.ContextKey]store.Context{ka: back}, inner.Seen())
	feed.compact <- struct{}{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go FollowContexts(ctx, feed, marksOf{{Key: ka, Seq: seqOf(t, bob)}}, keys(), lb, 0,
		func(bool) {}, func() {}, t.Logf)
	eventually(t, func() bool { return lb.next(ka) > seqOf(t, bob) })
	if _, err := b.GetContext(context.Background(), ka); !errors.Is(err, ErrNotLastWritten) {
		t.Fatalf("a put-back over a later login only the ledger record held was admitted after a rescan: %v", err)
	}
}

// A rescan's seed is followed as the scan is: on a ledger already loaded, a
// recorded mark below the base at a key with no entry makes none. Made the
// key's mark, it would admit at that key a record sealed between the mark
// and the base, which the base denied before the rescan (pre-flight I1).
// A recorded mark at a key with an entry still raises it.
func TestARescansSeedMakesNoEntryBelowTheBase(t *testing.T) {
	kc := store.ContextKey{NAS: "leaf-03", Username: "carol"}
	l := NewLedger()
	l.SetBase(150)
	l.Observe(ka, 100, 100, time.Time{}, time.Time{})
	feed := &feedOf{changes: make(chan store.ContextChange), compact: make(chan struct{}, 1)}
	feed.setScanned(map[store.ContextKey]store.Context{}, 500)
	feed.compact <- struct{}{}
	var rescans atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		until(func() bool { return rescans.Load() > 0 && l.next(ka) == 121 }, 10*time.Second)
		cancel()
	}()
	FollowContexts(ctx, feed, marksOf{{Key: kc, Seq: 60}, {Key: ka, Seq: 120}}, keys(), l, 150,
		func(bool) {}, func() { rescans.Add(1) }, t.Logf)
	if l.next(ka) != 121 {
		t.Fatalf("the seed did not raise a mark the ledger holds: next %d", l.next(ka))
	}
	if l.admits(kc, 100) {
		t.Fatal("a rescan's seed below the base made an entry, and admitted what the base denied")
	}
}

// Another process's revocation whose seal failed reaches this one through
// its feed alone (Task 8 review requirement 2). a revokes alice: the
// plaintext mark lands, the seal does not. b holds a mark at that
// sequence and never reads the marked record; its feed brings it. A store
// writer then puts back the record from before, revoked_at zeroed: b
// answers it revoked, from the floor the feed's plaintext revoked_at set.
// A feed that observed without the plaintext time left b answering it
// live.
func TestARevocationWhoseSealFailedReachesAnotherProcessThroughItsFeed(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_000_000, 0).UTC()
	inner := memory.New(func() time.Time { return now })
	fails := &sealFailsStore{RevStore: inner}
	la, lb := NewLedger(), NewLedger()
	la.SetBase(inner.Seen() + 1)
	lb.SetBase(inner.Seen() + 1)
	a := Wrap(fails, keys(), nil, WithLedger(la))
	b := Wrap(inner, keys(), nil, WithLedger(lb))
	login(t, a, "ctx-1", "user:alice")
	before, _ := inner.GetContext(ctx, ka)
	if _, err := b.GetContext(ctx, ka); err != nil {
		t.Fatal(err) // b's mark is before's sequence
	}
	a.SetRevokedAt(ctx, ka, now) // the plaintext lands; the seal does not
	fails.down.Store(false)
	marked, _ := inner.GetContext(ctx, ka)
	if seqOf(t, marked) != seqOf(t, before) || !marked.RevokedAt.Equal(now) {
		t.Fatalf("the plaintext mark alone: seq %d (before %d), revoked_at %v", seqOf(t, marked), seqOf(t, before),
			marked.RevokedAt)
	}
	feed := &feedOf{changes: make(chan store.ContextChange, 1), compact: make(chan struct{})}
	fctx, cancel := context.WithCancel(ctx)
	defer cancel()
	delivered := make(chan struct{})
	go FollowContexts(fctx, &tapFeed{feedOf: feed, after: func() { close(delivered) }}, nil, keys(), lb,
		before.Rev, func(bool) {}, func() {}, t.Logf)
	feed.changes <- store.ContextChange{Key: ka, Context: marked, Rev: marked.Rev}
	<-delivered
	before.RevokedAt = time.Time{}
	if err := inner.PutContext(ctx, ka, before, time.Hour); err != nil { // R, put back, plaintext zero
		t.Fatal(err)
	}
	got, err := b.GetContext(ctx, ka)
	if err == nil && !got.RevokedAt.Equal(now) {
		t.Fatalf("b answered the record put back live: revoked_at %v", got.RevokedAt)
	}
	var u *store.UnreadableContextError
	if err != nil && (!errors.As(err, &u) || !u.RevokedAt.Equal(now)) {
		t.Fatalf("b denied the record put back without the revocation: %v", err)
	}
}

// replayFeed brings what a re-watch or a rescan can bring in any order the
// feed's contract allows: each watch delivers the next batch of changes and
// then fails, as a watch that ends does, or is compacted; it records the
// revision each watch was asked to follow from.
type replayFeed struct {
	feedOf
	batches [][]store.ContextChange
	ends    []error // each watch's end, after its batch
	froms   []uint64
	served  atomic.Int32
}

func (f *replayFeed) WatchContexts(ctx context.Context, after uint64, fn func(store.ContextChange),
	progress func(uint64), _ <-chan struct{}) error {
	f.mu.Lock()
	f.froms = append(f.froms, after)
	i := len(f.froms) - 1
	f.mu.Unlock()
	if i >= len(f.batches) {
		f.served.Store(int32(i))
		<-ctx.Done()
		return ctx.Err()
	}
	for _, c := range f.batches[i] {
		fn(c)
		progress(c.Rev)
	}
	return f.ends[i]
}

// Across a re-watch and a rescan, nothing the feed brings again lowers a
// mark, or sets a revocation floor from a record sealed below the mark
// (Task 8 review requirement 3). a revoked record at seq 20, then a
// login at seq 30: a watch that ends and is followed again from what it
// delivered, and a compacted watch's rescan that finds the record at 20
// put back with its plaintext revoked_at, raise nothing. The record at 30
// is read live, and each re-watch follows from the highest revision
// delivered, never from below it.
func TestARewatchOrARescanNeitherLowersAMarkNorRevokesBelowIt(t *testing.T) {
	now := time.Unix(1_000_000, 0).UTC()
	l := NewLedger()
	l.SetBase(10)
	revoked := sealedAt(t, ka, 20)
	revoked.RevokedAt = now
	later := sealedAt(t, ka, 30)
	feed := &replayFeed{
		batches: [][]store.ContextChange{
			{{Key: ka, Context: revoked, Rev: 20}, {Key: ka, Context: later, Rev: 30}},
			{{Key: ka, Context: revoked, Rev: 20}}, // brought again below what was delivered
			{},
		},
		ends: []error{store.ErrUnavailable, store.ErrCompacted, store.ErrCompacted},
	}
	feed.setScanned(map[store.ContextKey]store.Context{ka: revoked}, 25) // a scan behind the watch
	var rescans atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	go func() { until(func() bool { return feed.served.Load() > 0 }, 10*time.Second); cancel() }()
	FollowContexts(ctx, feed, nil, keys(), l, 10, func(bool) {}, func() { rescans.Add(1) }, t.Logf)
	if l.next(ka) != 31 || !l.floor(ka).IsZero() {
		t.Fatalf("next %d, floor %v: a record below the mark lowered it or revoked it", l.next(ka), l.floor(ka))
	}
	if rescans.Load() != 2 || len(feed.froms) != 4 || feed.froms[0] != 10 || feed.froms[1] != 30 ||
		feed.froms[2] != 30 || feed.froms[3] != 30 {
		t.Fatalf("rescans %d, each watch's from %v", rescans.Load(), feed.froms)
	}
	inner := memory.New(time.Now)
	if err := inner.PutContext(context.Background(), ka, later, time.Hour); err != nil {
		t.Fatal(err)
	}
	if c, err := Wrap(inner, keys(), nil, WithLedger(l)).GetContext(context.Background(), ka); err != nil ||
		!c.RevokedAt.IsZero() {
		t.Fatalf("the login at the mark: revoked_at %v, %v", c.RevokedAt, err)
	}
}

// tapFeed is feedOf that calls after once its first change is delivered.
type tapFeed struct {
	*feedOf
	after func()
	once  sync.Once
}

func (f *tapFeed) WatchContexts(ctx context.Context, from uint64, fn func(store.ContextChange),
	progress func(uint64), asks <-chan struct{}) error {
	return f.feedOf.WatchContexts(ctx, from, func(c store.ContextChange) { fn(c); f.once.Do(f.after) }, progress, asks)
}
