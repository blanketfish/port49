package crypt

import (
	"context"
	"errors"
	"fmt"
	"strings"
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
	// fail ends the watch with what is sent on it, and progressed is each
	// progress notification the watch tells.
	fail       chan error
	progressed chan uint64
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
		case rev := <-f.progressed:
			progress(rev)
		case <-f.compact:
			return store.ErrCompacted
		case err := <-f.fail:
			return err
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

// LoadLedger attaches the fence at the scan's revision: from there a
// fenced read of a record written after the scan waits for the feed, and
// with no feed running is unavailable (pre-flight C1; review 8a I-1).
func TestLoadLedgerAttachesTheFenceAtTheScan(t *testing.T) {
	inner, a, _, _, _ := twoProcesses(t)
	feed := &feedOf{rev: inner.Seen()}
	l := NewLedger()
	rev, _, _, err := LoadLedger(context.Background(), feed, nil, keys(), l)
	if err != nil || l.Fence().At() != rev {
		t.Fatalf("the fence at %d after a scan at %d: %v", l.Fence().At(), rev, err)
	}
	login(t, a, "ctx-alice", "user:alice")
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := Fenced(inner, l).GetContext(ctx, ka); !errors.Is(err, ErrFeedBehind) {
		t.Fatalf("a read past the scan with no feed running: %v", err)
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
	var rescans, cleared atomic.Int32
	l.attach(evicterFunc{clear: func() { cleared.Add(1) }})
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		until(func() bool { return rescans.Load() > 0 && l.next(kd) == 401 && l.Fence().At() >= 500 },
			10*time.Second)
		cancel()
	}()
	FollowContexts(ctx, feed, nil, keys(), l, 150, func(bool) {}, func() { rescans.Add(1) }, t.Logf)
	if rescans.Load() != 1 || l.next(kd) != 401 {
		t.Fatalf("rescans %d, next at an unseen key above the base %d", rescans.Load(), l.next(kd))
	}
	// A compacted watch delivers no delete, so the rescan's clear is what
	// evicts a deleted context from a cache (plan 7f, review M-1).
	if cleared.Load() != 1 {
		t.Fatalf("the cache was told of the rescan %d times, want 1", cleared.Load())
	}
	if l.Fence().At() < 500 {
		t.Fatalf("the rescan at 500 left the fence at %d", l.Fence().At())
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

// An entry that holds only a revocation floor (a recorded floor at a key
// whose record never opened, say a form-3 context) counts as no mark: a
// record the feed brings below the base makes none there, and the read
// still judges it by the base. Taken as a mark, the record became the
// key's high-water, cleared the floor, and was admitted live (Task 8
// review I1; pre-flight I1).
func TestAFedPutBackAtAFloorOnlyKeyIsDeniedByTheBase(t *testing.T) {
	now := time.Unix(1_000_000, 0).UTC()
	l := NewLedger()
	l.Seed(store.LedgerMark{Key: ka, Seq: 0, RevokedAt: now})
	l.SetBase(150)
	observe(l, keys(), ka, sealedAt(t, ka, 60), false)
	if l.admits(ka, 60) {
		t.Fatal("a put-back below the base at a floor-only key was admitted")
	}
	if !l.floor(ka).Equal(now) {
		t.Fatalf("the floor went: %v", l.floor(ka))
	}
}

// A record the feed brings sealed at exactly the base, at a key with no
// mark, makes one: the base is the least sequence a read admits there, so
// the feed's mark agrees with the read (Task 8 review M4).
func TestAFedRecordAtTheBaseMakesAMark(t *testing.T) {
	l := NewLedger()
	l.SetBase(150)
	observe(l, keys(), ka, sealedAt(t, ka, 150), false)
	if l.next(ka) != 151 {
		t.Fatalf("a record at the base made no mark: next %d", l.next(ka))
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

// The keeper writes what was raised, keeps what a failed write owed for the
// next round, and reports what is owed; when it stops it reports 0, so an
// ex-runner's gauge is never stale (pre-flight I11).
func TestTheKeeperWritesRaisedMarksAndRetriesAFailure(t *testing.T) {
	l := NewLedger()
	l.Fence().SetUp(true)
	l.Observe(ka, 10, 10, time.Time{}, time.Now().Add(time.Hour))
	sink := &flakySink{fail: 1}
	var reports []report
	ctx, cancel := context.WithCancel(context.Background())
	go func() { until(func() bool { return sink.landed() == 1 }, 10*time.Second); cancel() }()
	var lines []string
	KeepLedger(ctx, l, sink, 10*time.Millisecond, func(n int, behind bool) {
		reports = append(reports, report{n, behind})
	}, func(f string, args ...any) { lines = append(lines, fmt.Sprintf(f, args...)) })
	if sink.calls() < 2 || l.Pending() != 0 || reports[0] != (report{1, false}) {
		t.Fatalf("calls %d pending %d reports %v", sink.calls(), l.Pending(), reports)
	}
	if last := reports[len(reports)-1]; last != (report{0, false}) {
		t.Fatalf("a keeper that stopped last reported %v", last)
	}
	if len(lines) != 2 || !strings.Contains(lines[0], "writing the ledger record failed") ||
		!strings.Contains(lines[1], "written again") {
		t.Fatalf("the failure and its end, said once each: %q", lines)
	}
}

// A keeper that stops while it owes marks and its feed is down reports
// (0, false) last: the gauges of a runner whose duties stopped say nothing
// stale (pre-flight I11).
func TestAStoppedKeeperLeavesNoStaleGauge(t *testing.T) {
	l := NewLedger()
	l.Fence().SetUp(false)
	l.Observe(ka, 10, 10, time.Time{}, time.Now().Add(time.Hour))
	var mu sync.Mutex
	var reports []report
	var lines []string
	last := func() report { mu.Lock(); defer mu.Unlock(); return reports[len(reports)-1] }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		KeepLedger(ctx, l, &flakySink{fail: 1 << 30}, 10*time.Millisecond, func(n int, behind bool) {
			mu.Lock()
			reports = append(reports, report{n, behind})
			mu.Unlock()
		}, func(f string, args ...any) {
			mu.Lock()
			lines = append(lines, fmt.Sprintf(f, args...))
			mu.Unlock()
		})
	}()
	eventually(t, func() bool { mu.Lock(); defer mu.Unlock(); return len(reports) > 0 })
	if got := last(); got != (report{1, true}) {
		t.Fatalf("a keeper owing one mark with its feed down reported %v", got)
	}
	cancel()
	<-done
	if got := last(); got != (report{0, false}) {
		t.Fatalf("a keeper that stopped last reported %v", got)
	}
	// One line for the run of failures, and one for the stop, which is not
	// tried again (review M-1).
	if len(lines) != 2 || !strings.Contains(lines[0], "writing the ledger record failed") ||
		!strings.Contains(lines[1], "stopping with 1 ledger mark(s) not written to the ledger record") {
		t.Fatalf("a run of failures and the stop: %q", lines)
	}
}

// While the context feed is down, the keeper reports itself behind: its
// pending count cannot see the logins other processes make (pre-flight
// I11).
func TestTheKeeperIsBehindWhileTheFeedIsDown(t *testing.T) {
	l := NewLedger()
	l.Fence().SetUp(false)
	sink := &flakySink{}
	var mu sync.Mutex
	var reports []report
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go KeepLedger(ctx, l, sink, 10*time.Millisecond, func(n int, behind bool) {
		mu.Lock()
		reports = append(reports, report{n, behind})
		mu.Unlock()
	}, t.Logf)
	eventually(t, func() bool { mu.Lock(); defer mu.Unlock(); return len(reports) > 0 && reports[len(reports)-1].behind })
	l.Fence().SetUp(true)
	eventually(t, func() bool { mu.Lock(); defer mu.Unlock(); return !reports[len(reports)-1].behind })
}

// A keeper that stops writes what it still owes once, so a graceful stop
// leaves no mark raised in its last round out of the record: the restart
// that follows it is the one the record is for.
func TestAStoppingKeeperWritesWhatItOwes(t *testing.T) {
	l := NewLedger()
	l.Observe(ka, 10, 10, time.Time{}, time.Now().Add(time.Hour))
	sink := &flakySink{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	KeepLedger(ctx, l, sink, time.Hour, func(int, bool) {}, t.Logf)
	if sink.landed() != 1 || l.Pending() != 0 {
		t.Fatalf("a stopping keeper landed %d write(s), %d mark(s) still owed", sink.landed(), l.Pending())
	}
}

type report struct {
	pending int
	behind  bool
}

// flakySink fails its first fail calls with store.ErrUnavailable and
// records what lands, under a lock: KeepLedger calls it on its own
// goroutine (pre-flight M4, the race). A call on an ended ctx lands
// nothing, as etcd's does (review M-2).
type flakySink struct {
	mu          sync.Mutex
	fail, n, ok int
}

func (s *flakySink) PutLedgerMarks(ctx context.Context, ms []store.LedgerMark) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.n++
	if s.n <= s.fail {
		return 0, store.ErrUnavailable
	}
	s.ok++
	return len(ms), nil
}

func (s *flakySink) calls() int  { s.mu.Lock(); defer s.mu.Unlock(); return s.n }
func (s *flakySink) landed() int { s.mu.Lock(); defer s.mu.Unlock(); return s.ok }

// recordOf is a ledger record for these tests: what PutLedgerMarks wrote,
// the last write per key, read back by LedgerMarks.
type recordOf struct {
	mu sync.Mutex
	m  map[store.ContextKey]store.LedgerMark
}

func (r *recordOf) PutLedgerMarks(_ context.Context, ms []store.LedgerMark) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.m == nil {
		r.m = map[store.ContextKey]store.LedgerMark{}
	}
	for _, m := range ms {
		r.m[m.Key] = m
	}
	return len(ms), nil
}

func (r *recordOf) LedgerMarks(context.Context) (uint64, []store.LedgerMark, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []store.LedgerMark
	for _, m := range r.m {
		out = append(out, m)
	}
	return 1, out, nil
}

// restarted is l's marks written to a record and loaded into a fresh
// ledger, as a stop and a start do.
func restarted(t *testing.T, l *Ledger) *Ledger {
	t.Helper()
	return restartedScanning(t, l, map[store.ContextKey]store.Context{})
}

// restartedScanning is restarted with a start whose scan finds scanned.
func restartedScanning(t *testing.T, l *Ledger, scanned map[store.ContextKey]store.Context) *Ledger {
	t.Helper()
	rec := &recordOf{}
	if _, err := rec.PutLedgerMarks(context.Background(), l.Dirty()); err != nil {
		t.Fatal(err)
	}
	fresh := NewLedger()
	feed := &feedOf{scanned: scanned, rev: 500}
	if _, _, _, err := LoadLedger(context.Background(), feed, rec, keys(), fresh); err != nil {
		t.Fatal(err)
	}
	return fresh
}

// A revocation floor survives a restart through every sequence it held
// before it (C1): revoked at a mark of 100 once the store had shown
// revision 151, it holds through 150, which a write sent before the
// revocation landed may be sealed at. Recorded at the mark alone, a
// record put back sealed at 140 would clear it after the restart.
func TestARevocationFloorSurvivesARestart(t *testing.T) {
	at := time.Unix(1_000_000, 0).UTC()
	l := NewLedger()
	l.Observe(ka, 100, 100, time.Time{}, time.Time{})
	l.revoked(ka, at, 151)
	fresh := restarted(t, l)
	fresh.Observe(ka, 140, 140, time.Time{}, time.Time{})
	if !fresh.floor(ka).Equal(at) {
		t.Fatalf("after a restart, a sequence the floor held through cleared it: floor %v", fresh.floor(ka))
	}
	fresh.Observe(ka, 151, 151, time.Time{}, time.Time{})
	if !fresh.floor(ka).IsZero() {
		t.Fatalf("a sequence past the floor's did not clear it: %v", fresh.floor(ka))
	}
}

// A revocation at a key whose mark is above every revision the store has
// shown holds its floor through the mark (revoked's hw term; C2): recorded
// through seen alone, it holds through nothing the mark admits, and the
// restart drops it.
func TestARevocationFloorHoldsThroughTheMarkAcrossARestart(t *testing.T) {
	at := time.Unix(1_000_000, 0).UTC()
	for _, seen := range []uint64{0, 51} {
		l := NewLedger()
		l.Observe(ka, 100, 100, time.Time{}, time.Time{})
		l.revoked(ka, at, seen)
		if fresh := restarted(t, l); !fresh.floor(ka).Equal(at) {
			t.Fatalf("seen %d: a floor at the mark was lost across a restart: %v", seen, fresh.floor(ka))
		}
	}
}

// failingSource is a ledger record that will not be read.
type failingSource struct{ calls atomic.Int32 }

func (f *failingSource) LedgerMarks(context.Context) (uint64, []store.LedgerMark, error) {
	f.calls.Add(1)
	return 0, nil, store.ErrUnavailable
}

// A start whose read of the ledger record fails fails, and sets no base and
// no fence: a base set without the record would admit every put-back at a
// key the record holds a later mark for (C3).
func TestALoadWhoseRecordFailsSetsNoBase(t *testing.T) {
	l := NewLedger()
	feed := &feedOf{scanned: map[store.ContextKey]store.Context{}, rev: 500}
	if _, _, _, err := LoadLedger(context.Background(), feed, &failingSource{}, keys(), l); !errors.Is(err,
		store.ErrUnavailable) {
		t.Fatalf("a failed read of the record: %v", err)
	}
	if l.Base() != 0 || l.Fence().At() != 0 {
		t.Fatalf("a failed load set base %d, fence %d", l.Base(), l.Fence().At())
	}
}

// flakySource fails its first read, with the feed's fence checked down at
// each, then holds marks.
type flakySource struct {
	l      *Ledger
	marks  []store.LedgerMark
	calls  atomic.Int32
	upOnce atomic.Bool // the fence was up at some read
}

func (f *flakySource) LedgerMarks(context.Context) (uint64, []store.LedgerMark, error) {
	if f.l.Fence().Up() {
		f.upOnce.Store(true)
	}
	if f.calls.Add(1) == 1 {
		return 0, nil, store.ErrUnavailable
	}
	return 1, f.marks, nil
}

// A compacted watch's rescan whose read of the ledger record fails is a
// failed watch (C3): said as the feed stopping, the fence down, and tried
// again; the next compacted watch's rescan seeds from the record.
func TestARescanWhoseRecordFailsIsAFailedWatch(t *testing.T) {
	l := NewLedger()
	l.SetBase(10)
	src := &flakySource{l: l, marks: []store.LedgerMark{{Key: ka, Seq: 120}}}
	feed := &replayFeed{batches: [][]store.ContextChange{{}, {}}, ends: []error{store.ErrCompacted, store.ErrCompacted}}
	feed.setScanned(map[store.ContextKey]store.Context{}, 200)
	var mu sync.Mutex
	var lines []string
	ctx, cancel := context.WithCancel(context.Background())
	go func() { until(func() bool { return feed.served.Load() > 0 }, 10*time.Second); cancel() }()
	FollowContexts(ctx, feed, src, keys(), l, 10, func(bool) {}, func() {}, func(f string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		lines = append(lines, fmt.Sprintf(f, args...))
	})
	if src.calls.Load() != 2 || src.upOnce.Load() || l.next(ka) != 121 {
		t.Fatalf("record reads %d, fence up at one %v, next %d", src.calls.Load(), src.upOnce.Load(), l.next(ka))
	}
	stopped := 0
	for _, line := range lines {
		if strings.Contains(line, "the context feed stopped") && strings.Contains(line, store.ErrUnavailable.Error()) {
			stopped++
		}
	}
	if stopped != 1 {
		t.Fatalf("a failed rescan was not said once as the feed stopping: %q", lines)
	}
}

// The record's floor is seeded where it holds and nowhere else (C1): not at
// a key whose mark is past its FloorSeq, not further than a mark with no
// floor says, never earlier than the floor this process holds, and on a
// rescan's seed as on a start's.
func TestTheRecordsFloorIsSeededOnlyWhereItHolds(t *testing.T) {
	at := time.Unix(1_000_000, 0).UTC()
	l := NewLedger()
	l.Observe(ka, 200, 200, time.Time{}, time.Time{})
	l.Seed(store.LedgerMark{Key: ka, Seq: 100, RevokedAt: at, FloorSeq: 150})
	if !l.floor(ka).IsZero() {
		t.Fatalf("a recorded floor through 150 was taken at a mark of 200: %v", l.floor(ka))
	}

	l = NewLedger()
	l.Observe(ka, 100, 100, time.Time{}, time.Time{})
	l.revoked(ka, at, 0) // held through 100
	l.Seed(store.LedgerMark{Key: ka, Seq: 100, FloorSeq: 150})
	l.Seed(store.LedgerMark{Key: ka, Seq: 100, RevokedAt: at.Add(-time.Hour), FloorSeq: 100})
	if !l.floor(ka).Equal(at) {
		t.Fatalf("an earlier recorded floor replaced a later one: %v", l.floor(ka))
	}
	l.Observe(ka, 140, 140, time.Time{}, time.Time{})
	if !l.floor(ka).IsZero() {
		t.Fatalf("a recorded mark with no floor held this process's past 100: %v", l.floor(ka))
	}

	l = NewLedger()
	l.SetBase(10)
	if _, err := seedFrom(context.Background(), marksOf{{Key: ka, Seq: 120, RevokedAt: at, FloorSeq: 130}}, l); err != nil {
		t.Fatal(err)
	}
	l.Observe(ka, 125, 125, time.Time{}, time.Time{})
	if !l.floor(ka).Equal(at) {
		t.Fatalf("a rescan's seed did not take the record's floor through 130: %v", l.floor(ka))
	}
}

// A floor-only record (a revocation at a key with no mark, say a form-3
// context at the 7e upgrade) still denies, after a restart, a put-back of
// a context sealed before the floor (review I-1): the start's scan raises
// the mark to it, at or below the floor's sequence, and the read is
// revoked.
func TestAFloorOnlyRecordDeniesAPreFloorPutBackAfterARestart(t *testing.T) {
	at := time.Unix(1_000_000, 0).UTC()
	l := NewLedger()
	l.revoked(ka, at, 151)
	back := sealedAt(t, ka, 100)
	fresh := restartedScanning(t, l, map[store.ContextKey]store.Context{ka: back})
	if !fresh.floor(ka).Equal(at) || fresh.next(ka) != 101 {
		t.Fatalf("after a restart over a floor-only record: floor %v, next %d", fresh.floor(ka), fresh.next(ka))
	}
	inner := memory.New(time.Now)
	if err := inner.PutContext(context.Background(), ka, back, time.Hour); err != nil {
		t.Fatal(err)
	}
	if c, err := Wrap(inner, keys(), nil, WithLedger(fresh)).GetContext(context.Background(), ka); err != nil ||
		!c.RevokedAt.Equal(at) {
		t.Fatalf("a pre-floor put-back after a restart: revoked_at %v, %v", c.RevokedAt, err)
	}
}

// A key seeded from a floor-only record is not a never context's (review
// I-1): its next login, with a ceiling, gives its mark a lease, and the
// mark is pruned past its keep.
func TestAFloorOnlyKeyRegainsALeaseAtItsNextLogin(t *testing.T) {
	at := time.Unix(1_000_000, 0).UTC()
	l := NewLedger()
	l.revoked(ka, at, 151)
	fresh := restarted(t, l)
	fresh.Dirty()
	ceiling := at.Add(time.Hour)
	fresh.Observe(ka, 600, 600, time.Time{}, ceiling)
	if ms := fresh.Dirty(); len(ms) != 1 || !ms[0].Until.Equal(ceiling.Add(DefaultLedgerKeep)) {
		t.Fatalf("the login after a floor-only seed: %+v", ms)
	}
	if n := fresh.Prune(ceiling.Add(DefaultLedgerKeep + time.Hour)); n != 1 {
		t.Fatalf("a floor-only key's later mark was not pruned past its keep: %d", n)
	}
}

// A ledger loaded from its record owes the record nothing it holds (review
// I-2): marks with a lease, a never context's, a floor through a later
// sequence and a floor-only one all seed clean. A raise after the load is
// owed alone.
func TestALedgerLoadedFromItsRecordOwesNothing(t *testing.T) {
	at := time.Unix(1_000_000, 0).UTC()
	l := NewLedger()
	for i := range 200 {
		k := store.ContextKey{NAS: "leaf-01", Username: fmt.Sprintf("u%03d", i)}
		switch i % 4 {
		case 0:
			l.Observe(k, uint64(10+i), uint64(10+i), time.Time{}, at.Add(time.Hour))
		case 1:
			l.Observe(k, uint64(10+i), uint64(10+i), time.Time{}, time.Time{})
		case 2:
			l.Observe(k, uint64(10+i), uint64(10+i), time.Time{}, at.Add(time.Hour))
			l.revoked(k, at, 1000)
		case 3:
			l.revoked(k, at, 1000)
		}
	}
	fresh := restarted(t, l)
	if n := fresh.Pending(); n != 0 {
		t.Fatalf("a ledger loaded from its record owes %d mark(s)", n)
	}
	fresh.Observe(ka, 2000, 2000, time.Time{}, at.Add(time.Hour))
	if n := fresh.Pending(); n != 1 {
		t.Fatalf("one raise after the load owes %d", n)
	}
}

// partSink lands the first `lands` marks of its first call and then fails,
// as a write whose deadline ends partway through does; every later call
// lands all, and is recorded.
type partSink struct {
	mu    sync.Mutex
	lands int
	calls [][]store.LedgerMark
}

func (s *partSink) PutLedgerMarks(_ context.Context, ms []store.LedgerMark) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, ms)
	if len(s.calls) == 1 {
		return s.lands, context.DeadlineExceeded
	}
	return len(ms), nil
}

func (s *partSink) seen() [][]store.LedgerMark {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([][]store.LedgerMark(nil), s.calls...)
}

// A write that lands part of a batch before its deadline owes only the
// rest (review I-2): on a record too large for one round's budget, every
// round makes progress instead of owing the whole batch again.
func TestAPartlyLandedWriteOwesOnlyTheRest(t *testing.T) {
	l := NewLedger()
	l.Fence().SetUp(true)
	for i := range 10 {
		l.Observe(store.ContextKey{NAS: "leaf-01", Username: fmt.Sprintf("u%d", i)}, 10, 10, time.Time{}, time.Time{})
	}
	sink := &partSink{lands: 4}
	var reports []report
	var lines []string
	ctx, cancel := context.WithCancel(context.Background())
	go func() { until(func() bool { return len(sink.seen()) >= 2 }, 10*time.Second); cancel() }()
	KeepLedger(ctx, l, sink, 10*time.Millisecond, func(n int, behind bool) {
		reports = append(reports, report{n, behind})
	}, func(f string, args ...any) { lines = append(lines, fmt.Sprintf(f, args...)) })
	calls := sink.seen()
	if len(lines) == 0 || !strings.Contains(lines[0], "6 mark(s) owed") { // review M-8
		t.Fatalf("the failure line does not count what is owed: %q", lines)
	}
	if len(calls) < 2 || reports[0] != (report{6, false}) {
		t.Fatalf("after a write that landed 4 of 10: reports %v, %d call(s)", reports, len(calls))
	}
	landed := map[store.ContextKey]bool{}
	for _, m := range calls[0][:4] {
		landed[m.Key] = true
	}
	if len(calls[1]) != 6 {
		t.Fatalf("the next round wrote %d mark(s), want the 6 that did not land", len(calls[1]))
	}
	for _, m := range calls[1] {
		if landed[m.Key] {
			t.Fatalf("a mark that landed was owed again: %v", m.Key)
		}
	}
}

// A rescan's floor-only mark at a key this process has no entry for takes
// the floor (review I-1): another process revoked a record there it could
// not open, and a record the feed then brings at or below the floor's
// sequence is read revoked. It makes no mark: the base still judges the
// key.
func TestARescansFloorOnlyMarkTakesTheFloor(t *testing.T) {
	at := time.Unix(1_000_000, 0).UTC()
	l := NewLedger()
	l.SetBase(10)
	if _, err := seedFrom(context.Background(), marksOf{{Key: ka, RevokedAt: at, FloorSeq: 130}}, l); err != nil {
		t.Fatal(err)
	}
	if !l.floor(ka).Equal(at) || l.admits(ka, 9) {
		t.Fatalf("a rescan's floor-only mark: floor %v, admits below the base %v", l.floor(ka), l.admits(ka, 9))
	}
	observe(l, keys(), ka, sealedAt(t, ka, 120), false)
	if !l.floor(ka).Equal(at) || l.next(ka) != 121 {
		t.Fatalf("a fed record under the floor: floor %v, next %d", l.floor(ka), l.next(ka))
	}
}

// A seed is settled only when the ledger would write what the record
// holds (review I-2): an entry owed with a later sequence, a later floor,
// a floor through a later sequence, or a later keep than the record's is
// still owed after a re-entry's seed.
func TestASeedBelowWhatTheLedgerHoldsIsStillOwed(t *testing.T) {
	at := time.Unix(1_000_000, 0).UTC()
	ceiling := at.Add(time.Hour)
	for name, c := range map[string]struct {
		owe    func(l *Ledger)
		record store.LedgerMark
	}{
		"seq": {func(l *Ledger) { l.Observe(ka, 100, 100, time.Time{}, time.Time{}) },
			store.LedgerMark{Key: ka, Seq: 90}},
		"floor": {func(l *Ledger) {
			l.Observe(ka, 100, 100, time.Time{}, time.Time{})
			l.revoked(ka, at, 151)
		}, store.LedgerMark{Key: ka, Seq: 100, RevokedAt: at.Add(-time.Hour), FloorSeq: 150}},
		"floor_seq": {func(l *Ledger) {
			l.Observe(ka, 100, 100, time.Time{}, time.Time{})
			l.revoked(ka, at, 201)
		}, store.LedgerMark{Key: ka, Seq: 100, RevokedAt: at, FloorSeq: 150}},
		"until": {func(l *Ledger) { l.Observe(ka, 100, 100, time.Time{}, ceiling) },
			store.LedgerMark{Key: ka, Seq: 100, Until: ceiling.Add(DefaultLedgerKeep - time.Minute)}},
	} {
		l := NewLedger()
		l.SetBase(10)
		c.owe(l)
		if _, err := seedFrom(context.Background(), marksOf{c.record}, l); err != nil {
			t.Fatal(err)
		}
		if l.Pending() != 1 {
			t.Fatalf("%s: a record behind the ledger was taken as written", name)
		}
	}
}

// A rescan's seed of marks the record holds, at keys this loaded ledger
// has not seen, makes their entries and owes the record nothing (review
// M-7): otherwise every compacted watch would write the whole record back.
func TestARescansSeedOwesTheRecordNothingItHolds(t *testing.T) {
	at := time.Unix(1_000_000, 0).UTC()
	l := NewLedger()
	l.SetBase(10)
	kb := store.ContextKey{NAS: "leaf-02", Username: "bob"}
	record := marksOf{
		{Key: ka, Seq: 100, Until: at.Add(time.Hour + DefaultLedgerKeep)},
		{Key: kb, Seq: 120, RevokedAt: at, FloorSeq: 150},
	}
	if _, err := seedFrom(context.Background(), record, l); err != nil {
		t.Fatal(err)
	}
	if l.next(ka) != 101 || !l.floor(kb).Equal(at) || l.Pending() != 0 {
		t.Fatalf("a rescan's seed: next %d, floor %v, %d owed", l.next(ka), l.floor(kb), l.Pending())
	}
}

// The context feed says each stop, not only its first, and says it
// follows the store again at the first change or progress a new watch
// delivers (final review 7e-1 I-2).
func TestTheContextFeedSaysEachStopAndEachReturn(t *testing.T) {
	feed := &feedOf{changes: make(chan store.ContextChange), compact: make(chan struct{}), fail: make(chan error),
		progressed: make(chan uint64)}
	var mu sync.Mutex
	var said []string
	kinds := func() string {
		mu.Lock()
		defer mu.Unlock()
		var out []string
		for _, s := range said {
			switch {
			case strings.Contains(s, "the context feed stopped"):
				out = append(out, "stopped")
			case strings.Contains(s, "store: the context feed follows the store again"):
				out = append(out, "again")
			}
		}
		return strings.Join(out, " ")
	}
	until := func(want string) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for kinds() != want {
			if time.Now().After(deadline) {
				t.Fatalf("said %q, want %q", kinds(), want)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go FollowContexts(ctx, feed, nil, keys(), NewLedger(), 0, func(bool) {}, func() {},
		func(format string, args ...any) {
			mu.Lock()
			defer mu.Unlock()
			said = append(said, fmt.Sprintf(format, args...))
		})
	k := store.ContextKey{NAS: "leaf-01", Username: "alice"}
	feed.fail <- store.ErrUnavailable
	feed.changes <- store.ContextChange{Key: k, Deleted: true, Rev: 3} // the next watch, a second later
	until("stopped again")
	feed.fail <- store.ErrUnavailable
	feed.progressed <- 4
	until("stopped again stopped again")
	feed.changes <- store.ContextChange{Key: k, Deleted: true, Rev: 5}
	feed.progressed <- 6
	if got := kinds(); got != "stopped again stopped again" {
		t.Fatalf("said %q", got)
	}
}

// A rescan's seed from a record an etcd restore rolled back, below what
// the running ledger knows at a key, owes that key: the record converges
// back to the ledger's mark and floor, so the next start is seeded from
// them, not the snapshot's (final review 7e-1 M-1). A key the record
// holds as the ledger does is still owed nothing.
func TestARescansSeedOwesTheRecordWhatTheLedgerKnowsAboveIt(t *testing.T) {
	at := time.Unix(1_000_000, 0).UTC()
	l := NewLedger()
	l.SetBase(10)
	kb := store.ContextKey{NAS: "leaf-02", Username: "bob"}
	kc := store.ContextKey{NAS: "leaf-03", Username: "carol"}
	l.Observe(ka, 200, 0, time.Time{}, at.Add(time.Hour))
	l.Observe(kb, 150, 0, at, at.Add(time.Hour)) // revoked at its mark
	l.Observe(kc, 120, 0, time.Time{}, at.Add(time.Hour))
	l.Dirty() // the keeper wrote them
	rolledBack := marksOf{
		{Key: ka, Seq: 100, Until: at.Add(time.Hour + DefaultLedgerKeep)},
		{Key: kb, Seq: 150, Until: at.Add(time.Hour + DefaultLedgerKeep)},
		{Key: kc, Seq: 120, Until: at.Add(time.Hour + DefaultLedgerKeep)},
	}
	if _, err := seedFrom(context.Background(), rolledBack, l); err != nil {
		t.Fatal(err)
	}
	owed := map[store.ContextKey]store.LedgerMark{}
	for _, m := range l.Dirty() {
		owed[m.Key] = m
	}
	if len(owed) != 2 || owed[ka].Seq != 200 || owed[kb].Seq != 150 || !owed[kb].RevokedAt.Equal(at) {
		t.Fatalf("owed after a rolled-back record's seed: %+v", owed)
	}
}

// followRevocation starts FollowContexts on l over a feed the test sends
// on, unbuffered: deliver returns once the change is observed.
func followRevocation(t *testing.T, l *Ledger) (deliver func(store.ContextChange)) {
	t.Helper()
	feed := &feedOf{changes: make(chan store.ContextChange), compact: make(chan struct{}),
		progressed: make(chan uint64)}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go FollowContexts(ctx, feed, nil, keys(), l, 0, func(bool) {}, func() {}, t.Logf)
	return func(c store.ContextChange) {
		feed.changes <- c
		feed.progressed <- c.Rev // back in the watch's select: c is observed
	}
}

// revokeKeyless puts back the record saved at ka and revokes it with no
// key, as a runner whose ledger denies it does (Ruling T13b-a), and
// returns the revoked record and its revision R.
func revokeKeyless(t *testing.T, inner *memory.Store, saved store.Context, at time.Time) (store.Context, uint64) {
	t.Helper()
	if err := inner.PutContext(context.Background(), ka, saved, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := inner.SetRevokedAt(context.Background(), ka, at); err != nil {
		t.Fatal(err)
	}
	rv, err := inner.GetContext(context.Background(), ka)
	if err != nil {
		t.Fatal(err)
	}
	return rv, rv.Rev
}

// Another process's keyless revocation of a record put back below this
// one's mark, brought by the feed, is a floor here through the mark, as a
// floor bounded by the revocation's revision (Ruling T15-a): the
// session's own record, sealed before it and put back after it, is
// answered revoked by a running process (spec, final review 7d-2 I-1).
func TestAFollowedRevocationBelowTheMarkHoldsTheRecordsSealedBeforeIt(t *testing.T) {
	inner, a, _, la, _ := twoProcesses(t)
	at := time.Unix(1_000_000, 0).UTC()
	login(t, a, "ctx-alice", "user:alice")
	s0, _ := inner.GetContext(context.Background(), ka)
	login(t, a, "ctx-alice", "user:alice")
	s1, _ := inner.GetContext(context.Background(), ka)
	deliver := followRevocation(t, la)
	rv, r := revokeKeyless(t, inner, s0, at)
	deliver(store.ContextChange{Key: ka, Context: rv, Rev: r})
	if err := inner.PutContext(context.Background(), ka, s1, time.Hour); err != nil {
		t.Fatal(err)
	}
	c, err := a.GetContext(context.Background(), ka)
	if err != nil || !c.RevokedAt.Equal(at) {
		t.Fatalf("the session's own record, put back after the revocation: revoked_at %v, %v; want %v",
			c.RevokedAt, err, at)
	}
}

// The bound, pinned at its edge: a record sealed at R-1 is held, so a
// bound of R-2 is not enough; a login sealed at R itself, which seqFor
// can seal (it compares on the revoked record's revision, R, and the
// store may have told it nothing later), is admitted, and stays admitted
// when the revocation is brought again, so neither R nor the mark alone
// is the bound (Ruling T15-a).
func TestAFollowedRevocationsFloorIsBoundedByItsRevision(t *testing.T) {
	at := time.Unix(1_000_000, 0).UTC()
	l := NewLedger()
	l.SetBase(1)
	l.Observe(ka, 10, 10, time.Time{}, at.Add(time.Hour))
	l.ObserveFollowed(ka, 5, 11, at, at.Add(time.Hour)) // R = 11: the mark is R-1
	if !l.floor(ka).Equal(at) {
		t.Fatalf("a record sealed at R-1 is not held by the floor: %v", l.floor(ka))
	}
	l.Observe(ka, 10, 12, time.Time{}, at.Add(time.Hour)) // it, put back after R
	if !l.floor(ka).Equal(at) {
		t.Fatal("the record sealed at R-1, put back after R, lifted the floor")
	}
	l.wrote(ka, 11, 13, at.Add(time.Hour)) // a login sealed at R
	if !l.floor(ka).IsZero() {
		t.Fatalf("a login sealed at R is held by the floor: %v", l.floor(ka))
	}
	l.ObserveFollowed(ka, 5, 11, at, at.Add(time.Hour)) // brought again
	if !l.floor(ka).IsZero() {
		t.Fatalf("the revocation brought again holds a login sealed at R: %v", l.floor(ka))
	}
}

// A login after the revocation is sealed at R (seqFor's fact) and
// admitted, and the revocation brought again, by a re-watch from an older
// revision or a compacted rescan, does not revoke it (Ruling T15-a).
func TestALoginAfterAFollowedRevocationStaysAdmittedWhenItIsBroughtAgain(t *testing.T) {
	inner, a, _, la, _ := twoProcesses(t)
	at := time.Unix(1_000_000, 0).UTC()
	login(t, a, "ctx-alice", "user:alice")
	s0, _ := inner.GetContext(context.Background(), ka)
	login(t, a, "ctx-alice", "user:alice")
	deliver := followRevocation(t, la)
	rv, r := revokeKeyless(t, inner, s0, at)
	deliver(store.ContextChange{Key: ka, Context: rv, Rev: r})
	login(t, a, "ctx-alice", "user:alice")
	after, _ := inner.GetContext(context.Background(), ka)
	if seq := seqOf(t, after); seq != r {
		t.Fatalf("the login after the revocation sealed at %d, R %d: the test no longer pins the edge", seq, r)
	}
	check := func(when string) {
		t.Helper()
		if c, err := a.GetContext(context.Background(), ka); err != nil || !c.RevokedAt.IsZero() {
			t.Fatalf("the login after the revocation, %s: revoked_at %v, %v", when, c.RevokedAt, err)
		}
	}
	check("once it landed")
	deliver(store.ContextChange{Key: ka, Context: rv, Rev: r}) // a re-watch from before R
	check("with the revocation brought again")
	l2 := NewLedger() // a rescan's observe, on a ledger loaded before
	l2.SetBase(1)
	l2.Observe(ka, seqOf(t, after), after.Rev, time.Time{}, at.Add(time.Hour))
	observe(l2, keys(), ka, rv, false)
	if !l2.floor(ka).IsZero() {
		t.Fatalf("a rescan's revoked record holds the later login: %v", l2.floor(ka))
	}
}

// The floor holds through R-1, not only through the mark (Ruling T15-a;
// Task 15 review M-1): a record sealed between the two, landed before the
// revocation and never seen here, is answered revoked when it is put back,
// whether it is sealed just above the mark or at R-1 itself.
func TestAFollowedRevocationHoldsEveryRecordSealedBeforeItsRevision(t *testing.T) {
	at := time.Unix(1_000_000, 0).UTC()
	for _, seq := range []uint64{8, 11} {
		l := NewLedger()
		l.SetBase(1)
		l.Observe(ka, 5, 5, time.Time{}, at.Add(time.Hour))
		l.ObserveFollowed(ka, 3, 12, at, at.Add(time.Hour)) // R = 12
		if !l.admits(ka, seq) {
			t.Fatalf("a record sealed at %d, above the mark, is not admitted", seq)
		}
		l.Observe(ka, seq, 13, time.Time{}, at.Add(time.Hour)) // put back after R
		if !l.floor(ka).Equal(at) {
			t.Fatalf("a record sealed at %d, before R 12, put back after it, lifted the floor", seq)
		}
		l.wrote(ka, 12, 14, at.Add(time.Hour)) // a login sealed at R
		if !l.floor(ka).IsZero() {
			t.Fatalf("a login sealed at R is held by the floor: %v", l.floor(ka))
		}
	}
}

// The floor a followed revocation takes below the mark is owed to the
// ledger record, so a restart holds it as far (Task 15 review M-3a).
func TestAFollowedRevocationsFloorIsOwedToTheRecord(t *testing.T) {
	at := time.Unix(1_000_000, 0).UTC()
	l := NewLedger()
	l.SetBase(1)
	l.Observe(ka, 10, 10, time.Time{}, at.Add(time.Hour))
	l.Dirty() // the keeper wrote it
	l.ObserveFollowed(ka, 5, 12, at, at.Add(time.Hour))
	ms := l.Dirty()
	if len(ms) != 1 || !ms[0].RevokedAt.Equal(at) || ms[0].FloorSeq != 11 {
		t.Fatalf("owed after a followed revocation below the mark: %+v; want revoked_at %v through 11", ms, at)
	}
	l.ObserveFollowed(ka, 5, 12, at, at.Add(time.Hour)) // brought again
	if ms := l.Dirty(); len(ms) != 0 {
		t.Fatalf("the same revocation brought again is owed again: %+v", ms)
	}
	// A plaintext bump of the revoked record (TouchContext, an accounting
	// record's AnnotateContext) brings it again at a later revision, with
	// the same revoked_at: the floor already holds past the mark, so it
	// owes nothing (Task 15 re-review M-10).
	for rev := uint64(13); rev < 18; rev++ {
		l.ObserveFollowed(ka, 5, rev, at, at.Add(time.Hour))
	}
	if ms := l.Dirty(); len(ms) != 0 {
		t.Fatalf("a plaintext bump of the revoked record is owed: %+v", ms)
	}
	// A later revocation time is owed, and raises the floor's reach.
	l.ObserveFollowed(ka, 5, 19, at.Add(time.Second), at.Add(time.Hour))
	if ms := l.Dirty(); len(ms) != 1 || !ms[0].RevokedAt.Equal(at.Add(time.Second)) || ms[0].FloorSeq != 18 {
		t.Fatalf("owed after a later revocation time: %+v", ms)
	}
	// A later time alone, within the floor's reach, is owed too.
	l.ObserveFollowed(ka, 5, 15, at.Add(2*time.Second), at.Add(time.Hour))
	if ms := l.Dirty(); len(ms) != 1 || !ms[0].RevokedAt.Equal(at.Add(2*time.Second)) || ms[0].FloorSeq != 18 {
		t.Fatalf("owed after a later revocation time within the floor's reach: %+v", ms)
	}
	// A floor taken at the mark, held through it alone, is raised past it
	// by a revocation below the mark at the same time: owed for its reach.
	k := store.ContextKey{NAS: "leaf-02", Username: "bob"}
	l.Observe(k, 10, 10, at, at.Add(time.Hour))
	l.Dirty()
	l.ObserveFollowed(k, 5, 12, at, at.Add(time.Hour))
	if ms := l.Dirty(); len(ms) != 1 || ms[0].FloorSeq != 11 {
		t.Fatalf("owed after a floor at the mark is raised past it: %+v; want through 11", ms)
	}
}

// A start's scan takes a revocation below the seeded mark as a floor too
// (Task 15 review M-2): a restart whose ledger record lacks the floor, the
// keeper not having written it, still answers the record at the mark,
// put back, revoked. The scan sees each key's latest record, so no later
// login is over a revoked record it finds.
func TestAStartsScanTakesARevocationBelowTheSeededMark(t *testing.T) {
	at := time.Unix(1_000_000, 0).UTC()
	rv := sealedAt(t, ka, 5)
	rv.Rev, rv.RevokedAt = 11, at
	feed := &feedOf{scanned: map[store.ContextKey]store.Context{ka: rv}, rev: 11}
	l := NewLedger()
	if _, _, _, err := LoadLedger(context.Background(), feed, marksOf{{Key: ka, Seq: 10}}, keys(), l); err != nil {
		t.Fatal(err)
	}
	if !l.floor(ka).Equal(at) {
		t.Fatalf("a start's scan took no floor from a revocation below the seeded mark: %v", l.floor(ka))
	}
	l.Observe(ka, 10, 12, time.Time{}, at.Add(time.Hour)) // the record at the mark, put back
	if !l.floor(ka).Equal(at) {
		t.Fatal("the record at the mark, put back, lifted the floor")
	}
}

// FollowContexts tells the ledger each change, a delete and a record that
// does not open included, so a cache evicts them (plan 7f, Ruling 5).
func TestTheFeedTellsTheLedgerEveryChange(t *testing.T) {
	l := NewLedger()
	var mu sync.Mutex
	var told []store.ContextKey
	l.attach(evicterFunc{evict: func(k store.ContextKey) { mu.Lock(); told = append(told, k); mu.Unlock() }})
	feed := &feedOf{changes: make(chan store.ContextChange, 3), compact: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go FollowContexts(ctx, feed, nil, keys(), l, 0, func(bool) {}, func() {}, t.Logf)
	kb := store.ContextKey{NAS: "leaf-02", Username: "bob"}
	feed.changes <- store.ContextChange{Key: ka, Context: sealedAt(t, ka, 10), Rev: 10}
	feed.changes <- store.ContextChange{Key: kb, Deleted: true, Rev: 11}
	feed.changes <- store.ContextChange{Key: ka, Context: store.Context{CtxID: "garbage"}, Rev: 12}
	eventually(t, func() bool { mu.Lock(); defer mu.Unlock(); return len(told) == 3 })
}

// evicterFunc is an evicter from funcs, for tests.
type evicterFunc struct {
	evict func(store.ContextKey)
	clear func()
}

func (e evicterFunc) evictKey(k store.ContextKey) {
	if e.evict != nil {
		e.evict(k)
	}
}
func (e evicterFunc) clearAll() {
	if e.clear != nil {
		e.clear()
	}
}
