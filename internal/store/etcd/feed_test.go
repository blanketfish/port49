package etcd

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
	"github.com/rhwendt/port49/internal/store/crypt"
	"github.com/rhwendt/port49/internal/store/etcd/etcdtest"
)

// A scan reads every live context at one revision; a watch from it brings
// every change after, a delete included, in revision order, with Seen
// raised by each.
func TestTheScanAndTheWatchMeetWithNoGap(t *testing.T) {
	ctx := context.Background()
	s := onShared(t, time.Now)
	k1 := store.ContextKey{NAS: "leaf/01", Username: "al%ce"} // escaping
	k2 := store.ContextKey{NAS: "leaf-02", Username: "bob"}
	put := func(k store.ContextKey, id string) {
		if err := s.PutContext(ctx, k, store.Context{CtxID: id, Principal: "user:x", Username: k.Username}, time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	put(k1, "c1")
	var got []store.ContextKey
	rev, err := s.ScanContexts(ctx, func(k store.ContextKey, c store.Context) { got = append(got, k) })
	if err != nil || len(got) != 1 || got[0] != k1 {
		t.Fatalf("scan: %v %v", got, err)
	}
	put(k2, "c2")
	if err := s.DeleteContext(ctx, k1); err != nil {
		t.Fatal(err)
	}
	wctx, cancel := context.WithCancel(ctx)
	var mu sync.Mutex
	var changes []store.ContextChange
	done := make(chan error, 1)
	go func() {
		done <- s.WatchContexts(wctx, rev, func(c store.ContextChange) {
			mu.Lock()
			changes = append(changes, c)
			n := len(changes)
			mu.Unlock()
			if n == 2 {
				cancel()
			}
		}, func(uint64) {}, nil)
	}()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the watch brought nothing")
	}
	if changes[0].Key != k2 || changes[0].Deleted || changes[1].Key != k1 || !changes[1].Deleted ||
		changes[0].Rev >= changes[1].Rev || s.Seen() < changes[1].Rev {
		t.Fatalf("changes %+v, Seen %d", changes, s.Seen())
	}
}

// A watch that catches up is answered with the store's revision in its
// header, above every event it carries: Seen takes the header's too, as
// Seen's contract says of a watch (Task 6), not only the events'. But
// progress is told only the highest event delivered, never the header: a
// header ahead of the events would let Task 8a's fence pass a read before
// the feed raised the mark (pre-flight C1).
func TestAWatchsHeaderRaisesSeen(t *testing.T) {
	ctx := context.Background()
	s := onShared(t, time.Now)
	rev, err := s.ScanContexts(ctx, func(store.ContextKey, store.Context) {})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.PutContext(ctx, store.ContextKey{NAS: "leaf-01", Username: "alice"},
		store.Context{CtxID: "c1", Principal: "user:x", Username: "alice"}, time.Hour); err != nil {
		t.Fatal(err)
	}
	other, err := s.ctx.Put(ctx, etcdtest.Prefix()+"elsewhere", "x") // a revision outside c/, after the event
	if err != nil {
		t.Fatal(err)
	}
	// A store of its own on the same keyspace has seen nothing: only the
	// watch can raise its Seen.
	w := newStore(s.ctx, s.ctx, Config{Prefix: strings.TrimSuffix(s.k.root, "v1/"), Now: time.Now})
	wctx, cancel := context.WithCancel(ctx)
	var top uint64
	var told []uint64
	done := make(chan error, 1)
	go func() {
		done <- w.WatchContexts(wctx, rev, func(c store.ContextChange) { top = c.Rev; cancel() },
			func(r uint64) { told = append(told, r) }, nil)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the watch brought nothing")
	}
	if top == 0 || top >= uint64(other.Header.Revision) || w.Seen() < uint64(other.Header.Revision) {
		t.Fatalf("event at %d, the store at %d, Seen %d", top, other.Header.Revision, w.Seen())
	}
	if len(told) == 0 {
		t.Fatal("the batch told progress nothing")
	}
	for _, r := range told {
		if r > top {
			t.Fatalf("progress told %d past the top event %d", r, top)
		}
	}
}

// A watch from a compacted revision is store.ErrCompacted, never a silent
// gap. On a member of its own: compacting the shared member would cut the
// history every other test in the package reads with WithRev (pre-flight
// M17).
func TestAWatchFromACompactedRevisionSaysSo(t *testing.T) {
	ctx := context.Background()
	srv := etcdtest.Start(t, etcdtest.Options{})
	s, err := Open(Config{Endpoints: []string{srv.Endpoint}, Prefix: "/port49/", Now: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	k := store.ContextKey{NAS: "leaf-01", Username: "alice"}
	s.PutContext(ctx, k, store.Context{CtxID: "c1", Principal: "user:x", Username: "alice"}, time.Hour)
	rev, _ := s.ScanContexts(ctx, func(store.ContextKey, store.Context) {})
	s.PutContext(ctx, k, store.Context{CtxID: "c2", Principal: "user:x", Username: "alice"}, time.Hour)
	// A write past the second put, so the compaction cuts the watch's first
	// revision (rev+1): a watch from the compaction's own revision is not
	// compacted.
	resp, err := s.ctx.Put(ctx, "compact-me", "x")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ctx.Compact(ctx, resp.Header.Revision); err != nil {
		t.Fatal(err)
	}
	wctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	err = s.WatchContexts(wctx, rev, func(store.ContextChange) {}, func(uint64) {}, nil)
	if !errors.Is(err, store.ErrCompacted) {
		t.Fatalf("%v", err)
	}
}

// A progress request is answered: with no change to deliver, progress is
// told a revision at least the store's, so a reader waiting on the feed is
// let through an idle family (Task 8a's fence). And an event is delivered
// before any progress at or above its revision, a request sent the moment
// after the write included: the fence rests on that order, which etcd
// fixed in #15220 (3.4.24, 3.5.8, every 3.6; re-check R2).
func TestAWatchAnswersAProgressRequest(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := onShared(t, time.Now)
	rev, _ := s.ScanContexts(ctx, func(store.ContextKey, store.Context) {})
	other, err := s.ctx.Put(ctx, etcdtest.Prefix()+"elsewhere", "x") // a revision outside c/
	if err != nil {
		t.Fatal(err)
	}
	type told struct{ at, delivered uint64 }
	var mu sync.Mutex
	var delivered uint64 // the highest event fn has been given
	var tolds []told     // each progress, with what had been delivered when it was told
	asks := make(chan struct{}, 1)
	got := make(chan uint64, 64)
	go s.WatchContexts(ctx, rev, func(c store.ContextChange) {
		mu.Lock()
		delivered = max(delivered, c.Rev)
		mu.Unlock()
	}, func(r uint64) {
		mu.Lock()
		tolds = append(tolds, told{at: r, delivered: delivered})
		mu.Unlock()
		select {
		case got <- r:
		default:
		}
	}, asks)
	ask := func() {
		select {
		case asks <- struct{}{}:
		default:
		}
	}
	waitPast := func(want uint64, why string) {
		deadline := time.After(10 * time.Second)
		for {
			ask()
			select {
			case r := <-got:
				if r >= want {
					return
				}
			case <-time.After(100 * time.Millisecond):
			case <-deadline:
				t.Fatal(why)
			}
		}
	}
	waitPast(uint64(other.Header.Revision), "no progress past a revision outside the family was told")
	put, err := s.PutContextRev(ctx, store.ContextKey{NAS: "leaf-01", Username: "alice"},
		store.Context{CtxID: "c1", Principal: "user:x", Username: "alice"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ask() // at once: an etcd without #15220 could answer it ahead of the event
	waitPast(put, "the write was never followed")
	mu.Lock()
	defer mu.Unlock()
	for _, x := range tolds {
		if x.at >= put && x.delivered < put {
			t.Fatalf("progress told %d before the event at %d was delivered (etcd #15220: needs 3.4.24, 3.5.8 or 3.6)",
				x.at, put)
		}
	}
}

// The marks feed: Revocations reads every mark at one revision, and a watch
// from it brings a put as (r, false) and a lift as (r, true), the lift
// carrying the kind and key parsed from its etcd key, each with its own
// revision, in revision order. A mark put before the read is not brought
// again.
func TestTheMarkFeedBringsPutsAndLifts(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := onShared(t, time.Now)
	at := time.Unix(1_000_000, 0).UTC()
	before := store.Revocation{Kind: store.RevocationPrincipal, Key: "user:before@example.com", At: at}
	if err := s.PutRevocation(ctx, before); err != nil {
		t.Fatal(err)
	}
	rev, rs, err := s.Revocations(ctx)
	if err != nil || rev == 0 || len(rs) != 1 || rs[0].Key != before.Key || !rs[0].At.Equal(at) {
		t.Fatalf("rev %d %v: %v", rev, rs, err)
	}
	cert := store.Revocation{Kind: store.RevocationCert, Key: store.CertKey("CN=Corp/CA", "0a"), At: at,
		Origin: "admin_socket uid 0"} // a '/' in the key: escaped, and parsed back
	if err := s.PutRevocation(ctx, cert); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteRevocation(ctx, cert.Kind, cert.Key); err != nil {
		t.Fatal(err)
	}
	type ev struct {
		r      store.Revocation
		lifted bool
		rev    uint64
	}
	got := make(chan ev, 8)
	go s.WatchRevocations(ctx, rev, func(r store.Revocation, lifted bool, at uint64) { got <- ev{r, lifted, at} },
		func(uint64) {})
	var evs []ev
	for len(evs) < 2 {
		select {
		case e := <-got:
			evs = append(evs, e)
		case <-time.After(10 * time.Second):
			t.Fatalf("the watch brought %+v", evs)
		}
	}
	put, lift := evs[0], evs[1]
	if put.lifted || put.r != cert || put.rev <= rev {
		t.Fatalf("the put came as %+v", put)
	}
	if !lift.lifted || lift.r != (store.Revocation{Kind: cert.Kind, Key: cert.Key}) || lift.rev <= put.rev {
		t.Fatalf("the lift came as %+v", lift)
	}
	select {
	case e := <-got:
		t.Fatalf("the watch brought more: %+v", e)
	case <-time.After(200 * time.Millisecond):
	}
}

// A mark that does not decode is never a mark skipped, nor an error that
// would fail every reload (Ruling T9-e): the load and the watch each
// stand the mark its key names, as of when they read it, and say so by its
// key.
func TestTheMarkFeedNeverSkipsAMarkThatDoesNotDecode(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	now := time.Unix(2_000_000, 0).UTC()
	s := onShared(t, func() time.Time { return now })
	rev, _, err := s.Revocations(ctx)
	if err != nil {
		t.Fatal(err)
	}
	key := s.k.mark(store.RevocationPrincipal, "user:garbled@example.com")
	if _, err := s.tok.Put(ctx, key, "{"); err != nil {
		t.Fatal(err)
	}
	var said []string
	s.logf = func(format string, args ...any) { said = append(said, fmt.Sprintf(format, args...)) }
	_, rs, err := s.Revocations(ctx)
	want := store.Revocation{Kind: store.RevocationPrincipal, Key: "user:garbled@example.com", At: now}
	if err != nil || len(rs) != 1 || rs[0] != want {
		t.Fatalf("the load: %+v %v", rs, err)
	}
	if len(said) != 1 || !strings.Contains(said[0], "garbled") || !strings.Contains(said[0], "stands it") {
		t.Fatalf("the load said %q", said)
	}
	got := make(chan store.Revocation, 1)
	go s.WatchRevocations(ctx, rev, func(r store.Revocation, lifted bool, _ uint64) {
		if !lifted {
			got <- r
		}
	}, func(uint64) {})
	select {
	case r := <-got:
		if r != want {
			t.Fatalf("the watch brought %+v", r)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the watch skipped the mark")
	}
}

// A marks watch from a compacted revision is store.ErrCompacted. On a
// member of its own, as TestAWatchFromACompactedRevisionSaysSo is.
func TestAMarkWatchFromACompactedRevisionSaysSo(t *testing.T) {
	ctx := context.Background()
	srv := etcdtest.Start(t, etcdtest.Options{})
	s, err := Open(Config{Endpoints: []string{srv.Endpoint}, Prefix: "/port49/", Now: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	r := store.Revocation{Kind: store.RevocationPrincipal, Key: "user:alice@example.com", At: time.Now()}
	s.PutRevocation(ctx, r)
	rev, _, _ := s.Revocations(ctx)
	s.DeleteRevocation(ctx, r.Kind, r.Key)
	resp, err := s.tok.Put(ctx, "compact-me", "x")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.tok.Compact(ctx, resp.Header.Revision); err != nil {
		t.Fatal(err)
	}
	wctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	err = s.WatchRevocations(wctx, rev, func(store.Revocation, bool, uint64) {}, func(uint64) {})
	if !errors.Is(err, store.ErrCompacted) {
		t.Fatalf("%v", err)
	}
}

// breakable is a store whose watches the test ends, as a leader change
// ends one under WithRequireLeader, recording where each watch began and
// the highest progress each feed was told.
type breakable struct {
	*Store
	endMarks, endContexts chan struct{}
	mu                    sync.Mutex
	marksFrom, ctxFrom    []uint64
	marksAt, ctxAt        uint64
}

// ending is ctx, ended by a receive on end.
func ending(ctx context.Context, end <-chan struct{}) (context.Context, context.CancelFunc) {
	wctx, cancel := context.WithCancel(ctx)
	go func() {
		select {
		case <-end:
			cancel()
		case <-wctx.Done():
		}
	}()
	return wctx, cancel
}

func (b *breakable) WatchRevocations(ctx context.Context, after uint64, fn func(store.Revocation, bool, uint64),
	progress func(uint64)) error {
	b.mu.Lock()
	b.marksFrom = append(b.marksFrom, after)
	b.mu.Unlock()
	wctx, cancel := ending(ctx, b.endMarks)
	defer cancel()
	return b.Store.WatchRevocations(wctx, after, fn, func(rev uint64) {
		b.mu.Lock()
		b.marksAt = max(b.marksAt, rev)
		b.mu.Unlock()
		progress(rev)
	})
}

func (b *breakable) WatchContexts(ctx context.Context, after uint64, fn func(store.ContextChange),
	progress func(uint64), asks <-chan struct{}) error {
	b.mu.Lock()
	b.ctxFrom = append(b.ctxFrom, after)
	b.mu.Unlock()
	wctx, cancel := ending(ctx, b.endContexts)
	defer cancel()
	return b.Store.WatchContexts(wctx, after, fn, func(rev uint64) {
		b.mu.Lock()
		b.ctxAt = max(b.ctxAt, rev)
		b.mu.Unlock()
		progress(rev)
	}, asks)
}

// A quiet feed's re-watch resumes from the progress etcd sent it, not from
// the last change it delivered: with nothing written to c/ or rv/ for
// longer than the compaction retention, a watch that ends (a leader
// change, a member restart) is watched again above the compaction, and
// neither feed reloads (final review 7e-1 I-1). Without progress
// notifications, each would be ErrCompacted, a reload, and a page.
func TestAQuietFeedResumesFromItsProgressNotARescan(t *testing.T) {
	ctx := context.Background()
	srv := etcdtest.Start(t, etcdtest.Options{ProgressNotify: 100 * time.Millisecond})
	s, err := Open(Config{Endpoints: []string{srv.Endpoint}, Prefix: "/port49/", Now: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	b := &breakable{Store: s, endMarks: make(chan struct{}), endContexts: make(chan struct{})}
	start, _, err := s.Revocations(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var rescans atomic.Int32
	fctx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	defer func() { cancel(); wg.Wait() }()
	wg.Add(2)
	go func() {
		defer wg.Done()
		store.FollowMarks(fctx, b, store.NewMarks(), start, nil, func(bool) {}, func() { rescans.Add(1) }, t.Logf)
	}()
	go func() {
		defer wg.Done()
		crypt.FollowContexts(fctx, b, nil, sealKeys, crypt.NewLedger(), start, func(bool) {},
			func() { rescans.Add(1) }, t.Logf)
	}()

	until := func(what string, ok func() bool) {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for {
			b.mu.Lock()
			done := ok()
			b.mu.Unlock()
			if done {
				return
			}
			if time.Now().After(deadline) {
				b.mu.Lock()
				state := fmt.Sprintf("marks at %d from %v, contexts at %d from %v", b.marksAt, b.marksFrom, b.ctxAt,
					b.ctxFrom)
				b.mu.Unlock()
				t.Fatalf("waited 10s for %s; %s", what, state)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	// Written elsewhere, never c/ or rv/, and compacted past where both
	// feeds began, once both watches are told progress through the first
	// write: a watch registered after the compaction would be compacted
	// itself.
	elsewhere := func() uint64 {
		t.Helper()
		resp, err := s.tok.Put(ctx, "/elsewhere", "x")
		if err != nil {
			t.Fatal(err)
		}
		return uint64(resp.Header.Revision)
	}
	first := elsewhere()
	until("both watches to be synced", func() bool { return b.marksAt >= first && b.ctxAt >= first })
	top := elsewhere()
	if _, err := s.tok.Compact(ctx, int64(top)); err != nil {
		t.Fatal(err)
	}
	until("a progress notification past the compaction",
		func() bool { return b.marksAt >= top && b.ctxAt >= top })
	b.endMarks <- struct{}{}
	b.endContexts <- struct{}{}
	until("each feed to watch again", func() bool { return len(b.marksFrom) == 2 && len(b.ctxFrom) == 2 })
	b.mu.Lock()
	marksFrom, ctxFrom := b.marksFrom[1], b.ctxFrom[1]
	b.mu.Unlock()
	if marksFrom < top || ctxFrom < top {
		t.Fatalf("re-watched from %d (marks) and %d (contexts), below the compaction at %d", marksFrom, ctxFrom, top)
	}
	// Running, not compacted: each new watch is told progress again.
	now := elsewhere()
	until("progress on the new watches", func() bool { return b.marksAt >= now && b.ctxAt >= now })
	if n := rescans.Load(); n != 0 {
		t.Fatalf("%d reload(s) after a re-watch within the progress etcd sent", n)
	}
}
