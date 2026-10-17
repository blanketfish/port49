package port49d

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/rhwendt/port49/internal/config"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/policy"
	"github.com/rhwendt/port49/internal/session"
	"github.com/rhwendt/port49/internal/store"
	etcdstore "github.com/rhwendt/port49/internal/store/etcd"
	"github.com/rhwendt/port49/internal/store/memory"
)

// hangingContexts holds the first context read until released, and lands
// a context write only while its ctx lives, as etcd sends nothing on a
// cancelled call; landed counts the writes that landed.
type hangingContexts struct {
	store.Store
	once             sync.Once
	entered, release chan struct{}
	landed           atomic.Int32
	// first is the ctx the held read received: the pass's own.
	first context.Context
}

func (h *hangingContexts) GetContext(ctx context.Context, k store.ContextKey) (store.Context, error) {
	h.once.Do(func() { h.first = ctx; close(h.entered); <-h.release })
	return h.Store.GetContext(ctx, k)
}

func (h *hangingContexts) land(ctx context.Context, write func() error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	err := write()
	if err == nil {
		h.landed.Add(1)
	}
	return err
}

func (h *hangingContexts) SetContextPolicy(ctx context.Context, k store.ContextKey, rev uint64, p store.ContextPolicy) error {
	return h.land(ctx, func() error { return h.Store.SetContextPolicy(ctx, k, rev, p) })
}

func (h *hangingContexts) SetRevokedAt(ctx context.Context, k store.ContextKey, at time.Time) error {
	return h.land(ctx, func() error { return h.Store.SetRevokedAt(ctx, k, at) })
}

func (h *hangingContexts) DeleteContextIf(ctx context.Context, k store.ContextKey, rev uint64) error {
	return h.land(ctx, func() error { return h.Store.DeleteContextIf(ctx, k, rev) })
}

// A pass in flight when the hold is lost writes no context after it: its
// context half runs under the duties' context too, so the lost hold ends
// it before the write, and the replica's next pass is the token half
// (Ruling 6; Task 15 review I-1).
func TestALostHoldEndsTheRunnersPassBeforeItWrites(t *testing.T) {
	rig := newReloadRig(t, minimalPolicy)
	k := rig.aliceLoggedIn(t)
	rig.write(t, showOnly)
	hung := &hangingContexts{Store: rig.st, entered: make(chan struct{}), release: make(chan struct{})}
	rig.b.Store = hung
	r := &runner{brk: rig.b}
	rig.r.pass = r.pass
	dctx, lose := context.WithCancel(context.Background())
	r.duty.Store(&dctx)
	done := make(chan struct{})
	go func() { defer close(done); rig.with(func() { rig.r.reload(context.Background(), "SIGHUP") }) }()
	select {
	case <-hung.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the runner's pass never read a context")
	}
	lose() // as run does on a lost hold: the duties stop, then duty is cleared
	r.duty.Store(nil)
	// The pass is tied to the duties by context.AfterFunc, which cancels in
	// a new goroutine: wait for it, as a write on a loaded machine would
	// otherwise reach land before the cancel does.
	select {
	case <-hung.first.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the pass's context was not cancelled by the lost hold")
	}
	close(hung.release)
	<-done
	if n := hung.landed.Load(); n != 0 {
		t.Fatalf("%d context write(s) landed after the hold was lost", n)
	}
	rig.now = rig.r.settle
	rig.with(func() { rig.r.refresh(context.Background()) })
	if c, err := rig.st.GetContext(context.Background(), k); err != nil || c.BlobHash != "sha256:before" {
		t.Fatalf("a replica whose hold was lost judged a context: %+v %v", c, err)
	}
}

// metaOf is a runner's meta/judged for these tests: Judged answers
// unavailable the first fail times; PutJudged records each bundle, and
// waits for hold while it is open.
type metaOf struct {
	inner  judgedStore
	fail   int
	reads  atomic.Int32
	hold   chan struct{}
	mu     sync.Mutex
	judged []string
}

func (m *metaOf) Judged(ctx context.Context) (etcdstore.JudgedRecord, bool, error) {
	if int(m.reads.Add(1)) <= m.fail {
		return etcdstore.JudgedRecord{}, false, store.ErrUnavailable
	}
	if m.inner == nil {
		return etcdstore.JudgedRecord{}, false, nil
	}
	return m.inner.Judged(ctx)
}

func (m *metaOf) PutJudgedSince(ctx context.Context, bundle string, raw []byte, rev uint64) (bool, error) {
	if m.hold != nil {
		select {
		case <-m.hold:
		case <-ctx.Done():
			return false, ctx.Err()
		}
	}
	m.mu.Lock()
	m.judged = append(m.judged, bundle)
	m.mu.Unlock()
	if m.inner == nil {
		return true, nil
	}
	return m.inner.PutJudgedSince(ctx, bundle, raw, rev)
}

func (m *metaOf) BundlesAt(ctx context.Context) ([]etcdstore.BundleRecord, uint64, error) {
	if m.inner == nil {
		return nil, 0, nil
	}
	return m.inner.BundlesAt(ctx)
}

func (m *metaOf) JudgeInDoubt(ctx context.Context, unless string) (string, bool, error) {
	if m.inner == nil {
		return "", false, nil
	}
	return m.inner.JudgeInDoubt(ctx, unless)
}

func (m *metaOf) RefreshOwed(ctx context.Context) (uint64, etcdstore.BundleRecord, bool, error) {
	if m.inner == nil {
		return 0, etcdstore.BundleRecord{}, false, nil
	}
	return m.inner.RefreshOwed(ctx)
}

func (m *metaOf) ClearRefreshOwed(ctx context.Context, rev uint64) error {
	if m.inner == nil {
		return nil
	}
	return m.inner.ClearRefreshOwed(ctx, rev)
}

func (m *metaOf) recorded() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.judged...)
}

// A settled pass never waits on the store: it hands the policy it settled
// on to the duties, which record it, so SIGHUP, the policy watch and the
// scheduled passes go on while meta/judged cannot be written; a later
// pass's policy replaces one not yet written, and the one written is the
// pass's, not whatever is in force when the write lands (Task 15 review
// M-5, M-6).
func TestASettledPassNeverWaitsOnTheStore(t *testing.T) {
	rig := newReloadRig(t, minimalPolicy)
	first := rig.b.Policy.Load()
	swapTo(t, rig, showOnly)
	second := rig.b.Policy.Load()
	meta := &metaOf{hold: make(chan struct{})}
	r := &runner{brk: rig.b, meta: meta, judge: make(chan *policy.Policy, 1)}
	r.settled(first) // not running: nothing to record
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r.duty.Store(&ctx)
	settled := make(chan struct{})
	go func() { defer close(settled); r.settled(first); r.settled(second) }()
	select {
	case <-settled:
	case <-time.After(5 * time.Second):
		t.Fatal("a settled pass waited on the store")
	}
	rig.write(t, minimalPolicy)
	rig.pollTwice() // in force now: neither settled pass's
	done := make(chan struct{})
	go func() { defer close(done); rig.with(func() { r.judging(ctx) }) }()
	close(meta.hold)
	deadline := time.Now().Add(10 * time.Second)
	for len(meta.recorded()) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	if got := meta.recorded(); len(got) != 1 || got[0] != second.Bundle {
		t.Fatalf("recorded %q, want only the later settled pass's %q", got, second.Bundle)
	}
}

// A policy swapped in between the takeover's carry and the duties ran its
// first pass as the token half, so the duties owe a whole pass at once;
// none when the policy in force is the one carried (Task 15 review M-6).
func TestASwapDuringTheTakeoverIsOwedAPass(t *testing.T) {
	rig := newReloadRig(t, minimalPolicy)
	carried := rig.b.Policy.Load()
	r := &runner{brk: rig.b, rel: rig.r, judge: make(chan *policy.Policy, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if !r.begin(ctx, carried) {
		t.Fatal("begin stopped with ctx live")
	}
	select {
	case now := <-rig.r.owed:
		t.Fatalf("a pass owed (now %v) with the carried policy in force", now)
	default:
	}
	if !r.running() {
		t.Fatal("not running once begun")
	}
	// A pass settled while this replica did not run, or in an earlier run,
	// is not this run's to record.
	r.duty.Store(nil)
	r.settled(carried)
	r.judge <- carried // an earlier run's, left unwritten
	if !r.begin(ctx, carried) {
		t.Fatal("begin stopped with ctx live")
	}
	if len(r.judge) != 0 {
		t.Fatal("a settled pass from before this run is left for it to record")
	}
	swapTo(t, rig, showOnly)
	if !r.begin(ctx, carried) {
		t.Fatal("begin stopped with ctx live")
	}
	select {
	case now := <-rig.r.owed:
		if !now {
			t.Fatal("the pass owed for a swap during the takeover is not owed at once")
		}
	default:
		t.Fatal("a swap during the takeover owed no pass")
	}
}

// refusingRevocations is a sealed store whose revocation list is refused
// with an error waiting does not mend.
type refusingRevocations struct{ store.Store }

func (refusingRevocations) ListRevocations(context.Context) ([]store.Revocation, error) {
	return nil, errors.New("the revocation list is refused")
}

// A takeover that stops on an error waiting does not mend lets the hold
// go, so another replica takes it within the runner's 5s wait; this
// replica's next try then names the holder, which is under this
// replica's name, as its own last run, never as one that runs the
// keyspace (Task 15 deviation 1; Task 15 review M-3b, M-3d).
func TestAFailedTakeoverLetsTheHoldGo(t *testing.T) {
	f := splitFleet(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bs, keys := openBrokerFor(t, ctx, f.broker, metrics.New(prometheus.NewRegistry()), io.Discard)
	other, _ := openBrokerFor(t, ctx, f.copyBroker(t), metrics.New(prometheus.NewRegistry()), io.Discard)
	cfg, _ := loadBroker(t, f.broker)
	var out syncBuffer
	e := stderr
	t.Cleanup(func() { stderr = e })
	stderr = &out
	r := &runner{cfg: cfg, raw: bs.raw, st: refusingRevocations{bs.st}, meta: bs.raw, keys: keys,
		m: metrics.New(prometheus.NewRegistry()), alarm: newKeyAlarm(),
		who: "port49-broker on replica-a (pid 4242, since 2026-10-04T00:00:00Z)"}
	rctx, rcancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { defer close(done); r.run(rctx) }()
	defer func() { rcancel(); <-done }()
	waitWithin(t, &out, "port49-broker: runner: the takeover stopped: ", 20*time.Second)
	hctx, hcancel := context.WithTimeout(ctx, 6*time.Second)
	defer hcancel()
	_, release, err := other.raw.Hold(hctx, cfg.Stores.Session.Etcd.HoldTTL, r.who, func(string) {})
	if err != nil {
		t.Fatalf("another replica could not take the hold after a failed takeover: %v", err)
	}
	defer release()
	waitWithin(t, &out, "is still held by this replica's last run", 15*time.Second)
	if strings.Contains(out.String(), "is run by") {
		t.Fatalf("this replica's own last run was said as another's:\n%s", out.String())
	}
}

// The takeover's meta/judged read is tried again while the store is
// unavailable, not taken as no record, which would purge every unspent
// token when the store's state did not call for it (Task 15 review M-3c).
func TestAnUnavailableJudgedReadIsTriedAgain(t *testing.T) {
	f := splitFleet(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := metrics.New(prometheus.NewRegistry())
	bs, keys := openBrokerFor(t, ctx, f.broker, m, io.Discard)
	cfg, _ := loadBroker(t, f.broker)
	bcfg := brokerConfig(t, minimalPolicy)
	_, b, err := buildBroker(bcfg, "inventory_file "+bcfg.InventoryFile, bs.st, seedMinter(),
		decision.NewJSONLines(io.Discard), m)
	if err != nil {
		t.Fatal(err)
	}
	b.Sessions = session.New(bs.st, time.Now, cfg.ContextIdleTTL, cfg.Session.IndexTTL)
	b.Marks = store.NewMarks()
	pol := b.Policy.Load()
	if err := bs.raw.PutJudged(ctx, pol.Bundle, pol.Raw()); err != nil {
		t.Fatal(err)
	}
	var out syncBuffer
	e := stderr
	t.Cleanup(func() { stderr = e })
	stderr = &out
	meta := &metaOf{inner: bs.raw, fail: 1}
	r := &runner{cfg: cfg, brk: b, raw: bs.raw, st: bs.st, meta: meta, keys: keys, m: m, alarm: newKeyAlarm()}
	if _, err := r.takeover(ctx); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "is the one the last runner judged; no unspent token purged") ||
		meta.reads.Load() < 2 {
		t.Fatalf("an unavailable meta/judged read (%d read(s)):\n%s", meta.reads.Load(), out.String())
	}
}

// skewMeta is meta/ for owed: the replicas' records and the ask, which
// the test sets, and the revisions cleared.
type skewMeta struct {
	metaOf
	mu      sync.Mutex
	recs    []etcdstore.BundleRecord
	reads   int
	askRev  uint64
	ask     etcdstore.BundleRecord
	cleared []uint64
	// kept is a clear that does not land: the ask stays.
	kept bool
	// readErr fails the replicas' records' read; moved is how many
	// records as judged find a replica's record written since.
	readErr error
	moved   int
	doubted int
}

func (s *skewMeta) BundlesAt(context.Context) ([]etcdstore.BundleRecord, uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reads++
	if s.readErr != nil {
		return nil, 0, s.readErr
	}
	return append([]etcdstore.BundleRecord(nil), s.recs...), uint64(s.reads), nil
}

func (s *skewMeta) PutJudgedSince(ctx context.Context, bundle string, raw []byte, rev uint64) (bool, error) {
	s.mu.Lock()
	moved := s.moved > 0
	if moved {
		s.moved--
	}
	s.mu.Unlock()
	if moved {
		return false, nil
	}
	return s.metaOf.PutJudgedSince(ctx, bundle, raw, rev)
}

func (s *skewMeta) JudgeInDoubt(context.Context, string) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.doubted++
	return "b-judged", s.doubted == 1, nil
}

func (s *skewMeta) RefreshOwed(context.Context) (uint64, etcdstore.BundleRecord, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.askRev, s.ask, s.askRev != 0, nil
}

func (s *skewMeta) ClearRefreshOwed(_ context.Context, rev uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleared = append(s.cleared, rev)
	if rev == s.askRev && !s.kept {
		s.askRev = 0
	}
	return nil
}

func (s *skewMeta) set(f func(s *skewMeta)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f(s)
}

func (s *skewMeta) bundleReads() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reads
}

// The runner's watch over the other replicas (pre-flight I3): a replica
// seen serving another bundle owes a full context pass once every token it
// could have minted has expired, though it never asks, as one that dies
// unreloaded never does; once, not at every look. A replica's ask newer
// than the one the takeover covered is a full pass, asked again while it
// fails, and cleared at its revision once it completes; the runner's own
// record never owes one.
func TestTheRunnerOwesAFullPassForAReplicaThatNeverAsks(t *testing.T) {
	rig := newReloadRig(t, minimalPolicy)
	var clock atomic.Int64
	start := time.Unix(1_000_000, 0)
	clock.Store(start.UnixNano())
	rig.b.Now = func() time.Time { return time.Unix(0, clock.Load()) }
	cfg := rig.cfg
	cfg.Policy = &config.PolicyConfig{File: rig.cfg.Policy.File, WatchInterval: 50 * time.Millisecond}
	meta := &skewMeta{askRev: 3, ask: etcdstore.BundleRecord{Who: "covered"}}
	rel := &reloader{fullPass: make(chan fullPassOwed)}
	r := &runner{cfg: cfg, brk: rig.b, meta: meta, rel: rel, who: "runner-a", covered: 3}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); r.owed(ctx) }()
	defer func() { cancel(); <-done }()
	none := func(what string) {
		t.Helper()
		select {
		case o := <-rel.fullPass:
			t.Fatalf("%s: a full pass owed by %s", what, o.who)
		case <-time.After(300 * time.Millisecond):
		}
	}
	next := func(what string) fullPassOwed {
		t.Helper()
		select {
		case o := <-rel.fullPass:
			return o
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: no full pass owed", what)
		}
		return fullPassOwed{}
	}
	none("the ask the takeover covered")
	mine := rig.b.Policy.Load().Bundle
	meta.set(func(s *skewMeta) {
		s.recs = []etcdstore.BundleRecord{{Who: "runner-a", Bundle: "b-runner-lags"}, {Who: "replica-b", Bundle: "b-old"}}
	})
	reads := meta.bundleReads()
	waitUntil(t, "the watch to see the replica", func() bool { return meta.bundleReads() > reads+1 })
	meta.set(func(s *skewMeta) { s.recs = []etcdstore.BundleRecord{{Who: "runner-a", Bundle: "b-runner-lags"}} })
	reads = meta.bundleReads()
	waitUntil(t, "the watch to see it gone", func() bool { return meta.bundleReads() > reads+1 })
	clock.Store(start.Add(policy.MaxTokenTTL - time.Second).UnixNano())
	none("a token life not yet past")
	clock.Store(start.Add(policy.MaxTokenTTL).UnixNano())
	o := next("a token life after the replica was last seen")
	if o.who != "a replica that served another bundle" || o.bundle != "b-old" {
		t.Fatalf("owed by %q (bundle %q)", o.who, o.bundle)
	}
	o.done <- nil
	clock.Store(start.Add(3 * policy.MaxTokenTTL).UnixNano())
	none("the pass is owed once")
	clock.Store(start.Add(5 * policy.MaxTokenTTL).UnixNano())
	none("the runner's own lagging record owes none")
	meta.set(func(s *skewMeta) {
		s.recs = []etcdstore.BundleRecord{{Who: "runner-a", Bundle: mine}}
		s.askRev, s.kept = 7, true // a clear that does not land: handled all the same
		s.ask = etcdstore.BundleRecord{Who: "port49-broker on b (pid 1, since 2026-10-04T00:00:00Z)", Bundle: "b-new"}
	})
	o = next("a replica's ask")
	if o.who != `"port49-broker on b (pid 1, since 2026-10-04T00:00:00Z)"` || o.bundle != "b-new" {
		t.Fatalf("owed by %q (bundle %q)", o.who, o.bundle)
	}
	o.done <- errors.New("the pass stopped")
	o = next("an ask whose pass failed")
	o.done <- nil
	waitUntil(t, "the ask cleared at its revision", func() bool {
		meta.mu.Lock()
		defer meta.mu.Unlock()
		return len(meta.cleared) == 2 && meta.cleared[0] == 3 && meta.cleared[1] == 7
	})
	none("an ask handled")
}

// No bundle is recorded as judged while any replica's record names
// another: its tokens, and the contexts they make, carry a policy no pass
// judged, so the record in place is marked in doubt and the next takeover
// must purge (Ruling 8 corrected; pre-flight I3; Task 15a review I-1).
// Nor while the replicas' records cannot be read (review M-2), nor over a
// replica's record written after they were read: they are read again, a
// few times (review I-1).
func TestNoBundleIsJudgedWhileAReplicaServesAnother(t *testing.T) {
	rig := newReloadRig(t, minimalPolicy)
	pol := rig.b.Policy.Load()
	meta := &skewMeta{recs: []etcdstore.BundleRecord{{Who: "runner-a", Bundle: pol.Bundle}, {Who: "replica-b", Bundle: "b-old"}}}
	r := &runner{brk: rig.b, meta: meta}
	rig.with(func() { r.recordJudged(context.Background(), pol, "a test") })
	if got := meta.recorded(); len(got) != 0 {
		t.Fatalf("recorded %q while a replica serves another bundle", got)
	}
	if !strings.Contains(rig.out.String(), "port49-broker: runner: not recording bundle "+pol.Bundle+
		" as judged: ? serves bundle b-old") ||
		!strings.Contains(rig.out.String(), "port49-broker: runner: the bundle last judged (b-judged) is in doubt: ? "+
			"serves bundle b-old; the next takeover purges the unspent tokens") || meta.doubted != 1 {
		t.Fatalf("said (%d mark(s)): %q", meta.doubted, rig.out.String())
	}
	meta.set(func(s *skewMeta) { s.recs, s.readErr = s.recs[:1], errors.New("the read is refused") })
	rig.with(func() { r.recordJudged(context.Background(), pol, "a test") })
	if got := meta.recorded(); len(got) != 0 {
		t.Fatalf("recorded %q with the replicas' records unread", got)
	}
	if !strings.Contains(rig.out.String(), "port49-broker: runner: not recording bundle "+pol.Bundle+" as judged: "+
		"reading the bundles the replicas serve: the read is refused; the next takeover purges the unspent tokens") {
		t.Fatalf("said: %q", rig.out.String())
	}
	meta.set(func(s *skewMeta) { s.readErr, s.moved = nil, judgeTries })
	reads := meta.bundleReads()
	rig.with(func() { r.recordJudged(context.Background(), pol, "a test") })
	if got := meta.recorded(); len(got) != 0 || meta.bundleReads() != reads+judgeTries {
		t.Fatalf("recorded %q over records that kept moving (%d read(s))", got, meta.bundleReads()-reads)
	}
	if !strings.Contains(rig.out.String(), "port49-broker: runner: not recording bundle "+pol.Bundle+" as judged: "+
		"the replicas' records changed at each of 3 reads; the next takeover purges the unspent tokens") {
		t.Fatalf("said: %q", rig.out.String())
	}
	meta.set(func(s *skewMeta) { s.moved = 1 })
	reads = meta.bundleReads()
	rig.with(func() { r.recordJudged(context.Background(), pol, "a test") })
	if got := meta.recorded(); len(got) != 1 || got[0] != pol.Bundle || meta.bundleReads() != reads+2 {
		t.Fatalf("recorded %q once every replica serves %s (%d read(s))", got, pol.Bundle, meta.bundleReads()-reads)
	}
}

// A takeover purges when the bundle last judged went in doubt, though the
// bundle in force is the one it names: a replica that served another
// bundle, seen by the runner's watch (owed), may have left unspent tokens
// no pass judged, though it has since stopped and its record is gone
// (Task 15a review I-1). The carry then records the bundle afresh.
func TestATakeoverPurgesOnceTheBundleJudgedIsInDoubt(t *testing.T) {
	f := splitFleet(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := metrics.New(prometheus.NewRegistry())
	bs, keys := openBrokerFor(t, ctx, f.broker, m, io.Discard)
	cfg, _ := loadBroker(t, f.broker)
	bcfg := brokerConfig(t, minimalPolicy)
	_, b, err := buildBroker(bcfg, "inventory_file "+bcfg.InventoryFile, bs.st, seedMinter(),
		decision.NewJSONLines(io.Discard), m)
	if err != nil {
		t.Fatal(err)
	}
	b.Sessions = session.New(bs.st, time.Now, cfg.ContextIdleTTL, cfg.Session.IndexTTL)
	b.Marks = store.NewMarks()
	pol := b.Policy.Load()
	if err := bs.raw.PutJudged(ctx, pol.Bundle, pol.Raw()); err != nil {
		t.Fatal(err)
	}
	c := "port49-broker on c (pid 3, since 2026-10-04T00:00:00Z)"
	if err := bs.raw.PutBundle(ctx, c, "b-stale", time.Minute); err != nil {
		t.Fatal(err)
	}
	var out syncBuffer
	e := stderr
	t.Cleanup(func() { stderr = e })
	stderr = &out
	wcfg := cfg
	wcfg.Policy = &config.PolicyConfig{File: bcfg.Policy.File, WatchInterval: 50 * time.Millisecond}
	w := &runner{cfg: wcfg, brk: b, meta: bs.raw, who: "runner-a"}
	wctx, wcancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { defer close(done); w.owed(wctx) }()
	waitWithin(t, &out, "port49-broker: runner: the bundle last judged ("+pol.Bundle+") is in doubt: "+
		lineHolder(c)+" serves bundle b-stale", 10*time.Second)
	wcancel()
	<-done
	if got, ok, err := bs.raw.Judged(ctx); !ok || err != nil || !got.InDoubt || got.Bundle != pol.Bundle {
		t.Fatalf("meta/judged after the watch saw the replica: %+v %v %v", got, ok, err)
	}
	if err := bs.raw.DeleteBundle(ctx, c); err != nil { // its graceful stop
		t.Fatal(err)
	}
	r := &runner{cfg: cfg, brk: b, raw: bs.raw, st: bs.st, meta: bs.raw, keys: keys, m: m, alarm: newKeyAlarm()}
	was, err := bs.raw.RestoreRead(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.takeover(ctx); err != nil {
		t.Fatal(err)
	}
	// The purge is done: port49d's restore guard leaves on meta/purged (Task 15d).
	if now, err := bs.raw.RestoreRead(ctx); err != nil || now.Purged <= was.Purged {
		t.Fatalf("a takeover's whole purge left meta/purged at %d (was %d): %v", now.Purged, was.Purged, err)
	}
	if !strings.Contains(out.String(), "port49-broker: runner: the bundle the last runner judged ("+pol.Bundle+
		") is in doubt, a replica having served another since; 0 unspent token(s) purged") {
		t.Fatalf("a takeover on a bundle in doubt:\n%s", out.String())
	}
	if got, ok, err := bs.raw.Judged(ctx); !ok || err != nil || got.InDoubt || got.Bundle != pol.Bundle {
		t.Fatalf("meta/judged after the carry: %+v %v %v", got, ok, err)
	}
}

// A replica that starts on a bundle other than the one last judged marks
// meta/judged in doubt itself, before anything that mints is served: one
// that stops before the runner's watch (owed) ever looks leaves no record
// to see, yet its unspent tokens carry a policy no pass judged, so a
// takeover on the judged bundle must purge (Task 15a re-review 1, I-2).
func TestAReplicaThatStartsOnAnotherBundleMarksTheJudgedInDoubt(t *testing.T) {
	f := splitFleet(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := metrics.New(prometheus.NewRegistry())
	bs, keys := openBrokerFor(t, ctx, f.broker, m, io.Discard)
	cfg, _ := loadBroker(t, f.broker)
	bcfg := brokerConfig(t, minimalPolicy)
	_, b, err := buildBroker(bcfg, "inventory_file "+bcfg.InventoryFile, bs.st, seedMinter(),
		decision.NewJSONLines(io.Discard), m)
	if err != nil {
		t.Fatal(err)
	}
	b.Sessions = session.New(bs.st, time.Now, cfg.ContextIdleTTL, cfg.Session.IndexTTL)
	b.Marks = store.NewMarks()
	pol := b.Policy.Load()
	if err := bs.raw.PutJudged(ctx, pol.Bundle, pol.Raw()); err != nil {
		t.Fatal(err)
	}
	var out syncBuffer
	e := stderr
	t.Cleanup(func() { stderr = e })
	stderr = &out
	c := "port49-broker on c (pid 3, since 2026-10-04T00:00:00Z)"
	if err := recordAtStart(ctx, bs.raw, c, "b-stale", time.Minute, time.Second, 10*time.Millisecond,
		&out); err != nil {
		t.Fatal(err)
	}
	if err := bs.raw.DeleteBundle(ctx, c); err != nil { // its graceful stop, before any look
		t.Fatal(err)
	}
	if got, ok, err := bs.raw.Judged(ctx); !ok || err != nil || !got.InDoubt || got.Bundle != pol.Bundle {
		t.Fatalf("meta/judged after a replica started on another bundle: %s in doubt %v, %v %v\n%s", got.Bundle,
			got.InDoubt, ok, err, out.String())
	}
	r := &runner{cfg: cfg, brk: b, raw: bs.raw, st: bs.st, meta: bs.raw, keys: keys, m: m, alarm: newKeyAlarm()}
	if _, err := r.takeover(ctx); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "port49-broker: runner: the bundle the last runner judged ("+pol.Bundle+
		") is in doubt, a replica having served another since; ") {
		t.Fatalf("a takeover after a replica served another bundle unseen:\n%s", out.String())
	}
}

// The runner's hook before a marks reload puts back what its copy holds
// and the store lost; a put-back that fails returns an error, so
// FollowMarks reloads nothing and the lost mark is never lifted, and the
// next compacted round puts it back, then reloads (re-review 1 C-2). A
// replica that does not run puts nothing back and keeps alice, whom its
// copy holds; its reload lifts bob, whom its copy lacks (pre-flight 7e-2
// P-3). Each call counts a rescan.
func TestTheRunnersReloadHookRefusesTheReloadOnAFailedPutBack(t *testing.T) {
	alice := store.Revocation{Kind: store.RevocationPrincipal, Key: "user:alice@example.com", At: time.Unix(10, 0).UTC()}
	var out syncBuffer
	e := stderr
	t.Cleanup(func() { stderr = e })
	stderr = &out
	rescans := prometheus.NewCounter(prometheus.CounterOpts{Name: "rescans"})
	bob := store.Revocation{Kind: store.RevocationPrincipal, Key: "user:bob@example.com", At: time.Unix(11, 0).UTC()}
	// newRunner's copy holds alice; its marks hold alice and bob, whom the
	// copy lacks.
	newRunner := func(st store.Store, running bool) *runner {
		c := openMarksCopy(filepath.Join(safeStateDir(t), "marks.json"), &out)
		c.Apply(store.MarkChange{Revocation: alice, Standing: true})
		marks := store.NewMarks()
		marks.Set(alice, true)
		marks.Set(bob, true)
		r := &runner{cfg: config.Config{Stores: config.StoresConfig{Session: config.StoreConfig{Etcd: &config.EtcdConfig{BulkTimeout: time.Second}}}},
			st: st, copy: c, marks: marks, marksReloaded: make(chan struct{}, 1)}
		if running {
			ctx := context.Background()
			r.duty.Store(&ctx)
		}
		return r
	}
	// follow runs FollowMarks over st's marks into r.marks, compacted
	// rounds times, and records each key a reload lifted.
	follow := func(r *runner, st store.Store, rounds int32) *sync.Map {
		var lifted sync.Map
		feed := &storeFeed{st: st}
		feed.compacted.Store(rounds)
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			defer close(done)
			store.FollowMarks(ctx, feed, r.marks, 1, func(c store.MarkChange) {
				if !c.Standing {
					lifted.Store(c.Key, true)
				}
			}, func(bool) {}, r.reloadHook(ctx, rescans), func(string, ...any) {})
		}()
		t.Cleanup(func() { cancel(); <-done })
		return &lifted
	}

	idle := memory.New(time.Now)
	rIdle := newRunner(idle, false)
	liftedIdle := follow(rIdle, idle, 1)
	waitUntil(t, "the idle replica's reload lifts bob", func() bool { _, ok := liftedIdle.Load(bob.Key); return ok })
	if _, ok := liftedIdle.Load(alice.Key); ok || !rIdle.marks.Holds(alice.Kind, alice.Key) {
		t.Fatal("an idle replica's reload lifted a mark its copy holds and the store lost")
	}
	if _, err := idle.GetRevocation(context.Background(), alice.Kind, alice.Key); err == nil {
		t.Fatal("a replica that does not run put a mark back")
	}

	st := &putsFailOnce{Store: memory.New(time.Now)}
	r := newRunner(st, true)
	lifted := follow(r, st, 2)
	waitUntil(t, "the runner puts alice back", func() bool {
		_, err := st.GetRevocation(context.Background(), alice.Kind, alice.Key)
		return err == nil
	})
	waitFor(t, &out, "port49-broker: runner: 1 revocation(s) in broker.state_dir/marks.json were missing from the "+
		"store")
	if _, ok := lifted.Load(alice.Key); ok || !r.marks.Holds(alice.Kind, alice.Key) {
		t.Fatal("a reload after a failed put-back lifted the mark the store lost")
	}
	waitUntil(t, "three rescans", func() bool { return testutil.ToFloat64(rescans) == 3 })
	select {
	case <-r.marksReloaded:
	default:
		t.Fatal("the put-back did not ask the duties to apply what it put back")
	}
}

// A replica that does not run, at its hook, refuses the reload when the
// marks cannot be read, and names the marks it keeps as this replica's,
// with a release that works (final review 7e-1 C-1; Task 14 review I-2;
// the intent of Task 15's interim hook's test, which this hook replaced).
func TestAnIdleReplicasReloadHookRefusesAFailedReadAndNamesWhatItKeeps(t *testing.T) {
	alice := store.Revocation{Kind: store.RevocationPrincipal, Key: "user:alice@example.com", At: time.Unix(10, 0).UTC()}
	carol := store.Revocation{Kind: store.RevocationPrincipal, Key: "user:carol@example.com", At: time.Unix(11, 0).UTC()}
	var out syncBuffer
	e := stderr
	t.Cleanup(func() { stderr = e })
	stderr = &out
	ctx := context.Background()
	c := openMarksCopy(filepath.Join(safeStateDir(t), "marks.json"), &out)
	c.Apply(store.MarkChange{Revocation: alice, Standing: true})
	c.Apply(store.MarkChange{Revocation: carol, Standing: true})
	marks := store.NewMarks()
	marks.Set(alice, true)
	marks.Set(carol, true)
	mem := memory.New(time.Now)
	if err := mem.PutRevocation(ctx, carol); err != nil { // the restore lost alice's
		t.Fatal(err)
	}
	rescans := prometheus.NewCounter(prometheus.CounterOpts{Name: "rescans"})
	r := &runner{cfg: config.Config{Stores: config.StoresConfig{Session: config.StoreConfig{Etcd: &config.EtcdConfig{BulkTimeout: time.Second}}}},
		st: refusingRevocations{mem}, copy: c, marks: marks, marksReloaded: make(chan struct{}, 1)}
	if err := r.reloadHook(ctx, rescans)(); err == nil {
		t.Fatal("a read that failed did not refuse the reload")
	}
	r.st = mem
	hook := r.reloadHook(ctx, rescans)
	if err := hook(); err != nil {
		t.Fatal(err)
	}
	if err := hook(); err != nil { // the same set again: said once
		t.Fatal(err)
	}
	const line = "port49-broker: store: 1 revocation(s) this replica enforces are missing from the store as its " +
		"marks feed reloads"
	if s := out.String(); strings.Count(s, line) != 1 || !strings.HasSuffix(s, "revoke it again on "+
		"port49-broker, then lift it with port49 revoke --lift): principal user:alice@example.com\n") ||
		strings.Contains(s, "or restart this replica") {
		t.Fatalf("said %q", s)
	}
	if _, err := store.LoadMarks(ctx, &storeFeed{st: mem}, marks, nil); err != nil {
		t.Fatal(err)
	}
	if !marks.Holds(alice.Kind, alice.Key) || !marks.Holds(carol.Kind, carol.Key) {
		t.Fatalf("the reload lifted a kept mark: %+v", marks.All())
	}
	if n := testutil.ToFloat64(rescans); n != 3 {
		t.Fatalf("counted %v rescans, want 3", n)
	}
}

// putsFailOnce is a store whose first PutRevocation fails unavailable, as
// the broker's guarded store does with its Token circuit open through a
// restore (re-review 1 C-2).
type putsFailOnce struct {
	store.Store
	failed atomic.Bool
}

func (p *putsFailOnce) PutRevocation(ctx context.Context, r store.Revocation) error {
	if p.failed.CompareAndSwap(false, true) {
		return store.ErrUnavailable
	}
	return p.Store.PutRevocation(ctx, r)
}

// storeFeed is a store.MarkFeed over st's marks, at revision 1, whose
// first compacted watches return store.ErrCompacted; later ones wait for
// ctx.
type storeFeed struct {
	st        store.Store
	compacted atomic.Int32
}

func (f *storeFeed) Revocations(ctx context.Context) (uint64, []store.Revocation, error) {
	rs, err := f.st.ListRevocations(ctx)
	return 1, rs, err
}

func (f *storeFeed) WatchRevocations(ctx context.Context, _ uint64, _ func(store.Revocation, bool, uint64),
	_ func(uint64)) error {
	if f.compacted.Add(-1) >= 0 {
		return store.ErrCompacted
	}
	<-ctx.Done()
	return ctx.Err()
}

// meta/purged is written over the witness the purge read, so a purge that
// finished on the store before a restore cannot release port49d's guard
// on the store after it: a refused write says so and writes nothing
// (Task 15d review M-2).
func TestAPurgeDoneOnAnotherStoreWritesNoPurgeRecord(t *testing.T) {
	f := splitFleet(t)
	ctx := context.Background()
	bs, _ := openBrokerFor(t, ctx, f.broker, metrics.New(prometheus.NewRegistry()), io.Discard)
	var out syncBuffer
	e := stderr
	t.Cleanup(func() { stderr = e })
	stderr = &out
	w, err := bs.raw.PutWitness(ctx, "runner-a", 0)
	if err != nil || w == 0 {
		t.Fatalf("%d %v", w, err)
	}
	r := &runner{raw: bs.raw, who: "runner-a"}
	if _, err := r.markPurged(ctx, w+1); err != nil { // the witness the purge read, not the store's
		t.Fatal(err)
	}
	if got, err := bs.raw.RestoreRead(ctx); err != nil || got.Purged != 0 {
		t.Fatalf("a purge read at another witness wrote meta/purged: %+v %v", got, err)
	}
	if !strings.Contains(out.String(), "meta/purged is not written") {
		t.Fatalf("a refused meta/purged was not said: %q", out.String())
	}
	if ok, err := r.markPurged(ctx, w); err != nil || !ok {
		t.Fatal(err)
	}
	if got, err := bs.raw.RestoreRead(ctx); err != nil || got.Purged == 0 {
		t.Fatalf("a purge read at the store's witness left no meta/purged: %+v %v", got, err)
	}
}
