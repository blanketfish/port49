package port49d

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/policy"
	"github.com/rhwendt/port49/internal/session"
	"github.com/rhwendt/port49/internal/store"
	etcdstore "github.com/rhwendt/port49/internal/store/etcd"
)

// hangingContexts holds the first context read until released, and lands
// a context write only while its ctx lives, as etcd sends nothing on a
// cancelled call; landed counts the writes that landed.
type hangingContexts struct {
	store.Store
	once             sync.Once
	entered, release chan struct{}
	landed           atomic.Int32
}

func (h *hangingContexts) GetContext(ctx context.Context, k store.ContextKey) (store.Context, error) {
	h.once.Do(func() { close(h.entered); <-h.release })
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

func (m *metaOf) PutJudged(ctx context.Context, bundle string, raw []byte) error {
	if m.hold != nil {
		select {
		case <-m.hold:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	m.mu.Lock()
	m.judged = append(m.judged, bundle)
	m.mu.Unlock()
	if m.inner == nil {
		return nil
	}
	return m.inner.PutJudged(ctx, bundle, raw)
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
	_, release, err := other.raw.Hold(hctx, cfg.Store.Etcd.HoldTTL, r.who, func(string) {})
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
