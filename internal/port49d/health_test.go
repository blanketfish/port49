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
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/rhwendt/port49/internal/daemon/metrics"
	etcdstore "github.com/rhwendt/port49/internal/store/etcd"
	"github.com/rhwendt/port49/internal/store/etcd/etcdtest"
)

// scripted is a check that answers from a script, one entry per call,
// the last entry repeated.
type scripted struct {
	mu    sync.Mutex
	steps []error
	calls int
}

func (s *scripted) check(context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	i := min(s.calls, len(s.steps)-1)
	s.calls++
	return s.steps[i]
}

func testHealth(check func(context.Context) error) *health {
	h := &health{every: 5 * time.Millisecond, timeout: 50 * time.Millisecond, closeAfter: 3, openAfter: 2,
		check: check, m: metrics.New(prometheus.NewRegistry()), state: &healthState{}, out: io.Discard}
	h.state.bind(h.m)
	return h
}

var errCheck = errors.New("no answer")

// close_after failures in a row are a store gone, told once; a pass
// between them starts the count again (Ruling 1; Review Focus 2).
func TestWatchNeedsTheFailuresInARow(t *testing.T) {
	s := &scripted{steps: []error{errCheck, errCheck, nil, errCheck, errCheck, errCheck, nil}}
	h := testHealth(s.check)
	var told atomic.Int32
	var why error
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	h.watch(ctx, func(e error) { told.Add(1); why = e })
	if told.Load() != 1 {
		t.Fatalf("told %d times", told.Load())
	}
	var g *storeGone
	if !errors.As(why, &g) || s.calls != 6 {
		t.Fatalf("gone %v after %d checks, want a storeGone after the sixth", why, s.calls)
	}
	if got := testutil.ToFloat64(h.m.StoreHealthChecks.WithLabelValues("fail")); got != 5 {
		t.Fatalf("failed checks counted %v, want 5", got)
	}
	// The close leaves the gauge at close_after, not 0: the process keeps it.
	if got := testutil.ToFloat64(h.m.StoreHealthFailures); got != 3 {
		t.Fatalf("port49_store_health_failures after the close = %v, want 3", got)
	}
}

// The failure count is the process's, not the run's: a run after a store gone
// builds a new registry, whose gauge reads what the last run left, and the
// passes hold it at close_after until the listeners open (plan 7f, I-1; the
// shape of TestARaisedAlarmIsGaugedWhileTheStoreIsAway). Without this the
// "above 0 for three intervals" alert resolves at the close, with the store
// still down.
func TestTheFailureCountSurvivesTheRunsRegistry(t *testing.T) {
	st := &healthState{}
	first := metrics.New(prometheus.NewRegistry())
	st.bind(first)
	st.set(3) // the watch's close_after-th failure
	next := metrics.New(prometheus.NewRegistry())
	st.bind(next)
	if got := testutil.ToFloat64(next.StoreHealthFailures); got != 3 {
		t.Fatalf("the next run's gauge reads %v, want 3 (the count the last run left)", got)
	}
	st.atLeast(2) // never lowers
	if st.count() != 3 {
		t.Fatalf("atLeast lowered the count to %d", st.count())
	}
	// passes: the gauge reads at least close_after through failures and a pass
	// between them, and 0 only once the listeners may open.
	s := &scripted{steps: []error{errCheck, nil, errCheck, nil, nil}}
	h := &health{every: 5 * time.Millisecond, timeout: 50 * time.Millisecond, closeAfter: 3, openAfter: 2,
		check: s.check, m: next, state: st, out: io.Discard}
	lowest := 1 << 30
	done := make(chan error, 1)
	go func() { done <- h.passes(context.Background()) }()
	for {
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
			if lowest < 3 {
				t.Fatalf("the gauge read %d while the listeners were still closed, under close_after 3", lowest)
			}
			if got := testutil.ToFloat64(next.StoreHealthFailures); got != 0 {
				t.Fatalf("after open_after passes the gauge reads %v, want 0", got)
			}
			return
		default:
			lowest = min(lowest, int(testutil.ToFloat64(next.StoreHealthFailures)))
			time.Sleep(time.Millisecond)
		}
	}
}

// passes returns once open_after checks pass in a row; a failure starts
// the count again (Review Focus 2).
func TestPassesNeedsThePassesInARow(t *testing.T) {
	s := &scripted{steps: []error{nil, errCheck, nil, errCheck, nil, nil}}
	h := testHealth(s.check)
	if err := h.passes(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s.calls != 6 {
		t.Fatalf("passes returned after %d checks, want 6", s.calls)
	}
}

// A check that never returns is a failure at the timeout, not a hang
// of the watch.
func TestAHungCheckFailsAtItsTimeout(t *testing.T) {
	h := testHealth(func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() })
	start := time.Now()
	gone := make(chan struct{})
	go h.watch(context.Background(), func(error) { close(gone) })
	select {
	case <-gone:
	case <-time.After(5 * time.Second):
		t.Fatal("a hung check never went dark")
	}
	if d := time.Since(start); d < 3*h.timeout {
		t.Fatalf("dark after %v, under three timeouts", d)
	}
}

// passes ends with ctx (Review Focus 5's unit).
func TestPassesEndsWithItsContext(t *testing.T) {
	h := testHealth(func(context.Context) error { return errCheck })
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(50 * time.Millisecond); cancel() }()
	if err := h.passes(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("%v", err)
	}
}

// Either connection failing fails the check (Review Focus 1).
func TestACheckFailsWhenEitherPoolFails(t *testing.T) {
	for _, c := range []struct {
		name     string
		ctx, tok error
	}{{"the context pool", errCheck, nil}, {"the token pool", nil, errCheck}} {
		check := storeCheck(pinger{c.ctx}, tokPinger{c.tok})
		if err := check(context.Background()); err == nil {
			t.Errorf("%s failing passed the check", c.name)
		}
	}
	if err := storeCheck(pinger{}, tokPinger{})(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// pinger and tokPinger are structs: Go allows no methods on a named
// interface type such as `type pinger error`.
type pinger struct{ err error }

func (p pinger) Ping(context.Context) error { return p.err }

type tokPinger struct{ err error }

func (p tokPinger) PingToken(context.Context) error { return p.err }

// A killed etcd leader does not fail close_after checks in a row at the
// default interval (Ruling 3, the default's tested reason): an election
// must not close the listeners. If this fails, the run it found goes to
// Ryan with OR-1; the default is not raised quietly.
func TestAKilledLeaderDoesNotFailFiveChecksInARow(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the default interval for 15s")
	}
	c := etcdtest.StartCluster(t)
	d, err := etcdstore.Open(etcdstore.Config{Endpoints: c.Endpoints})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	check := storeCheck(d, d)
	for i := 0; i < 3; i++ { // both connections up before the kill
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		if err := check(ctx); err != nil {
			t.Fatalf("before the kill: %v", err)
		}
		cancel()
	}
	c.Kill(c.Leader(t))
	run, worst := 0, 0
	for end := time.Now().Add(15 * time.Second); time.Now().Before(end); time.Sleep(time.Second) {
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		err := check(ctx)
		cancel()
		if err != nil {
			run++
		} else {
			run = 0
		}
		worst = max(worst, run)
	}
	t.Logf("the longest run of failed checks after the leader was killed: %d", worst)
	if worst >= 5 {
		t.Fatalf("%d failed checks in a row after a leader was killed: the default close_after (5) would close the "+
			"listeners on an election; report to Ryan (OR-1), do not raise the default", worst)
	}
}

// A hung minority member, with quorum healthy, does not fail close_after
// checks in a row either (Ruling 3, the default's second tested reason; the
// commoner bad day than a crashed leader): one member wedged, defragmenting
// or partitioned with its TCP connection alive. clientv3 balances reads
// round-robin and each check reads on two clients, so many checks land a read
// on that member; every replica sees the same member, so a long run would take
// the whole fleet dark while etcd has quorum. A proxy in front of one
// member's client endpoint holds its bytes. The test measures: a run of 5 or
// more is the finding (report it to Ryan with OR-1, do not raise the default
// and do not rerun it into passing).
func TestAHungMinorityMemberDoesNotFailFiveChecksInARow(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the default interval for 20s")
	}
	c := etcdtest.StartCluster(t)
	p := etcdtest.NewProxy(t, strings.TrimPrefix(c.Endpoints[0], "http://"))
	d, err := etcdstore.Open(etcdstore.Config{Endpoints: []string{"http://" + p.Addr(), c.Endpoints[1], c.Endpoints[2]}})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	check := storeCheck(d, d)
	for i := 0; i < 3; i++ { // both connections up before the hang
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		if err := check(ctx); err != nil {
			t.Fatalf("before the hang: %v", err)
		}
		cancel()
	}
	p.Hang(true)
	run, worst, failed, total := 0, 0, 0, 0
	for end := time.Now().Add(20 * time.Second); time.Now().Before(end); time.Sleep(time.Second) { // the default interval, and call_timeout
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		err := check(ctx)
		cancel()
		total++
		if err != nil {
			run++
			failed++
		} else {
			run = 0
		}
		worst = max(worst, run)
	}
	t.Logf("with one member hung: %d of %d checks failed, the longest run %d", failed, total, worst)
	if worst >= 5 {
		t.Fatalf("%d failed checks in a row with one member hung and quorum healthy: the default close_after (5) "+
			"would take every replica dark with etcd up; report to Ryan (OR-1), do not raise the default", worst)
	}
}
