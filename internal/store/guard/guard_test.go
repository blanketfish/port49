package guard

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/etcd"
	"github.com/rhwendt/port49/internal/store/etcd/etcdtest"
	"github.com/rhwendt/port49/internal/store/memory"
	"github.com/rhwendt/port49/internal/store/storetest"
)

func testMetrics() Metrics {
	return Metrics{
		Calls:   prometheus.NewCounterVec(prometheus.CounterOpts{Name: "c"}, []string{"component", "pool", "outcome"}),
		Seconds: prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "s"}, []string{"component", "pool"}),
		Open:    prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "o"}, []string{"component", "pool"}),
	}
}

// stuck is a store whose GetContext, PutToken and ActivePrincipals answer
// as the test says: with err, after delay or at their context's end,
// whichever is first; and GetContext alone, while hold is set, only once
// hold is closed, whatever its context says (pre-flight I11): a call the
// guard's deadline cannot end, which holds its slot.
type stuck struct {
	store.Store
	mu    sync.Mutex
	err   error
	delay time.Duration
	hold  chan struct{}
	calls int
}

func (s *stuck) do(ctx context.Context, holdable bool) error {
	s.mu.Lock()
	s.calls++
	err, delay, hold := s.err, s.delay, s.hold
	s.mu.Unlock()
	if holdable && hold != nil {
		<-hold
		return err
	}
	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return err
}

func (s *stuck) GetContext(ctx context.Context, _ store.ContextKey) (store.Context, error) {
	return store.Context{}, s.do(ctx, true)
}

func (s *stuck) PutToken(ctx context.Context, _ store.TokenKey, _ store.Token) (int, error) {
	return 0, s.do(ctx, false)
}

func (s *stuck) ActivePrincipals(ctx context.Context) ([]string, error) { return nil, s.do(ctx, false) }

func (s *stuck) set(err error, delay time.Duration) {
	s.mu.Lock()
	s.err, s.delay = err, delay
	s.mu.Unlock()
}

func (s *stuck) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

type told struct {
	mu    sync.Mutex
	lines []string
}

func (t *told) add(l string) { t.mu.Lock(); t.lines = append(t.lines, l); t.mu.Unlock() }
func (t *told) all() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]string(nil), t.lines...)
}

func config(said, gone *told) Config {
	return Config{Component: "daemon", CallTimeout: 50 * time.Millisecond, BulkTimeout: time.Second,
		MaxInFlight: map[Pool]int{Token: 2, Context: 2, Bulk: 1}, Failures: 3, OpenFor: 100 * time.Millisecond,
		StopAfter: time.Hour, Unhealthy: gone.add, Now: time.Now, Metrics: testMetrics(), Say: said.add}
}

var k = store.ContextKey{NAS: "leaf-01", Username: "alice"}

// A call the store does not answer within call_timeout is
// store.ErrUnavailable at the deadline, never later (Ruling 8).
func TestACallPastItsTimeoutIsUnavailable(t *testing.T) {
	var said, gone told
	g := Wrap(&stuck{delay: time.Hour}, config(&said, &gone))
	start := time.Now()
	_, err := g.GetContext(context.Background(), k)
	if !errors.Is(err, store.ErrUnavailable) || time.Since(start) > 500*time.Millisecond {
		t.Fatalf("%v after %v", err, time.Since(start))
	}
}

// After Failures consecutive failures a pool's circuit opens: calls fail
// at once without reaching the store, the line says so, and the gauge is
// 1; after OpenFor one probe goes through, and its success closes it.
func TestTheCircuitOpensAfterFailuresAndProbes(t *testing.T) {
	var said, gone told
	inner := &stuck{err: store.ErrUnavailable}
	c := config(&said, &gone)
	g := Wrap(inner, c)
	for i := 0; i < 3; i++ {
		g.GetContext(context.Background(), k)
	}
	before := inner.count()
	start := time.Now()
	if _, err := g.GetContext(context.Background(), k); !errors.Is(err, store.ErrUnavailable) || inner.count() != before ||
		time.Since(start) > 10*time.Millisecond {
		t.Fatalf("an open circuit reached the store or waited: %v, %d calls, %v", err, inner.count()-before, time.Since(start))
	}
	if v := testutil.ToFloat64(c.Metrics.Open.WithLabelValues("daemon", "context")); v != 1 {
		t.Fatalf("circuit gauge %v", v)
	}
	if l := said.all(); len(l) != 1 || !strings.Contains(l[0], "context pool's circuit is open after 3 consecutive failures") {
		t.Fatalf("said %q", l)
	}
	// The token pool is its own: still closed.
	if _, err := g.PutToken(context.Background(), store.TokenKey{}, store.Token{}); !errors.Is(err, store.ErrUnavailable) ||
		inner.count() != before+1 {
		t.Fatalf("the token pool should have reached the store: %v", err)
	}
	time.Sleep(110 * time.Millisecond)
	inner.set(nil, 0)
	if _, err := g.GetContext(context.Background(), k); err != nil {
		t.Fatalf("the probe: %v", err)
	}
	if v := testutil.ToFloat64(c.Metrics.Open.WithLabelValues("daemon", "context")); v != 0 || len(said.all()) != 2 ||
		!strings.Contains(said.all()[1], "closed") {
		t.Fatalf("after a good probe: gauge %v, said %q", v, said.all())
	}
}

// A failed probe opens the circuit again for OpenFor.
func TestAFailedProbeOpensItAgain(t *testing.T) {
	var said, gone told
	inner := &stuck{err: store.ErrUnavailable}
	g := Wrap(inner, config(&said, &gone))
	for i := 0; i < 3; i++ {
		g.GetContext(context.Background(), k)
	}
	time.Sleep(110 * time.Millisecond)
	g.GetContext(context.Background(), k) // the probe, failing
	before := inner.count()
	g.GetContext(context.Background(), k)
	if inner.count() != before {
		t.Fatal("a failed probe left the circuit closed")
	}
}

// Not found, a conflict, past-grace and a refusal are answers, never
// failures: a thousand of them never open the circuit.
func TestAnswersNeverTripIt(t *testing.T) {
	var said, gone told
	for _, err := range []error{store.ErrNotFound, store.ErrConflict, store.ErrPastGrace, store.ErrRefused} {
		inner := &stuck{err: err}
		g := Wrap(inner, config(&said, &gone))
		for i := 0; i < 1000; i++ {
			g.GetContext(context.Background(), k)
		}
		if inner.count() != 1000 {
			t.Fatalf("%v opened the circuit", err)
		}
	}
}

// A caller that goes away (a device's connection dropping mid-call) is
// not the store failing: the circuit does not count it, and its slot is
// given back (Review Focus 7).
func TestACallerThatGoesAwayIsNotAFailure(t *testing.T) {
	var said, gone told
	inner := &stuck{delay: time.Hour}
	c := config(&said, &gone)
	c.CallTimeout, c.Failures = time.Hour, 1
	g := Wrap(inner, c)
	for i := 0; i < 5; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		time.AfterFunc(10*time.Millisecond, cancel)
		_, err := g.GetContext(ctx, k)
		if !errors.Is(err, context.Canceled) || errors.Is(err, store.ErrUnavailable) {
			t.Fatalf("a caller that went away: %v", err)
		}
	}
	if v := testutil.ToFloat64(c.Metrics.Open.WithLabelValues("daemon", "context")); v != 0 || inner.count() != 5 {
		t.Fatalf("the caller's going away opened the circuit (%v) or held slots (%d calls)", v, inner.count())
	}
}

// A caller's deadline that strikes mid-call (a packet's
// store.packet_deadline, on the daemon) is the store too slow for it: it
// is counted, as outcome deadline, and enough of them open the circuit
// even though no call reached call_timeout (pre-flight I10).
func TestACallersDeadlineIsAFailure(t *testing.T) {
	var said, gone told
	inner := &stuck{delay: time.Hour}
	c := config(&said, &gone)
	c.CallTimeout = time.Hour
	g := Wrap(inner, c)
	for i := 0; i < 3; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		g.GetContext(ctx, k)
		cancel()
	}
	if v := testutil.ToFloat64(c.Metrics.Open.WithLabelValues("daemon", "context")); v != 1 {
		t.Fatalf("three callers' deadlines left the circuit closed (%v)", v)
	}
	if n := testutil.ToFloat64(c.Metrics.Calls.WithLabelValues("daemon", "context", "deadline")); n != 3 {
		t.Fatalf("deadline outcomes: %v", n)
	}
}

// A store slow but alive: every call is cut by its caller's deadline, the
// circuit opens, every probe fails as slowly, and once the circuit has
// stayed open for StopAfter the guard says so, once (Ruling 8; Ruling 11;
// pre-flight I10).
func TestASlowStoreGoesDark(t *testing.T) {
	var said, gone told
	inner := &stuck{delay: 40 * time.Millisecond}
	c := config(&said, &gone)
	c.Failures, c.OpenFor, c.StopAfter = 2, 50*time.Millisecond, 300*time.Millisecond
	g := Wrap(inner, c)
	deadline := time.Now().Add(3 * time.Second)
	for len(gone.all()) == 0 && time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
		g.GetContext(ctx, k)
		cancel()
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond) // more calls must not say it again
	g.GetContext(context.Background(), k)
	if l := gone.all(); len(l) != 1 || !strings.Contains(l[0], "context pool's circuit has been open for") {
		t.Fatalf("told %q", l)
	}
}

// A store that refuses every call (the daemon's role revoked at runtime)
// never opens a circuit, but once a steady run of refusals has lasted
// StopAfter the guard says so. An answer in between starts the count
// again (pre-flight I10). So does a gap longer than OpenFor: two refusals
// far apart are not a store refusing (re-check R-I5).
func TestRefusalsGoDark(t *testing.T) {
	var said, gone told
	c := config(&said, &gone) // Failures 3, OpenFor 100ms
	c.StopAfter = 200 * time.Millisecond
	// Four refusals, more than Failures, over more than StopAfter: only
	// the gaps between them keep them from going dark.
	sparse := Wrap(&stuck{err: store.ErrRefused}, c)
	for i := 0; i < 4; i++ {
		if i > 0 {
			time.Sleep(150 * time.Millisecond)
		}
		sparse.GetContext(context.Background(), k)
	}
	if l := gone.all(); len(l) != 0 {
		t.Fatalf("refusals with gaps past OpenFor went dark: %q", l)
	}
	inner := &stuck{err: store.ErrRefused}
	g := Wrap(inner, c)
	steady := func(d time.Duration) {
		for end := time.Now().Add(d); time.Now().Before(end); time.Sleep(20 * time.Millisecond) {
			g.GetContext(context.Background(), k)
		}
	}
	steady(150 * time.Millisecond)
	inner.set(nil, 0)
	g.GetContext(context.Background(), k) // an answer: the count starts again
	inner.set(store.ErrRefused, 0)
	steady(150 * time.Millisecond)
	if l := gone.all(); len(l) != 0 {
		t.Fatalf("an answer did not restart the count: %q", l)
	}
	steady(100 * time.Millisecond)
	if l := gone.all(); len(l) != 1 || !strings.Contains(l[0], "refused") {
		t.Fatalf("told %q", l)
	}
	if v := testutil.ToFloat64(c.Metrics.Open.WithLabelValues("daemon", "context")); v != 0 {
		t.Fatal("refusals opened the circuit")
	}
}

// The bulk pool's circuit, open for StopAfter, is said and gauged and
// never takes port49d dark: a slow scan is not a store gone while the
// hot pools answer (re-check R-I5).
func TestTheBulkPoolNeverGoesDark(t *testing.T) {
	var said, gone told
	c := config(&said, &gone)
	c.StopAfter = 100 * time.Millisecond
	g := Wrap(&stuck{err: store.ErrUnavailable}, c)
	for end := time.Now().Add(400 * time.Millisecond); time.Now().Before(end); time.Sleep(20 * time.Millisecond) {
		g.ActivePrincipals(context.Background())
	}
	if l := gone.all(); len(l) != 0 {
		t.Fatalf("the bulk pool took port49d dark: %q", l)
	}
	if testutil.ToFloat64(c.Metrics.Open.WithLabelValues("daemon", "bulk")) != 1 ||
		len(said.all()) == 0 || !strings.Contains(said.all()[0], "bulk pool's circuit is open") {
		t.Fatalf("the bulk circuit was not alarmed: said %q", said.all())
	}
}

// A pool's slots are its own: with every context slot held by a call the
// store does not answer, a further context call is refused at its
// deadline without reaching the store, and a token call and a bulk call
// are served (pre-flight I11, I14).
func TestPoolsAreSeparate(t *testing.T) {
	var said, gone told
	inner := &stuck{hold: make(chan struct{})}
	c := config(&said, &gone)
	c.CallTimeout, c.Failures = 300*time.Millisecond, 100
	g := Wrap(inner, c)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); g.GetContext(context.Background(), k) }()
	}
	eventually(t, "both context slots held", func() bool { return inner.count() == 2 })
	start := time.Now()
	if _, err := g.GetContext(context.Background(), k); !errors.Is(err, store.ErrUnavailable) ||
		time.Since(start) < 250*time.Millisecond || inner.count() != 2 {
		t.Fatalf("a third context call with both slots held: %v after %v, %d calls", err, time.Since(start), inner.count())
	}
	if _, err := g.PutToken(context.Background(), store.TokenKey{}, store.Token{}); err != nil {
		t.Fatalf("a token call while the context pool is full: %v", err)
	}
	if _, err := g.ActivePrincipals(context.Background()); err != nil {
		t.Fatalf("a bulk call while the context pool is full: %v", err)
	}
	close(inner.hold)
	wg.Wait()
}

// A caller whose own deadline strikes while it waits for a slot met a full
// pool, not a store that failed: it is saturated, as a call that waited out
// call_timeout is, so the series an operator reads names the cause; and,
// like that call, it opens no circuit.
func TestACallersDeadlineWaitingForASlotIsSaturated(t *testing.T) {
	var said, gone told
	inner := &stuck{hold: make(chan struct{})}
	c := config(&said, &gone)
	c.CallTimeout, c.Failures = time.Hour, 1
	g := Wrap(inner, c)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); g.GetContext(context.Background(), k) }()
	}
	eventually(t, "both context slots held", func() bool { return inner.count() == 2 })
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	_, err := g.GetContext(ctx, k)
	cancel()
	if !errors.Is(err, store.ErrUnavailable) || inner.count() != 2 {
		t.Fatalf("a caller's deadline with both slots held: %v, %d calls", err, inner.count())
	}
	if n := testutil.ToFloat64(c.Metrics.Calls.WithLabelValues("daemon", "context", "saturated")); n != 1 {
		t.Fatalf("saturated outcomes: %v", n)
	}
	if v := testutil.ToFloat64(c.Metrics.Open.WithLabelValues("daemon", "context")); v != 0 {
		t.Fatal("a full pool opened the circuit")
	}
	close(inner.hold)
	wg.Wait()
}

// A caller whose deadline has already passed (a packet whose earlier store
// calls spent store.packet_deadline) is the store too slow for it, on an
// idle pool every time: deadline, counted, never saturated, and it never
// reaches the store (review I1). Enough of them open the circuit.
func TestACallerAlreadyPastItsDeadlineIsADeadline(t *testing.T) {
	var said, gone told
	inner := &stuck{}
	c := config(&said, &gone)
	c.Failures = 1000
	g := Wrap(inner, c)
	past, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	for i := 0; i < 200; i++ {
		if _, err := g.GetContext(past, k); !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, store.ErrUnavailable) {
			t.Fatalf("a call past its deadline: %v", err)
		}
	}
	for _, o := range outcomes {
		want := 0.0
		if o == "deadline" {
			want = 200
		}
		if n := testutil.ToFloat64(c.Metrics.Calls.WithLabelValues("daemon", "context", o)); n != want {
			t.Errorf("outcome %s: %v, want %v", o, n, want)
		}
	}
	if inner.count() != 0 {
		t.Fatalf("%d calls past their deadline reached the store", inner.count())
	}
	c = config(&said, &gone)
	g = Wrap(inner, c)
	for i := 0; i < 3; i++ {
		g.GetContext(past, k)
	}
	if v := testutil.ToFloat64(c.Metrics.Open.WithLabelValues("daemon", "context")); v != 1 {
		t.Fatalf("three calls past their deadline left the circuit closed (%v)", v)
	}
}

// An open circuit that Unhealthy was told about, whose probe is then
// refused, is not told again: the open run and the refused run each tell
// once (review M1).
func TestAnOpenCircuitIsToldOnce(t *testing.T) {
	var said, gone told
	inner := &stuck{err: store.ErrUnavailable}
	c := config(&said, &gone)
	c.OpenFor, c.StopAfter = 20*time.Millisecond, 50*time.Millisecond
	g := Wrap(inner, c)
	for i := 0; i < 3; i++ {
		g.GetContext(context.Background(), k)
	}
	time.Sleep(60 * time.Millisecond)
	inner.set(store.ErrRefused, 0)
	for i := 0; i < 3; i++ {
		g.GetContext(context.Background(), k) // the first is told; each later one probes, refused
		time.Sleep(25 * time.Millisecond)
	}
	l := gone.all()
	n := 0
	for _, line := range l {
		if strings.Contains(line, "circuit has been open") {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("the open circuit was told %d times: %q", n, l)
	}
}

// A bulk call has its own deadline and circuit: a scan that fails opens
// the bulk pool's, never the context pool's (pre-flight I14).
func TestABulkFailureLeavesTheHotPoolsClosed(t *testing.T) {
	var said, gone told
	inner := &stuck{err: store.ErrUnavailable}
	c := config(&said, &gone)
	g := Wrap(inner, c)
	for i := 0; i < 3; i++ {
		g.ActivePrincipals(context.Background())
	}
	if testutil.ToFloat64(c.Metrics.Open.WithLabelValues("daemon", "bulk")) != 1 ||
		testutil.ToFloat64(c.Metrics.Open.WithLabelValues("daemon", "context")) != 0 {
		t.Fatal("a bulk failure reached the context pool's circuit, or not the bulk pool's")
	}
}

// The guard passes every method through unchanged: every storetest
// property holds through it.
func TestTheGuardHoldsEveryProperty(t *testing.T) {
	storetest.Run(t, storetest.Backend{New: func(t *testing.T, clock func() time.Time) store.Store {
		var said, gone told
		c := config(&said, &gone)
		c.CallTimeout, c.BulkTimeout = 5*time.Second, 5*time.Second
		c.MaxInFlight = map[Pool]int{Token: 64, Context: 64, Bulk: 8}
		return Wrap(memory.New(clock), c)
	}})
}

// On a real etcd losing its quorum, the circuit opens and calls then fail
// at once (spec §14, "Quorum lost").
func TestAGuardedEtcdLosingQuorumOpensItsCircuit(t *testing.T) {
	cl := etcdtest.StartCluster(t)
	s, err := etcd.Open(etcd.Config{Endpoints: cl.Endpoints, Prefix: etcdtest.Prefix()})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var said, gone told
	c := config(&said, &gone)
	c.CallTimeout = 200 * time.Millisecond
	g := Wrap(s, c)
	cl.Stop(1)
	cl.Stop(2)
	for i := 0; i < 3; i++ {
		g.GetContext(context.Background(), k)
	}
	start := time.Now()
	if _, err := g.GetContext(context.Background(), k); !errors.Is(err, store.ErrUnavailable) || time.Since(start) > 20*time.Millisecond {
		t.Fatalf("an open circuit on a lost quorum: %v after %v", err, time.Since(start))
	}
}

// On a real etcd behind a partition (a proxy that stops forwarding and
// closes nothing), each call is store.ErrUnavailable at call_timeout and
// never later, the circuit opens, and once the partition heals the probe
// after OpenFor is answered and closes it (Task 5 review M3).
func TestAGuardedEtcdBehindAHungProxy(t *testing.T) {
	srv := etcdtest.Start(t, etcdtest.Options{})
	p := etcdtest.NewProxy(t, strings.TrimPrefix(srv.Endpoint, "http://"))
	s, err := etcd.Open(etcd.Config{Endpoints: []string{"http://" + p.Addr()}, Prefix: etcdtest.Prefix()})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var said, gone told
	c := config(&said, &gone)
	c.CallTimeout = 200 * time.Millisecond
	g := Wrap(s, c)
	if _, err := g.GetContext(context.Background(), k); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("before the hang: %v", err)
	}
	p.Hang(true)
	for i := 0; i < 3; i++ {
		start := time.Now()
		if _, err := g.GetContext(context.Background(), k); !errors.Is(err, store.ErrUnavailable) ||
			time.Since(start) > 400*time.Millisecond {
			t.Fatalf("a call through a hung proxy: %v after %v", err, time.Since(start))
		}
	}
	if v := testutil.ToFloat64(c.Metrics.Open.WithLabelValues("daemon", "context")); v != 1 {
		t.Fatalf("three timeouts left the circuit closed (%v)", v)
	}
	if n := testutil.ToFloat64(c.Metrics.Calls.WithLabelValues("daemon", "context", "timeout")); n != 3 {
		t.Fatalf("timeout outcomes: %v", n)
	}
	p.Hang(false)
	eventually(t, "a probe answered once the partition healed", func() bool {
		_, err := g.GetContext(context.Background(), k)
		return errors.Is(err, store.ErrNotFound)
	})
	if v := testutil.ToFloat64(c.Metrics.Open.WithLabelValues("daemon", "context")); v != 0 {
		t.Fatalf("an answered probe left the circuit open (%v)", v)
	}
}

// Every store.Store method has a pool, and each guarded method runs in
// the pool PoolOf names: driven through the guard over the memory store
// with zero arguments, each moves exactly that pool's call counter
// (pre-flight M30).
func TestEveryMethodIsRoutedToItsPool(t *testing.T) {
	var said, gone told
	c := config(&said, &gone)
	c.CallTimeout, c.BulkTimeout = 5*time.Second, 5*time.Second
	// WrapRev's is Wrap's with the RevStore twins, which the sealing layer
	// calls in place of their plain methods: each runs in its pool too.
	g := reflect.ValueOf(WrapRev(memory.New(time.Now), c))
	st := reflect.TypeOf((*store.RevStore)(nil)).Elem()
	for i := 0; i < st.NumMethod(); i++ {
		m := st.Method(i)
		// Seen makes no call, so it has no pool and takes no context.
		if m.Name == "Seen" {
			continue
		}
		p := PoolOf(m.Name)
		if p != Token && p != Context && p != Bulk {
			t.Errorf("%s has no pool", m.Name)
			continue
		}
		before := poolCalls(c.Metrics.Calls, p)
		args := []reflect.Value{reflect.ValueOf(context.Background())}
		for j := 1; j < m.Type.NumIn(); j++ {
			args = append(args, reflect.Zero(m.Type.In(j)))
		}
		g.MethodByName(m.Name).Call(args)
		if got := poolCalls(c.Metrics.Calls, p); got != before+1 {
			t.Errorf("%s ran %v calls in the %s pool, want 1", m.Name, got-before, p)
		}
	}
}

func poolCalls(c *prometheus.CounterVec, p Pool) float64 {
	n := 0.0
	for _, o := range outcomes {
		n += testutil.ToFloat64(c.WithLabelValues("daemon", string(p), o))
	}
	return n
}

// revStuck is a RevStore whose GetContext is stuck's, whose Seen is seen,
// and whose Ping answers ping.
type revStuck struct {
	store.RevStore
	s    *stuck
	seen uint64
	ping error
}

func (r *revStuck) GetContext(ctx context.Context, k store.ContextKey) (store.Context, error) {
	return r.s.GetContext(ctx, k)
}
func (r *revStuck) Seen() uint64                   { return r.seen }
func (r *revStuck) Ping(ctx context.Context) error { return r.ping }

// Seen makes no call: it reaches the inner store at once with every
// context slot held, and counts nothing (plan 7e, Ruling 3; pre-flight M15).
func TestSeenPassesThroughWithNoSlot(t *testing.T) {
	var said, gone told
	inner := &revStuck{RevStore: memory.New(time.Now), s: &stuck{hold: make(chan struct{})}, seen: 42}
	c := config(&said, &gone)
	c.CallTimeout, c.MaxInFlight[Context] = time.Hour, 1
	g := WrapRev(inner, c)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); g.GetContext(context.Background(), k) }()
	eventually(t, "the context slot held", func() bool { return inner.s.count() == 1 })
	got := make(chan uint64, 1)
	go func() { got <- g.Seen() }()
	select {
	case n := <-got:
		if n != 42 {
			t.Fatalf("Seen %d through the guard, want the inner's 42", n)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Seen waited for a context slot")
	}
	for _, p := range []Pool{Token, Context, Bulk} {
		if n := poolCalls(c.Metrics.Calls, p); n != 0 {
			t.Errorf("Seen counted %v calls in the %s pool", n, p)
		}
	}
	close(inner.s.hold)
	wg.Wait()
}

// Ping runs in the context pool: a store that does not answer it is one
// context-pool failure, and the token and bulk pools see nothing (plan 7e,
// Ruling 11).
func TestPingIsTheContextPools(t *testing.T) {
	var said, gone told
	c := config(&said, &gone)
	g := WrapRev(&revStuck{RevStore: memory.New(time.Now), ping: store.ErrUnavailable}, c)
	if err := g.Ping(context.Background()); !errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("Ping: %v", err)
	}
	if n := testutil.ToFloat64(c.Metrics.Calls.WithLabelValues("daemon", "context", "unavailable")); n != 1 {
		t.Fatalf("context pool failures: %v", n)
	}
	if poolCalls(c.Metrics.Calls, Context) != 1 || poolCalls(c.Metrics.Calls, Token) != 0 || poolCalls(c.Metrics.Calls, Bulk) != 0 {
		t.Fatal("Ping ran outside the context pool alone")
	}
}
