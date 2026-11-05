package guard

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/blanketfish/port49/internal/store"
	"github.com/blanketfish/port49/internal/store/etcd"
	"github.com/blanketfish/port49/internal/store/etcd/etcdtest"
	"github.com/blanketfish/port49/internal/store/memory"
	"github.com/blanketfish/port49/internal/store/storetest"
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
	return Config{Proc: "port49d", Component: "daemon", CallTimeout: 50 * time.Millisecond, BulkTimeout: time.Second,
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
	if errors.Is(err, store.ErrNotSent) { // it was sent: its write may land
		t.Fatalf("a call that reached the store is classed not sent: %v", err)
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
	if _, err := g.GetContext(context.Background(), k); !errors.Is(err, store.ErrUnavailable) || !errors.Is(err, store.ErrNotSent) || inner.count() != before ||
		time.Since(start) > 10*time.Millisecond {
		t.Fatalf("an open circuit reached the store or waited: %v, %d calls, %v", err, inner.count()-before, time.Since(start))
	}
	if v := testutil.ToFloat64(c.Metrics.Open.WithLabelValues("daemon", "context")); v != 1 {
		t.Fatalf("circuit gauge %v", v)
	}
	if l := said.all(); len(l) != 1 || !strings.Contains(l[0], "context pool's circuit is open after 3 consecutive failures") {
		t.Fatalf("said %q", l)
	}
	// The line names the calls that fed the run, so an operator sees which op failed.
	if l := said.all(); !strings.Contains(l[0], "by call: GetContext 3") {
		t.Fatalf("the open line does not name the failing calls: %q", l)
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
// packet_deadline, on the daemon) is the store too slow for it: it
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
	if !errors.Is(err, store.ErrUnavailable) || !errors.Is(err, store.ErrNotSent) || inner.count() != 2 {
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

// A call that arrives past its deadline was spent by the caller's earlier
// calls, not by this one: deadline_on_entry, counted apart, never saturated,
// never sent, and never a failure of the pool's circuit (decision 56 ruling 8,
// reversing review I1; stores I3).
func TestACallArrivingPastItsDeadlineDoesNotOpenTheCircuit(t *testing.T) {
	var said, gone told
	inner := &stuck{}
	c := config(&said, &gone)
	c.Failures = 5
	g := Wrap(inner, c)
	past, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	for i := 0; i < 200; i++ {
		if _, err := g.GetContext(past, k); !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, store.ErrUnavailable) || !errors.Is(err, store.ErrNotSent) {
			t.Fatalf("a call past its deadline: %v", err)
		}
	}
	for _, o := range outcomes {
		want := 0.0
		if o == "deadline_on_entry" {
			want = 200
		}
		if n := testutil.ToFloat64(c.Metrics.Calls.WithLabelValues("daemon", "context", o)); n != want {
			t.Errorf("outcome %s: %v, want %v", o, n, want)
		}
	}
	if inner.count() != 0 {
		t.Fatalf("%d calls past their deadline reached the store", inner.count())
	}
	if v := testutil.ToFloat64(c.Metrics.Open.WithLabelValues("daemon", "context")); v != 0 {
		t.Fatalf("200 calls past their deadline opened the circuit (%v)", v)
	}
	if l := said.all(); len(l) != 0 {
		t.Fatalf("said %q", l)
	}
}

// A deadline that strikes inside the store is the store too slow for the
// caller: it still counts, and opens the circuit.
func TestADeadlineStruckMidCallStillCounts(t *testing.T) {
	var said, gone told
	inner := &stuck{delay: time.Hour}
	c := config(&said, &gone)
	c.Failures, c.CallTimeout = 5, time.Hour
	g := Wrap(inner, c)
	for i := 0; i < 5; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		g.GetContext(ctx, k)
		cancel()
	}
	if v := testutil.ToFloat64(c.Metrics.Open.WithLabelValues("daemon", "context")); v != 1 {
		t.Fatalf("five deadlines struck mid-call left the circuit closed (%v)", v)
	}
	if n := testutil.ToFloat64(c.Metrics.Calls.WithLabelValues("daemon", "context", "deadline")); n != 5 {
		t.Fatalf("deadline outcomes: %v", n)
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

// Every store.Enrollments method runs in the pool PoolOf names, as the
// store's do: Export, Import and the principals list in the bulk pool, the
// rest in the token pool (plan 9e, Task 4).
func TestEveryEnrollmentMethodIsRoutedToItsPool(t *testing.T) {
	var said, gone told
	c := config(&said, &gone)
	c.CallTimeout, c.BulkTimeout = 5*time.Second, 5*time.Second
	g := reflect.ValueOf(WrapEnrollments(memory.NewEnrollments(time.Now), c))
	et := reflect.TypeOf((*store.Enrollments)(nil)).Elem()
	for i := 0; i < et.NumMethod(); i++ {
		m := et.Method(i)
		p := PoolOf(m.Name)
		if p != Token && p != Context && p != Bulk {
			t.Errorf("%s has no pool", m.Name)
			continue
		}
		if want := map[string]Pool{"SecondFactorPrincipals": Bulk, "Export": Bulk, "Import": Bulk}[m.Name]; want != "" && p != want {
			t.Errorf("%s is in the %s pool, want %s", m.Name, p, want)
		} else if want == "" && p != Token {
			t.Errorf("%s is in the %s pool, want token", m.Name, p)
		}
		before := componentCalls(c.Metrics.Calls, "daemon_enrollments", p)
		args := []reflect.Value{reflect.ValueOf(context.Background())}
		for j := 1; j < m.Type.NumIn(); j++ {
			args = append(args, reflect.Zero(m.Type.In(j)))
		}
		g.MethodByName(m.Name).Call(args)
		if got := componentCalls(c.Metrics.Calls, "daemon_enrollments", p); got != before+1 {
			t.Errorf("%s ran %v calls in the %s pool, want 1", m.Name, got-before, p)
		}
	}
}

// downEnrollments is an enrollment store that does not answer.
type downEnrollments struct{ store.Enrollments }

func (downEnrollments) GetEnrollmentMark(context.Context) (store.EnrollmentMark, error) {
	return store.EnrollmentMark{}, store.ErrUnavailable
}

// The enrollment guard's circuit is its own series: tripping it moves
// "<component>_enrollments", never the store guard's gauge, and the line
// says what it means for sign-in (plan 9e, Task 4 review I4).
func TestTheEnrollmentCircuitHasItsOwnComponent(t *testing.T) {
	var said, gone told
	c := config(&said, &gone)
	c.Component = "broker"
	g := WrapEnrollments(downEnrollments{memory.NewEnrollments(time.Now)}, c)
	for i := 0; i < 3; i++ {
		g.GetEnrollmentMark(context.Background())
	}
	if v := testutil.ToFloat64(c.Metrics.Open.WithLabelValues("broker_enrollments", "token")); v != 1 {
		t.Fatalf("the enrollment circuit's gauge is %v", v)
	}
	if v := testutil.ToFloat64(c.Metrics.Open.WithLabelValues("broker", "token")); v != 0 {
		t.Fatalf("the store's gauge moved: %v", v)
	}
	if l := said.all(); len(l) != 1 || !strings.Contains(l[0], "the broker_enrollments's token pool") ||
		!strings.Contains(l[0], "password sign-in") {
		t.Fatalf("said %q", l)
	}
}

// The guard passes every enrollment method through unchanged.
func TestTheGuardHoldsEveryEnrollmentProperty(t *testing.T) {
	storetest.RunEnrollments(t, storetest.EnrollmentsBackend{
		New: func(t *testing.T, clock func() time.Time) store.Enrollments {
			var said, gone told
			c := config(&said, &gone)
			c.CallTimeout, c.BulkTimeout = 5*time.Second, 5*time.Second
			return WrapEnrollments(memory.NewEnrollments(clock), c)
		}})
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

func poolCalls(c *prometheus.CounterVec, p Pool) float64 { return componentCalls(c, "daemon", p) }

func componentCalls(c *prometheus.CounterVec, component string, p Pool) float64 {
	n := 0.0
	for _, o := range outcomes {
		n += testutil.ToFloat64(c.WithLabelValues(component, string(p), o))
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

// Each circuit line begins with its process's name, and only a guard that
// ends its process's run says the process closes its listeners:
// port49-broker's never does (Task 15a C1).
func TestTheCircuitsLinesNameTheirProcess(t *testing.T) {
	for _, tc := range []struct {
		proc, component string
		stopAfter       time.Duration
		closes          bool
		impact          string
	}{
		{"port49d", "daemon", time.Hour, true, "devices see store_unavailable, and break-glass is refused (L4)"},
		// The broker's pools serve the API: devices and break-glass are
		// port49d's (Task 15a review M-4).
		{"port49-broker", "broker", 0, false, "mints, refreshes and revocations through it fail"},
	} {
		var said, gone told
		c := config(&said, &gone)
		c.Proc, c.Component, c.StopAfter = tc.proc, tc.component, tc.stopAfter
		g := Wrap(&stuck{err: store.ErrUnavailable}, c)
		for i := 0; i < 3; i++ {
			g.GetContext(context.Background(), k)
		}
		l := said.all()
		if len(l) != 1 || !strings.HasPrefix(l[0], tc.proc+": store: the "+tc.component+"'s context pool's circuit "+
			"is open") || strings.Contains(l[0], "closes its listeners") != tc.closes ||
			!strings.Contains(l[0], "succeeds; "+tc.impact) || (tc.component == "broker" &&
			(strings.Contains(l[0], "break-glass") || strings.Contains(l[0], "devices"))) {
			t.Fatalf("%s: said %q", tc.proc, l)
		}
	}
}

// A directory store of its own is named by its lines (plan 11a): the noun
// after the process, and, where the guard ends the run, the key it names.
func TestTheCircuitsLinesNameTheirStore(t *testing.T) {
	for _, tc := range []struct{ store, key, wantNoun, wantKey string }{
		{"", "", "port49d: store: the", "etcd.hold_ttl"},
		{"directory store", "stores.session.etcd.hold_ttl", "port49d: directory store: the", "stores.session.etcd.hold_ttl"},
	} {
		var said, gone told
		c := config(&said, &gone)
		c.Store, c.HoldTTLKey = tc.store, tc.key
		g := Wrap(&stuck{err: store.ErrUnavailable}, c)
		for i := 0; i < 3; i++ {
			g.GetContext(context.Background(), k)
		}
		l := said.all()
		if len(l) != 1 || !strings.HasPrefix(l[0], tc.wantNoun) || !strings.Contains(l[0], "if the store is gone for "+tc.wantKey) {
			t.Fatalf("%q: said %q", tc.store, l)
		}
	}
}

// feedBehind is a store whose GetContext waits for its context to end and
// then says why, as crypt.Fenced does when its feed has not arrived.
type feedBehind struct {
	store.Store
	why error
}

func (f feedBehind) GetContext(ctx context.Context, _ store.ContextKey) (store.Context, error) {
	<-ctx.Done()
	return store.Context{}, fmt.Errorf("%w: the feed is behind", f.why)
}

// A guarded timeout is store.ErrUnavailable and still wraps what the inner call
// said (plan 7f, I-2): the context cache reads store.ErrFeedBehind through it
// to tell a fence timeout, where etcd answered, from an outage. It is still
// counted a timeout.
func TestAGuardedTimeoutKeepsTheInnerError(t *testing.T) {
	var said, gone told
	errInner := errors.New("inner")
	c := config(&said, &gone)
	g := Wrap(feedBehind{why: errInner}, c)
	_, err := g.GetContext(context.Background(), k)
	if !errors.Is(err, store.ErrUnavailable) || !errors.Is(err, errInner) {
		t.Fatalf("a guarded timeout: %v, want ErrUnavailable wrapping the inner error", err)
	}
	if n := testutil.ToFloat64(c.Metrics.Calls.WithLabelValues("daemon", "context", "timeout")); n != 1 {
		t.Fatalf("timeout outcomes: %v, want 1", n)
	}
}

// fenceTimeout answers a context read, after the call's deadline, as the fence
// does when this process's feed has not reached the record's revision.
type fenceTimeout struct{ store.Store }

func (fenceTimeout) GetContext(ctx context.Context, _ store.ContextKey) (store.Context, error) {
	<-ctx.Done()
	return store.Context{}, fmt.Errorf("%w (the feed at revision 332, the record at 346)", store.ErrFeedBehind)
}

// A fence timeout is the store having answered with a record this process's
// feed has not reached, not a failed store call: it does not count toward the
// circuit however many there are (the health check handles a feed that is
// behind), and is counted as its own outcome.
func TestAFenceTimeoutDoesNotOpenTheCircuit(t *testing.T) {
	var said, gone told
	c := config(&said, &gone)
	g := Wrap(fenceTimeout{}, c)
	for i := 0; i < 3*c.Failures; i++ {
		if _, err := g.GetContext(context.Background(), k); !errors.Is(err, store.ErrFeedBehind) || errors.Is(err, store.ErrNotSent) {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	if v := testutil.ToFloat64(c.Metrics.Open.WithLabelValues("daemon", "context")); v != 0 {
		t.Fatalf("the circuit opened on fence timeouts (gauge %v)", v)
	}
	if l := said.all(); len(l) != 0 {
		t.Fatalf("said %q", l)
	}
	if v := testutil.ToFloat64(c.Metrics.Calls.WithLabelValues("daemon", "context", "feed_behind")); v != float64(3*c.Failures) {
		t.Fatalf("feed_behind outcomes counted %v, want %d", v, 3*c.Failures)
	}
}

// A passing health check closes the token and context circuits at once, the
// close said and gauged as a probe's is, and leaves the bulk pool's alone
// (stores I2).
func TestCloseCircuitsClosesTokenAndContextNotBulk(t *testing.T) {
	var said, gone told
	inner := &stuck{err: store.ErrUnavailable}
	c := config(&said, &gone)
	c.OpenFor = time.Hour // only CloseCircuits can let a call through
	g := Wrap(inner, c)
	for i := 0; i < 3; i++ {
		g.GetContext(context.Background(), k)
		g.PutToken(context.Background(), store.TokenKey{}, store.Token{})
		g.ActivePrincipals(context.Background())
	}
	for _, p := range []string{"token", "context", "bulk"} {
		if testutil.ToFloat64(c.Metrics.Open.WithLabelValues("daemon", p)) != 1 {
			t.Fatalf("the %s circuit did not open", p)
		}
	}
	g.(Closer).CloseCircuits("a store health check passed")
	for p, want := range map[string]float64{"token": 0, "context": 0, "bulk": 1} {
		if v := testutil.ToFloat64(c.Metrics.Open.WithLabelValues("daemon", p)); v != want {
			t.Fatalf("%s gauge %v, want %v", p, v, want)
		}
	}
	before := inner.count()
	g.PutToken(context.Background(), store.TokenKey{}, store.Token{})
	g.GetContext(context.Background(), k)
	if inner.count() != before+2 {
		t.Fatalf("a closed circuit did not send its calls to the store: %d calls", inner.count()-before)
	}
	// Closed means fails=0: two more failures do not reopen a threshold of 3.
	g.PutToken(context.Background(), store.TokenKey{}, store.Token{})
	if testutil.ToFloat64(c.Metrics.Open.WithLabelValues("daemon", "token")) != 0 {
		t.Fatal("the failure count survived the close")
	}
	if _, err := g.ActivePrincipals(context.Background()); !errors.Is(err, store.ErrNotSent) {
		t.Fatalf("the bulk pool should still refuse: %v", err)
	}
	closed := 0
	for _, l := range said.all() {
		if strings.Contains(l, "circuit is closed") && strings.Contains(l, "a store health check passed") {
			closed++
		}
	}
	if closed != 2 {
		t.Fatalf("said %q", said.all())
	}
}

// A store whose health check passes while its real calls fail must still go
// dark at StopAfter (decision 35, the hold_ttl backstop): CloseCircuits ends
// the circuit, not the failing run the backstop measures, and only an
// answered call ends that (stores I2 review I1).
func TestAPassingHealthCheckDoesNotRestartTheHoldBackstop(t *testing.T) {
	var said, gone told
	inner := &stuck{err: store.ErrUnavailable}
	c := config(&said, &gone)
	c.StopAfter, c.OpenFor = 300*time.Millisecond, 100*time.Millisecond
	g := Wrap(inner, c)
	end := time.Now().Add(1200 * time.Millisecond)
	for next := time.Now(); time.Now().Before(end); time.Sleep(5 * time.Millisecond) {
		if time.Now().After(next) {
			g.(Closer).CloseCircuits("a store health check passed")
			next = time.Now().Add(50 * time.Millisecond)
		}
		g.PutToken(context.Background(), store.TokenKey{}, store.Token{})
	}
	if l := gone.all(); len(l) != 1 || !strings.Contains(l[0], "token pool's circuit has been open") {
		t.Fatalf("Unhealthy told %d times: %q", len(l), l)
	}
}

// A circuit a health check closed, then no token call for longer than
// StopAfter, then a new blip: the new open is a new run, not an hours-old
// one, so it must not go dark at once and "open for" must be true.
func TestAHealthClosedRunIsNotRevivedByALaterBlip(t *testing.T) {
	var said, gone told
	inner := &stuck{err: store.ErrUnavailable}
	c := config(&said, &gone)
	c.StopAfter, c.OpenFor = 300*time.Millisecond, 20*time.Millisecond
	g := Wrap(inner, c)
	for i := 0; i < 3; i++ { // the third failure opens it
		g.PutToken(context.Background(), store.TokenKey{}, store.Token{})
	}
	g.(Closer).CloseCircuits("a store health check passed")
	time.Sleep(400 * time.Millisecond) // no token call, longer than StopAfter
	for i := 0; i < 4; i++ {           // three failures open it again, one more is refused or a probe
		g.PutToken(context.Background(), store.TokenKey{}, store.Token{})
	}
	if l := gone.all(); len(l) != 0 {
		t.Fatalf("a blip after a failure-free gap went dark at once: %q", l)
	}
}

// An answered call ends the failing run: a later failing run is timed from
// its own start.
func TestAnAnsweredCallRestartsTheHoldBackstop(t *testing.T) {
	var said, gone told
	inner := &stuck{err: store.ErrUnavailable}
	c := config(&said, &gone)
	c.StopAfter, c.OpenFor = 300*time.Millisecond, 20*time.Millisecond
	g := Wrap(inner, c)
	g.PutToken(context.Background(), store.TokenKey{}, store.Token{})
	time.Sleep(350 * time.Millisecond)
	inner.set(nil, 0)
	g.PutToken(context.Background(), store.TokenKey{}, store.Token{}) // answered: the run ends
	inner.set(store.ErrUnavailable, 0)
	for i := 0; i < 3; i++ {
		g.PutToken(context.Background(), store.TokenKey{}, store.Token{})
	}
	if l := gone.all(); len(l) != 0 {
		t.Fatalf("a new run was timed from the old one: %q", l)
	}
}

// A probe already in flight when CloseCircuits runs belongs to the circuit
// that was closed: its one failure does not open the new one.
func TestAProbeInFlightAtTheCloseDoesNotReopenOnOneFailure(t *testing.T) {
	var said, gone told
	inner := &stuck{err: store.ErrUnavailable}
	c := config(&said, &gone)
	c.CallTimeout = time.Hour
	g := Wrap(inner, c)
	for i := 0; i < 3; i++ {
		g.GetContext(context.Background(), k)
	}
	time.Sleep(110 * time.Millisecond) // OpenFor: the next call probes
	hold := make(chan struct{})
	inner.mu.Lock()
	inner.hold = hold
	inner.mu.Unlock()
	done := make(chan struct{})
	go func() { defer close(done); g.GetContext(context.Background(), k) }()
	eventually(t, "the probe to reach the store", func() bool { return inner.count() == 4 })
	g.(Closer).CloseCircuits("a store health check passed")
	close(hold) // the probe fails, after the close
	<-done
	if v := testutil.ToFloat64(c.Metrics.Open.WithLabelValues("daemon", "context")); v != 0 {
		t.Fatalf("a probe from before the close reopened the circuit on one failure (%v)", v)
	}
}

// The hold_ttl clock starts when the circuit first opens, not at the run's
// first failure: one stray failure, a long quiet gap and then a blip that
// opens the circuit must not go dark at once on "open for StopAfter".
func TestTheHoldBackstopIsTimedFromTheFirstOpen(t *testing.T) {
	var said, gone told
	inner := &stuck{err: store.ErrUnavailable}
	c := config(&said, &gone)
	c.StopAfter, c.OpenFor = 300*time.Millisecond, 20*time.Millisecond
	g := Wrap(inner, c)
	g.PutToken(context.Background(), store.TokenKey{}, store.Token{}) // a stray failure
	time.Sleep(400 * time.Millisecond)                                // longer than StopAfter
	for i := 0; i < 2; i++ {                                          // the third failure opens it
		g.PutToken(context.Background(), store.TokenKey{}, store.Token{})
	}
	g.PutToken(context.Background(), store.TokenKey{}, store.Token{}) // refused or a probe, just after the open
	if l := gone.all(); len(l) != 0 {
		t.Fatalf("told before the circuit had been open for StopAfter: %q", l)
	}
	time.Sleep(350 * time.Millisecond)
	g.PutToken(context.Background(), store.TokenKey{}, store.Token{})
	if l := gone.all(); len(l) != 1 {
		t.Fatalf("told %d times after StopAfter open: %q", len(l), l)
	}
}
