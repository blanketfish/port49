package directory

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/rhwendt/port49/internal/daemon/metrics"
)

func poolCfg(site string, servers ...Server) Config {
	return Config{Servers: servers, Site: site, QueryTimeout: time.Second, HealthInterval: 30 * time.Second,
		HealthTimeout: 2 * time.Second, FailureThreshold: 3, ProbeInterval: time.Minute, StabilityWindow: 5 * time.Minute}
}

type lines struct {
	mu sync.Mutex
	l  []string
}

func (s *lines) say(f string, a ...any) {
	s.mu.Lock()
	s.l = append(s.l, fmt.Sprintf(f, a...))
	s.mu.Unlock()
}
func (s *lines) count(sub string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, l := range s.l {
		if strings.Contains(l, sub) {
			n++
		}
	}
	return n
}

func (s *lines) has(sub string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, l := range s.l {
		if strings.Contains(l, sub) {
			return true
		}
	}
	return false
}

func noCheck(context.Context, Searcher) error { return nil }

var (
	west1 = Server{URI: "ldaps://dc-01", Priority: 100, Site: "us-west"}
	west2 = Server{URI: "ldaps://dc-02", Priority: 90, Site: "us-west"}
	east  = Server{URI: "ldaps://dc-03", Priority: 200, Site: "us-east"}
)

// Same site first, then priority, then file order (Ruling 9): dc-03's
// higher priority does not pull a us-west broker across sites.
func TestRankingIsSameSiteFirstThenPriority(t *testing.T) {
	p := NewPool(poolCfg("us-west", east, west2, west1), newFakeServers().dial, noCheck, newClock().Now,
		metrics.New(prometheus.NewRegistry()), (&lines{}).say)
	got := p.Ranked()
	if got[0] != west1 || got[1] != west2 || got[2] != east {
		t.Fatalf("%v", got)
	}
	p = NewPool(poolCfg("", east, west2, west1), newFakeServers().dial, noCheck, newClock().Now,
		metrics.New(prometheus.NewRegistry()), (&lines{}).say)
	if got := p.Ranked(); got[0] != east {
		t.Fatalf("with no site, priority alone: %v", got)
	}
}

// Sticky: every query goes to the selected server while it answers, and a
// query error that is the server's answer (no such object) is not a
// fault and moves nothing.
func TestStickyUntilAFault(t *testing.T) {
	f := newFakeServers(west1.URI, west2.URI)
	f.dirs[west1.URI].err["(bad)"] = ldap.NewError(ldap.LDAPResultNoSuchObject, errors.New("no such object"))
	p := NewPool(poolCfg("us-west", west1, west2), f.dial, noCheck, newClock().Now,
		metrics.New(prometheus.NewRegistry()), (&lines{}).say)
	for i := 0; i < 5; i++ {
		srv, err := p.Do(context.Background(), func(s Searcher) error {
			_, err := s.Search(&ldap.SearchRequest{Filter: "(x)"})
			return err
		})
		if err != nil || srv != west1 {
			t.Fatalf("query %d: %v %v", i, srv, err)
		}
	}
	srv, err := p.Do(context.Background(), func(s Searcher) error {
		_, err := s.Search(&ldap.SearchRequest{Filter: "(bad)"})
		return err
	})
	if srv != west1 || !ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
		t.Fatalf("a query's answer: %v %v", srv, err)
	}
	if sel, _ := p.Selected(); sel != west1 {
		t.Fatalf("an answer moved the selection to %v", sel)
	}
}

// A slow server (answers after query_timeout) fails the query over to the
// next within the one query_timeout, and opens its breaker after
// failure_threshold such queries; queries do not retry it while open
// (Review Focus 2).
func TestASlowServerFailsOverWithinTheQueryTimeout(t *testing.T) {
	f := newFakeServers(west1.URI, west2.URI)
	f.dirs[west1.URI].delay = 2 * time.Second
	cfg := poolCfg("us-west", west1, west2)
	cfg.QueryTimeout, cfg.HealthTimeout = 600*time.Millisecond, 300*time.Millisecond
	m := metrics.New(prometheus.NewRegistry())
	say := &lines{}
	search := func(_ context.Context, s Searcher) error {
		_, err := s.Search(&ldap.SearchRequest{Filter: "(x)"})
		return err
	}
	p := NewPool(cfg, f.dial, search, newClock().Now, m, say.say)
	query := func() (Server, error) {
		return p.Do(context.Background(), func(s Searcher) error { return search(context.Background(), s) })
	}
	start := time.Now()
	if _, err := query(); err != nil && !errors.Is(err, ErrUnavailable) {
		t.Fatalf("the first query: %v", err)
	}
	if time.Since(start) > cfg.QueryTimeout+300*time.Millisecond {
		t.Fatalf("the first query took %v; query_timeout bounds it", time.Since(start))
	}
	if sel, _ := p.Selected(); sel != west2 {
		t.Fatalf("a fault did not end dc-01's selection: %v", sel)
	}
	calls := len(f.dirs[west1.URI].calls)
	for i := 0; i < 2; i++ {
		if srv, err := query(); err != nil || srv != west2 {
			t.Fatalf("query %d: %v %v", i, srv, err)
		}
	}
	if len(f.dirs[west1.URI].calls) != calls {
		t.Fatal("a query went back to dc-01 before failback")
	}
	for i := 0; i < 3; i++ { // dc-01 answers each check too late
		p.Check(context.Background())
	}
	if testutil.ToFloat64(m.DirectoryServerUp.WithLabelValues(west1.label())) != 0 || !say.has("its breaker is open") {
		t.Fatalf("the breaker did not open on slow checks: %v", say.l)
	}
}

// Failback waits for stability_window of passing health checks: a server
// that returns is not selected again at its first pass, and a fault inside
// the window starts it again (Review Focus 2).
func TestFailbackWaitsForTheStabilityWindow(t *testing.T) {
	f := newFakeServers(west1.URI, west2.URI)
	clk := newClock()
	say := &lines{}
	p := NewPool(poolCfg("us-west", west1, west2), f.dial, noCheck, clk.Now, metrics.New(prometheus.NewRegistry()), say.say)
	f.setDown(west1.URI, true)
	for i := 0; i < 3; i++ {
		p.Check(context.Background())
		clk.Add(30 * time.Second)
	}
	if sel, _ := p.Selected(); sel != west2 {
		t.Fatalf("dc-01 down: selected %v", sel)
	}
	f.setDown(west1.URI, false)
	clk.Add(time.Minute) // past probe_interval
	p.Check(context.Background())
	if sel, _ := p.Selected(); sel != west2 {
		t.Fatalf("selected again at its first pass: %v", sel)
	}
	clk.Add(3 * time.Minute)
	f.setDown(west1.URI, true)
	p.Check(context.Background()) // a fault inside the window
	f.setDown(west1.URI, false)
	clk.Add(3 * time.Minute)
	p.Check(context.Background())
	if sel, _ := p.Selected(); sel != west2 {
		t.Fatalf("a fault inside the window did not restart it: %v", sel)
	}
	clk.Add(5 * time.Minute)
	p.Check(context.Background())
	if sel, _ := p.Selected(); sel != west1 || !say.has("passed every health check for 5m0s") {
		t.Fatalf("after the window: %v %v", sel, say.l)
	}
}

// A breaker opens after failure_threshold faults, and only the health
// check probes it, once per probe_interval.
func TestTheBreakerOpensAfterThresholdAndOnlyTheCheckProbesIt(t *testing.T) {
	f := newFakeServers(west1.URI, west2.URI)
	clk := newClock()
	p := NewPool(poolCfg("us-west", west1, west2), f.dial, noCheck, clk.Now, metrics.New(prometheus.NewRegistry()), (&lines{}).say)
	f.setDown(west1.URI, true)
	for i := 0; i < 3; i++ {
		p.Check(context.Background())
	}
	dials := f.dials[west1.URI]
	clk.Add(30 * time.Second)
	p.Check(context.Background()) // inside probe_interval: not dialled
	if f.dials[west1.URI] != dials {
		t.Fatal("an open breaker was dialled before probe_interval")
	}
	clk.Add(31 * time.Second)
	p.Check(context.Background())
	if f.dials[west1.URI] != dials+1 {
		t.Fatal("the probe did not dial")
	}
}

// A site crossing is a consistency event: said with both sites and both
// servers, and counted (design §10: "MUST be logged").
func TestASiteCrossingIsAConsistencyEvent(t *testing.T) {
	f := newFakeServers(west1.URI, east.URI)
	m := metrics.New(prometheus.NewRegistry())
	say := &lines{}
	p := NewPool(poolCfg("us-west", west1, east), f.dial, noCheck, newClock().Now, m, say.say)
	f.setDown(west1.URI, true)
	if srv, err := p.Do(context.Background(), func(s Searcher) error {
		_, err := s.Search(&ldap.SearchRequest{Filter: "(x)"})
		return err
	}); err != nil || srv != east {
		t.Fatalf("%v %v", srv, err)
	}
	if testutil.ToFloat64(m.DirectorySiteCrossings) != 1 ||
		!say.has("consistency event: crossing from site us-west to us-east (dc-01 to dc-03)") {
		t.Fatalf("%v", say.l)
	}
}

// A caller that went away is no fault: a cancelled mint must not open a
// healthy server's breaker.
func TestACallerThatWentAwayIsNoFault(t *testing.T) {
	f := newFakeServers(west1.URI)
	f.dirs[west1.URI].delay = 200 * time.Millisecond
	p := NewPool(poolCfg("us-west", west1), f.dial, noCheck, newClock().Now, metrics.New(prometheus.NewRegistry()), (&lines{}).say)
	for i := 0; i < 5; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		go func() { time.Sleep(20 * time.Millisecond); cancel() }()
		_, _ = p.Do(ctx, func(s Searcher) error {
			_, err := s.Search(&ldap.SearchRequest{Filter: "(x)"})
			return err
		})
	}
	if sel, ok := p.Selected(); !ok || sel != west1 {
		t.Fatalf("cancelled callers moved the selection: %v %v", sel, ok)
	}
}

// Fault is the server's, not the query's: network, timeout, busy,
// unavailable, unwilling, other, time limit; never no-such-object or
// invalid credentials of a query.
func TestFaultClassifies(t *testing.T) {
	for code, want := range map[uint16]bool{ldap.ErrorNetwork: true, ldap.LDAPResultBusy: true,
		ldap.LDAPResultUnavailable: true, ldap.LDAPResultUnwillingToPerform: true, ldap.LDAPResultOther: true,
		ldap.LDAPResultTimeLimitExceeded: true, ldap.LDAPResultNoSuchObject: false,
		ldap.LDAPResultSizeLimitExceeded: false, ldap.LDAPResultFilterError: false} {
		if got := Fault(ldap.NewError(code, errors.New("x"))); got != want {
			t.Errorf("code %d: %v", code, got)
		}
	}
	if !Fault(context.DeadlineExceeded) {
		t.Error("a deadline is a fault")
	}
}

func searchFor(filter string) func(Searcher) error {
	return func(s Searcher) error {
		_, err := s.Search(&ldap.SearchRequest{Filter: filter})
		return err
	}
}

// One query slow past query_timeout among twenty fast ones on the same
// connection: the slow one abandons its own search, the fast ones answer,
// the connection is never closed under them, and the breaker stays closed
// (pre-flight I-3).
func TestOneSlowQueryLeavesTheOthersAlone(t *testing.T) {
	f := newFakeServers(west1.URI, west2.URI)
	f.dirs[west1.URI].delay = 50 * time.Millisecond
	f.dirs[west1.URI].slow["(slow)"] = 2 * time.Second
	cfg := poolCfg("us-west", west1, west2)
	cfg.QueryTimeout = 500 * time.Millisecond
	m := metrics.New(prometheus.NewRegistry())
	p := NewPool(cfg, f.dial, noCheck, newClock().Now, m, (&lines{}).say)
	if _, err := p.Do(context.Background(), searchFor("(x)")); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 20)
	wg.Add(1)
	go func() { defer wg.Done(); _, _ = p.Do(context.Background(), searchFor("(slow)")) }()
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := p.Do(context.Background(), searchFor("(x)")); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("a fast query: %v", err)
	}
	if testutil.ToFloat64(m.DirectoryServerUp.WithLabelValues(west1.label())) != 1 {
		t.Fatal("one slow query opened dc-01's breaker")
	}
	if n := testutil.ToFloat64(m.DirectoryQueries.WithLabelValues(west1.label(), "fault")); n > 1 {
		t.Fatalf("%v faults counted on dc-01; one slow query is one", n)
	}
	if f.dials[west1.URI] != 1 || f.open(west1.URI) != 1 {
		t.Fatalf("dc-01 dialled %d times, %d open: its connection was closed under the others",
			f.dials[west1.URI], f.open(west1.URI))
	}
}

// Queries racing to dial an idle server keep one connection and close the
// rest (pre-flight M-8).
func TestRacingQueriesKeepOneConnection(t *testing.T) {
	f := newFakeServers(west1.URI)
	f.dialDelay = 50 * time.Millisecond
	p := NewPool(poolCfg("us-west", west1), f.dial, noCheck, newClock().Now, metrics.New(prometheus.NewRegistry()),
		(&lines{}).say)
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, _ = p.Do(context.Background(), searchFor("(x)")) }()
	}
	wg.Wait()
	if n := f.open(west1.URI); n != 1 {
		t.Fatalf("%d connections to dc-01 left open, want 1", n)
	}
}

// A refused bind is this server not answering (pre-flight I-2): the query
// fails over; with every server refusing it is ErrUnavailable, so grace
// applies above; the refusal is said once an hour per server with the
// mechanism and the result code; and a refusal neither opens the breaker
// nor resets the fault count the health checks built.
func TestABindRefusalFailsOverAndReachesUnavailable(t *testing.T) {
	f := newFakeServers(west1.URI, west2.URI)
	invalid := ldap.NewError(ldap.LDAPResultInvalidCredentials, errors.New("invalid credentials"))
	f.setRefuse(west1.URI, invalid)
	cfg := poolCfg("us-west", west1, west2)
	cfg.Bind.Mechanism = "simple"
	m := metrics.New(prometheus.NewRegistry())
	say := &lines{}
	p := NewPool(cfg, f.dial, noCheck, newClock().Now, m, say.say)
	if srv, err := p.Do(context.Background(), searchFor("(x)")); err != nil || srv != west2 {
		t.Fatalf("a refusal on dc-01 did not fail over: %v %v", srv, err)
	}
	f.setRefuse(west2.URI, invalid)
	for _, c := range f.conns[west2.URI] { // dc-02's bound connection goes with the next bind refused
		_ = c.Close()
	}
	for i := 0; i < 3; i++ {
		if _, err := p.Do(context.Background(), searchFor("(x)")); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("every server refusing: %v, want ErrUnavailable", err)
		}
	}
	if n := say.count("dc-01 refused the bind (simple): LDAP Result Code 49"); n != 1 {
		t.Fatalf("the refusal said %d times in the hour: %v", n, say.l)
	}
	if testutil.ToFloat64(m.DirectoryServerUp.WithLabelValues(west1.label())) != 1 {
		t.Fatal("invalid credentials opened the breaker")
	}
	f.setRefuse(west1.URI, nil)
	f.setDown(west1.URI, true)
	p.Check(context.Background())
	p.Check(context.Background()) // two faults in a row
	f.setDown(west1.URI, false)
	f.setRefuse(west1.URI, invalid)
	p.Check(context.Background()) // a refusal between: neither counted nor a reset
	f.setRefuse(west1.URI, nil)
	f.setDown(west1.URI, true)
	p.Check(context.Background()) // the third fault
	if testutil.ToFloat64(m.DirectoryServerUp.WithLabelValues(west1.label())) != 0 {
		t.Fatal("a refusal reset the fault count the health checks built")
	}
}

// With no broker site, a selection whose server's site differs from the
// previous selection's is a crossing, said and counted (pre-flight M-7).
func TestACrossingWithNoBrokerSiteIsCounted(t *testing.T) {
	f := newFakeServers(east.URI, west1.URI)
	m := metrics.New(prometheus.NewRegistry())
	say := &lines{}
	p := NewPool(poolCfg("", east, west1), f.dial, noCheck, newClock().Now, m, say.say)
	f.setDown(east.URI, true)
	if srv, err := p.Do(context.Background(), searchFor("(x)")); err != nil || srv != west1 {
		t.Fatalf("%v %v", srv, err)
	}
	if testutil.ToFloat64(m.DirectorySiteCrossings) != 1 ||
		!say.has("consistency event: crossing from site us-east to us-west (dc-03 to dc-01)") {
		t.Fatalf("%v", say.l)
	}
}

// With every breaker open a query fails at once with ErrUnavailable: it
// does not wait out query_timeout, and does not dial.
func TestEveryBreakerOpenFailsFast(t *testing.T) {
	f := newFakeServers(west1.URI)
	p := NewPool(poolCfg("us-west", west1), f.dial, noCheck, newClock().Now, metrics.New(prometheus.NewRegistry()),
		(&lines{}).say)
	f.setDown(west1.URI, true)
	for i := 0; i < 3; i++ {
		p.Check(context.Background())
	}
	dials := f.dials[west1.URI]
	start := time.Now()
	if _, err := p.Do(context.Background(), searchFor("(x)")); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("%v", err)
	}
	if time.Since(start) > 100*time.Millisecond || f.dials[west1.URI] != dials {
		t.Fatalf("not fast: %v, %d dials", time.Since(start), f.dials[west1.URI]-dials)
	}
}

// A server's name in the log and in metrics is its host:port, never the
// URI.
func TestServersAreNamedByHostPort(t *testing.T) {
	s := Server{URI: "ldaps://dc-01.example.net:3269/ou=x?y"}
	if s.label() != "dc-01.example.net:3269" {
		t.Fatal(s.label())
	}
}

// Run neither checks nor leaks a goroutine once its ctx is done, and a
// Check on a done ctx dials nothing.
func TestRunStopsWithItsContext(t *testing.T) {
	f := newFakeServers(west1.URI)
	p := NewPool(poolCfg("us-west", west1), f.dial, noCheck, newClock().Now, metrics.New(prometheus.NewRegistry()),
		(&lines{}).say)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { p.Run(ctx); close(done) }()
	deadline := time.Now().Add(2 * time.Second)
	for {
		f.mu.Lock()
		n := f.dials[west1.URI]
		f.mu.Unlock()
		if n > 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run outlived its context")
	}
	f.mu.Lock()
	before := f.dials[west1.URI]
	f.mu.Unlock()
	p.Check(ctx)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.dials[west1.URI] != before {
		t.Fatal("Check dialled on a done context")
	}
}
