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

// poolCfg pins the bind mechanism to simple, whose refusals hold the whole
// pool off (AD's shared lockout); the external tests set their own.
func poolCfg(site string, servers ...Server) Config {
	return Config{Servers: servers, Site: site, QueryTimeout: time.Second, HealthInterval: 30 * time.Second,
		HealthTimeout: 2 * time.Second, FailureThreshold: 3, ProbeInterval: time.Minute, StabilityWindow: 5 * time.Minute,
		Bind: Bind{Mechanism: "simple"}}
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
	if testutil.ToFloat64(m.DirectoryServerUp.WithLabelValues(west1.Label())) != 0 || !say.has("its breaker is open") {
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
		!say.has("consistency event: crossing from site us-west to us-east (dc-01:636 to dc-03:636)") {
		t.Fatalf("%v", say.l)
	}
}

// A caller that went away is no fault: a cancelled mint must not open a
// healthy server's breaker.
func TestACallerThatWentAwayIsNoFault(t *testing.T) {
	f := newFakeServers(west1.URI)
	f.dirs[west1.URI].delay = 200 * time.Millisecond
	m := metrics.New(prometheus.NewRegistry())
	p := NewPool(poolCfg("us-west", west1), f.dial, noCheck, newClock().Now, m, (&lines{}).say)
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
	if testutil.ToFloat64(m.DirectoryServerUp.WithLabelValues(west1.Label())) != 1 ||
		testutil.ToFloat64(m.DirectoryQueries.WithLabelValues(west1.Label(), "fault")) != 0 {
		t.Fatal("cancelled callers counted as faults against dc-01")
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
	if testutil.ToFloat64(m.DirectoryServerUp.WithLabelValues(west1.Label())) != 1 {
		t.Fatal("one slow query opened dc-01's breaker")
	}
	if n := testutil.ToFloat64(m.DirectoryQueries.WithLabelValues(west1.Label(), "fault")); n > 1 {
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

// A refused bind is the credential refused, shared by every server: the
// query is ErrUnavailable (grace applies above) and no other server is
// bound meanwhile (Ruling PF7g-g); the refusal is said once an hour per
// server with the mechanism and the result code; and a refusal neither
// opens the breaker nor resets the fault count the health checks built.
func TestABindRefusalReachesUnavailableAndBindsNoOtherServer(t *testing.T) {
	f := newFakeServers(west1.URI, west2.URI)
	invalid := ldap.NewError(ldap.LDAPResultInvalidCredentials, errors.New("invalid credentials"))
	f.setRefuse(west1.URI, invalid)
	cfg := poolCfg("us-west", west1, west2)
	cfg.Bind.Mechanism = "simple"
	m := metrics.New(prometheus.NewRegistry())
	say := &lines{}
	clk := newClock()
	p := NewPool(cfg, f.dial, noCheck, clk.Now, m, say.say)
	for i := 0; i < 3; i++ {
		if _, err := p.Do(context.Background(), searchFor("(x)")); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("a refused bind: %v, want ErrUnavailable", err)
		}
	}
	if f.dials[west2.URI] != 0 || f.dials[west1.URI] != 1 {
		t.Fatalf("binds: dc-01 %d, dc-02 %d; the refusal holds every bind off", f.dials[west1.URI], f.dials[west2.URI])
	}
	if n := say.count("dc-01:636 refused the bind (simple): LDAP Result Code 49"); n != 1 {
		t.Fatalf("the refusal said %d times in the hour: %v", n, say.l)
	}
	if testutil.ToFloat64(m.DirectoryServerUp.WithLabelValues(west1.Label())) != 1 {
		t.Fatal("invalid credentials opened the breaker")
	}
	f.setRefuse(west1.URI, nil)
	clk.Add(2 * time.Minute)
	p.Check(context.Background())                                           // the probe: accepted, the hold-off is clear
	if _, err := p.Do(context.Background(), searchFor("(x)")); err != nil { // dc-02 bound: dc-01 is checked again
		t.Fatal(err)
	}
	f.setDown(west1.URI, true)
	p.Check(context.Background())
	p.Check(context.Background()) // two faults in a row
	f.setDown(west1.URI, false)
	f.setRefuse(west1.URI, invalid)
	p.Check(context.Background()) // a refusal between: neither counted nor a reset
	f.setRefuse(west1.URI, nil)
	f.setDown(west1.URI, true)
	clk.Add(2 * time.Minute)
	p.Check(context.Background()) // the third fault
	if testutil.ToFloat64(m.DirectoryServerUp.WithLabelValues(west1.Label())) != 0 {
		t.Fatal("a refusal reset the fault count the health checks built")
	}
}

func binds(f *fakeServers) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.dials {
		n += c
	}
	return n
}

// dcs is n servers of one site, ranked in order.
func dcs(n int) []Server {
	out := make([]Server, n)
	for i := range out {
		out[i] = Server{URI: fmt.Sprintf("ldaps://dc-%02d", i+1), Priority: 1000 - i, Site: "us-west"}
	}
	return out
}

// failedBinds runs a wrong password over d, a query every 6s and a Check
// every 30s, and counts the binds.
func failedBinds(t *testing.T, servers []Server, d time.Duration) int {
	t.Helper()
	invalid := ldap.NewError(ldap.LDAPResultInvalidCredentials, errors.New("invalid credentials"))
	f := newFakeServers()
	for _, s := range servers {
		f.dirs[s.URI] = newFakeDir()
		f.setRefuse(s.URI, invalid)
	}
	clk := newClock()
	p := NewPool(poolCfg("us-west", servers...), f.dial, noCheck, clk.Now, metrics.New(prometheus.NewRegistry()),
		(&lines{}).say)
	for at := time.Duration(0); at < d; at += 6 * time.Second {
		if _, err := p.Do(context.Background(), searchFor("(x)")); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("at %v: %v", at, err)
		}
		if (at/(6*time.Second))%5 == 4 {
			p.Check(context.Background())
		}
		clk.Add(6 * time.Second)
	}
	return binds(f)
}

// A wrong password everywhere: AD counts every DC's failed binds toward one
// lockout. With N servers the bound is N+4 failed binds in the first 30
// minutes (each server's first refusal holds the pool at 1m, so N binds in
// the first N minutes; then probes at N, N+2, N+6 and N+14 minutes, the
// hold-off doubling per refusal from a server that had refused before, to
// its 15m cap) and then one per 15 minutes: 6 for three servers in 10
// minutes, 9 for five servers in 30.
func TestAWrongPasswordBindsAtMostNPlusFourTimesInThirtyMinutes(t *testing.T) {
	if n := failedBinds(t, dcs(3), 10*time.Minute); n > 6 {
		t.Fatalf("%d bind attempts in 10 minutes across 3 servers, want at most 6", n)
	}
	if n := failedBinds(t, dcs(5), 30*time.Minute); n > 9 {
		t.Fatalf("%d bind attempts in 30 minutes across 5 servers, want at most 9 (N+4)", n)
	}
	if n := failedBinds(t, dcs(1), 30*time.Minute); n > 5 {
		t.Fatalf("%d bind attempts in 30 minutes on one server, want at most 5", n)
	}
}

// Five misconfigured DCs ranked above one good one (Re-review I-4): each
// first refusal holds the pool at 1m without doubling it, so the probe
// walks them one a minute and reaches the good DC at once; 120 logins over
// two hours lose only those first minutes.
func TestFiveBadDCsAboveAGoodOneCostFiveMinutes(t *testing.T) {
	servers := dcs(6)
	f := newFakeServers()
	for _, s := range servers {
		f.dirs[s.URI] = newFakeDir()
	}
	for _, s := range servers[:5] {
		f.setRefuse(s.URI, ldap.NewError(ldap.LDAPResultInvalidCredentials, errors.New("invalid credentials")))
	}
	clk := newClock()
	say := &lines{}
	p := NewPool(poolCfg("us-west", servers...), f.dial, noCheck, clk.Now, metrics.New(prometheus.NewRegistry()), say.say)
	failed := 0
	for at := time.Duration(0); at < 2*time.Hour; at += 30 * time.Second {
		p.Check(context.Background())
		if at%time.Minute == 0 {
			if _, err := p.Do(context.Background(), searchFor("(x)")); err != nil {
				failed++
				if at > 6*time.Minute {
					t.Fatalf("a login at %v failed: %v\n%s", at, err, strings.Join(say.l, "\n"))
				}
			}
		}
		clk.Add(30 * time.Second)
	}
	if failed > 6 {
		t.Fatalf("%d logins failed, want only the first minutes", failed)
	}
}

// One slow dial charges one fault, not one per query waiting on it
// (Re-review N-4).
func TestOneSlowDialChargesOneFault(t *testing.T) {
	f := newFakeServers(west1.URI)
	f.dialDelay = 300 * time.Millisecond
	cfg := poolCfg("us-west", west1)
	cfg.QueryTimeout = 100 * time.Millisecond
	m := metrics.New(prometheus.NewRegistry())
	p := NewPool(cfg, f.dial, noCheck, newClock().Now, m, (&lines{}).say)
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, _ = p.Do(context.Background(), searchFor("(x)")) }()
	}
	wg.Wait()
	if n := testutil.ToFloat64(m.DirectoryQueries.WithLabelValues(west1.Label(), "fault")); n > 1 {
		t.Fatalf("%v faults charged for one slow dial", n)
	}
}

// The password fixed: the first bind after the hold-off is the probe, it
// succeeds, and queries resume at once and keep their connection.
func TestTheFirstProbeAfterTheHoldoffResumesQueries(t *testing.T) {
	invalid := ldap.NewError(ldap.LDAPResultInvalidCredentials, errors.New("invalid credentials"))
	f := newFakeServers(west1.URI, west2.URI)
	f.setRefuse(west1.URI, invalid)
	f.setRefuse(west2.URI, invalid)
	clk := newClock()
	say := &lines{}
	m := metrics.New(prometheus.NewRegistry())
	p := NewPool(poolCfg("us-west", west1, west2), f.dial, noCheck, clk.Now, m, say.say)
	if _, err := p.Do(context.Background(), searchFor("(x)")); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	f.setRefuse(west1.URI, nil)
	f.setRefuse(west2.URI, nil)
	clk.Add(30 * time.Second)
	if _, err := p.Do(context.Background(), searchFor("(x)")); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("inside the hold-off: %v", err)
	}
	if binds(f) != 1 {
		t.Fatalf("%d binds inside the hold-off", binds(f))
	}
	clk.Add(31 * time.Second)
	if srv, err := p.Do(context.Background(), searchFor("(x)")); err != nil {
		t.Fatalf("the probe: %v %v", srv, err)
	}
	if testutil.ToFloat64(m.DirectoryBindHoldoff) != 0 || !say.has("hold-off cleared") {
		t.Fatalf("the hold-off is not clear: %v", say.l)
	}
	before := binds(f)
	for i := 0; i < 3; i++ {
		if _, err := p.Do(context.Background(), searchFor("(x)")); err != nil {
			t.Fatal(err)
		}
	}
	if binds(f) != before {
		t.Fatal("queries after the probe bound again")
	}
}

// A connection already bound keeps serving through a hold-off that another
// server's refusal started, and Check binds nothing meanwhile.
func TestABoundConnectionServesThroughTheHoldoff(t *testing.T) {
	f := newFakeServers(west1.URI, west2.URI)
	clk := newClock()
	p := NewPool(poolCfg("us-west", west1, west2), f.dial, noCheck, clk.Now, metrics.New(prometheus.NewRegistry()),
		(&lines{}).say)
	if srv, err := p.Do(context.Background(), searchFor("(x)")); err != nil || srv != west1 {
		t.Fatalf("%v %v", srv, err)
	}
	f.setRefuse(west2.URI, ldap.NewError(ldap.LDAPResultInvalidCredentials, errors.New("invalid credentials")))
	p.Check(context.Background()) // dc-02 refuses: the hold-off starts
	before := binds(f)
	clk.Add(10 * time.Second)
	p.Check(context.Background())
	for i := 0; i < 5; i++ {
		if srv, err := p.Do(context.Background(), searchFor("(x)")); err != nil || srv != west1 {
			t.Fatalf("query %d: %v %v", i, srv, err)
		}
	}
	if binds(f) != before {
		t.Fatal("a bind was made during the hold-off")
	}
}

// The hold-off is 1m, doubling per further refusal to a 15m cap, and the
// gauge reports what is left of it.
func TestTheHoldoffDoublesToACapAndTheGaugeReportsIt(t *testing.T) {
	f := newFakeServers(west1.URI)
	f.setRefuse(west1.URI, ldap.NewError(ldap.LDAPResultInvalidCredentials, errors.New("invalid credentials")))
	clk := newClock()
	m := metrics.New(prometheus.NewRegistry())
	say := &lines{}
	p := NewPool(poolCfg("us-west", west1), f.dial, noCheck, clk.Now, m, say.say)
	if testutil.ToFloat64(m.DirectoryBindHoldoff) != 0 {
		t.Fatal("not clear at the start")
	}
	for _, want := range []float64{60, 120, 240, 480, 900, 900} {
		_, _ = p.Do(context.Background(), searchFor("(x)"))
		if got := testutil.ToFloat64(m.DirectoryBindHoldoff); got != want {
			t.Fatalf("holdoff %v, want %v", got, want)
		}
		clk.Add(time.Duration(want/2) * time.Second)
		if got := testutil.ToFloat64(m.DirectoryBindHoldoff); got != want/2 {
			t.Fatalf("half way: %v, want %v", got, want/2)
		}
		clk.Add(time.Duration(want/2) * time.Second)
		if got := testutil.ToFloat64(m.DirectoryBindHoldoff); got != 0 {
			t.Fatalf("expired: %v", got)
		}
	}
	if !say.has("dc-01:636 refused the bind; no server is bound for 15m0s, until ") {
		t.Fatalf("%v", say.l)
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
		!say.has("consistency event: crossing from site us-east to us-west (dc-03:636 to dc-01:636)") {
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
	for uri, want := range map[string]string{
		"ldaps://dc-01.example.net:3269/ou=x?y": "dc-01.example.net:3269",
		"ldaps://dc-01.example.net":             "dc-01.example.net:636",
		"ldap://dc-01.example.net/":             "dc-01.example.net:389",
	} {
		if got := (Server{URI: uri}).Label(); got != want {
			t.Errorf("%s: %s", uri, got)
		}
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

// A server that healthy past the window and then refuses the bind is not
// failed back to at the next check (it has not passed every check), and is
// selected again only after a whole window of passes since its last refusal.
func TestARefusingServerIsNotFailedBackTo(t *testing.T) {
	f := newFakeServers(west1.URI, west2.URI)
	clk := newClock()
	say := &lines{}
	p := NewPool(poolCfg("us-west", west1, west2), f.dial, noCheck, clk.Now, metrics.New(prometheus.NewRegistry()), say.say)
	p.mu.Lock()
	p.sel = 1
	p.mu.Unlock()
	if _, err := p.Do(context.Background(), searchFor("(x)")); err != nil { // dc-02 bound
		t.Fatal(err)
	}
	p.mu.Lock()
	p.sel = 0
	p.mu.Unlock()
	p.Check(context.Background())
	clk.Add(6 * time.Minute)
	p.Check(context.Background())
	f.setRefuse(west1.URI, ldap.NewError(ldap.LDAPResultInvalidCredentials, errors.New("invalid credentials")))
	if srv, err := p.Do(context.Background(), searchFor("(x)")); err != nil || srv != west2 {
		t.Fatalf("%v %v", srv, err)
	}
	for i := 0; i < 5; i++ {
		clk.Add(30 * time.Second)
		p.Check(context.Background())
		if sel, _ := p.Selected(); sel != west2 {
			t.Fatalf("round %d: failed back to a server that refuses: %v", i, sel)
		}
	}
	f.setRefuse(west1.URI, nil)
	clk.Add(20 * time.Minute) // past the hold-off
	p.Check(context.Background())
	clk.Add(6 * time.Minute)
	p.Check(context.Background())
	if sel, _ := p.Selected(); sel != west1 {
		t.Fatalf("not selected after a full window of passes: %v", sel)
	}
}

// When Run returns the pool holds no connection: each bound connection is
// closed, so a rebuilt pool leaks none.
func TestRunClosesTheConnectionsOnExit(t *testing.T) {
	f := newFakeServers(west1.URI, west2.URI)
	p := NewPool(poolCfg("us-west", west1, west2), f.dial, noCheck, newClock().Now, metrics.New(prometheus.NewRegistry()),
		(&lines{}).say)
	if _, err := p.Do(context.Background(), searchFor("(x)")); err != nil {
		t.Fatal(err)
	}
	if f.open(west1.URI) != 1 {
		t.Fatal("the query left no connection")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { p.Run(ctx); close(done) }()
	cancel()
	<-done
	if f.open(west1.URI)+f.open(west2.URI) != 0 {
		t.Fatalf("%d connections left open after Run", f.open(west1.URI)+f.open(west2.URI))
	}
}

// With a same-site server that has one fault and a remote one with none,
// the same-site server is tried before the selection crosses sites.
func TestSameSiteWithAFaultBeatsARemoteServer(t *testing.T) {
	f := newFakeServers(west1.URI, west2.URI, east.URI)
	p := NewPool(poolCfg("us-west", west1, west2, east), f.dial, noCheck, newClock().Now,
		metrics.New(prometheus.NewRegistry()), (&lines{}).say)
	p.mu.Lock()
	p.srv[1].faults = 1 // dc-02
	p.mu.Unlock()
	p.mu.Lock()
	j := p.bestLocked(0)
	p.mu.Unlock()
	if p.srv[j].Server != west2 {
		t.Fatalf("crossed to %v with a same-site server closed", p.srv[j].Server)
	}
}

// A query whose budget ran out in a later server's dial charges that server
// no fault.
func TestBudgetSpentInALaterDialIsNoFault(t *testing.T) {
	f := newFakeServers(west1.URI, west2.URI)
	f.setDown(west1.URI, true)
	cfg := poolCfg("us-west", west1, west2)
	cfg.QueryTimeout = 500 * time.Millisecond
	m := metrics.New(prometheus.NewRegistry())
	dial := func(ctx context.Context, s Server) (Client, error) {
		if s == west2 {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return f.dial(ctx, s)
	}
	p := NewPool(cfg, dial, noCheck, newClock().Now, m, (&lines{}).say)
	if _, err := p.Do(context.Background(), searchFor("(x)")); err == nil {
		t.Fatal("want an error")
	}
	if n := testutil.ToFloat64(m.DirectoryQueries.WithLabelValues(west2.Label(), "fault")); n != 0 {
		t.Fatalf("dc-02 charged %v faults for a budget it was not given", n)
	}
}

// One misconfigured top-ranked DC and one good one (Re-review C-1): the
// refusal is that server's, so the hold-off's probes go to the other. After
// the first step logins succeed, the good DC keeps being health-checked, and
// the bad one is dialled at most once per its own backoff.
func TestOneRefusingDCDoesNotHoldOffTheGoodOne(t *testing.T) {
	f := newFakeServers(west1.URI, west2.URI)
	f.setRefuse(west1.URI, ldap.NewError(ldap.LDAPResultInvalidCredentials, errors.New("invalid credentials")))
	clk := newClock()
	p := NewPool(poolCfg("us-west", west1, west2), f.dial, noCheck, clk.Now, metrics.New(prometheus.NewRegistry()),
		(&lines{}).say)
	var failed []time.Duration
	for at := time.Duration(0); at <= time.Hour; at += 30 * time.Second {
		if at > 0 {
			clk.Add(30 * time.Second)
		}
		p.Check(context.Background())
		if at%(5*time.Minute) == 0 {
			if _, err := p.Do(context.Background(), searchFor("(x)")); err != nil {
				failed = append(failed, at)
			}
		}
	}
	for _, at := range failed {
		if at > time.Minute {
			t.Fatalf("a login at %v failed with a good DC up: %v", at, failed)
		}
	}
	f.mu.Lock()
	bad, good := f.dials[west1.URI], f.dials[west2.URI]
	f.mu.Unlock()
	if bad > 8 { // 0, 1m, 3m, 7m, 15m, 30m, 45m, 60m
		t.Fatalf("dc-01 dialled %d times in an hour; its own backoff allows 8", bad)
	}
	if good < 100 {
		t.Fatalf("dc-02 was dialled %d times: it is not health-checked", good)
	}
}

// 200 concurrent queries at a hold-off's expiry bind exactly once: the
// probe is one bind, and the step is taken as it ends (Re-review I-3).
func TestExactlyOneProbeBindsAtExpiry(t *testing.T) {
	invalid := ldap.NewError(ldap.LDAPResultInvalidCredentials, errors.New("invalid credentials"))
	f := newFakeServers(west1.URI, west2.URI)
	f.setRefuse(west1.URI, invalid)
	f.setRefuse(west2.URI, invalid)
	clk := newClock()
	p := NewPool(poolCfg("us-west", west1, west2), f.dial, noCheck, clk.Now, metrics.New(prometheus.NewRegistry()),
		(&lines{}).say)
	_, _ = p.Do(context.Background(), searchFor("(x)"))
	clk.Add(61 * time.Second)
	f.mu.Lock()
	f.dialDelay = 20 * time.Millisecond
	f.mu.Unlock()
	before := binds(f)
	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, _ = p.Do(context.Background(), searchFor("(x)")) }()
	}
	wg.Wait()
	if n := binds(f) - before; n != 1 {
		t.Fatalf("%d binds at the expiry, want 1", n)
	}
}

// The same for the first refusal: 200 concurrent first queries bind once.
func TestExactlyOneBindOnTheFirstRefusal(t *testing.T) {
	f := newFakeServers(west1.URI, west2.URI)
	f.setRefuse(west1.URI, ldap.NewError(ldap.LDAPResultInvalidCredentials, errors.New("invalid credentials")))
	f.dialDelay = 20 * time.Millisecond
	p := NewPool(poolCfg("us-west", west1, west2), f.dial, noCheck, newClock().Now, metrics.New(prometheus.NewRegistry()),
		(&lines{}).say)
	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, _ = p.Do(context.Background(), searchFor("(x)")) }()
	}
	wg.Wait()
	if n := binds(f); n != 1 {
		t.Fatalf("%d binds, want 1", n)
	}
}

// Only a refusal starts the hold-off (Re-review N-1): a dial that fails
// some other way (an unreachable KDC) is a fault, fails over and counts
// toward the breaker.
func TestAnUnknownDialErrorIsAFaultNotARefusal(t *testing.T) {
	f := newFakeServers(west1.URI, west2.URI)
	f.setRefuse(west1.URI, errors.New("gssapi: KDC unreachable"))
	m := metrics.New(prometheus.NewRegistry())
	p := NewPool(poolCfg("us-west", west1, west2), f.dial, noCheck, newClock().Now, m, (&lines{}).say)
	if srv, err := p.Do(context.Background(), searchFor("(x)")); err != nil || srv != west2 {
		t.Fatalf("%v %v", srv, err)
	}
	if testutil.ToFloat64(m.DirectoryBindHoldoff) != 0 ||
		testutil.ToFloat64(m.DirectoryQueries.WithLabelValues(west1.Label(), "fault")) != 1 {
		t.Fatal("an unknown dial error was not a plain fault")
	}
	if !Refusal(fmt.Errorf("x: %w", ErrBindRefused)) || !Refusal(ldap.NewError(ldap.LDAPResultStrongAuthRequired, errors.New("x"))) ||
		Refusal(errors.New("x")) || Refusal(ldap.NewError(ldap.ErrorNetwork, errors.New("x"))) {
		t.Fatal("Refusal misclassifies")
	}
}

func externalCfg(servers ...Server) Config {
	cfg := poolCfg("us-west", servers...)
	cfg.Bind.Mechanism = "external"
	return cfg
}

var errInvalid = ldap.NewError(ldap.LDAPResultInvalidCredentials, errors.New("invalid credentials"))

// Under external a refusal is the certificate's at that DC (unmapped, or its
// KDC down), not the shared service account's: the query fails over to the
// next DC at once, the pool is not held off, and the refuser waits out its
// own backoff alone (L44 OR-1).
func TestExternalOneRefusingDCFailsOverAtOnce(t *testing.T) {
	f := newFakeServers(west1.URI, west2.URI)
	f.setRefuse(west1.URI, errInvalid)
	clk := newClock()
	say := &lines{}
	m := metrics.New(prometheus.NewRegistry())
	p := NewPool(externalCfg(west1, west2), f.dial, noCheck, clk.Now, m, say.say)
	if srv, err := p.Do(context.Background(), searchFor("(x)")); err != nil || srv != west2 {
		t.Fatalf("first query: %v %v, want dc-02", srv, err)
	}
	if p.holdoffSeconds() != 0 || testutil.ToFloat64(m.DirectoryBindHoldoff) != 0 {
		t.Fatal("one refusing DC started the pool hold-off under external")
	}
	for i := 0; i < 5; i++ {
		clk.Add(10 * time.Second)
		if srv, err := p.Do(context.Background(), searchFor("(x)")); err != nil || srv != west2 {
			t.Fatalf("query %d: %v %v", i, srv, err)
		}
	}
	if f.dials[west1.URI] != 1 {
		t.Fatalf("dc-01 dialled %d times inside its own backoff", f.dials[west1.URI])
	}
	clk.Add(11 * time.Second) // past 1m
	p.Check(context.Background())
	if f.dials[west1.URI] != 2 {
		t.Fatalf("dc-01 dialled %d times after its backoff, want 2", f.dials[west1.URI])
	}
	if !say.has("refused the bind (external)") ||
		!say.has("a certificate that is not mapped, or that DC's KDC not answering (check its Kerberos service before the broker's certificate)") ||
		!say.has("failed over") || !say.has("its own backoff") {
		t.Fatalf("the refusal line lacks the AD hint or the fail-over note: %v", say.l)
	}
	if say.has("no server is bound for") {
		t.Fatalf("a hold-off line under external: %v", say.l)
	}
}

// Every DC refusing under external is today's behaviour: the pool hold-off
// starts and the lockout bound is N+4 failed binds in 30 minutes.
func TestExternalEveryDCRefusingBindsAtMostNPlusFour(t *testing.T) {
	servers := dcs(5)
	f := newFakeServers()
	for _, s := range servers {
		f.dirs[s.URI] = newFakeDir()
		f.setRefuse(s.URI, errInvalid)
	}
	clk := newClock()
	say := &lines{}
	m := metrics.New(prometheus.NewRegistry())
	p := NewPool(externalCfg(servers...), f.dial, noCheck, clk.Now, m, say.say)
	sawHold := false
	for at := time.Duration(0); at < 30*time.Minute; at += 6 * time.Second {
		if _, err := p.Do(context.Background(), searchFor("(x)")); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("at %v: %v", at, err)
		}
		if (at/(6*time.Second))%5 == 4 {
			p.Check(context.Background())
		}
		if testutil.ToFloat64(m.DirectoryBindHoldoff) > 0 {
			sawHold = true
		}
		clk.Add(6 * time.Second)
	}
	if !sawHold || !say.has("no server is bound for") {
		t.Fatalf("the pool hold-off never started: %v", say.l)
	}
	if n := binds(f); n > 9 {
		t.Fatalf("%d bind attempts in 30 minutes across 5 servers, want at most 9 (N+4)", n)
	}
}

// The hold-off starts at the refusal that leaves no server bindable.
func TestExternalTheSecondRefusalStartsTheHoldoff(t *testing.T) {
	f := newFakeServers(west1.URI, west2.URI)
	f.setRefuse(west1.URI, errInvalid)
	clk := newClock()
	m := metrics.New(prometheus.NewRegistry())
	p := NewPool(externalCfg(west1, west2), f.dial, noCheck, clk.Now, m, (&lines{}).say)
	// A query that finds dc-02 down as well refuses on dc-01 first.
	f.setRefuse(west2.URI, errInvalid)
	if _, err := p.Do(context.Background(), searchFor("(x)")); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("%v", err)
	}
	if p.holdoffSeconds() <= 0 {
		t.Fatal("every DC refused and the pool is not held off")
	}
}

func TestExternalFirstRefusalThenSecondLaterStartsTheHoldoff(t *testing.T) {
	f := newFakeServers(west1.URI, west2.URI)
	f.setRefuse(west1.URI, errInvalid)
	clk := newClock()
	p := NewPool(externalCfg(west1, west2), f.dial, noCheck, clk.Now, metrics.New(prometheus.NewRegistry()), (&lines{}).say)
	if srv, err := p.Do(context.Background(), searchFor("(x)")); err != nil || srv != west2 {
		t.Fatalf("%v %v", srv, err)
	}
	if p.holdoffSeconds() != 0 {
		t.Fatal("hold-off after one refusal")
	}
	// dc-02 loses its connection and now refuses too, inside dc-01's backoff.
	p.mu.Lock()
	_ = p.srv[1].conn.Close()
	p.srv[1].conn = nil
	p.srv[1].gen++
	p.mu.Unlock()
	f.setRefuse(west2.URI, errInvalid)
	clk.Add(10 * time.Second)
	if _, err := p.Do(context.Background(), searchFor("(x)")); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("%v", err)
	}
	if p.holdoffSeconds() <= 0 {
		t.Fatal("the second refusal, with dc-01 still in its backoff, did not start the hold-off")
	}
}

// AD takes EXTERNAL only over StartTLS: a 7 over ldaps:// says so and names
// the key; the same 7 over ldap:// with start_tls does not.
func TestExternalAuthMethodNotSupportedOverLdapsNamesStartTLS(t *testing.T) {
	notSupported := ldap.NewError(ldap.LDAPResultAuthMethodNotSupported, errors.New("auth method not supported"))
	run := func(s Server) *lines {
		f := newFakeServers(s.URI)
		f.setRefuse(s.URI, notSupported)
		say := &lines{}
		p := NewPool(externalCfg(s), f.dial, noCheck, newClock().Now, metrics.New(prometheus.NewRegistry()), say.say)
		_, _ = p.Do(context.Background(), searchFor("(x)"))
		return say
	}
	const hint = "Active Directory takes SASL EXTERNAL only over StartTLS ([MS-ADTS] 5.1.1.2): use ldap:// with start_tls: true"
	if say := run(west1); !say.has(hint) {
		t.Fatalf("no StartTLS hint over ldaps: %v", say.l)
	}
	if say := run(Server{URI: "ldap://dc-01", Priority: 100, Site: "us-west", StartTLS: true}); say.has("StartTLS") ||
		!say.has("refused the bind (external)") {
		t.Fatalf("ldap+StartTLS 7: %v", say.l)
	}
}

// The AD hint belongs to external's 49 alone.
func TestTheExternalHintIsNotSaidForOtherMechanisms(t *testing.T) {
	f := newFakeServers(west1.URI)
	f.setRefuse(west1.URI, errInvalid)
	say := &lines{}
	p := NewPool(poolCfg("us-west", west1), f.dial, noCheck, newClock().Now, metrics.New(prometheus.NewRegistry()), say.say)
	_, _ = p.Do(context.Background(), searchFor("(x)"))
	if say.has("Kerberos service") || say.has("failed over") {
		t.Fatalf("external hint under simple: %v", say.l)
	}
}

// Under simple one refusing DC still holds the whole pool off (the lockout
// is shared); see also TestABindRefusalReachesUnavailableAndBindsNoOtherServer.
func TestSimpleOneRefusingDCStillHoldsTheWholePoolOff(t *testing.T) {
	f := newFakeServers(west1.URI, west2.URI)
	f.setRefuse(west1.URI, errInvalid)
	p := NewPool(poolCfg("us-west", west1, west2), f.dial, noCheck, newClock().Now, metrics.New(prometheus.NewRegistry()), (&lines{}).say)
	_, _ = p.Do(context.Background(), searchFor("(x)"))
	if p.holdoffSeconds() <= 0 || f.dials[west2.URI] != 0 {
		t.Fatalf("simple: hold-off %v, dc-02 dialled %d", p.holdoffSeconds(), f.dials[west2.URI])
	}
}
