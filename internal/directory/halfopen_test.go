package directory

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/blanketfish/port49/internal/daemon/metrics"
)

// silentLDAPConn is a real go-ldap connection whose peer reads every request
// and never answers or closes: what a NAT or firewall that dropped its state
// leaves behind (no RST, no FIN).
func silentLDAPConn(t *testing.T) *ldap.Conn {
	t.Helper()
	cc, sc := net.Pipe()
	go func() { _, _ = io.Copy(io.Discard, sc) }()
	conn := ldap.NewConn(cc, false)
	conn.Start()
	t.Cleanup(func() { conn.Close(); sc.Close() })
	return conn
}

// A pooled connection that went half-open must not outlive the query it
// timed. Before the fix the pool kept it, and every later query waited its
// full query_timeout on the dead socket while the health check, which dials
// a fresh connection, kept the server looking healthy (audit F1-3).
func TestAHalfOpenPooledConnectionIsReplacedAfterOneTimeout(t *testing.T) {
	w := newWorld(t)
	cfg := w.r.Cfg
	cfg.QueryTimeout = 300 * time.Millisecond
	silent := silentLDAPConn(t)
	dials := 0
	dial := func(context.Context, Server) (Client, error) {
		dials++
		if dials == 1 {
			return ldapClient{c: silent}, nil
		}
		return ldapClient{c: &scriptedConn{pages: []scriptedPage{{entries: []*ldap.Entry{pageEntry("cn=a")}}, {}, {}}}}, nil
	}
	m := metrics.New(prometheus.NewRegistry())
	p := NewPool(cfg, dial, noCheck, w.clk.Now, m, w.say.say)
	q := func() (*ldap.SearchResult, error) {
		var res *ldap.SearchResult
		_, err := p.Do(context.Background(), func(s Searcher) (err error) { res, err = s.Search(searchReq()); return })
		return res, err
	}
	if _, err := q(); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("the query on the silent connection: %v, want ErrUnavailable", err)
	}
	if !silent.IsClosing() {
		t.Error("the pool kept the half-open connection after a query got no response on it")
	}
	start := time.Now()
	res, err := q()
	if err != nil || len(res.Entries) != 1 {
		t.Fatalf("the next query: %d entries, %v; want an answer on a fresh dial", len(res.Entries), err)
	}
	if d := time.Since(start); d >= cfg.QueryTimeout || dials != 2 {
		t.Errorf("the next query took %v after %d dial(s); want a fresh dial and no wait", d, dials)
	}
}

// Faults earned on a pooled connection are not cleared by a health check that
// dialled a connection of its own: three slow queries on one connection, a
// passing check between each, still open the breaker.
func TestAPassingHealthCheckDoesNotClearAPooledConnectionsFaults(t *testing.T) {
	f := newFakeServers(west1.URI)
	f.dirs[west1.URI].slow["(slow)"] = 2 * time.Second
	cfg := poolCfg("us-west", west1)
	cfg.QueryTimeout = 100 * time.Millisecond
	m := metrics.New(prometheus.NewRegistry())
	say := &lines{}
	p := NewPool(cfg, f.dial, noCheck, newClock().Now, m, say.say)
	for i := 0; i < 3; i++ {
		_, _ = p.Do(context.Background(), searchFor("(slow)"))
		p.Check(context.Background())
	}
	if testutil.ToFloat64(m.DirectoryServerUp.WithLabelValues(west1.Label())) != 0 {
		t.Fatalf("three faults on one connection did not open the breaker; the health check cleared them: %v", say.l)
	}
}

// hangConn is a searchConn whose searches get no answer until their context
// ends. bump, when set, runs as the search starts waiting: another search on
// the connection being answered.
type hangConn struct{ bump func() }

func (hangConn) IsClosing() bool { return false }
func (hangConn) Close() error    { return nil }
func (h hangConn) SearchAsync(ctx context.Context, _ *ldap.SearchRequest, _ int) ldap.Response {
	return hangResponse{ctx: ctx, bump: h.bump}
}

type hangResponse struct {
	ctx  context.Context
	bump func()
}

func (r hangResponse) Next() bool {
	if r.bump != nil {
		r.bump()
	}
	<-r.ctx.Done()
	return false
}
func (hangResponse) Entry() *ldap.Entry       { return nil }
func (hangResponse) Referral() string         { return "" }
func (hangResponse) Controls() []ldap.Control { return nil }
func (hangResponse) Err() error               { return nil }

// A search that times out while the connection is still answering others is
// only slow: it is no half-open connection, and the connection stays.
func TestATimeoutWhileTheConnectionAnswersOthersIsNotUnresponsive(t *testing.T) {
	seen := new(atomic.Uint64)
	run := func(c ldapClient) error {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		_, err := c.SearchContext(ctx, searchReq(), 0)
		return err
	}
	var u unresponsiveError
	if err := run(ldapClient{c: hangConn{}, seen: seen}); !errors.As(err, &u) || !Fault(err) {
		t.Fatalf("a silent connection: %v, want an unresponsive fault", err)
	}
	err := run(ldapClient{c: hangConn{bump: func() { seen.Add(1) }}, seen: seen})
	if errors.As(err, &u) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("a connection answering another search: %v, want a plain deadline", err)
	}
}

// A caller whose own deadline is shorter than query_timeout leaves no
// half-open connection behind either: the query is its ctx's error, no fault,
// and the silent connection is still dropped.
func TestAHalfOpenConnectionIsDroppedWhenTheCallersDeadlineEndsFirst(t *testing.T) {
	w := newWorld(t)
	closed := &closeCounter{hangConn: hangConn{}}
	dials := 0
	dial := func(context.Context, Server) (Client, error) {
		dials++
		if dials == 1 {
			return ldapClient{c: closed}, nil
		}
		return ldapClient{c: &scriptedConn{pages: []scriptedPage{{entries: []*ldap.Entry{pageEntry("cn=a")}}}}}, nil
	}
	m := metrics.New(prometheus.NewRegistry())
	p := NewPool(w.r.Cfg, dial, noCheck, w.clk.Now, m, w.say.say)
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	if _, err := p.Do(ctx, func(s Searcher) error { _, err := s.Search(searchReq()); return err }); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("the caller's deadline: %v", err)
	}
	if closed.n.Load() != 1 {
		t.Fatalf("the silent connection was closed %d times, want once", closed.n.Load())
	}
	if n := testutil.ToFloat64(m.DirectoryQueries.WithLabelValues(dc01Label(w), "fault")); n != 0 {
		t.Fatalf("%v faults counted for a caller that went away", n)
	}
	if _, err := p.Do(context.Background(), func(s Searcher) error { _, err := s.Search(searchReq()); return err }); err != nil || dials != 2 {
		t.Fatalf("the next query: %v after %d dial(s), want an answer on a fresh dial", err, dials)
	}
}

type closeCounter struct {
	hangConn
	n atomic.Int32
}

func (c *closeCounter) Close() error { c.n.Add(1); return nil }

func dc01Label(w *world) string { return w.r.Cfg.Servers[0].Label() }
