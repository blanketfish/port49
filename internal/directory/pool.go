package directory

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"slices"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/printsafe"
)

// Searcher is what one query sees: a connection whose searches are
// bounded by that query's deadline.
type Searcher interface {
	Search(req *ldap.SearchRequest) (*ldap.SearchResult, error)
	SearchWithPaging(req *ldap.SearchRequest, pagingSize uint32) (*ldap.SearchResult, error)
}

// Client is one bound connection to one server, shared by concurrent
// queries. SearchContext past ctx abandons its own message and returns
// ctx.Err(), leaving the connection and every other search on it alone
// (pre-flight I-3). pagingSize 0 is one unpaged search.
type Client interface {
	SearchContext(ctx context.Context, req *ldap.SearchRequest, pagingSize uint32) (*ldap.SearchResult, error)
	Close() error
}

// Dialer opens and binds a connection to s within ctx.
type Dialer func(ctx context.Context, s Server) (Client, error)

// ErrUnavailable is no server answering a query within query_timeout:
// directory_unavailable unless grace serves it (spec §5.7).
var ErrUnavailable = errors.New("directory: no server answered")

// Fault reports whether err is the server's fault rather than the query's
// answer (Ruling 9): it counts toward the server's breaker and fails the
// query over.
func Fault(err error) bool {
	var ne net.Error
	switch {
	case err == nil:
		return false
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne):
		return true
	}
	for _, code := range []uint16{ldap.ErrorNetwork, ldap.LDAPResultBusy, ldap.LDAPResultUnavailable,
		ldap.LDAPResultUnwillingToPerform, ldap.LDAPResultOther, ldap.LDAPResultTimeLimitExceeded} {
		if ldap.IsErrorWithCode(err, code) {
			return true
		}
	}
	return false
}

// Label names a server in the log and in metric labels: its host:port, the
// scheme's default port when the URI has none. The config refuses userinfo
// in a URI and two servers with one label, and nothing past the authority is
// needed to tell servers apart.
func (s Server) Label() string {
	u, err := url.Parse(s.URI)
	if err != nil || u.Host == "" {
		return s.URI
	}
	if u.Port() == "" {
		switch u.Scheme {
		case "ldaps":
			return net.JoinHostPort(u.Hostname(), "636")
		case "ldap":
			return net.JoinHostPort(u.Hostname(), "389")
		}
	}
	return u.Host
}

type serverState struct {
	Server
	conn         Client
	gen          int       // bumped each time the pool closes or replaces conn
	refusedSaid  time.Time // the last bind refusal said (once an hour)
	faults       int       // consecutive
	open         bool      // the breaker
	openedAt     time.Time // its last probe or opening
	healthySince time.Time // the first pass since the last fault; zero while faulting
}

// Pool is design §10's server pool. One pool per broker process; every
// query and every health check goes through it.
type Pool struct {
	cfg   Config
	dial  Dialer
	check func(ctx context.Context, s Searcher) error
	now   func() time.Time
	m     *metrics.Metrics
	say   func(format string, args ...any)

	mu  sync.Mutex
	srv []*serverState // ranked
	sel int            // index into srv; -1 none yet

	// The bind hold-off (Ruling PF7g-g): one service account serves every
	// server, and the directory counts failed binds from all of them toward
	// one lockout. holdStep is the current backoff, 0 when clear; no server
	// without a bound connection is dialled before holdUntil, and after it
	// exactly one probe bind (probing) decides.
	holdUntil time.Time
	holdStep  time.Duration
	probing   bool
}

const (
	holdoffFirst = time.Minute
	holdoffCap   = 15 * time.Minute
)

// errHoldoff is a dial the bind hold-off did not allow: no fault, no refusal.
var errHoldoff = errors.New("bind hold-off in force")

// NewPool ranks cfg.Servers same-site first, then by priority descending,
// then in file order. check is the health check's query on a bound
// connection (RootDSE outside tests).
func NewPool(cfg Config, dial Dialer, check func(ctx context.Context, s Searcher) error, now func() time.Time,
	m *metrics.Metrics, say func(format string, args ...any)) *Pool {
	p := &Pool{cfg: cfg, dial: dial, check: check, now: now, m: m, say: say, sel: -1}
	m.SetDirectoryBindHoldoff(p.holdoffSeconds)
	for _, s := range cfg.Servers {
		p.srv = append(p.srv, &serverState{Server: s})
		m.DirectoryServerUp.WithLabelValues(s.Label()).Set(1)
		m.DirectorySelected.WithLabelValues(s.Label()).Set(0)
	}
	slices.SortStableFunc(p.srv, func(a, b *serverState) int {
		if cfg.Site != "" {
			ah, bh := a.Site == cfg.Site, b.Site == cfg.Site
			if ah != bh {
				if ah {
					return -1
				}
				return 1
			}
		}
		return b.Priority - a.Priority
	})
	return p
}

// Ranked is the servers in the order selection prefers them.
func (p *Pool) Ranked() []Server {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]Server, len(p.srv))
	for i, s := range p.srv {
		out[i] = s.Server
	}
	return out
}

// Selected is the sticky selection, and false before the first.
func (p *Pool) Selected() (Server, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.sel < 0 {
		return Server{}, false
	}
	return p.srv[p.sel].Server, true
}

// Do runs f on the selected server, failing over to the next closed one
// in rank on a server fault, within query_timeout for the whole query. A
// query error that is the server's answer is returned as it is, from the
// server that gave it. A dial or bind the server refused is that server
// not answering (pre-flight I-2): the query fails over. No server
// answering is ErrUnavailable, wrapping the last fault or refusal, so
// grace applies above. A caller that went away is no fault (its ctx's
// error).
func (p *Pool) Do(ctx context.Context, f func(Searcher) error) (Server, error) {
	qctx, cancel := context.WithTimeout(ctx, p.cfg.QueryTimeout)
	defer cancel()
	tried := map[int]bool{}
	var last error
	for {
		if ctx.Err() != nil {
			return Server{}, ctx.Err()
		}
		if last != nil && qctx.Err() != nil {
			// The budget is spent: no server is charged a fault for time it
			// was never given.
			return Server{}, fmt.Errorf("%w (the last: %v)", ErrUnavailable, last)
		}
		i, conn, gen, err := p.acquire(qctx, tried)
		if i < 0 {
			if last == nil {
				last = errors.New("every server's breaker is open")
				if p.holding() {
					last = errors.New("a directory server refused the bind; no server is bound until the hold-off ends")
				}
			}
			return Server{}, fmt.Errorf("%w (the last: %v)", ErrUnavailable, last)
		}
		tried[i] = true
		srv := p.srv[i].Server
		if errors.Is(err, errHoldoff) {
			last = fmt.Errorf("%s: %v", srv.Label(), err)
			continue
		}
		if err == nil {
			err = f(bound{ctx: qctx, c: conn})
		} else if ctx.Err() == nil && !Fault(err) {
			p.refused(i, err)
			p.moveFrom(i)
			last = fmt.Errorf("%s: %v", srv.Label(), err)
			continue
		}
		if ctx.Err() != nil {
			// A caller that went away is no fault. Its own search was
			// abandoned; the connection stays for every other query.
			return Server{}, ctx.Err()
		}
		if err != nil && last != nil && qctx.Err() != nil {
			// The budget ran out inside this later server's turn: it was
			// never given the time, so it is charged no fault.
			return Server{}, fmt.Errorf("%w (the last: %v)", ErrUnavailable, err)
		}
		switch {
		case err == nil:
			p.answered(i, "ok")
			return srv, nil
		case !Fault(err):
			p.answered(i, "error")
			return srv, err
		}
		p.fault(i, gen, err)
		p.moveFrom(i)
		last = fmt.Errorf("%s: %v", srv.Label(), err)
	}
}

// bound is a Client as one query sees it: every search under the query's
// deadline.
type bound struct {
	ctx context.Context
	c   Client
}

func (b bound) Search(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
	return b.c.SearchContext(b.ctx, req, 0)
}

func (b bound) SearchWithPaging(req *ldap.SearchRequest, pagingSize uint32) (*ldap.SearchResult, error) {
	return b.c.SearchContext(b.ctx, req, pagingSize)
}

// moveFrom ends the sticky selection of i after a query's fault on it:
// the next closed server in rank after i is selected, one with no faults
// first (Ruling 9). Only Check moves a selection back up.
func (p *Pool) moveFrom(i int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.sel != i {
		return
	}
	if j := p.bestLocked(i); j >= 0 {
		p.selectLocked(j, "")
	}
}

// bestLocked is the best closed server other than skip: same-site before
// remote (a local server with a fault still beats crossing sites), and
// within a site one with no faults in a row before one with some, in rank
// order; -1 for none.
func (p *Pool) bestLocked(skip int) int {
	best, bestTier := -1, 0
	for j, s := range p.srv {
		if j == skip || s.open {
			continue
		}
		tier := 0
		if p.cfg.Site != "" && s.Site != p.cfg.Site {
			tier += 2
		}
		if s.faults > 0 {
			tier++
		}
		if best < 0 || tier < bestTier {
			best, bestTier = j, tier
		}
	}
	return best
}

// acquire is the server a query tries next: the selected one if its
// breaker is closed and it is untried, else the best-ranked such, which is
// then selected. It dials when the server holds no connection; queries
// racing to dial keep the first connection and close the others
// (pre-flight M-8). gen is the connection's generation, for fault. -1 is
// none.
func (p *Pool) acquire(ctx context.Context, tried map[int]bool) (int, Client, int, error) {
	p.mu.Lock()
	i := -1
	holding := p.holdingLocked()
	// Under a hold-off only a server with a bound connection is eligible.
	eligible := func(j int) bool {
		s := p.srv[j]
		return !s.open && !tried[j] && (s.conn != nil || !holding)
	}
	if p.sel >= 0 && eligible(p.sel) {
		i = p.sel
	} else {
		for j := range p.srv {
			if eligible(j) {
				i = j
				break
			}
		}
	}
	if i < 0 {
		p.mu.Unlock()
		return -1, nil, 0, nil
	}
	if i != p.sel {
		p.selectLocked(i, "")
	}
	s := p.srv[i]
	conn, gen := s.conn, s.gen
	if conn != nil {
		p.mu.Unlock()
		return i, conn, gen, nil
	}
	allowed, probe := p.bindAllowedLocked()
	p.mu.Unlock()
	if !allowed {
		return i, nil, gen, errHoldoff
	}
	conn, err := p.dial(ctx, s.Server)
	p.mu.Lock()
	defer p.mu.Unlock()
	p.bindDoneLocked(s, probe, err)
	if err != nil {
		return i, nil, gen, err
	}
	if s.conn != nil {
		_ = conn.Close()
		return i, s.conn, s.gen, nil
	}
	s.conn = conn
	s.gen++
	return i, conn, s.gen, nil
}

func (p *Pool) answered(i int, outcome string) {
	p.m.DirectoryQueries.WithLabelValues(p.srv[i].Label(), outcome).Inc()
	p.mu.Lock()
	defer p.mu.Unlock()
	p.srv[i].faults = 0
}

// broken reports whether err leaves the connection unusable: a network
// error. A deadline abandons its own search alone (pre-flight I-3), and a
// server's busy or unavailable answer arrived on a working connection.
func broken(err error) bool {
	var ne net.Error
	return ldap.IsErrorWithCode(err, ldap.ErrorNetwork) || (errors.As(err, &ne) && !ne.Timeout())
}

// fault counts a server fault against i: a broken connection is dropped,
// its stability window restarts, and failure_threshold in a row open its
// breaker. gen is the generation of the connection the fault came on; an
// error on a connection the pool has since closed or replaced is no fault
// of the server's and counts nothing. A health check passes gen -1.
func (p *Pool) fault(i, gen int, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	s := p.srv[i]
	if gen >= 0 && gen != s.gen {
		return
	}
	p.m.DirectoryQueries.WithLabelValues(s.Label(), "fault").Inc()
	if s.conn != nil && gen >= 0 && broken(err) {
		_ = s.conn.Close()
		s.conn = nil
		s.gen++
	}
	s.faults++
	s.healthySince = time.Time{}
	if !s.open && s.faults >= p.cfg.FailureThreshold {
		s.open, s.openedAt = true, p.now()
		p.m.DirectoryServerUp.WithLabelValues(s.Label()).Set(0)
		p.say("directory: %s: %d faults in a row (the last: %s); its breaker is open; probed every %s", s.Label(),
			s.faults, printsafe.Line(err.Error(), 300), p.cfg.ProbeInterval)
		if s.conn != nil {
			_ = s.conn.Close()
			s.conn = nil
			s.gen++
		}
	}
}

// refused is a dial or bind the server refused without a fault
// (pre-flight I-2): invalid credentials (49), strongAuthRequired,
// confidentialityRequired, a KDC's refusal. The breaker's count is left as
// it is, neither raised (a wrong password is not a down server) nor reset.
//
// The refusal is the shared service account's, so it starts a pool-wide
// bind hold-off (Ruling PF7g-g): 1m, doubling per further refusal to 15m.
// Until it ends no server without a bound connection is dialled, and one
// probe bind decides after it; AD counts failed binds from every DC toward
// one lockout, and a locked account stays locked after the password is
// fixed. Said once per server an hour with the mechanism and the result
// code, and at each hold-off step with the next attempt's time; the error
// carries neither the password nor the keytab (Task 7). Operators: exempt
// the service account from lockout or set its threshold above 6 per 30
// minutes.
func (p *Pool) refused(i int, err error) {
	p.m.DirectoryQueries.WithLabelValues(p.srv[i].Label(), "refused").Inc()
	p.mu.Lock()
	defer p.mu.Unlock()
	s := p.srv[i]
	// A server that refuses has not passed every check: its stability window
	// restarts, so failback does not return to it every interval. faults is
	// left as it is.
	s.healthySince = time.Time{}
	now := p.now()
	p.probing = false
	if p.holdStep == 0 || !now.Before(p.holdUntil) {
		switch {
		case p.holdStep == 0:
			p.holdStep = holdoffFirst
		default:
			p.holdStep = min(2*p.holdStep, holdoffCap)
		}
		p.holdUntil = now.Add(p.holdStep)
		p.say("directory: %s refused the bind; no server is bound for %s, until %s (the next attempt is one probe "+
			"bind); queries on a bound connection continue, and the rest fall to directory.grace",
			s.Label(), p.holdStep, p.holdUntil.UTC().Format(time.RFC3339))
	}
	if !s.refusedSaid.IsZero() && now.Sub(s.refusedSaid) < time.Hour {
		return
	}
	s.refusedSaid = now
	p.say("directory: %s refused the bind (%s): %s", s.Label(), p.cfg.Bind.Mechanism,
		printsafe.Line(err.Error(), 300))
}

// holdingLocked reports whether a dial to a server with no bound
// connection is barred now: inside the hold-off, or while its probe runs.
func (p *Pool) holdingLocked() bool {
	return p.holdStep > 0 && (p.now().Before(p.holdUntil) || p.probing)
}

func (p *Pool) holding() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.holdingLocked()
}

// bindAllowedLocked is whether a bind may be made now, and whether it is
// the probe after a hold-off, of which only one runs at a time.
func (p *Pool) bindAllowedLocked() (allowed, probe bool) {
	switch {
	case p.holdStep == 0:
		return true, false
	case p.now().Before(p.holdUntil), p.probing:
		return false, false
	}
	p.probing = true
	return true, true
}

// bindDoneLocked ends a bind attempt: an accepted one clears the hold-off
// and its backoff; a probe that failed otherwise lets the next one probe (a
// refusal, which doubles the hold-off, is counted by refused).
func (p *Pool) bindDoneLocked(s *serverState, probe bool, err error) {
	if probe {
		p.probing = false
	}
	if err == nil && p.holdStep > 0 {
		p.holdStep, p.holdUntil = 0, time.Time{}
		p.say("directory: %s accepted the bind; the bind hold-off cleared", s.Label())
	}
}

// holdoffSeconds is what port49_directory_bind_holdoff_seconds reports.
func (p *Pool) holdoffSeconds() float64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	if left := p.holdUntil.Sub(p.now()); p.holdStep > 0 && left > 0 {
		return left.Seconds()
	}
	return 0
}

// selectLocked makes i the sticky selection, saying so, and a site
// crossing as a consistency event (design §10). why, when set, is said
// instead of the plain line.
func (p *Pool) selectLocked(i int, why string) {
	prev := p.sel
	p.sel = i
	s := p.srv[i]
	for _, o := range p.srv {
		p.m.DirectorySelected.WithLabelValues(o.Label()).Set(0)
	}
	p.m.DirectorySelected.WithLabelValues(s.Label()).Set(1)
	if why != "" {
		p.say("%s", why)
	} else {
		p.say("directory: selected %s (%s, priority %d)", s.Label(), or(s.Site, "no site"), s.Priority)
	}
	from, fromURI := p.cfg.Site, ""
	if prev >= 0 {
		from, fromURI = p.srv[prev].Site, p.srv[prev].Label()
	}
	// With a broker site, the first selection is measured from it; without
	// one, a change between two selections is the crossing (pre-flight M-7).
	if (p.cfg.Site != "" || prev >= 0) && s.Site != from {
		p.m.DirectorySiteCrossings.Inc()
		p.say("directory: consistency event: crossing from site %s to %s (%s to %s); membership read there may lag "+
			"replication from %s", or(from, "none"), or(s.Site, "none"), or(fromURI, "none"), s.Label(), or(from, "none"))
	}
}

// Check is one round of health checks (Ruling 9): every server whose
// breaker is closed, or open past probe_interval, is dialled, bound and
// checked within health_check.timeout, on a connection of its own that it
// closes. A refused bind is said and counts nothing. Then failback: a
// server ranked above the selection that has passed every check for
// stability_window is selected. With nothing selected, the best closed
// server is.
func (p *Pool) Check(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	now := p.now()
	for i, s := range p.srv {
		p.mu.Lock()
		skip := s.open && now.Sub(s.openedAt) < p.cfg.ProbeInterval
		var allowed, probe bool
		if !skip {
			allowed, probe = p.bindAllowedLocked()
			skip = !allowed
		}
		if s.open && !skip {
			s.openedAt = now // a probe resets its clock
		}
		p.mu.Unlock()
		if skip {
			continue
		}
		cctx, cancel := context.WithTimeout(ctx, p.cfg.HealthTimeout)
		conn, err := p.dial(cctx, s.Server)
		p.mu.Lock()
		p.bindDoneLocked(s, probe, err)
		p.mu.Unlock()
		dialed := err == nil
		if dialed {
			err = p.check(cctx, bound{ctx: cctx, c: conn})
			_ = conn.Close()
		}
		cancel()
		if ctx.Err() != nil {
			return
		}
		switch {
		case err != nil && !dialed && !Fault(err):
			p.refused(i, err)
			continue
		case err != nil:
			p.fault(i, -1, err)
			continue
		}
		p.mu.Lock()
		s.faults = 0
		if s.open {
			s.open = false
			p.m.DirectoryServerUp.WithLabelValues(s.Label()).Set(1)
			p.say("directory: %s answers its health check again; its breaker is closed", s.Label())
		}
		if s.healthySince.IsZero() {
			s.healthySince = now
		}
		p.mu.Unlock()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.sel < 0 || p.srv[p.sel].open {
		if j := p.bestLocked(-1); j >= 0 {
			p.selectLocked(j, "")
		}
		return
	}
	for j := 0; j < p.sel; j++ {
		s := p.srv[j]
		if !s.open && !s.healthySince.IsZero() && now.Sub(s.healthySince) >= p.cfg.StabilityWindow {
			p.selectLocked(j, fmt.Sprintf("directory: %s passed every health check for %s (failback.stability_window); "+
				"selected again", s.Label(), p.cfg.StabilityWindow))
			return
		}
	}
}

// Run checks every health_check.interval until ctx ends, starting at once,
// and closes every bound connection when it returns.
func (p *Pool) Run(ctx context.Context) {
	defer p.closeConns()
	t := time.NewTicker(p.cfg.HealthInterval)
	defer t.Stop()
	for {
		p.Check(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// closeConns closes every bound connection, bumping gen so an error on one
// counts as no fault.
func (p *Pool) closeConns() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, s := range p.srv {
		if s.conn != nil {
			_ = s.conn.Close()
			s.conn = nil
			s.gen++
		}
	}
}

func or(s, d string) string {
	if s == "" {
		return d
	}
	return s
}
