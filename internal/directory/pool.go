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

// errWaitEnded is a query's budget ending while it waited for another
// query's dial: that dial's outcome is the only one charged to the server.
var errWaitEnded = errors.New("budget spent waiting for another query's dial")

// ErrBindRefused is what a Dialer wraps a refusal in that is not an LDAP
// result code (a KDC refusing the principal): the credential was refused,
// not the server down.
var ErrBindRefused = errors.New("directory: bind refused")

// Refusal reports whether a dial error is the credential refused rather
// than the server not answering: invalidCredentials (49),
// inappropriateAuthentication (48), strongAuthRequired (8),
// confidentialityRequired (13), authMethodNotSupported (7), or
// ErrBindRefused. Only a refusal starts the bind hold-off (under external,
// only when every server is refusing); any other dial error is a fault.
func Refusal(err error) bool {
	if errors.Is(err, ErrBindRefused) {
		return true
	}
	for _, code := range []uint16{ldap.LDAPResultInvalidCredentials, ldap.LDAPResultInappropriateAuthentication,
		ldap.LDAPResultStrongAuthRequired, ldap.LDAPResultConfidentialityRequired, ldap.LDAPResultAuthMethodNotSupported} {
		if ldap.IsErrorWithCode(err, code) {
			return true
		}
	}
	return false
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

	// This server's own refusal backoff, 1m doubling to 15m, cleared only by
	// its own accepted bind: a DC that cannot map the certificate, or has
	// not yet replicated a rotated password, is not dialled again until it
	// ends, whatever the pool's hold-off says.
	refuseUntil time.Time
	refuseStep  time.Duration
	dialing     chan struct{} // non-nil while a query binds this server; the others wait for it
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
		if errors.Is(err, errWaitEnded) {
			if ctx.Err() != nil {
				return Server{}, ctx.Err()
			}
			return Server{}, fmt.Errorf("%w (the last: %s: %v)", ErrUnavailable, srv.Label(), err)
		}
		dialErr := err != nil
		if err == nil {
			err = f(bound{ctx: qctx, c: conn})
		} else if ctx.Err() == nil && Refusal(err) {
			// The refusal is counted and the hold-off stepped as the bind
			// ended (bindDoneLocked); the query fails over to a server
			// already bound.
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
		case !dialErr && !Fault(err):
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
		if s.conn == nil && p.now().Before(s.refuseUntil) {
			tier += 4 // not bindable until its own backoff ends
		}
		if best < 0 || tier < bestTier {
			best, bestTier = j, tier
		}
	}
	return best
}

// orderLocked is the order servers are tried to bind: those that have not
// refused first (fewest refusals, then rank), so a probe goes to the
// best-ranked server not under refusal and a server that has refused is
// probed again only when none that has not is bindable.
func (p *Pool) orderLocked() []int {
	order := make([]int, len(p.srv))
	for j := range order {
		order[j] = j
	}
	slices.SortStableFunc(order, func(a, b int) int { return int(p.srv[a].refuseStep - p.srv[b].refuseStep) })
	return order
}

// acquire is the server a query tries next: the selected one if its
// breaker is closed, it is untried and it can be used, else the best such,
// which is then selected. A server with no connection can be used when the
// bind hold-off and its own backoff allow a bind (bindableLocked). It dials
// when the server holds no connection; queries racing to dial wait for the
// one dial rather than each binding (pre-flight M-8, Re-review I-3). gen
// is the connection's generation, for fault. -1 is none.
func (p *Pool) acquire(ctx context.Context, tried map[int]bool) (int, Client, int, error) {
	for {
		p.mu.Lock()
		i := -1
		eligible := func(j int) bool {
			s := p.srv[j]
			return !s.open && !tried[j] && (s.conn != nil || s.dialing != nil || p.bindableLocked(s))
		}
		// The selection is kept unless it is an unbound server that has
		// refused: then the order below finds a better one to bind.
		if p.sel >= 0 && eligible(p.sel) && (p.srv[p.sel].conn != nil || p.srv[p.sel].refuseStep == 0) {
			i = p.sel
		} else {
			for _, j := range p.orderLocked() {
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
		if s.conn != nil {
			conn, gen := s.conn, s.gen
			p.mu.Unlock()
			return i, conn, gen, nil
		}
		if wait := s.dialing; wait != nil {
			p.mu.Unlock()
			select {
			case <-wait:
				continue
			case <-ctx.Done():
				return i, nil, 0, errWaitEnded
			}
		}
		probe := p.beginBindLocked()
		s.dialing = make(chan struct{})
		gen := s.gen
		p.mu.Unlock()
		conn, err := p.dial(ctx, s.Server)
		p.mu.Lock()
		defer p.mu.Unlock()
		close(s.dialing)
		s.dialing = nil
		p.bindDoneLocked(s, probe, err)
		if err != nil {
			return i, nil, gen, err
		}
		s.conn = conn
		s.gen++
		return i, conn, s.gen, nil
	}
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

// bindableLocked reports whether a bind to s may be made now (Ruling
// PF7g-g). A refusal is the shared service account's, so it starts a
// pool-wide bind hold-off, 1m doubling per further refusal to 15m, during
// which no server without a bound connection is dialled; AD counts failed
// binds from every DC toward one lockout, and a locked account stays
// locked after the password is fixed. After it exactly one probe bind
// decides. A refusal is also its server's own: s is not dialled again until
// its own backoff (the same schedule) ends, and orderLocked tries servers
// that have not refused first, so one misconfigured DC does not hold off
// the good ones. Under external the hold-off starts only when every server
// is under its own backoff (holdsOffLocked): one DC's refusal holds that DC
// off alone and the query fails over. Any accepted bind clears the pool's
// hold-off; a server's own backoff clears only on its own accepted bind.
func (p *Pool) bindableLocked(s *serverState) bool {
	now := p.now()
	switch {
	case now.Before(s.refuseUntil):
		return false
	case p.holdStep == 0:
		return true
	}
	return !now.Before(p.holdUntil) && !p.probing
}

// leaveRefuserLocked is whether Check leaves a server that has refused
// alone this round: nothing is bound yet and another closed server has
// never refused, so a query is about to bind that one and a refusal here
// would start a hold-off in its way. Once a server is bound, or when every
// server has refused, a refuser is retried per its own backoff.
func (p *Pool) leaveRefuserLocked(s *serverState) bool {
	if s.refuseStep == 0 {
		return false
	}
	good := false
	for _, o := range p.srv {
		switch {
		case o == s:
		case o.conn != nil:
			return false
		case !o.open && o.refuseStep == 0:
			good = true
		}
	}
	return good
}

// beginBindLocked marks the start of a bind: after a hold-off it is the
// probe, of which one runs at a time.
func (p *Pool) beginBindLocked() (probe bool) {
	if p.holdStep > 0 {
		p.probing = true
		return true
	}
	return false
}

// bindDoneLocked ends a bind attempt, under the lock that ended the dial so
// no other bind starts between the dial's end and the step it causes
// (Re-review I-3). An accepted bind clears the pool's hold-off and the
// server's own backoff. A refusal is counted, restarts the server's
// stability window (it has not passed every check; faults is left as it is,
// neither raised, since a wrong password is not a down server, nor reset),
// steps its own backoff, and starts or steps the pool's hold-off: said once
// per server an hour with the mechanism and the result code, and at each
// pool step with the next attempt's time. Under external the pool's
// hold-off starts only when no server is left to try (holdsOffLocked); the
// line says when the query failed over, plus Active Directory's remedy
// for a 49 or for a 7 over ldaps. The error carries neither the password
// nor the keytab (Task 7).
//
// Operators: with every one of N servers refusing, the pool makes at most
// N+4 failed binds in the first 30 minutes (N, one a minute, as each
// server's first refusal holds the pool at 1m; then probes at N, N+2, N+6
// and N+14 minutes as the hold-off doubles to its 15m cap) and one per 15
// minutes after: 9 for five servers. Once any server accepts, each server
// that keeps refusing is bound again only per its own backoff, 1m doubling
// to 15m, so at most 4 an hour each at the cap. Under external one refusing
// server holds off only itself and the query goes to the next server; the
// N+4 bound above still holds when every server refuses, since the hold-off
// then starts as today. Exempt the service account
// from lockout, or set its threshold above N+4 per 30 minutes.
func (p *Pool) bindDoneLocked(s *serverState, probe bool, err error) {
	if probe {
		p.probing = false
	}
	now := p.now()
	switch {
	case err == nil:
		s.refuseStep, s.refuseUntil = 0, time.Time{}
		if p.holdStep > 0 {
			p.holdStep, p.holdUntil = 0, time.Time{}
			p.say("directory: %s accepted the bind; the bind hold-off cleared", s.Label())
		}
		return
	case !Refusal(err):
		return
	}
	p.m.DirectoryQueries.WithLabelValues(s.Label(), "refused").Inc()
	s.healthySince = time.Time{}
	first := s.refuseStep == 0
	s.refuseStep = nextBackoff(s.refuseStep)
	s.refuseUntil = now.Add(s.refuseStep)
	holds := p.holdsOffLocked()
	if holds && (p.holdStep == 0 || !now.Before(p.holdUntil)) {
		// A server's first refusal holds the pool at its current step (1m
		// from clear) without doubling it, so a probe walks the servers that
		// have not refused at one a minute (Re-review I-4).
		if p.holdStep == 0 || !first {
			p.holdStep = nextBackoff(p.holdStep)
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
	line := fmt.Sprintf("directory: %s refused the bind (%s): %s", s.Label(), p.cfg.Bind.Mechanism,
		printsafe.Line(err.Error(), 300))
	if p.cfg.Bind.Mechanism == "external" {
		switch {
		case ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials):
			line += "; on Active Directory this is a certificate that is not mapped, or that DC's KDC not answering " +
				"(check its Kerberos service before the broker's certificate)"
		case ldap.IsErrorWithCode(err, ldap.LDAPResultAuthMethodNotSupported) && s.scheme() == "ldaps":
			line += "; Active Directory takes SASL EXTERNAL only over StartTLS ([MS-ADTS] 5.1.1.2): " +
				"use ldap:// with start_tls: true"
		}
		if !holds {
			line += fmt.Sprintf("; the query failed over, and this server is retried after its own backoff of %s, at %s",
				s.refuseStep, s.refuseUntil.UTC().Format(time.RFC3339))
		}
	}
	p.say("%s", line)
}

// holdsOffLocked is whether the refusal just counted on a server starts or
// steps the pool's bind hold-off. Always, except under external: there a
// refusal is the certificate's at that DC (not mapped, or its KDC not
// answering) and counts toward no shared lockout, so only that server is held
// off and the query fails over, unless a hold-off is already running or every
// server whose breaker is not open is now under its own refusal backoff with
// none bound, when it is today's behaviour.
func (p *Pool) holdsOffLocked() bool {
	if p.cfg.Bind.Mechanism != "external" || p.holdStep > 0 {
		return true
	}
	now := p.now()
	for _, o := range p.srv {
		switch {
		case o.open:
		case o.conn != nil, o.refuseStep == 0, !now.Before(o.refuseUntil):
			return false
		}
	}
	return true
}

func (s Server) scheme() string {
	u, err := url.Parse(s.URI)
	if err != nil {
		return ""
	}
	return u.Scheme
}

// nextBackoff is the step after d: 1m, doubling to 15m.
func nextBackoff(d time.Duration) time.Duration {
	if d == 0 {
		return holdoffFirst
	}
	return min(2*d, holdoffCap)
}

func (p *Pool) holding() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.holdStep > 0 && (p.now().Before(p.holdUntil) || p.probing)
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
	p.mu.Lock()
	order := p.orderLocked()
	p.mu.Unlock()
	for _, i := range order {
		s := p.srv[i]
		p.mu.Lock()
		skip := (s.open && now.Sub(s.openedAt) < p.cfg.ProbeInterval) || !p.bindableLocked(s) || p.leaveRefuserLocked(s)
		var probe bool
		if !skip {
			probe = p.beginBindLocked()
			if s.open {
				s.openedAt = now // a probe resets its clock
			}
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
		case err != nil && !dialed && Refusal(err):
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
