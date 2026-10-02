// Package guard is design §12's mitigations for a store that is slow or
// gone, around any store.Store (plan 7d; spec §13, decision 35):
//   - a hard timeout on every call;
//   - a circuit breaker per pool, which stops calling a store that keeps
//     failing and probes it;
//   - three pools of in-flight slots (token, context and bulk), so mint
//     pressure cannot starve authorization and a slow scan cannot open
//     the circuit that holds a revocation's writes. A call that cannot get
//     a slot within its deadline is refused: a queue is worse than a
//     refusal.
//
// It reports a token or context pool that has stayed failed, or stayed
// refused, for StopAfter, and port49d goes dark on that (Ruling 11); the
// bulk pool's circuit is said and gauged, never reported. It sits under the
// sealing layer, so a record that will not decrypt is never counted as
// the store failing.
package guard

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/rhwendt/port49/internal/store"
)

// Pool is one of the three.
type Pool string

const (
	Token   Pool = "token"
	Context Pool = "context"
	Bulk    Pool = "bulk"
)

var pools = map[string]Pool{
	"GetContext": Context, "PutContext": Context, "SwapContext": Context, "SwapLogin": Context,
	"RewriteContext": Context, "TouchContext": Context, "SetPrivilege": Context, "AnnotateContext": Context,
	"RefreshContext": Context, "SetRevokedAt": Context, "SetContextPolicy": Context, "DeleteContext": Context,
	"DeleteContextIf": Context, "GetBlob": Context, "BumpBlob": Context, "IndexContext": Context,
	"UnindexContext": Context, "UnindexRef": Context, "ContextsByPrincipal": Context, "ContextsBySid": Context,
	"ContextsByCert": Context, "ReindexSid": Context,

	"ActivePrincipals": Bulk, "DeleteReceiptsByPrincipal": Bulk, "ListRevocations": Bulk, "PurgeTokens": Bulk,

	"PutToken": Token, "Candidates": Token, "RedeemAndReceipt": Token, "DeleteTokens": Token, "DeleteToken": Token,
	"GetReceipt": Token, "ExtendReceipt": Token, "FailReceipt": Token, "PutBlob": Token, "IndexToken": Token,
	"TokensByPrincipal": Token, "TokensByCert": Token, "ReserveIdempotency": Token, "CompleteIdempotency": Token,
	"ReleaseIdempotency": Token, "PutRevocation": Token, "GetRevocation": Token, "DeleteRevocation": Token,
}

// PoolOf is the pool method runs in, and "" for a name the table does not
// hold: there is no default, so a method added to store.Store without a
// row fails TestEveryMethodIsRoutedToItsPool.
func PoolOf(method string) Pool { return pools[method] }

// Config is one component's guard.
type Config struct {
	Component   string        // "daemon" or "broker": the metrics' label and the lines' subject
	CallTimeout time.Duration // the token and context pools' deadline per call
	BulkTimeout time.Duration // the bulk pool's
	MaxInFlight map[Pool]int
	Failures    int           // consecutive failures that open a pool's circuit
	OpenFor     time.Duration // how long it stays open before a probe
	// StopAfter is how long a token or context pool's circuit may stay
	// open, or its calls be refused in a steady run, before Unhealthy is
	// told, once (store.etcd.hold_ttl); zero never tells it. The bulk pool
	// never tells it (re-check R-I5).
	StopAfter time.Duration
	Unhealthy func(why string)
	Now       func() time.Time
	Say       func(line string) // told when a circuit opens or closes; nil says nothing
	Metrics   Metrics
}

// Metrics are the guard's series; nil fields count nothing.
type Metrics struct {
	Calls   *prometheus.CounterVec   // component, pool, outcome
	Seconds *prometheus.HistogramVec // component, pool
	Open    *prometheus.GaugeVec     // component, pool
}

// outcomes is every value of the outcome label: whether each is counted
// toward the breaker, and whether it is a failure there.
var outcomes = []string{"ok", "not_found", "conflict", "error", "timeout", "deadline", "unavailable", "refused",
	"canceled", "saturated", "circuit_open"}

type pool struct {
	name    Pool
	slots   chan struct{}
	timeout time.Duration
	mu      sync.Mutex
	fails   int
	open    bool
	until   time.Time
	probe   bool
	cause   error
	// openedAt is when the circuit last opened from closed; a failed probe
	// opens it again without moving it. refusedSince is the first refusal
	// of the current run, lastRefused its latest, and refused its count: a
	// run ends at an answer, or at a refusal more than OpenFor after the
	// one before it, which starts the next (re-check R-I5). told is whether
	// Unhealthy has been told about this run of either.
	openedAt, refusedSince, lastRefused time.Time
	refused                             int
	told                                bool
}

type guarded struct {
	inner store.Store
	c     Config
	pools map[Pool]*pool
}

// Wrap guards inner.
func Wrap(inner store.Store, c Config) store.Store {
	if c.Now == nil {
		c.Now = time.Now
	}
	g := &guarded{inner: inner, c: c, pools: map[Pool]*pool{}}
	for _, p := range []Pool{Token, Context, Bulk} {
		n := c.MaxInFlight[p]
		if n <= 0 {
			n = 64
		}
		timeout := c.CallTimeout
		if p == Bulk {
			timeout = c.BulkTimeout
		}
		g.pools[p] = &pool{name: p, slots: make(chan struct{}, n), timeout: timeout}
		if c.Metrics.Open != nil {
			c.Metrics.Open.WithLabelValues(c.Component, string(p)).Set(0)
		}
	}
	return g
}

// enter decides whether a call may go: always while closed; while open,
// only one probe once OpenFor has passed.
func (p *pool) enter(now time.Time) (probe, ok bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	switch {
	case !p.open:
		return false, true
	case now.Before(p.until) || p.probe:
		return false, false
	}
	p.probe = true
	return true, true
}

// leave records how a call ended, and reports whether the circuit changed
// and how it now stands. A call not counted (a caller that went away, a
// refusal, a slot never got) changes nothing but the probe it held; a
// refusal also starts or continues the refused run, and an answer ends it.
func (p *pool) leave(now time.Time, probe bool, outcome string, cause error, threshold int, openFor time.Duration) (changed, open bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if probe {
		p.probe = false
	}
	switch outcome {
	case "refused":
		if p.refusedSince.IsZero() || now.Sub(p.lastRefused) > openFor {
			p.refusedSince, p.refused, p.told = now, 0, false
		}
		p.lastRefused = now
		p.refused++
		return false, p.open
	case "canceled", "saturated":
		return false, p.open
	case "timeout", "deadline", "unavailable":
		p.fails++
		p.cause = cause
		if probe || !p.open && p.fails >= threshold {
			was := p.open
			p.open, p.until = true, now.Add(openFor)
			if !was {
				p.openedAt = now
			}
			return !was, true
		}
		return false, p.open
	}
	// An answer: ok, not_found, conflict, error.
	p.fails, p.refusedSince, p.refused, p.told = 0, time.Time{}, 0, false
	if p.open {
		p.open = false
		return true, false
	}
	return false, false
}

// gone reports, once per run, a pool whose circuit has stayed open, or
// whose every call has been refused, for stopAfter: a refused run of at
// least minRefused calls, none more than OpenFor apart (leave). whose
// names the pool ("the daemon's context pool").
func (p *pool) gone(now time.Time, stopAfter time.Duration, minRefused int, whose string) (why string, tell bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if stopAfter <= 0 || p.told {
		return "", false
	}
	switch {
	case p.open && now.Sub(p.openedAt) >= stopAfter:
		p.told = true
		return fmt.Sprintf("%s's circuit has been open for %v (%v)", whose, stopAfter, p.cause), true
	case !p.refusedSince.IsZero() && p.refused >= minRefused && now.Sub(p.refusedSince) >= stopAfter:
		p.told = true
		return fmt.Sprintf("every call on %s has been refused by the store for %v (its role no longer grants it)",
			whose, stopAfter), true
	}
	return "", false
}

// do runs one call in pool p.
func (g *guarded) do(ctx context.Context, p Pool, f func(context.Context) error) error {
	pl := g.pools[p]
	defer g.watch(pl)
	probe, ok := pl.enter(g.c.Now())
	if !ok {
		g.count(p, "circuit_open")
		return fmt.Errorf("%w: the %s pool's circuit is open", store.ErrUnavailable, p)
	}
	cctx, cancel := context.WithTimeout(ctx, pl.timeout)
	defer cancel()
	select {
	case pl.slots <- struct{}{}:
	case <-cctx.Done():
		pl.leave(g.c.Now(), probe, "saturated", nil, g.c.Failures, g.c.OpenFor)
		if errors.Is(ctx.Err(), context.Canceled) {
			g.count(p, "canceled")
			return ctx.Err()
		}
		// The caller's deadline or the pool's: either way every slot was
		// held for as long as this call could wait.
		g.count(p, "saturated")
		return fmt.Errorf("%w: every %s slot was busy for as long as the call could wait", store.ErrUnavailable, p)
	}
	start := time.Now()
	err := f(cctx)
	<-pl.slots
	if g.c.Metrics.Seconds != nil {
		g.c.Metrics.Seconds.WithLabelValues(g.c.Component, string(p)).Observe(time.Since(start).Seconds())
	}
	outcome := classify(ctx, cctx, err)
	if outcome == "timeout" {
		err = fmt.Errorf("%w: no answer in %v", store.ErrUnavailable, pl.timeout)
	}
	g.count(p, outcome)
	if changed, open := pl.leave(g.c.Now(), probe, outcome, err, g.c.Failures, g.c.OpenFor); changed {
		g.changed(p, open, err)
	}
	return err
}

// classify names how a call ended. The caller's own context is read
// before the error, because a backend maps a caller's expired deadline to
// store.ErrUnavailable like any other (pre-flight M26): a caller that went
// away is canceled, never counted; a caller whose deadline struck mid-call
// is deadline, a failure, since the store was too slow for it (a packet's
// store.packet_deadline on the daemon; pre-flight I10). A store answer is
// read first of all: it is an answer whatever the caller's context did
// after it.
func classify(caller, call context.Context, err error) string {
	switch {
	case err == nil:
		return "ok"
	case errors.Is(err, store.ErrNotFound):
		return "not_found"
	case errors.Is(err, store.ErrConflict), errors.Is(err, store.ErrPastGrace):
		return "conflict"
	case errors.Is(err, store.ErrRefused):
		return "refused"
	case errors.Is(caller.Err(), context.Canceled):
		return "canceled"
	case errors.Is(caller.Err(), context.DeadlineExceeded):
		return "deadline"
	case call.Err() != nil:
		return "timeout"
	case errors.Is(err, store.ErrUnavailable):
		return "unavailable"
	}
	return "error" // an answer the store gave that is none of the above: a record that does not decode, a request too large
}

func (g *guarded) count(p Pool, outcome string) {
	if g.c.Metrics.Calls != nil {
		g.c.Metrics.Calls.WithLabelValues(g.c.Component, string(p), outcome).Inc()
	}
}

// watch tells Unhealthy, outside every lock, when pl has gone dark. The
// bulk pool never does (re-check R-I5): a scan slow at scale, or a
// refused one, while the token and context pools answer, is not a store
// gone, and closing every listener on it would undo the pools' separation
// (pre-flight I14). Its circuit is said and gauged (changed), and that is
// the alarm. A pool with no calls never reaches watch, so an idle pool
// whose circuit is open is never told: harmless, since an idle pool
// serves no one (re-check R-M5).
func (g *guarded) watch(pl *pool) {
	if pl.name == Bulk {
		return
	}
	whose := fmt.Sprintf("the %s's %s pool", g.c.Component, pl.name)
	if why, tell := pl.gone(g.c.Now(), g.c.StopAfter, g.c.Failures, whose); tell && g.c.Unhealthy != nil {
		g.c.Unhealthy(why)
	}
}

// changed gauges and says a circuit that opened or closed. The gauge is
// set from the pool's state under its lock, not from open: two calls that
// change the circuit at once may get here in either order, and the later
// must not leave the gauge on the state the earlier one saw.
func (g *guarded) changed(p Pool, open bool, cause error) {
	if g.c.Metrics.Open != nil {
		pl := g.pools[p]
		pl.mu.Lock()
		v := 0.0
		if pl.open {
			v = 1
		}
		g.c.Metrics.Open.WithLabelValues(g.c.Component, string(p)).Set(v)
		pl.mu.Unlock()
	}
	if g.c.Say == nil {
		return
	}
	if open && p == Bulk {
		g.c.Say(fmt.Sprintf("port49d: store: the %s's bulk pool's circuit is open after %d consecutive failures (%v); "+
			"the scans (the refresh, a revocation by principal, a start's purge) fail until a probe in %v succeeds; "+
			"logins and commands are unaffected", g.c.Component, g.c.Failures, cause, g.c.OpenFor))
		return
	}
	if open {
		g.c.Say(fmt.Sprintf("port49d: store: the %s's %s pool's circuit is open after %d consecutive failures (%v); "+
			"each call on it fails at once until a probe in %v succeeds; devices see store_unavailable, and "+
			"break-glass is refused (L4); port49d closes its listeners if the store is gone for store.etcd.hold_ttl",
			g.c.Component, p, g.c.Failures, cause, g.c.OpenFor))
		return
	}
	g.c.Say(fmt.Sprintf("port49d: store: the %s's %s pool's circuit is closed: a probe was answered", g.c.Component, p))
}
func (g *guarded) PutToken(ctx context.Context, k store.TokenKey, t store.Token) (n int, err error) {
	err = g.do(ctx, Token, func(ctx context.Context) (e error) { n, e = g.inner.PutToken(ctx, k, t); return })
	return
}

func (g *guarded) Candidates(ctx context.Context, k store.TokenKey) (ts []store.Token, err error) {
	err = g.do(ctx, Token, func(ctx context.Context) (e error) { ts, e = g.inner.Candidates(ctx, k); return })
	return
}

func (g *guarded) RedeemAndReceipt(ctx context.Context, k store.TokenKey, tokenID string, w store.ReceiptWrite) error {
	return g.do(ctx, Token, func(ctx context.Context) error { return g.inner.RedeemAndReceipt(ctx, k, tokenID, w) })
}

func (g *guarded) DeleteTokens(ctx context.Context, k store.TokenKey) error {
	return g.do(ctx, Token, func(ctx context.Context) error { return g.inner.DeleteTokens(ctx, k) })
}

func (g *guarded) DeleteToken(ctx context.Context, k store.TokenKey, id string) error {
	return g.do(ctx, Token, func(ctx context.Context) error { return g.inner.DeleteToken(ctx, k, id) })
}

func (g *guarded) PurgeTokens(ctx context.Context) (n int, err error) {
	err = g.do(ctx, Bulk, func(ctx context.Context) (e error) { n, e = g.inner.PurgeTokens(ctx); return })
	return
}

func (g *guarded) GetReceipt(ctx context.Context, rk store.ReceiptKey) (r store.Receipt, err error) {
	err = g.do(ctx, Token, func(ctx context.Context) (e error) { r, e = g.inner.GetReceipt(ctx, rk); return })
	return
}

func (g *guarded) ExtendReceipt(ctx context.Context, rk store.ReceiptKey, idleExpiresAt time.Time) error {
	return g.do(ctx, Token, func(ctx context.Context) error { return g.inner.ExtendReceipt(ctx, rk, idleExpiresAt) })
}

func (g *guarded) FailReceipt(ctx context.Context, rk store.ReceiptKey) error {
	return g.do(ctx, Token, func(ctx context.Context) error { return g.inner.FailReceipt(ctx, rk) })
}

func (g *guarded) DeleteReceiptsByPrincipal(ctx context.Context, principal string) (n int, err error) {
	err = g.do(ctx, Bulk, func(ctx context.Context) (e error) { n, e = g.inner.DeleteReceiptsByPrincipal(ctx, principal); return })
	return
}

func (g *guarded) PutContext(ctx context.Context, k store.ContextKey, c store.Context, ttl time.Duration) error {
	return g.do(ctx, Context, func(ctx context.Context) error { return g.inner.PutContext(ctx, k, c, ttl) })
}

func (g *guarded) GetContext(ctx context.Context, k store.ContextKey) (c store.Context, err error) {
	err = g.do(ctx, Context, func(ctx context.Context) (e error) { c, e = g.inner.GetContext(ctx, k); return })
	return
}

func (g *guarded) SwapContext(ctx context.Context, k store.ContextKey, rev uint64, c store.Context, ttl time.Duration) error {
	return g.do(ctx, Context, func(ctx context.Context) error { return g.inner.SwapContext(ctx, k, rev, c, ttl) })
}

func (g *guarded) SwapLogin(ctx context.Context, k store.ContextKey, rev uint64, c store.Context, ttl time.Duration, w store.LoginWrite) error {
	return g.do(ctx, Context, func(ctx context.Context) error { return g.inner.SwapLogin(ctx, k, rev, c, ttl, w) })
}

func (g *guarded) RewriteContext(ctx context.Context, k store.ContextKey, rev uint64, c store.Context, ttl time.Duration, policyMoved bool) error {
	return g.do(ctx, Context, func(ctx context.Context) error { return g.inner.RewriteContext(ctx, k, rev, c, ttl, policyMoved) })
}

func (g *guarded) TouchContext(ctx context.Context, k store.ContextKey, ttl time.Duration) error {
	return g.do(ctx, Context, func(ctx context.Context) error { return g.inner.TouchContext(ctx, k, ttl) })
}

func (g *guarded) SetPrivilege(ctx context.Context, k store.ContextKey, level uint8) error {
	return g.do(ctx, Context, func(ctx context.Context) error { return g.inner.SetPrivilege(ctx, k, level) })
}

func (g *guarded) AnnotateContext(ctx context.Context, k store.ContextKey, discHash string, state string) error {
	return g.do(ctx, Context, func(ctx context.Context) error { return g.inner.AnnotateContext(ctx, k, discHash, state) })
}

func (g *guarded) RefreshContext(ctx context.Context, k store.ContextKey, r store.ContextRefresh, ttl time.Duration) error {
	return g.do(ctx, Context, func(ctx context.Context) error { return g.inner.RefreshContext(ctx, k, r, ttl) })
}

func (g *guarded) SetRevokedAt(ctx context.Context, k store.ContextKey, at time.Time) error {
	return g.do(ctx, Context, func(ctx context.Context) error { return g.inner.SetRevokedAt(ctx, k, at) })
}

func (g *guarded) SetContextPolicy(ctx context.Context, k store.ContextKey, policyRev uint64, p store.ContextPolicy) error {
	return g.do(ctx, Context, func(ctx context.Context) error { return g.inner.SetContextPolicy(ctx, k, policyRev, p) })
}

func (g *guarded) DeleteContext(ctx context.Context, k store.ContextKey) error {
	return g.do(ctx, Context, func(ctx context.Context) error { return g.inner.DeleteContext(ctx, k) })
}

func (g *guarded) DeleteContextIf(ctx context.Context, k store.ContextKey, rev uint64) error {
	return g.do(ctx, Context, func(ctx context.Context) error { return g.inner.DeleteContextIf(ctx, k, rev) })
}

func (g *guarded) PutBlob(ctx context.Context, hash string, body []byte, ttl time.Duration) error {
	return g.do(ctx, Token, func(ctx context.Context) error { return g.inner.PutBlob(ctx, hash, body, ttl) })
}

func (g *guarded) GetBlob(ctx context.Context, hash string) (body []byte, err error) {
	err = g.do(ctx, Context, func(ctx context.Context) (e error) { body, e = g.inner.GetBlob(ctx, hash); return })
	return
}

func (g *guarded) BumpBlob(ctx context.Context, hash string, ttl time.Duration) error {
	return g.do(ctx, Context, func(ctx context.Context) error { return g.inner.BumpBlob(ctx, hash, ttl) })
}

func (g *guarded) IndexContext(ctx context.Context, principal string, sid string, certKey string, ref store.ContextRef, ttl time.Duration) error {
	return g.do(ctx, Context, func(ctx context.Context) error { return g.inner.IndexContext(ctx, principal, sid, certKey, ref, ttl) })
}

func (g *guarded) UnindexContext(ctx context.Context, principal string, sid string, certKey string, ref store.ContextRef) error {
	return g.do(ctx, Context, func(ctx context.Context) error { return g.inner.UnindexContext(ctx, principal, sid, certKey, ref) })
}

func (g *guarded) UnindexRef(ctx context.Context, ref store.ContextRef) error {
	return g.do(ctx, Context, func(ctx context.Context) error { return g.inner.UnindexRef(ctx, ref) })
}

func (g *guarded) ContextsByPrincipal(ctx context.Context, principal string) (refs []store.ContextRef, err error) {
	err = g.do(ctx, Context, func(ctx context.Context) (e error) { refs, e = g.inner.ContextsByPrincipal(ctx, principal); return })
	return
}

func (g *guarded) ContextsBySid(ctx context.Context, sid string) (refs []store.ContextRef, err error) {
	err = g.do(ctx, Context, func(ctx context.Context) (e error) { refs, e = g.inner.ContextsBySid(ctx, sid); return })
	return
}

func (g *guarded) ContextsByCert(ctx context.Context, certKey string) (refs []store.ContextRef, err error) {
	err = g.do(ctx, Context, func(ctx context.Context) (e error) { refs, e = g.inner.ContextsByCert(ctx, certKey); return })
	return
}

func (g *guarded) ReindexSid(ctx context.Context, oldSid string, newSid string, ref store.ContextRef, ttl time.Duration) error {
	return g.do(ctx, Context, func(ctx context.Context) error { return g.inner.ReindexSid(ctx, oldSid, newSid, ref, ttl) })
}

func (g *guarded) ActivePrincipals(ctx context.Context) (ps []string, err error) {
	err = g.do(ctx, Bulk, func(ctx context.Context) (e error) { ps, e = g.inner.ActivePrincipals(ctx); return })
	return
}

func (g *guarded) IndexToken(ctx context.Context, principal string, certKey string, k store.TokenKey, ttl time.Duration) error {
	return g.do(ctx, Token, func(ctx context.Context) error { return g.inner.IndexToken(ctx, principal, certKey, k, ttl) })
}

func (g *guarded) TokensByPrincipal(ctx context.Context, principal string) (keys []store.TokenKey, err error) {
	err = g.do(ctx, Token, func(ctx context.Context) (e error) { keys, e = g.inner.TokensByPrincipal(ctx, principal); return })
	return
}

func (g *guarded) TokensByCert(ctx context.Context, certKey string) (keys []store.TokenKey, err error) {
	err = g.do(ctx, Token, func(ctx context.Context) (e error) { keys, e = g.inner.TokensByCert(ctx, certKey); return })
	return
}

func (g *guarded) ReserveIdempotency(ctx context.Context, principal string, key string, rec store.Idempotency) (got store.Idempotency, ok bool, err error) {
	err = g.do(ctx, Token, func(ctx context.Context) (e error) {
		got, ok, e = g.inner.ReserveIdempotency(ctx, principal, key, rec)
		return
	})
	return
}

func (g *guarded) CompleteIdempotency(ctx context.Context, principal string, key string, expect string, rec store.Idempotency) error {
	return g.do(ctx, Token, func(ctx context.Context) error { return g.inner.CompleteIdempotency(ctx, principal, key, expect, rec) })
}

func (g *guarded) ReleaseIdempotency(ctx context.Context, principal string, key string, holder string) error {
	return g.do(ctx, Token, func(ctx context.Context) error { return g.inner.ReleaseIdempotency(ctx, principal, key, holder) })
}

func (g *guarded) PutRevocation(ctx context.Context, r store.Revocation) error {
	return g.do(ctx, Token, func(ctx context.Context) error { return g.inner.PutRevocation(ctx, r) })
}

func (g *guarded) GetRevocation(ctx context.Context, kind string, key string) (r store.Revocation, err error) {
	err = g.do(ctx, Token, func(ctx context.Context) (e error) { r, e = g.inner.GetRevocation(ctx, kind, key); return })
	return
}

func (g *guarded) DeleteRevocation(ctx context.Context, kind string, key string) error {
	return g.do(ctx, Token, func(ctx context.Context) error { return g.inner.DeleteRevocation(ctx, kind, key) })
}

func (g *guarded) ListRevocations(ctx context.Context) (rs []store.Revocation, err error) {
	err = g.do(ctx, Bulk, func(ctx context.Context) (e error) { rs, e = g.inner.ListRevocations(ctx); return })
	return
}

var _ store.Store = (*guarded)(nil)
