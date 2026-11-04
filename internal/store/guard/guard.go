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
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/blanketfish/port49/internal/store"
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
	"RefreshContext": Context, "SetRevokedAt": Context, "SetContextPolicy": Context, "StampRefreshed": Context, "DeleteContext": Context,
	"DeleteContextIf": Context, "GetBlob": Context, "BumpBlob": Context, "IndexContext": Context,
	"UnindexContext": Context, "UnindexRef": Context, "ContextsByPrincipal": Context, "ContextsBySid": Context,
	"ContextsByCert": Context, "ReindexSid": Context,
	"PutContextRev": Context, "SwapContextRev": Context, "SwapLoginRev": Context, "RewriteContextRev": Context,
	"Ping": Context,

	"ActivePrincipals": Bulk, "DeleteReceiptsByPrincipal": Bulk, "ListRevocations": Bulk, "PurgeTokens": Bulk,

	"PutToken": Token, "Candidates": Token, "TokenIDs": Token, "RedeemAndReceipt": Token, "DeleteTokens": Token, "DeleteToken": Token,
	"GetReceipt": Token, "ExtendReceipt": Token, "FailReceipt": Token, "PutBlob": Token,
	"TokensByPrincipal": Token, "TokensByCert": Token, "ReserveIdempotency": Token, "CompleteIdempotency": Token,
	"ReleaseIdempotency": Token, "PutRevocation": Token, "GetRevocation": Token, "DeleteRevocation": Token, "GetLift": Token,
	"SupersedeTokens": Token, "SupersedeAll": Token, "SupersededAt": Token,
	"PutMembership": Token, "PutPin": Token, "RefuseMapKeys": Token, "GetMembership": Token, "MembershipByKey": Token,
	"MembershipPrincipals": Token, "DeleteMembership": Token,
	"PutOnce": Token, "TakeOnce": Token, "PutOIDCOwner": Token, "OIDCOwner": Token, "PutLogout": Token,
	"GetLogout": Token, "PutMFAProof": Token, "GetMFAProof": Token,
	"NoteSignInAttempt": Token, "UndoSignInAttempt": Token, "ClearSignInAttempts": Token,

	// store.Enrollments (plan 9e), guarded by WrapEnrollments.
	"GetSecondFactor": Token, "SwapSecondFactor": Token, "GetEnrollmentMark": Token,
	"GetUnlock": Token, "PutUnlock": Token,
	"CreateEnrollmentMark": Token, "PutEnrollmentMark": Token, "SwapEnrollmentMark": Token,
	"SecondFactorPrincipals": Bulk, "Export": Bulk, "Import": Bulk,
}

// PoolOf is the pool method runs in, and "" for a name the table does not
// hold: there is no default, so a method added to store.Store without a
// row fails TestEveryMethodIsRoutedToItsPool.
func PoolOf(method string) Pool { return pools[method] }

// Config is one component's guard.
type Config struct {
	Proc      string // "port49d" or "port49-broker": the process whose lines these are
	Component string // "daemon" or "broker": the metrics' label and the lines' subject
	// Store is the noun each line leads with after the process: "store" when
	// empty, "directory store" for a directory store of its own (plan 11a).
	Store string
	// HoldTTLKey is the config key the "closes its listeners" clause names;
	// empty, "etcd.hold_ttl".
	HoldTTLKey  string
	CallTimeout time.Duration // the token and context pools' deadline per call
	BulkTimeout time.Duration // the bulk pool's
	MaxInFlight map[Pool]int
	Failures    int           // consecutive failures that open a pool's circuit
	OpenFor     time.Duration // how long it stays open before a probe
	// StopAfter is how long a token or context pool's circuit may stay
	// open, or its calls be refused in a steady run, before Unhealthy is
	// told (the hold_ttl key), once per open circuit and once per
	// refused run; zero never tells it. The bulk pool never tells it
	// (re-check R-I5).
	StopAfter time.Duration
	// Unhealthy is called on the goroutine of the store call that found
	// the pool gone, a TACACS+ handler's among them: it must not block.
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
	// ops counts the failures of the current run by the store method that
	// made the call, and openOps is that run as it stood when the circuit
	// last opened: the open line names which calls fed it.
	ops     map[string]int
	openOps string
	// openedAt is when the circuit last opened from closed; a failed probe
	// opens it again without moving it. refusedSince is the first refusal
	// of the current run, lastRefused its latest, and refused its count: a
	// run ends at an answer, or at a refusal more than OpenFor after the
	// one before it, which starts the next (re-check R-I5). toldOpen is
	// whether Unhealthy has been told of this open circuit, and toldRefused
	// of this refused run: each is its own, so a refused probe on an open
	// circuit already told does not tell it again (review M1).
	openedAt, refusedSince, lastRefused time.Time
	refused                             int
	toldOpen, toldRefused               bool
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

// WrapRev guards inner as Wrap does, keeping the revision each
// whole-context write committed at (store.RevStore) for the sealing layer
// above it, which calls those twins alone: port49d's stores on etcd are
// crypt.Wrap(WrapRev(the component's store)) (plan 7d).
func WrapRev(inner store.RevStore, c Config) store.RevStore {
	return revGuarded{guarded: Wrap(inner, c).(*guarded), rev: inner}
}

// revGuarded is guarded with inner's RevStore twins, each in the context
// pool as its plain method is.
type revGuarded struct {
	*guarded
	rev store.RevStore
}

func (g revGuarded) PutContextRev(ctx context.Context, k store.ContextKey, c store.Context, ttl time.Duration) (rev uint64, err error) {
	err = g.do(ctx, Context, func(ctx context.Context) (e error) { rev, e = g.rev.PutContextRev(ctx, k, c, ttl); return })
	return
}

func (g revGuarded) SwapContextRev(ctx context.Context, k store.ContextKey, rev uint64, c store.Context, ttl time.Duration) (n uint64, err error) {
	err = g.do(ctx, Context, func(ctx context.Context) (e error) { n, e = g.rev.SwapContextRev(ctx, k, rev, c, ttl); return })
	return
}

func (g revGuarded) SwapLoginRev(ctx context.Context, k store.ContextKey, rev uint64, c store.Context, ttl time.Duration, w store.LoginWrite) (n uint64, err error) {
	err = g.do(ctx, Context, func(ctx context.Context) (e error) { n, e = g.rev.SwapLoginRev(ctx, k, rev, c, ttl, w); return })
	return
}

func (g revGuarded) RewriteContextRev(ctx context.Context, k store.ContextKey, rev uint64, c store.Context, ttl time.Duration, policyMoved bool) (n uint64, err error) {
	err = g.do(ctx, Context, func(ctx context.Context) (e error) {
		n, e = g.rev.RewriteContextRev(ctx, k, rev, c, ttl, policyMoved)
		return
	})
	return
}

// Seen makes no call, so it takes no slot and no deadline (store.RevStore).
func (g revGuarded) Seen() uint64 { return g.rev.Seen() }

func (g revGuarded) Ping(ctx context.Context) error {
	return g.do(ctx, Context, func(ctx context.Context) error { return g.rev.Ping(ctx) })
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
func (p *pool) leave(now time.Time, probe bool, outcome, op string, cause error, threshold int, openFor time.Duration) (changed, open bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if probe {
		p.probe = false
	}
	switch outcome {
	case "refused":
		if p.refusedSince.IsZero() || now.Sub(p.lastRefused) > openFor {
			p.refusedSince, p.refused, p.toldRefused = now, 0, false
		}
		p.lastRefused = now
		p.refused++
		return false, p.open
	case "canceled", "saturated", "feed_behind":
		return false, p.open
	case "timeout", "deadline", "unavailable":
		p.fails++
		p.cause = cause
		if p.ops == nil {
			p.ops = map[string]int{}
		}
		p.ops[op]++
		if probe || !p.open && p.fails >= threshold {
			was := p.open
			p.open, p.until = true, now.Add(openFor)
			if !was {
				p.openedAt, p.toldOpen = now, false
				p.openOps = opTally(p.ops)
			}
			return !was, true
		}
		return false, p.open
	}
	// An answer: ok, not_found, conflict, error.
	p.fails, p.refusedSince, p.refused, p.toldRefused = 0, time.Time{}, 0, false
	clear(p.ops)
	if p.open {
		p.open = false
		return true, false
	}
	return false, false
}

// gone reports, once per run, a pool whose circuit has stayed open, or
// whose every call has been refused, for stopAfter: a refused run of at
// least minRefused calls, none more than OpenFor apart (leave). The
// line names the pool by component ("the daemon's context pool"), formatted
// only when it is told, never on the hot path (review M3).
func (p *pool) gone(now time.Time, stopAfter time.Duration, minRefused int, component string) (why string, tell bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if stopAfter <= 0 {
		return "", false
	}
	switch {
	case p.open && !p.toldOpen && now.Sub(p.openedAt) >= stopAfter:
		p.toldOpen = true
		return fmt.Sprintf("the %s's %s pool's circuit has been open for %v (%v)", component, p.name, stopAfter, p.cause), true
	case !p.toldRefused && !p.refusedSince.IsZero() && p.refused >= minRefused && now.Sub(p.refusedSince) >= stopAfter:
		p.toldRefused = true
		return fmt.Sprintf("every call on the %s's %s pool has been refused by the store for %v (its role no longer grants it)",
			component, p.name, stopAfter), true
	}
	return "", false
}

// opTally is a run's failures by op, "GetContext 3, PutToken 2".
func opTally(ops map[string]int) string {
	names := make([]string, 0, len(ops))
	for n := range ops {
		names = append(names, n)
	}
	sort.Strings(names)
	for i, n := range names {
		names[i] = fmt.Sprintf("%s %d", n, ops[n])
	}
	return strings.Join(names, ", ")
}

// callerOp is the store method that called do: the guard's methods each call
// it directly, so the frame above do is the method.
func callerOp() string {
	pc, _, _, ok := runtime.Caller(2)
	if !ok {
		return "unknown"
	}
	name := runtime.FuncForPC(pc).Name()
	return name[strings.LastIndex(name, ".")+1:]
}

// do runs one call in pool p.
func (g *guarded) do(ctx context.Context, p Pool, f func(context.Context) error) error {
	op := callerOp()
	pl := g.pools[p]
	defer g.watch(pl)
	probe, ok := pl.enter(g.c.Now())
	if !ok {
		g.count(p, "circuit_open")
		return fmt.Errorf("%w: the %s pool's circuit is open (%w)", store.ErrUnavailable, p, store.ErrNotSent)
	}
	// A caller already gone, or already past its deadline, is read before
	// the slot wait: a select on a free slot and a closed Done picks either
	// at random, and the outcome must not (review I1). Past its deadline
	// is a packet whose earlier calls spent the packet_deadline: the
	// store too slow for it, a deadline as one struck mid-call is.
	if err := ctx.Err(); err != nil {
		outcome := "canceled"
		if errors.Is(err, context.DeadlineExceeded) {
			outcome, err = "deadline", fmt.Errorf("%w: the caller's deadline had passed (%w, %w)", store.ErrUnavailable, err, store.ErrNotSent)
		}
		g.count(p, outcome)
		if changed, open := pl.leave(g.c.Now(), probe, outcome, op, err, g.c.Failures, g.c.OpenFor); changed {
			g.changed(p, open, err)
		}
		return err
	}
	cctx, cancel := context.WithTimeout(ctx, pl.timeout)
	defer cancel()
	select {
	case pl.slots <- struct{}{}:
	case <-cctx.Done():
		pl.leave(g.c.Now(), probe, "saturated", op, nil, g.c.Failures, g.c.OpenFor)
		if errors.Is(ctx.Err(), context.Canceled) {
			g.count(p, "canceled")
			return ctx.Err()
		}
		// The caller's deadline or the pool's: either way every slot was
		// held for as long as this call could wait.
		g.count(p, "saturated")
		return fmt.Errorf("%w: every %s slot was busy for as long as the call could wait (%w)", store.ErrUnavailable, p, store.ErrNotSent)
	}
	start := time.Now()
	err := f(cctx)
	<-pl.slots
	if g.c.Metrics.Seconds != nil {
		g.c.Metrics.Seconds.WithLabelValues(g.c.Component, string(p)).Observe(time.Since(start).Seconds())
	}
	outcome := classify(ctx, cctx, err)
	if outcome == "timeout" && errors.Is(err, store.ErrFeedBehind) {
		// The store answered with a record this process's feed has not reached:
		// not a failed store call, so the circuit does not count it. A feed that
		// stays behind is the health check's to see, and closes the listeners.
		outcome = "feed_behind"
	}
	if outcome == "timeout" {
		// The inner error stays wrapped: the context cache tells a fence
		// timeout (crypt.ErrFeedBehind: the store answered with a later
		// record) from an outage by it (plan 7f, I-2). classify has already
		// run, so what is counted is unchanged.
		err = fmt.Errorf("%w: no answer in %v (%w)", store.ErrUnavailable, pl.timeout, err)
	}
	g.count(p, outcome)
	if changed, open := pl.leave(g.c.Now(), probe, outcome, op, err, g.c.Failures, g.c.OpenFor); changed {
		g.changed(p, open, err)
	}
	return err
}

// classify names how a call ended. The caller's own context is read
// before the error, because a backend maps a caller's expired deadline to
// store.ErrUnavailable like any other (pre-flight M26): a caller that went
// away is canceled, never counted; a caller whose deadline struck mid-call
// is deadline, a failure, since the store was too slow for it (a packet's
// the packet_deadline key on the daemon; pre-flight I10). A store answer is
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
	if why, tell := pl.gone(g.c.Now(), g.c.StopAfter, g.c.Failures, g.c.Component); tell && g.c.Unhealthy != nil {
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
		g.c.Say(fmt.Sprintf("%s: %s: the %s's bulk pool's circuit is open after %d consecutive failures (%v); "+
			"the scans (the refresh, a revocation by principal, a start's purge) fail until a probe in %v succeeds; "+
			"logins and commands are unaffected", g.c.Proc, g.noun(), g.c.Component, g.c.Failures, cause, g.c.OpenFor))
		return
	}
	if open {
		// Only a guard that tells Unhealthy closes its process's listeners;
		// port49-broker's never does (StopAfter 0).
		closes := ""
		if g.c.StopAfter > 0 {
			closes = fmt.Sprintf("; %s closes its listeners if the store is gone for %s", g.c.Proc, g.holdTTLKey())
		}
		// The broker's pools serve its API; devices and break-glass are the
		// daemon's (Task 15a review M-4).
		impact := "devices see store_unavailable, and break-glass is refused (L4)"
		switch {
		case g.c.Component == "broker":
			impact = "mints, refreshes and revocations through it fail"
		case strings.HasSuffix(g.c.Component, enrollmentsSuffix):
			impact = "password sign-in and second-factor enrollment through it are refused"
		}
		pl := g.pools[p]
		pl.mu.Lock()
		ops := pl.openOps
		pl.mu.Unlock()
		g.c.Say(fmt.Sprintf("%s: %s: the %s's %s pool's circuit is open after %d consecutive failures (%v; by call: %s); "+
			"each call on it fails at once until a probe in %v succeeds; %s%s", g.c.Proc, g.noun(), g.c.Component, p,
			g.c.Failures, cause, ops, g.c.OpenFor, impact, closes))
		return
	}
	g.c.Say(fmt.Sprintf("%s: %s: the %s's %s pool's circuit is closed: a probe was answered", g.c.Proc,
		g.noun(), g.c.Component, p))
}

// noun is what the guard's lines call the store.
func (g *guarded) noun() string {
	if g.c.Store == "" {
		return "store"
	}
	return g.c.Store
}

// holdTTLKey is the key a "closes its listeners" clause names.
func (g *guarded) holdTTLKey() string {
	if g.c.HoldTTLKey == "" {
		return "etcd.hold_ttl"
	}
	return g.c.HoldTTLKey
}

func (g *guarded) PutToken(ctx context.Context, k store.TokenKey, t store.Token) (n int, err error) {
	err = g.do(ctx, Token, func(ctx context.Context) (e error) { n, e = g.inner.PutToken(ctx, k, t); return })
	return
}

func (g *guarded) Candidates(ctx context.Context, k store.TokenKey) (ts []store.Token, err error) {
	err = g.do(ctx, Token, func(ctx context.Context) (e error) { ts, e = g.inner.Candidates(ctx, k); return })
	return
}

func (g *guarded) TokenIDs(ctx context.Context, k store.TokenKey) (ids []string, err error) {
	err = g.do(ctx, Token, func(ctx context.Context) (e error) { ids, e = g.inner.TokenIDs(ctx, k); return })
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

func (g *guarded) StampRefreshed(ctx context.Context, k store.ContextKey, policyRev uint64, at time.Time) error {
	return g.do(ctx, Context, func(ctx context.Context) error { return g.inner.StampRefreshed(ctx, k, policyRev, at) })
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

func (g *guarded) DeleteRevocation(ctx context.Context, kind string, key string, by store.Lift) error {
	return g.do(ctx, Token, func(ctx context.Context) error { return g.inner.DeleteRevocation(ctx, kind, key, by) })
}

func (g *guarded) GetLift(ctx context.Context, kind string, key string) (l store.Lift, err error) {
	err = g.do(ctx, Token, func(ctx context.Context) (e error) { l, e = g.inner.GetLift(ctx, kind, key); return })
	return
}

func (g *guarded) ListRevocations(ctx context.Context) (rs []store.Revocation, err error) {
	err = g.do(ctx, Bulk, func(ctx context.Context) (e error) { rs, e = g.inner.ListRevocations(ctx); return })
	return
}

func (g *guarded) SupersedeTokens(ctx context.Context, k store.TokenKey, at time.Time) error {
	return g.do(ctx, Token, func(ctx context.Context) error { return g.inner.SupersedeTokens(ctx, k, at) })
}

func (g *guarded) SupersedeAll(ctx context.Context, at time.Time) error {
	return g.do(ctx, Token, func(ctx context.Context) error { return g.inner.SupersedeAll(ctx, at) })
}

func (g *guarded) SupersededAt(ctx context.Context, k store.TokenKey) (at time.Time, err error) {
	err = g.do(ctx, Token, func(ctx context.Context) (e error) { at, e = g.inner.SupersededAt(ctx, k); return })
	return
}

func (g *guarded) PutMembership(ctx context.Context, m store.Membership, ttl time.Duration) error {
	return g.do(ctx, Token, func(ctx context.Context) error { return g.inner.PutMembership(ctx, m, ttl) })
}

func (g *guarded) PutPin(ctx context.Context, m store.Membership, expect store.PinExpect) error {
	return g.do(ctx, Token, func(ctx context.Context) error { return g.inner.PutPin(ctx, m, expect) })
}

func (g *guarded) RefuseMapKeys(ctx context.Context, mapKeys []string, at time.Time, ttl time.Duration) error {
	return g.do(ctx, Token, func(ctx context.Context) error { return g.inner.RefuseMapKeys(ctx, mapKeys, at, ttl) })
}

func (g *guarded) GetMembership(ctx context.Context, principal string) (m store.Membership, err error) {
	err = g.do(ctx, Token, func(ctx context.Context) (e error) { m, e = g.inner.GetMembership(ctx, principal); return })
	return
}

func (g *guarded) MembershipByKey(ctx context.Context, mapKey string) (m store.Membership, err error) {
	err = g.do(ctx, Token, func(ctx context.Context) (e error) { m, e = g.inner.MembershipByKey(ctx, mapKey); return })
	return
}

func (g *guarded) MembershipPrincipals(ctx context.Context) (ps []string, err error) {
	err = g.do(ctx, Token, func(ctx context.Context) (e error) { ps, e = g.inner.MembershipPrincipals(ctx); return })
	return
}

func (g *guarded) DeleteMembership(ctx context.Context, principal string) (m store.Membership, err error) {
	err = g.do(ctx, Token, func(ctx context.Context) (e error) { m, e = g.inner.DeleteMembership(ctx, principal); return })
	return
}

func (g *guarded) PutOnce(ctx context.Context, key string, value []byte, ttl time.Duration) (ok bool, err error) {
	err = g.do(ctx, Token, func(ctx context.Context) (e error) { ok, e = g.inner.PutOnce(ctx, key, value, ttl); return })
	return
}

func (g *guarded) TakeOnce(ctx context.Context, key string) (v []byte, err error) {
	err = g.do(ctx, Token, func(ctx context.Context) (e error) { v, e = g.inner.TakeOnce(ctx, key); return })
	return
}

func (g *guarded) PutOIDCOwner(ctx context.Context, key, principal string, ttl time.Duration) error {
	return g.do(ctx, Token, func(ctx context.Context) error { return g.inner.PutOIDCOwner(ctx, key, principal, ttl) })
}

func (g *guarded) OIDCOwner(ctx context.Context, key string) (o store.OIDCOwner, err error) {
	err = g.do(ctx, Token, func(ctx context.Context) (e error) { o, e = g.inner.OIDCOwner(ctx, key); return })
	return
}

func (g *guarded) PutLogout(ctx context.Context, l store.Logout, ttl time.Duration) error {
	return g.do(ctx, Token, func(ctx context.Context) error { return g.inner.PutLogout(ctx, l, ttl) })
}

func (g *guarded) GetLogout(ctx context.Context, key string) (l store.Logout, err error) {
	err = g.do(ctx, Token, func(ctx context.Context) (e error) { l, e = g.inner.GetLogout(ctx, key); return })
	return
}

func (g *guarded) PutMFAProof(ctx context.Context, p store.MFAProof, ttl time.Duration) error {
	return g.do(ctx, Token, func(ctx context.Context) error { return g.inner.PutMFAProof(ctx, p, ttl) })
}

func (g *guarded) GetMFAProof(ctx context.Context, key string) (p store.MFAProof, err error) {
	err = g.do(ctx, Token, func(ctx context.Context) (e error) { p, e = g.inner.GetMFAProof(ctx, key); return })
	return
}

func (g *guarded) NoteSignInAttempt(ctx context.Context, key string, window time.Duration) (n int, end time.Time, err error) {
	err = g.do(ctx, Token, func(ctx context.Context) (e error) { n, end, e = g.inner.NoteSignInAttempt(ctx, key, window); return })
	return
}

func (g *guarded) UndoSignInAttempt(ctx context.Context, key string) error {
	return g.do(ctx, Token, func(ctx context.Context) error { return g.inner.UndoSignInAttempt(ctx, key) })
}

func (g *guarded) ClearSignInAttempts(ctx context.Context, key string) (n int, err error) {
	err = g.do(ctx, Token, func(ctx context.Context) (e error) { n, e = g.inner.ClearSignInAttempts(ctx, key); return })
	return
}

var _ store.Store = (*guarded)(nil)

// guardedEnrollments is the enrollment store behind the same pools, circuit
// and metrics a Store has (plan 9e, D12): every method in the token pool but
// the three that read or write every record, which run in the bulk pool.
type guardedEnrollments struct {
	inner store.Enrollments
	g     *guarded
}

// enrollmentsSuffix is what WrapEnrollments adds to c.Component, so the
// enrollment handle's circuit gauge, calls and lines are its own: an
// enrollment store on another etcd than the store's must not share a series
// with it.
const enrollmentsSuffix = "_enrollments"

// WrapEnrollments guards inner, the enrollment handle on etcd, as Wrap
// guards a Store, under the component c.Component + "_enrollments".
func WrapEnrollments(inner store.Enrollments, c Config) store.Enrollments {
	c.Component += enrollmentsSuffix
	return &guardedEnrollments{inner: inner, g: Wrap(nil, c).(*guarded)}
}

func (e *guardedEnrollments) GetSecondFactor(ctx context.Context, principal string) (f store.SecondFactor, err error) {
	err = e.g.do(ctx, Token, func(ctx context.Context) (x error) { f, x = e.inner.GetSecondFactor(ctx, principal); return })
	return
}

func (e *guardedEnrollments) SwapSecondFactor(ctx context.Context, f store.SecondFactor, rev uint64) error {
	return e.g.do(ctx, Token, func(ctx context.Context) error { return e.inner.SwapSecondFactor(ctx, f, rev) })
}

func (e *guardedEnrollments) SecondFactorPrincipals(ctx context.Context) (ps []string, err error) {
	err = e.g.do(ctx, Bulk, func(ctx context.Context) (x error) { ps, x = e.inner.SecondFactorPrincipals(ctx); return })
	return
}

func (e *guardedEnrollments) GetUnlock(ctx context.Context, principal string) (at time.Time, err error) {
	err = e.g.do(ctx, Token, func(ctx context.Context) (x error) { at, x = e.inner.GetUnlock(ctx, principal); return })
	return
}

func (e *guardedEnrollments) PutUnlock(ctx context.Context, principal string, at time.Time) error {
	return e.g.do(ctx, Token, func(ctx context.Context) error { return e.inner.PutUnlock(ctx, principal, at) })
}

func (e *guardedEnrollments) GetEnrollmentMark(ctx context.Context) (m store.EnrollmentMark, err error) {
	err = e.g.do(ctx, Token, func(ctx context.Context) (x error) { m, x = e.inner.GetEnrollmentMark(ctx); return })
	return
}

func (e *guardedEnrollments) CreateEnrollmentMark(ctx context.Context, m store.EnrollmentMark) error {
	return e.g.do(ctx, Token, func(ctx context.Context) error { return e.inner.CreateEnrollmentMark(ctx, m) })
}

func (e *guardedEnrollments) PutEnrollmentMark(ctx context.Context, m store.EnrollmentMark) error {
	return e.g.do(ctx, Token, func(ctx context.Context) error { return e.inner.PutEnrollmentMark(ctx, m) })
}

func (e *guardedEnrollments) SwapEnrollmentMark(ctx context.Context, m store.EnrollmentMark, rev uint64) error {
	return e.g.do(ctx, Token, func(ctx context.Context) error { return e.inner.SwapEnrollmentMark(ctx, m, rev) })
}

func (e *guardedEnrollments) Export(ctx context.Context) (b []byte, err error) {
	err = e.g.do(ctx, Bulk, func(ctx context.Context) (x error) { b, x = e.inner.Export(ctx); return })
	return
}

func (e *guardedEnrollments) Import(ctx context.Context, sealed []byte, replace bool) (n int, at time.Time, err error) {
	err = e.g.do(ctx, Bulk, func(ctx context.Context) (x error) { n, at, x = e.inner.Import(ctx, sealed, replace); return })
	return
}

var _ store.Enrollments = (*guardedEnrollments)(nil)
