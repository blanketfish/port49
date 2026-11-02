package port49d

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/blanketfish/port49/internal/policy"
	etcdstore "github.com/blanketfish/port49/internal/store/etcd"
)

// restoreSkew is the allowance on top of policy.MaxTokenTTL before the guard
// lifts on its own: the brokers' clock skew plus the witness's lead over the
// snapshot's last mint (at most 61 s). It is the largest clock disagreement
// port49 tolerates anywhere (broker.identity.clock_skew's ceiling, an
// inventory's published_at lead, OCSP and CRL ThisUpdate); spec decision 55
// ruling 15. port49d's own clock error cancels: the lift time and a restored
// token's expiry are both broker-stamped times it compares with its own clock.
const restoreSkew = 5 * time.Minute

// restoreBound is how long after the restored witness's time every token the
// snapshot could hold has expired.
const restoreBound = policy.MaxTokenTTL + restoreSkew

// restoreLift is when the guard lifts on its own for a witness written at at,
// read at now on port49d's clock. A zero at, or one more than restoreSkew
// ahead of now (a runner's clock too far ahead, or port49d's too far behind:
// the two cannot be told apart, and either breaks the bound's premise), arms
// no bound: lift is zero, and why says so.
func restoreLift(at, now time.Time) (lift time.Time, why string) {
	switch {
	case at.IsZero():
		return time.Time{}, "meta/witness carries no time"
	case at.After(now.Add(restoreSkew)):
		return time.Time{}, fmt.Sprintf("meta/witness's time %s is more than %v ahead of this port49d's clock",
			at.UTC().Format(time.RFC3339), restoreSkew)
	}
	return at.Add(restoreBound), ""
}

// restoreGuard is port49d's half of the restore witness (plan 7e, Task
// 15d): an etcd restore brings back every single-use token redeemed
// since its snapshot, unspent, and a port49d would redeem it again until
// the first broker runner purges. It keeps the highest meta/witness
// ModRevision it has followed, for the process's life (run): a restore
// that outlasts hold_ttl ends a run, and the next must still know. A read
// that shows the witness below that, or gone after one was seen, guards:
// every token redemption is refused store_unavailable, and nothing else
// is. Two things lift it, the first of: a meta/purged written after the
// read that found the drop (the runner writes one once a purge of every
// unspent token is done, and a plain witness write is no purge), or the
// restored witness's time plus restoreBound, on port49d's clock, by which
// every token the snapshot could hold has expired. A witness with no usable
// time arms no bound: only the purge lifts it. A read that fails changes
// nothing, said once per run of failures. A port49d started after the
// restore has followed nothing and cannot tell: the runbook's token
// delete covers it.
type restoreGuard struct {
	out     io.Writer
	mu      sync.Mutex
	high    uint64 // the highest witness followed
	seen    bool
	guarded bool
	// dropAt is the header of the read that found the drop: a meta/purged
	// at or below it may be the snapshot's own.
	dropAt uint64
	// guardHigh is the highest witness read or followed since the drop: a
	// read below it is a second restore.
	guardHigh uint64
	// liftAt is when the guard lifts on its own; zero: only a purge lifts it.
	liftAt time.Time
	now    func() time.Time
	until  prometheus.Gauge
	// checked is false from a run's begin, once a witness was followed,
	// until a read judges the store: the outage that ended the last run
	// may have been the restore.
	checked bool
	failing bool
	gauge   prometheus.Gauge
	ops     *prometheus.CounterVec // port49_store_operations_total; nil counts nothing
}

func newRestoreGuard(out io.Writer) *restoreGuard {
	return &restoreGuard{out: out, checked: true, now: time.Now}
}

// begin starts a run: gauge is its port49_redemption_restore_guarded, set
// at once, until its port49_redemption_restore_guard_until_timestamp_seconds
// (nil sets nothing), ops counts each read as op "restore_read", and redemptions wait
// for the run's first read once a witness was followed.
func (g *restoreGuard) begin(gauge, until prometheus.Gauge, ops *prometheus.CounterVec) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.gauge, g.until, g.ops, g.checked, g.failing = gauge, until, ops, !g.seen, false
	g.setGauge()
}

// Allows reports whether a token may be redeemed now.
func (g *restoreGuard) Allows() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.checked && !g.guarded
}

// guardFollowed is told each revision of meta/witness port49d's follower gave
// g, after g took it, and restorePassed each completed pass of g. Only tests
// swap them, to wait on port49d's guard instead of sleeping; both are keyed
// by the guard, not by process, because a test process may run several
// daemons.
var (
	guardFollowed = func(g *restoreGuard, rev uint64) {}
	restorePassed = func(g *restoreGuard) {}
)

// followed is what port49d's FollowWitness calls: Saw, then the hook.
func (g *restoreGuard) followed(rev uint64) {
	g.Saw(rev)
	guardFollowed(g, rev)
}

// Saw raises the witness followed. It never lifts the guard.
func (g *restoreGuard) Saw(rev uint64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.seen || rev > g.high {
		g.high, g.seen = rev, true
	}
	if g.guarded {
		g.guardHigh = max(g.guardHigh, rev)
	}
}

// recorded is the witness followed so far, and the guard's own record
// (guardHigh), taken before a read, as the runner's readWitness takes its
// record: a witness followed while the read is in flight is newer than the
// read, not proof of a drop or of a second restore.
func (g *restoreGuard) recorded() (high uint64, seen bool, guardHigh uint64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.high, g.seen, g.guardHigh
}

// judge is one read of the store's witness and purge (RestoreRead), or
// its error; high, seen and guardHigh are the record taken before it.
func (g *restoreGuard) judge(r etcdstore.RestoreRead, err error, high uint64, seen bool, guardHigh uint64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.ops != nil {
		outcome := "ok"
		if err != nil {
			outcome = "error"
		}
		g.ops.WithLabelValues("restore_read", outcome).Inc()
	}
	if err != nil {
		// A failed read is no restore, but the outage may be one: once a
		// witness was followed, redemptions wait for a read that answers.
		if g.seen {
			g.checked = false
		}
		if !g.failing {
			fmt.Fprintf(g.out, "port49d: store: reading meta/witness, to tell whether the store was restored: %v; "+
				"token redemptions are %s until a read answers; tried again every %v\n", err,
				g.state(), witnessEvery)
		}
		g.failing = true
		return
	}
	g.failing = false
	g.checked = true
	switch {
	case g.guarded && r.Purged > g.dropAt:
		g.lift(r)
		fmt.Fprintln(g.out, "port49d: store: the broker runner's purge after the restore is done; token "+
			"redemptions are served again")
	case g.guarded && r.Witness < guardHigh:
		// A second restore under the guard: the store now holds only this
		// snapshot's tokens, so the bound is this read's alone.
		g.drop(r, guardHigh)
	case g.guarded && !g.liftAt.IsZero() && !g.now().Before(g.liftAt):
		g.lift(r)
		fmt.Fprintf(g.out, "port49d: store: every token the restored snapshot could hold has now expired (its "+
			"witness's time %s + %v token_ttl ceiling + %v for the brokers' clocks); token redemptions are "+
			"served again\n", g.liftAt.Add(-restoreBound).UTC().Format(time.RFC3339), policy.MaxTokenTTL, restoreSkew)
	case g.guarded:
		g.high = max(g.high, r.Witness)
		g.guardHigh = max(g.guardHigh, r.Witness)
	case seen && r.Witness < high:
		g.drop(r, high)
	case r.Witness > g.high:
		g.high, g.seen = r.Witness, true
	}
	g.setGauge()
}

// lift ends the guard, taking the store's witness as the record; g.mu is held.
func (g *restoreGuard) lift(r etcdstore.RestoreRead) {
	g.guarded, g.liftAt = false, time.Time{}
	g.high, g.seen = r.Witness, r.Witness > 0
}

// drop is a read that found the witness below followed: a restore. A
// snapshot whose bound has already passed holds no live token and guards
// nothing; any other guards, until a purge or its bound. g.mu is held.
func (g *restoreGuard) drop(r etcdstore.RestoreRead, followed uint64) {
	at := fmt.Sprintf("at revision %d", r.Witness)
	if r.Witness == 0 {
		at = "absent"
	}
	liftAt, why := restoreLift(r.WitnessAt, g.now())
	if !liftAt.IsZero() && !g.now().Before(liftAt) {
		g.lift(r)
		fmt.Fprintf(g.out, "port49d: store: meta/witness is %s, below the %d this port49d followed: the store was "+
			"restored from a snapshot whose witness is from %s, more than %v ago, so every token it could hold has "+
			"expired; token redemptions are served. A broker runner still purges; follow the restore runbook "+
			"(design §13) for the marks and revocations the snapshot lost\n", at, followed,
			r.WitnessAt.UTC().Format(time.RFC3339), restoreBound)
		return
	}
	g.guarded, g.dropAt, g.guardHigh, g.liftAt = true, r.Header, r.Witness, liftAt
	until := "until a broker runner's purge is done (" + why + ", so only the purge lifts it)"
	if !liftAt.IsZero() {
		until = "until a broker runner's purge is done or, at the latest, " + liftAt.UTC().Format(time.RFC3339) +
			", when every token the snapshot could hold has expired (its witness's time + " +
			policy.MaxTokenTTL.String() + " token_ttl ceiling + " + restoreSkew.String() + " for the brokers' clocks)"
	}
	fmt.Fprintf(g.out, "port49d: store: meta/witness is %s, below the %d this port49d followed: the store was "+
		"restored from a snapshot, which brings back every token redeemed since it, unspent; every token "+
		"redemption is refused (store_unavailable) %s, and a device whose "+
		"authentication ERROR is final (IOS-XE) refuses break-glass too: start the brokers; a runner's purge "+
		"line releases this port49d. If no runner says one (its purge landed before this port49d's first "+
		"read, or meta/judged survived the restore and no witness record was kept), delete the restored "+
		"tokens as etcd's root (etcdctl del --prefix <prefix>v1/t/) and then restart this port49d, or stop every "+
		"port49-broker, delete meta/judged and start them, so a takeover purges; never restart this port49d before "+
		"the restored tokens are deleted: it forgets the drop and redeems them. Follow the restore runbook's "+
		"step 3 (design §13) before another restore\n", at, followed, until)
}

func (g *restoreGuard) state() string {
	if g.guarded || !g.checked {
		return "refused"
	}
	return "served"
}

// setGauge sets the run's gauges: 1 while guarded, not while a run waits
// for its first read or a failed read; and the time the guard lifts on its
// own, 0 while it does not hold or only a purge lifts it. g.mu is held.
func (g *restoreGuard) setGauge() {
	if g.gauge != nil {
		g.gauge.Set(b2f(g.guarded))
	}
	if g.until != nil {
		if g.guarded && !g.liftAt.IsZero() {
			g.until.Set(float64(g.liftAt.Unix()))
		} else {
			g.until.Set(0)
		}
	}
}

// keep follows meta/witness and reads it, with meta/purged, at once and
// every witnessEvery, each read given the store's own deadline, the longer
// of witnessEvery and callTimeout, until ctx ends: the watch alone can wait at a
// revision a store restored without --bump-revision has not reached, and
// never tell.
func (g *restoreGuard) keep(ctx context.Context, s *etcdstore.Store, callTimeout time.Duration) {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); s.FollowWitness(ctx, g.followed) }()
	defer wg.Wait()
	t := time.NewTicker(witnessEvery)
	defer t.Stop()
	for {
		if !g.pass(ctx, callTimeout, s.RestoreRead) {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// pass is one read and its judgment: the record is taken before the read
// (recorded), so a witness followed while it is in flight is no drop. It
// reports false once ctx ended, with nothing judged.
func (g *restoreGuard) pass(ctx context.Context, callTimeout time.Duration,
	read func(context.Context) (etcdstore.RestoreRead, error)) bool {
	high, seen, guardHigh := g.recorded()
	rctx, cancel := context.WithTimeout(ctx, max(witnessEvery, callTimeout))
	r, err := read(rctx)
	cancel()
	if ctx.Err() != nil {
		return false
	}
	g.judge(r, err, high, seen, guardHigh)
	restorePassed(g)
	return true
}
