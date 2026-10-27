package port49d

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	etcdstore "github.com/rhwendt/port49/internal/store/etcd"
)

// restoreGuard is port49d's half of the restore witness (plan 7e, Task
// 15d): an etcd restore brings back every single-use token redeemed
// since its snapshot, unspent, and a port49d would redeem it again until
// the first broker runner purges. It keeps the highest meta/witness
// ModRevision it has followed, for the process's life (run): a restore
// that outlasts hold_ttl ends a run, and the next must still know. A read
// that shows the witness below that, or gone after one was seen, guards:
// every token redemption is refused store_unavailable, and nothing else
// is. Only a meta/purged written after the read that found the drop
// lifts it: the runner writes one once a purge of every unspent token is
// done, and a plain witness write is no purge. A read that fails changes
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
	// checked is false from a run's begin, once a witness was followed,
	// until a read judges the store: the outage that ended the last run
	// may have been the restore.
	checked bool
	failing bool
	gauge   prometheus.Gauge
	ops     *prometheus.CounterVec // port49_store_operations_total; nil counts nothing
}

func newRestoreGuard(out io.Writer) *restoreGuard {
	return &restoreGuard{out: out, checked: true}
}

// begin starts a run: gauge is its port49_redemption_restore_guarded, set
// at once, ops counts each read as op "restore_read", and redemptions wait
// for the run's first read once a witness was followed.
func (g *restoreGuard) begin(gauge prometheus.Gauge, ops *prometheus.CounterVec) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.gauge, g.ops, g.checked, g.failing = gauge, ops, !g.seen, false
	g.setGauge()
}

// Allows reports whether a token may be redeemed now.
func (g *restoreGuard) Allows() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.checked && !g.guarded
}

// Saw raises the witness followed. It never lifts the guard.
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

func (g *restoreGuard) Saw(rev uint64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.seen || rev > g.high {
		g.high, g.seen = rev, true
	}
}

// recorded is the witness followed so far, taken before a read, as the
// runner's readWitness takes its record: a witness followed while the
// read is in flight is newer than the read, not proof of a drop.
func (g *restoreGuard) recorded() (high uint64, seen bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.high, g.seen
}

// judge is one read of the store's witness and purge (RestoreRead), or
// its error; high and seen are the record taken before it.
func (g *restoreGuard) judge(r etcdstore.RestoreRead, err error, high uint64, seen bool) {
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
		g.guarded, g.high, g.seen = false, r.Witness, r.Witness > 0
		fmt.Fprintln(g.out, "port49d: store: the broker runner's purge after the restore is done; token "+
			"redemptions are served again")
	case g.guarded:
		g.high = max(g.high, r.Witness)
	case seen && r.Witness < high:
		at := fmt.Sprintf("at revision %d", r.Witness)
		if r.Witness == 0 {
			at = "absent"
		}
		g.guarded, g.dropAt = true, r.Header
		fmt.Fprintf(g.out, "port49d: store: meta/witness is %s, below the %d this port49d followed: the store was "+
			"restored from a snapshot, which brings back every token redeemed since it, unspent; every token "+
			"redemption is refused (store_unavailable) until a broker runner's purge is done, and a device whose "+
			"authentication ERROR is final (IOS-XE) refuses break-glass too: start the brokers; a runner's purge "+
			"line releases this port49d. If no runner says one (its purge landed before this port49d's first "+
			"read, or meta/judged survived the restore and no witness record was kept), delete the restored "+
			"tokens as etcd's root (etcdctl del --prefix <prefix>v1/t/) and then restart this port49d, or stop every "+
			"port49-broker, delete meta/judged and start them, so a takeover purges; never restart this port49d before "+
			"the restored tokens are deleted: it forgets the drop and redeems them. Follow the restore runbook's "+
			"step 3 (design §13) before another restore\n", at, high)
	case r.Witness > g.high:
		g.high, g.seen = r.Witness, true
	}
	g.setGauge()
}

func (g *restoreGuard) state() string {
	if g.guarded || !g.checked {
		return "refused"
	}
	return "served"
}

// setGauge sets the run's gauge: 1 while guarded, not while a run waits
// for its first read or a failed read; g.mu is held.
func (g *restoreGuard) setGauge() {
	if g.gauge == nil {
		return
	}
	g.gauge.Set(b2f(g.guarded))
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
	high, seen := g.recorded()
	rctx, cancel := context.WithTimeout(ctx, max(witnessEvery, callTimeout))
	r, err := read(rctx)
	cancel()
	if ctx.Err() != nil {
		return false
	}
	g.judge(r, err, high, seen)
	restorePassed(g)
	return true
}
