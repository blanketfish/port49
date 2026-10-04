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
}

func newRestoreGuard(out io.Writer) *restoreGuard {
	return &restoreGuard{out: out, checked: true}
}

// begin starts a run: gauge is its port49_redemption_restore_guarded, set
// at once, and redemptions wait for the run's first read once a witness
// was followed.
func (g *restoreGuard) begin(gauge prometheus.Gauge) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.gauge, g.checked, g.failing = gauge, !g.seen, false
	g.setGauge()
}

// Allows reports whether a token may be redeemed now.
func (g *restoreGuard) Allows() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.checked && !g.guarded
}

// Saw raises the witness followed. It never lifts the guard.
func (g *restoreGuard) Saw(rev uint64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.seen || rev > g.high {
		g.high, g.seen = rev, true
	}
}

// judge is one read of the store's witness and purge (RestoreRead), or
// its error.
func (g *restoreGuard) judge(r etcdstore.RestoreRead, err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if err != nil {
		if !g.failing {
			fmt.Fprintf(g.out, "port49d: store: reading meta/witness, to tell whether the store was restored: %v; "+
				"redemptions stay as they are (%s) until a read answers; tried again every %v\n", err,
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
	case g.seen && r.Witness < g.high:
		at := fmt.Sprintf("at revision %d", r.Witness)
		if r.Witness == 0 {
			at = "absent"
		}
		g.guarded, g.dropAt = true, r.Header
		fmt.Fprintf(g.out, "port49d: store: meta/witness is %s, below the %d this port49d followed: the store was "+
			"restored from a snapshot, which brings back every token redeemed since it, unspent; every token "+
			"redemption is refused (store_unavailable) until a broker runner's purge is done: start the brokers, "+
			"and follow the restore runbook's step 3 (design §13) before another restore\n", at, g.high)
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

// setGauge sets the run's gauge: 1 while redemptions are refused; g.mu is
// held.
func (g *restoreGuard) setGauge() {
	if g.gauge == nil {
		return
	}
	g.gauge.Set(b2f(g.guarded || !g.checked))
}

// keep follows meta/witness and reads it, with meta/purged, at once and
// every witnessEvery, until ctx ends: the watch alone can wait at a
// revision a store restored without --bump-revision has not reached, and
// never tell.
func (g *restoreGuard) keep(ctx context.Context, s *etcdstore.Store) {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); s.FollowWitness(ctx, g.Saw) }()
	defer wg.Wait()
	t := time.NewTicker(witnessEvery)
	defer t.Stop()
	for {
		rctx, cancel := context.WithTimeout(ctx, witnessEvery)
		r, err := s.RestoreRead(rctx)
		cancel()
		if ctx.Err() != nil {
			return
		}
		g.judge(r, err)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
