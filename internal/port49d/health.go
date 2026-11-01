package port49d

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/blanketfish/port49/internal/daemon/metrics"
)

// health is port49d's store health check on etcd (plan 7f; spec §13,
// decision 37), which replaced plan 7e's probe. It checks every `every`
// on its own clock, whether or not a device asks, so an idle port49d goes
// dark as fast as a loaded one: within closeAfter × every + timeout of
// the store stopping. Each check is bounded by timeout (call_timeout).
type health struct {
	every, timeout        time.Duration
	closeAfter, openAfter int
	check                 func(context.Context) error
	m                     *metrics.Metrics
	state                 *healthState
	out                   io.Writer
}

// healthState is the failed checks in a row, owned by `run` beside the alarm,
// the ledger and the marks, so it outlives a run (plan 7f, I-1). The
// registry is per run (main.go: metrics.New(reg)), and a gauge set only by
// the run that ended would read 0 in the next run's, resolving the alert
// "above 0 for three intervals" at the close, while the store is still down
// and port49d waits for it. The rule: while the listeners are closed the
// gauge never reads below close_after. A run binds its registry to it with
// bind, and `passes` holds it until the listeners may open.
type healthState struct {
	mu      sync.Mutex
	failing int
	m       *metrics.Metrics // the current run's registry
}

// bind points the state at a run's new registry and gauges the count in it
// at once, before the run first waits for the store.
func (s *healthState) bind(m *metrics.Metrics) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m = m
	m.StoreHealthFailures.Set(float64(s.failing))
}

// set records n failed checks in a row, and gauges it.
func (s *healthState) set(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failing = n
	if s.m != nil {
		s.m.StoreHealthFailures.Set(float64(n))
	}
}

// atLeast raises the count to n and never lowers it.
func (s *healthState) atLeast(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n > s.failing {
		s.failing = n
		if s.m != nil {
			s.m.StoreHealthFailures.Set(float64(n))
		}
	}
}

// count is the failed checks in a row now.
func (s *healthState) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.failing
}

// storeCheck is one health check (Ruling 1): a linearizable read on each
// of the daemon's two etcd connections, made at once. ctxPool is the
// daemon's store fenced on its ledger, so a context feed that has stopped
// fails the check as a store does; tokPool reads on the token connection,
// so a store that answers one pool and not the other fails it. It runs
// under the guard: no slot, no circuit, nothing the guard refuses.
func storeCheck(ctxPool interface{ Ping(context.Context) error },
	tokPool interface{ PingToken(context.Context) error }) func(context.Context) error {
	return func(ctx context.Context) error {
		var wg sync.WaitGroup
		var ce, te error
		wg.Add(2)
		go func() { defer wg.Done(); ce = ctxPool.Ping(ctx) }()
		go func() { defer wg.Done(); te = tokPool.PingToken(ctx) }()
		wg.Wait()
		switch {
		case ce != nil:
			return fmt.Errorf("the context pool: %w", ce)
		case te != nil:
			return fmt.Errorf("the token pool: %w", te)
		}
		return nil
	}
}

// once is one check within h.timeout, counted. A check that ctx's end cut
// short is not counted: the run ending is not the store failing.
func (h *health) once(ctx context.Context) error {
	cctx, cancel := context.WithTimeout(ctx, h.timeout)
	defer cancel()
	err := h.check(cctx)
	if ctx.Err() != nil {
		return err
	}
	outcome := "pass"
	if err != nil {
		outcome = "fail"
	}
	h.m.StoreHealthChecks.WithLabelValues(outcome).Inc()
	return err
}

// watch checks every h.every until ctx ends, and tells gone once, a
// storeGone, when closeAfter checks have failed in a row; a pass starts
// the count again. A check that ctx's end cut short is not a failure.
func (h *health) watch(ctx context.Context, gone func(error)) {
	t := time.NewTicker(h.every)
	defer t.Stop()
	fails, first := 0, time.Time{}
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		err := h.once(ctx)
		if ctx.Err() != nil {
			return
		}
		if err == nil {
			fails = 0
			h.state.set(0)
			continue
		}
		if fails == 0 {
			first = time.Now()
		}
		fails++
		h.state.set(fails) // at the close it stays: the next run's gauge reads it
		if fails >= h.closeAfter {
			gone(&storeGone{why: fmt.Sprintf("%d consecutive store health checks failed over %v (the last: %v)",
				fails, time.Since(first).Round(100*time.Millisecond), err)})
			return
		}
	}
}

// passes checks every h.every until openAfter checks have passed in a
// row, and returns nil then, or ctx's error. A failure starts the count
// again and is said once per run of failures. Throughout, the failure
// gauge reads at least closeAfter (the listeners are closed and the store
// is not yet trusted): failed checks count on from closeAfter, and it is
// set to 0 only on the way out, when the listeners are about to open.
func (h *health) passes(ctx context.Context) error {
	t := time.NewTicker(h.every)
	defer t.Stop()
	h.state.atLeast(h.closeAfter)
	ok, failing, fails := 0, false, 0
	for ok < h.openAfter {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
		err := h.once(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err == nil {
			ok, failing, fails = ok+1, false, 0
			h.state.set(h.closeAfter)
			continue
		}
		ok = 0
		fails++
		h.state.set(h.closeAfter + fails)
		if !failing {
			fmt.Fprintf(h.out, "port49d: store: a health check failed while the listeners wait to open (%v); "+
				"counting %d passes again\n", err, h.openAfter)
			failing = true
		}
	}
	h.state.set(0)
	return nil
}
