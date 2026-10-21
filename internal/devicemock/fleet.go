package devicemock

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"
)

// Fleet plays one profile as N concurrent devices (plan 11b, fleet mode).
type Fleet struct {
	Profile     *Profile
	N           int
	Concurrency int // at most this many plays at once; 0 means N
	Scenario    string
}

// FleetResult counts what a fleet did. Outcomes are keyed by outcome name
// only: no device, login or credential is kept.
type FleetResult struct {
	Plays    int
	Outcomes map[string]int
	Errors   int
	// ErrorKinds counts Errors by a fixed class name (no_reaction, connection,
	// context, other), never by error text.
	ErrorKinds map[string]int
	// P50 and P99 are nearest-rank over the plays that reached an outcome;
	// a play that ended in an error is not a latency.
	P50, P99 time.Duration
}

// errorKind names an error's class. The text is not kept: it may carry a
// platform, a step or an address, and a fleet's errors are not read one by one.
func errorKind(err error) string {
	var nr *noReactionError
	switch {
	case errors.As(err, &nr):
		return "no_reaction"
	case errors.Is(err, errConn):
		return "connection"
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return "context"
	}
	return "other"
}

// percentile is the nearest-rank p-th percentile of sorted: element
// ceil(p*n/100)-1.
func percentile(sorted []time.Duration, p int) time.Duration {
	n := len(sorted)
	if n == 0 {
		return 0
	}
	return sorted[max(0, (p*n+99)/100-1)]
}

// LoopbackSource is fleet device i's source address: 127.0.1.1 to 127.0.1.254,
// then 127.0.2.1 and on. Linux answers all of 127.0.0.0/8 with no set-up.
func LoopbackSource(i int) string {
	return fmt.Sprintf("127.0.%d.%d", 1+i/254, 1+i%254)
}

// Run plays device 0 to N-1, at most Concurrency at a time, and aggregates.
// target and login are called from the player goroutines, so they must be
// safe for that: index a slice built beforehand.
func (f Fleet) Run(ctx context.Context, target func(i int) Target, login func(i int) Login) FleetResult {
	c := f.Concurrency
	if c <= 0 {
		c = f.N
	}
	sem := make(chan struct{}, c)
	var (
		mu    sync.Mutex
		wg    sync.WaitGroup
		res   = FleetResult{Outcomes: map[string]int{}, ErrorKinds: map[string]int{}}
		times []time.Duration
	)
	for i := range f.N {
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
		}
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			start := time.Now()
			tr, err := Play(ctx, f.Profile, f.Scenario, target(i), login(i))
			d := time.Since(start)
			mu.Lock()
			defer mu.Unlock()
			res.Plays++
			if err != nil {
				res.Errors++
				res.ErrorKinds[errorKind(err)]++
				return
			}
			times = append(times, d)
			res.Outcomes[tr.Outcome]++
		}()
	}
	wg.Wait()
	slices.Sort(times)
	res.P50, res.P99 = percentile(times, 50), percentile(times, 99)
	return res
}
