package devicemock

import (
	"context"
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
	P50, P99 time.Duration
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
		res   = FleetResult{Outcomes: map[string]int{}}
		times []time.Duration
	)
	for i := range f.N {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			start := time.Now()
			tr, err := Play(ctx, f.Profile, f.Scenario, target(i), login(i))
			d := time.Since(start)
			mu.Lock()
			defer mu.Unlock()
			res.Plays++
			times = append(times, d)
			if err != nil {
				res.Errors++ // never printed: a transcript names steps, but a fleet's are not read one by one
				return
			}
			res.Outcomes[tr.Outcome]++
		}()
	}
	wg.Wait()
	slices.Sort(times)
	if n := len(times); n > 0 {
		res.P50, res.P99 = times[n/2], times[min(n-1, n*99/100)]
	}
	return res
}
