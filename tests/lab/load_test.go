//go:build lab

package lab

import (
	"context"
	"fmt"
	"maps"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/devicemock"
)

// The ceiling cell c stops at, and the gate it applies (ruling F7): the
// device-observed account step p99, and any rise in spool drops. There is no
// Offer-latency metric.
const (
	loadAcctP99Gate = 50 * time.Millisecond
	loadAcctSteps   = 10 // 170 x 1.5^9 is 6500 a second: past what one host's loopback shows
	loadHangBound   = 10 * time.Second
	loadMintBurst   = 20 // cell e's concurrent batch mints
	loadBatchSize   = 100
)

// TestLoad runs the load cells (a to f) at the design §5 rate, one at a time,
// under the lab lock. It refuses unless PORT49_LAB_LOAD=1: it is hours of load
// on this host. PORT49_LAB_LOAD_CELLS selects cells; the note is written
// whatever the verdict, then the test fails on any cell that did not pass.
func TestLoad(t *testing.T) {
	if os.Getenv("PORT49_LAB_LOAD") != "1" {
		t.Skip("TestLoad is hours of load; set PORT49_LAB_LOAD=1 (make lab-load)")
	}
	ids, err := parseLoadCells(os.Getenv("PORT49_LAB_LOAD_CELLS"))
	if err != nil {
		t.Fatalf("INVALID: %v", err)
	}
	plan := map[string]loadCell{
		"a": {ID: "a", Transport: "tcp", Rate: loadRate, Duration: loadMinDuration},
		"b": {ID: "b", Transport: "tls", Rate: loadRate, Duration: loadMinDuration},
		"c": {ID: "c", Transport: "tcp", Rate: loadRate, Duration: loadStepDuration},
		"d": {ID: "d", Transport: "tcp", Rate: loadRate, Duration: loadMinDuration},
		"e": {ID: "e", Transport: "tcp", Rate: loadRate, Duration: loadMinDuration},
		"f": {ID: "f", Transport: "tcp", Rate: loadRate, Duration: loadNetemRun},
	}
	for _, id := range ids {
		if err := validateLoadCell(plan[id]); err != nil {
			t.Fatalf("INVALID: %v", err)
		}
	}
	guard := func() {
		if err := labGuardAt(l66StopSentinel, "/", l66DiskFloorMB); err != nil {
			t.Fatalf("INVALID: %v", err)
		}
	}
	guard()
	if root == "" {
		r, err := repoRoot()
		if err != nil {
			t.Fatalf("INVALID: repo root: %v", err)
		}
		root = r
		t.Cleanup(func() { root = "" })
	}
	if err := labOccupyForRun(labLockPath, "TestLoad pid "+strconv.Itoa(os.Getpid())); err != nil {
		t.Fatal(err)
	}
	r := loadStack(t, 3, loadDevices)
	// The STOP sentinel and the disk floor are polled every second, so every
	// cell stops driving within about a second of either, not at its end.
	ctx, stopped := loadStopOnSentinel(context.Background(), func() error {
		return labGuardAt(l66StopSentinel, "/", l66DiskFloorMB)
	}, time.Second)
	defer stopped()

	var cells []loadCell
	for _, id := range ids {
		guard()
		c := plan[id]
		t.Logf("cell %s: %s at %.0f/s for %s", id, c.Transport, c.Rate, c.Duration)
		switch id {
		case "a":
			c = r.cellLogins(ctx, c)
		case "b":
			r.useTransport("tls")
			c = r.cellLogins(ctx, c)
		case "c":
			r.useTransport("tcp")
			c = r.cellAccounting(ctx, c)
		case "d":
			r.useTransport("tcp")
			c = r.cellFaults(ctx, c)
		case "e":
			r.useTransport("tcp")
			c = r.cellMintBurst(ctx, c)
		case "f":
			r.useTransport("tcp")
			c = r.cellNetem(ctx, c)
		}
		t.Logf("cell %s: pass=%v", id, c.Pass)
		cells = append(cells, c)
	}

	if err := stopped(); err != nil {
		t.Fatalf("INVALID: the run was stopped (%v); no note written for a partial run", err)
	}
	host := readHostFacts(r.dir)
	note, err := loadNote(cells, host)
	if err != nil {
		t.Fatalf("INVALID: %v", err)
	}
	path := filepath.Join(root, "tests", "lab", "results", "load-"+host.Host+".md")
	if err := os.WriteFile(path, []byte(note), 0o644); err != nil {
		t.Fatalf("INVALID: %v", err)
	}
	for _, c := range cells {
		if !c.Pass {
			t.Errorf("cell %s did not pass; see %s", c.ID, path)
		}
	}
}

// measure runs one cell's load under a sampler on each process's metrics, and
// records the fleet result plus each process's CPU and peak RSS and the
// store-call p99 the daemon and the broker saw during it.
func (r *loadRun) measure(c loadCell, run func() devicemock.FleetResult) (loadCell, devicemock.FleetResult) {
	r.takeMints() // a cell's mints are its own
	before := r.usage()
	dsam, bsam := startLoadSampler(loadDaemonMetrics), startLoadSampler(loadBrokerMetrics)
	res := run()
	dsam.finish()
	bsam.finish()
	p50, p99, mintErrs := r.takeMints()
	c.Observed = loadObserved(res, p50, p99)
	num := func(v float64) string { return strconv.FormatFloat(v, 'f', 0, 64) }
	c.Observed["mint_errors"] = strconv.Itoa(mintErrs)
	c.Observed["peak_port49_connections"] = num(dsam.peakConns)
	c.Observed["peak_spool_depth"] = num(dsam.peakDepth)
	c.Observed["spool_drops_during"] = num(dsam.last.SpoolDrops - dsam.first.SpoolDrops)
	c.Observed["daemon_store_call_p99_ms"] = loadMS(dsam.last.Sub(dsam.first).Quantile(0.99))
	c.Observed["broker_store_call_p99_ms"] = loadMS(bsam.last.Sub(bsam.first).Quantile(0.99))
	for name, after := range r.usage() {
		c.Observed["cpu_seconds_"+name] = strconv.FormatFloat(after[0]-before[name][0], 'f', 1, 64)
		c.Observed["peak_rss_mb_"+name] = num(after[1] / 1024)
	}
	return c, res
}

// drops is the daemon's port49_accounting_spool_drops_total now, every stage.
func (r *loadRun) drops() float64 {
	m, err := loadScrape(loadDaemonMetrics)
	if err != nil {
		return math.NaN() // a NaN delta is never "no drops": cell c reads it as a rise
	}
	return m.SpoolDrops
}

// cellLogins is cells a and b: log in, authorize and play the profile's
// steps at the design rate. PASS iff no error, no late play and
// command_permitted p99 under 5 ms.
func (r *loadRun) cellLogins(ctx context.Context, c loadCell) loadCell {
	c, res := r.measure(c, func() devicemock.FleetResult {
		return r.fleet(ctx, c.Transport, c.Rate, c.Duration, false)
	})
	c.Pass = res.Errors == 0 && res.Late == 0 && res.StepP99["command_permitted"] < 5*time.Millisecond
	return c
}

// cellAccounting is cell c: account_start and account_stop alone, the rate
// stepped x1.5 every 60 s from 170 until the device-observed p99 of either
// passes 50 ms or spool drops rise at all (ruling F7; there is no Offer
// latency metric), or a play errors or starts late. The capacity is the last
// step under all of them; PASS iff the design rate itself is.
func (r *loadRun) cellAccounting(ctx context.Context, c loadCell) loadCell {
	var (
		total    time.Duration
		capacity float64
		steps    = map[string]string{}
	)
	c, _ = r.measure(c, func() devicemock.FleetResult {
		var res devicemock.FleetResult
		for n, rate := 0, c.Rate; n < loadAcctSteps; n, rate = n+1, rate*1.5 {
			before := r.drops()
			res = r.fleet(ctx, "tcp", rate, loadStepDuration, true)
			total += loadStepDuration
			p99 := max(res.StepP99["account_start"], res.StepP99["account_stop"])
			drops := r.drops() - before
			k := fmt.Sprintf("step_%d_", n+1)
			steps[k+"rate_per_s"] = strconv.FormatFloat(rate, 'f', 0, 64)
			steps[k+"account_p99_ms"] = loadMS(p99)
			steps[k+"spool_drops"] = strconv.FormatFloat(drops, 'f', 0, 64)
			steps[k+"errors_late"] = fmt.Sprintf("%d, %d", res.Errors, res.Late)
			if p99 > loadAcctP99Gate || !(drops <= 0) || res.Errors > 0 || res.Late > 0 {
				return res
			}
			capacity = rate
		}
		return res
	})
	c.Duration = total
	maps.Copy(c.Observed, steps)
	c.Observed["capacity_per_s"] = strconv.FormatFloat(capacity, 'f', 0, 64)
	c.Rate = capacity
	c.Pass = capacity >= loadRate
	return c
}

// cellFaults is cell d: the design rate with a policy edit a third of the
// way in and a session-store fault (the member stopped, then continued, 20 s)
// at two thirds of the run, both scheduled from the cell's start and each
// checking ctx, so a STOP ends them. The swap is awaited concurrently with the
// fault. PASS iff no play hangs past 10 s (a play's time includes its mint, so
// the broker is covered too), port49d and the broker each said the edit swapped
// (the seconds each took are recorded), and the fault fell wholly inside the
// fleet's run.
func (r *loadRun) cellFaults(ctx context.Context, c loadCell) loadCell {
	var (
		wg             sync.WaitGroup
		swapObs        map[string]string
		swapped        bool
		stopAt, contAt time.Time
		fleetEnd       time.Time
		sessArgs       = []string{"--data-dir", r.sess.data}
	)
	cont := func() { _ = loadSignal(r.sess.pidfile(), sessArgs, syscall.SIGCONT) }
	r.onAbort(2, cont)
	c, res := r.measure(c, func() devicemock.FleetResult {
		t0 := time.Now()
		wg.Add(2)
		go func() { // the edit, and the wait for each process's swap
			defer wg.Done()
			if !sleepUntil(ctx, t0.Add(c.Duration/3)) {
				return
			}
			swapObs, swapped = r.reloadPolicy(ctx)
		}()
		go func() { // the fault, whatever the reload is doing
			defer wg.Done()
			if !sleepUntil(ctx, t0.Add(2*c.Duration/3)) {
				return
			}
			if why := loadSignal(r.sess.pidfile(), sessArgs, syscall.SIGSTOP); why != "" {
				r.t.Logf("cell d: the session store was not stopped: %s", why)
				return
			}
			stopAt = time.Now()
			sleepCtx(ctx, 20*time.Second)
			cont()
			contAt = time.Now()
		}()
		res := r.fleet(ctx, c.Transport, c.Rate, c.Duration, false)
		fleetEnd = time.Now()
		return res
	})
	wg.Wait()
	cont() // whatever happened above, the member runs again
	maps.Copy(c.Observed, swapObs)
	c.Observed["fault"] = "policy edit at one third; session store stopped 20s at two thirds"
	c.Observed["hang_bound_ms"] = loadMS(loadHangBound)
	inside := loadFaultInWindow(stopAt, contAt, fleetEnd)
	c.Observed["fault_inside_run"] = strconv.FormatBool(inside)
	c.Pass = res.Max <= loadHangBound && swapped && swapObs != nil && inside && ctx.Err() == nil
	return c
}

// loadSwapWait bounds how long a process has to say it swapped: two parses at
// fleet size (loadBoth) with room.
const loadSwapWait = 6 * time.Minute

// reloadPolicy edits the policy (one person's token_ttl, so the bundle really
// changes) and waits for port49d and the broker each to say "policy reloaded",
// answering the seconds each took, or the processes that never did. It gives up
// when ctx ends.
func (r *loadRun) reloadPolicy(ctx context.Context) (map[string]string, bool) {
	r.reloads++
	r.daemon.mark()
	r.broker.mark()
	start := time.Now()
	if err := os.WriteFile(r.policyPath, []byte(loadEditedPolicy(r.reloads)), 0o600); err != nil {
		r.t.Logf("cell d: the policy edit: %v", err)
		return map[string]string{"policy_edit": "not written"}, false
	}
	obs, ok := r.awaitReloads(ctx, start)
	if !ok {
		return obs, false
	}
	// Put the original back and wait for that reload too, so a later cell, or a
	// restart in runLoop, never reads a policy that differs from the stack's.
	r.daemon.mark()
	r.broker.mark()
	start = time.Now()
	if err := os.WriteFile(r.policyPath, []byte(loadPolicy()), 0o600); err != nil {
		r.t.Logf("cell d: the policy restore: %v", err)
		obs["policy_restore"] = "not written"
		return obs, false
	}
	if _, ok := r.awaitReloads(ctx, start); !ok {
		obs["policy_restore"] = "not reloaded"
		return obs, false
	}
	return obs, true
}

// loadEditedPolicy is the load policy with one person's token_ttl edited, so the
// bundle really changes. It edits downward: MaxTokenTTL (900s) is the ceiling,
// and a value above it is refused by both processes.
func loadEditedPolicy(reloads int) string {
	return strings.Replace(loadPolicy(), "username: human000, token_ttl: 900s",
		"username: human000, token_ttl: "+strconv.Itoa(900-reloads)+"s", 1)
}

// awaitReloads waits for port49d and the broker each to say "policy reloaded"
// after their marks, answering the seconds each took, or the processes that
// never did.
func (r *loadRun) awaitReloads(ctx context.Context, start time.Time) (map[string]string, bool) {
	wait := func(p *regionProc) func() (time.Duration, error) {
		return func() (time.Duration, error) {
			for !strings.Contains(p.said(), "policy reloaded (") {
				if time.Since(start) > loadSwapWait {
					return 0, fmt.Errorf("%s did not say it reloaded within %v", p.name, loadSwapWait)
				}
				if !sleepCtx(ctx, 250*time.Millisecond) {
					return 0, ctx.Err()
				}
			}
			return time.Since(start), nil
		}
	}
	return loadAwaitSwaps(map[string]func() (time.Duration, error){"port49d": wait(r.daemon), "port49_broker": wait(r.broker)})
}

// sleepCtx sleeps d and reports whether it slept it all: false when ctx ended first.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	select {
	case <-time.After(d):
		return ctx.Err() == nil
	case <-ctx.Done():
		return false
	}
}

// sleepUntil is sleepCtx to the instant at.
func sleepUntil(ctx context.Context, at time.Time) bool { return sleepCtx(ctx, time.Until(at)) }

// cellMintBurst is cell e: 20 concurrent batch mints (100 devices each) from
// one principal, halfway through the design rate's run. PASS iff none errors;
// the burst's p99 is recorded.
func (r *loadRun) cellMintBurst(ctx context.Context, c loadCell) loadCell {
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		took []time.Duration
		errs int
	)
	c, _ = r.measure(c, func() devicemock.FleetResult {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if !sleepCtx(ctx, c.Duration/2) {
				return
			}
			var burst sync.WaitGroup
			for n := range loadMintBurst {
				burst.Add(1)
				go func() {
					defer burst.Done()
					var devs []string
					for i := range loadBatchSize {
						devs = append(devs, loadDeviceName((n*loadBatchSize+i)%loadDevices))
					}
					start := time.Now()
					out, err := r.mintBatch(0, devs)
					d := time.Since(start)
					mu.Lock()
					defer mu.Unlock()
					took = append(took, d)
					if err != nil || len(out.Results) != len(devs) {
						errs++
					}
					for _, it := range out.Results {
						if it.Login == "" {
							errs++
							break
						}
					}
				}()
			}
			burst.Wait()
		}()
		return r.fleet(ctx, c.Transport, c.Rate, c.Duration, false)
	})
	wg.Wait()
	slices.Sort(took)
	c.Observed["burst_mints"] = strconv.Itoa(loadMintBurst)
	c.Observed["burst_devices_each"] = strconv.Itoa(loadBatchSize)
	c.Observed["burst_p50_ms"] = loadMS(loadPercentile(took, 50))
	c.Observed["burst_p99_ms"] = loadMS(loadPercentile(took, 99))
	c.Observed["burst_errors"] = strconv.Itoa(errs)
	c.Pass = errs == 0 && len(took) == loadMintBurst
	return c
}

// cellNetem is cell f: the directory store behind a 40 ms delay (tc netem on
// its members' client ports, as lab-regions applies it under sudo -n), the
// sign-in p99 recorded, and the call timeout compared with the round trip.
// PASS iff no error and the daemon's store-call p99 stays under the call timeout.
func (r *loadRun) cellNetem(ctx context.Context, c loadCell) loadCell {
	undo := r.loadNetemOn()
	defer undo()
	c, res := r.measure(c, func() devicemock.FleetResult {
		return r.fleet(ctx, c.Transport, c.Rate, c.Duration, false)
	})
	undo()
	c.Observed["netem_delay"] = loadNetemDelay
	c.Observed["call_timeout_ms"] = loadMS(loadCallTimeout)
	c.Observed["signin_p99_ms"] = loadMS(res.StepP99["login"])
	var p99 time.Duration
	if f, err := strconv.ParseFloat(c.Observed["daemon_store_call_p99_ms"], 64); err == nil {
		p99 = time.Duration(f * float64(time.Millisecond))
	}
	c.Pass = res.Errors == 0 && p99 < loadCallTimeout
	return c
}
