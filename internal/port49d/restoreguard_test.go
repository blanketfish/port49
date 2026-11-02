package port49d

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/blanketfish/port49/internal/store"
	etcdstore "github.com/blanketfish/port49/internal/store/etcd"
)

// judgeNow is one read as keep takes it: the record, then the read.
func judgeNow(g *restoreGuard, r etcdstore.RestoreRead, err error) {
	high, seen, guardHigh := g.recorded()
	g.judge(r, err, high, seen, guardHigh)
}

// The guard's states (Task 15d): it enters when a read shows the witness
// below the highest followed, or gone after one was seen; a read that
// fails leaves it where it is, said once per run of failures; a plain
// witness write, or a purge from before the drop, does not lift it; a
// purge written after the drop does.
func TestTheRestoreGuardEntersOnADropAndLeavesOnlyOnAPurge(t *testing.T) {
	var out bytes.Buffer
	gauge := prometheus.NewGauge(prometheus.GaugeOpts{Name: "g"})
	g := newRestoreGuard(&out)
	g.begin(gauge, nil, nil)
	unavailable := errors.Join(store.ErrUnavailable, errors.New("down"))
	judgeNow(g, etcdstore.RestoreRead{Witness: 10, Header: 12}, nil)
	g.Saw(20) // a witness followed
	judgeNow(g, etcdstore.RestoreRead{Witness: 20, Purged: 5, Header: 25}, nil)
	if !g.Allows() || testutil.ToFloat64(gauge) != 0 {
		t.Fatalf("guarded with nothing restored: %q", out.String())
	}
	judgeNow(g, etcdstore.RestoreRead{}, unavailable)
	judgeNow(g, etcdstore.RestoreRead{}, unavailable)
	if g.Allows() || testutil.ToFloat64(gauge) != 0 || strings.Count(out.String(), "reading meta/witness") != 1 ||
		strings.Contains(out.String(), "was restored from a snapshot") {
		t.Fatalf("a failed read guarded, left redemptions open, or was said per read: %q", out.String())
	}
	judgeNow(g, etcdstore.RestoreRead{Witness: 12, Purged: 5, Header: 30}, nil) // the drop
	if g.Allows() || testutil.ToFloat64(gauge) != 1 ||
		!strings.Contains(out.String(), "meta/witness is at revision 12, below the 20 this port49d followed") {
		t.Fatalf("a drop did not guard: %v %q", g.Allows(), out.String())
	}
	for name, step := range map[string]func(){
		"a failed read":           func() { judgeNow(g, etcdstore.RestoreRead{}, unavailable) },
		"a plain witness write":   func() { judgeNow(g, etcdstore.RestoreRead{Witness: 31, Purged: 5, Header: 31}, nil) },
		"a witness followed":      func() { g.Saw(40) },
		"a purge at the drop":     func() { judgeNow(g, etcdstore.RestoreRead{Witness: 31, Purged: 30, Header: 31}, nil) },
		"a purge before the drop": func() { judgeNow(g, etcdstore.RestoreRead{Witness: 41, Purged: 29, Header: 42}, nil) },
	} {
		step()
		if g.Allows() || testutil.ToFloat64(gauge) != 1 {
			t.Fatalf("%s lifted the guard", name)
		}
	}
	judgeNow(g, etcdstore.RestoreRead{Witness: 45, Purged: 44, Header: 46}, nil) // the runner's purge
	if !g.Allows() || testutil.ToFloat64(gauge) != 0 || !strings.Contains(out.String(), "redemptions are served again") {
		t.Fatalf("a purge after the drop did not lift the guard: %q", out.String())
	}
	judgeNow(g, etcdstore.RestoreRead{Witness: 46, Purged: 44, Header: 47}, nil)
	if !g.Allows() {
		t.Fatal("the witness after the purge guarded again")
	}

	// Gone after one was seen guards too; gone before any was seen does not.
	fresh := newRestoreGuard(&out)
	fresh.begin(gauge, nil, nil)
	judgeNow(fresh, etcdstore.RestoreRead{Header: 3}, nil)
	if !fresh.Allows() {
		t.Fatal("no witness on a new keyspace guarded")
	}
	fresh.Saw(7)
	judgeNow(fresh, etcdstore.RestoreRead{Header: 50}, nil)
	if fresh.Allows() || !strings.Contains(out.String(), "meta/witness is absent, below the 7 this port49d followed") {
		t.Fatalf("a witness gone after one was seen did not guard: %q", out.String())
	}
}

// A run after a store gone refuses redemptions until its first read
// judges the store: the outage may have been the restore (Task 15d).
func TestARunAfterAStoreGoneRedeemsOnlyOnceTheStoreIsJudged(t *testing.T) {
	gauge := prometheus.NewGauge(prometheus.GaugeOpts{Name: "g"})
	g := newRestoreGuard(&bytes.Buffer{})
	g.begin(gauge, nil, nil)
	if !g.Allows() {
		t.Fatal("a cold start with nothing followed refused")
	}
	g.Saw(20)
	g.begin(gauge, nil, nil) // the next run
	if g.Allows() {
		t.Fatal("a run after one that followed a witness redeemed before judging the store")
	}
	judgeNow(g, etcdstore.RestoreRead{}, errors.New("down"))
	if g.Allows() {
		t.Fatal("a failed first read opened redemptions")
	}
	judgeNow(g, etcdstore.RestoreRead{Witness: 20, Header: 21}, nil)
	if !g.Allows() {
		t.Fatal("the first read that found nothing restored left redemptions refused")
	}
}

// A witness the runner writes while port49d's read is in flight, followed
// before the read is judged, is no restore: the record is taken before
// the read, as the runner's is (Task 15c, readWitness).
func TestAWitnessFollowedDuringTheGuardsReadIsNoDrop(t *testing.T) {
	var out bytes.Buffer
	g := newRestoreGuard(&out)
	g.Saw(100)
	high, seen, guardHigh := g.recorded()
	g.Saw(160) // the runner's next witness, followed while the read was in flight
	g.judge(etcdstore.RestoreRead{Witness: 100, Header: 150}, nil, high, seen, guardHigh)
	if !g.Allows() {
		t.Fatalf("a routine witness write guarded port49d: %q", out.String())
	}
}

// The guard's line gives the way out of every state it can be left in, and
// never advises a restart before the restored tokens are deleted: a restart
// forgets the drop and redeems them (final review 7e-2 I-3). It says that a
// device whose authentication ERROR is final refuses break-glass meanwhile.
func TestTheGuardLineGivesTheSafeWayOut(t *testing.T) {
	var out bytes.Buffer
	g := newRestoreGuard(&out)
	g.Saw(20)
	judgeNow(g, etcdstore.RestoreRead{Witness: 12, Header: 30}, nil)
	line := out.String()
	for _, want := range []string{
		"a device whose authentication ERROR is final (IOS-XE) refuses break-glass too",
		"etcdctl del --prefix <prefix>v1/t/",
		"stop every port49-broker, delete meta/judged and start them",
		"never restart this port49d before the restored tokens are deleted",
	} {
		if !strings.Contains(line, want) {
			t.Errorf("the line lacks %q: %s", want, line)
		}
	}
	if strings.Contains(line, "already said its purge line for this restore, restart this port49d") {
		t.Errorf("the line still advises a bare restart: %s", line)
	}
}

// pass takes the record before it reads, never after: a witness followed
// while the read is in flight (the read here calls Saw, as the watch does)
// is newer than the read, no drop (final review 7e-2 I-4; mutant m27 moved
// the record after the read and survived every other guard test).
func TestAPassTakesTheRecordBeforeItReads(t *testing.T) {
	var out bytes.Buffer
	g := newRestoreGuard(&out)
	g.Saw(100)
	g.pass(context.Background(), time.Second, func(context.Context) (etcdstore.RestoreRead, error) {
		g.Saw(160) // the runner's next witness, followed while the read is in flight
		return etcdstore.RestoreRead{Witness: 100, Header: 150}, nil
	})
	if !g.Allows() {
		t.Fatalf("a routine witness write followed during a read guarded port49d: %q", out.String())
	}
	// A real drop is still caught by the same pass.
	g.pass(context.Background(), time.Second, func(context.Context) (etcdstore.RestoreRead, error) {
		return etcdstore.RestoreRead{Witness: 40, Header: 200}, nil
	})
	if g.Allows() {
		t.Fatal("a pass that read the witness below the record did not guard")
	}
}

// Once a witness was followed, a read that fails leaves redemptions
// refused until one answers: the outage may be the restore, and a
// redemption must not land between the store's return and the next read
// (Task 15d, ruling M-3). It is no guard: the gauge counts it, the
// guard's entry line is not said.
func TestAFailedReadRefusesRedemptionsUntilOneAnswers(t *testing.T) {
	var out bytes.Buffer
	g := newRestoreGuard(&out)
	g.begin(prometheus.NewGauge(prometheus.GaugeOpts{Name: "g"}), nil, nil)
	g.Saw(20)
	judgeNow(g, etcdstore.RestoreRead{Witness: 20, Header: 21}, nil)
	judgeNow(g, etcdstore.RestoreRead{}, errors.New("down"))
	if g.Allows() {
		t.Fatal("a failed read left redemptions open")
	}
	judgeNow(g, etcdstore.RestoreRead{}, errors.New("down"))
	if strings.Count(out.String(), "reading meta/witness") != 1 {
		t.Fatalf("a run of failures was said more than once: %q", out.String())
	}
	judgeNow(g, etcdstore.RestoreRead{Witness: 20, Header: 30}, nil)
	if !g.Allows() {
		t.Fatal("a read that found nothing restored left redemptions refused")
	}
	// Before any witness was followed, a failed read refuses nothing.
	fresh := newRestoreGuard(&out)
	fresh.begin(prometheus.NewGauge(prometheus.GaugeOpts{Name: "g"}), nil, nil)
	judgeNow(fresh, etcdstore.RestoreRead{}, errors.New("down"))
	if !fresh.Allows() {
		t.Fatal("a failed read refused redemptions on a keyspace with no witness")
	}
}

// Each read is counted in port49_store_operations_total{op="restore_read"},
// the failed ones as errors: when only the guard's read fails, every other
// store metric looks healthy (Task 15d re-review M-7).
func TestTheGuardsReadsAreCountedByOutcome(t *testing.T) {
	ops := prometheus.NewCounterVec(prometheus.CounterOpts{Name: "ops"}, []string{"op", "outcome"})
	g := newRestoreGuard(&bytes.Buffer{})
	g.begin(prometheus.NewGauge(prometheus.GaugeOpts{Name: "g"}), nil, ops)
	judgeNow(g, etcdstore.RestoreRead{}, errors.Join(store.ErrUnavailable, errors.New("down")))
	judgeNow(g, etcdstore.RestoreRead{}, errors.New("down"))
	judgeNow(g, etcdstore.RestoreRead{Witness: 5, Header: 6}, nil)
	if got := testutil.ToFloat64(ops.WithLabelValues("restore_read", "error")); got != 2 {
		t.Fatalf("%v failed reads counted, want 2", got)
	}
	if got := testutil.ToFloat64(ops.WithLabelValues("restore_read", "ok")); got != 1 {
		t.Fatalf("%v good reads counted, want 1", got)
	}
}

// The time bound (plan 12c, Task 9a): the guard lifts on its own once every
// token the snapshot could hold has expired, at the restored witness's time
// plus token_ttl's ceiling plus 5m, on port49d's clock.

var guardClock = time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)

// boundGuard is a begun guard on a test clock that followed witness 20, with
// both gauges.
func boundGuard(t *testing.T) (g *restoreGuard, now *time.Time, out *bytes.Buffer, guarded, until prometheus.Gauge) {
	t.Helper()
	out = &bytes.Buffer{}
	clock := guardClock
	guarded = prometheus.NewGauge(prometheus.GaugeOpts{Name: "g"})
	until = prometheus.NewGauge(prometheus.GaugeOpts{Name: "u"})
	g = newRestoreGuard(out)
	g.now = func() time.Time { return clock }
	g.begin(guarded, until, nil)
	g.Saw(20)
	return g, &clock, out, guarded, until
}

// The guard's clock is the pointer the test steps.
func setNow(g *restoreGuard, now *time.Time) { g.now = func() time.Time { return *now } }

func TestAnOldWitnessLiftsNoGuard(t *testing.T) {
	g, now, out, guarded, until := boundGuard(t)
	setNow(g, now)
	at := now.Add(-21 * time.Minute)
	judgeNow(g, etcdstore.RestoreRead{Witness: 12, Header: 30, WitnessAt: at}, nil)
	if !g.Allows() || testutil.ToFloat64(guarded) != 0 || testutil.ToFloat64(until) != 0 ||
		!strings.Contains(out.String(), "more than 20m0s ago") {
		t.Fatalf("an old snapshot guarded, or was not said: %v %q", g.Allows(), out.String())
	}
	judgeNow(g, etcdstore.RestoreRead{Witness: 12, Header: 31, WitnessAt: at}, nil)
	if !g.Allows() || strings.Count(out.String(), "port49d: store: meta/witness") != 1 {
		t.Fatalf("the next read at the same witness tripped again: %q", out.String())
	}
}

func TestARecentWitnessGuardsUntilItsTimeAndTheBound(t *testing.T) {
	g, now, out, guarded, until := boundGuard(t)
	setNow(g, now)
	at := now.Add(-5 * time.Minute)
	lift := at.Add(20 * time.Minute)
	judgeNow(g, etcdstore.RestoreRead{Witness: 12, Header: 30, WitnessAt: at}, nil)
	if g.Allows() || testutil.ToFloat64(guarded) != 1 || testutil.ToFloat64(until) != float64(lift.Unix()) {
		t.Fatalf("a recent snapshot did not guard to its bound: %q", out.String())
	}
	*now = lift.Add(-time.Second)
	judgeNow(g, etcdstore.RestoreRead{Witness: 12, Header: 31, WitnessAt: at}, nil)
	if g.Allows() {
		t.Fatal("lifted a second before the bound")
	}
	*now = lift
	judgeNow(g, etcdstore.RestoreRead{Witness: 12, Header: 32, WitnessAt: at}, nil)
	if !g.Allows() || testutil.ToFloat64(guarded) != 0 || testutil.ToFloat64(until) != 0 ||
		!strings.Contains(out.String(), "every token the restored snapshot could hold has now expired") {
		t.Fatalf("not lifted at the bound: %v %q", g.Allows(), out.String())
	}
	judgeNow(g, etcdstore.RestoreRead{Witness: 12, Header: 33, WitnessAt: at}, nil)
	if !g.Allows() {
		t.Fatal("the witness after the lift guarded again")
	}
}

func TestAPurgeBeforeTheBoundLifts(t *testing.T) {
	g, now, out, guarded, until := boundGuard(t)
	setNow(g, now)
	at := now.Add(-5 * time.Minute)
	judgeNow(g, etcdstore.RestoreRead{Witness: 12, Header: 30, WitnessAt: at}, nil)
	*now = at.Add(6 * time.Minute)
	judgeNow(g, etcdstore.RestoreRead{Witness: 40, Purged: 39, Header: 41, WitnessAt: at}, nil)
	if !g.Allows() || testutil.ToFloat64(guarded) != 0 || testutil.ToFloat64(until) != 0 ||
		!strings.Contains(out.String(), "the broker runner's purge after the restore is done") {
		t.Fatalf("a purge did not lift: %q", out.String())
	}
}

func TestAWitnessWithNoUsableTimeGuardsUntilThePurge(t *testing.T) {
	cases := map[string]etcdstore.RestoreRead{
		"the witness absent":     {Header: 30},
		"no time in the witness": {Witness: 12, Header: 30},
		"a time ahead":           {Witness: 12, Header: 30, WitnessAt: guardClock.Add(5*time.Minute + time.Second)},
	}
	for name, r := range cases {
		t.Run(name, func(t *testing.T) {
			g, now, out, guarded, until := boundGuard(t)
			setNow(g, now)
			judgeNow(g, r, nil)
			if g.Allows() || testutil.ToFloat64(guarded) != 1 || testutil.ToFloat64(until) != 0 ||
				!strings.Contains(out.String(), "only the purge lifts it") {
				t.Fatalf("no bound should be armed: %q", out.String())
			}
			*now = now.Add(24 * time.Hour)
			r.Header = 31
			judgeNow(g, r, nil)
			if g.Allows() || testutil.ToFloat64(guarded) != 1 || testutil.ToFloat64(until) != 0 {
				t.Fatal("a day later it lifted without a purge")
			}
			r.Header, r.Purged = 40, 39
			judgeNow(g, r, nil)
			if !g.Allows() || testutil.ToFloat64(guarded) != 0 {
				t.Fatal("a purge after the drop did not lift it")
			}
		})
	}
}

// A port49d 3m behind the runner, within the allowance: it lifts at the
// witness's time + 20m on its own clock, which is 23m of its time.
func TestPort49dsClockBehind(t *testing.T) {
	g, now, _, _, until := boundGuard(t)
	setNow(g, now)
	at := now.Add(3 * time.Minute)
	judgeNow(g, etcdstore.RestoreRead{Witness: 12, Header: 30, WitnessAt: at}, nil)
	if g.Allows() || testutil.ToFloat64(until) != float64(at.Add(20*time.Minute).Unix()) {
		t.Fatal("not guarded to at + 20m")
	}
	*now = guardClock.Add(23*time.Minute - time.Second)
	judgeNow(g, etcdstore.RestoreRead{Witness: 12, Header: 31, WitnessAt: at}, nil)
	if g.Allows() {
		t.Fatal("lifted before 23m of its own time")
	}
	*now = guardClock.Add(23 * time.Minute)
	judgeNow(g, etcdstore.RestoreRead{Witness: 12, Header: 32, WitnessAt: at}, nil)
	if !g.Allows() {
		t.Fatal("not lifted at 23m of its own time")
	}
}

// Over port49d's clock offset against the runner and a minting broker's
// offset against the runner: a token minted 61 s after the witness's time,
// at token_ttl 15m, is never redeemable (ExpiresAt after port49d's now, the
// check liveTokens makes) while the guard allows it. The 5m allowance is the
// broker skew plus the witness's lead, so 3m59s of skew is the edge.
func TestTheGuardOutlastsEveryRestoredTokenOnPort49dsClock(t *testing.T) {
	const lead = 61 * time.Second
	for _, p := range []time.Duration{-10 * time.Minute, -3 * time.Minute, 0, 3 * time.Minute, 10 * time.Minute} {
		for _, m := range []time.Duration{-3 * time.Minute, 0, 3 * time.Minute, 4*time.Minute - time.Second} {
			t.Run(fmt.Sprintf("p=%v,m=%v", p, m), func(t *testing.T) {
				g, now, _, _, until := boundGuard(t)
				setNow(g, now)
				// The restore lands as the snapshot's last mint is done, on
				// port49d's clock p ahead of the runner's.
				at := now.Add(-lead - p)
				expires := at.Add(lead + m + 15*time.Minute)
				start := *now
				aheadPast := at.After(start.Add(5 * time.Minute))
				for step := time.Duration(0); step <= 30*time.Minute; step += time.Second {
					*now = start.Add(step)
					judgeNow(g, etcdstore.RestoreRead{Witness: 12, Header: 30 + uint64(step/time.Second), WitnessAt: at}, nil)
					if g.Allows() && expires.After(*now) {
						t.Fatalf("redeemable token at +%v with the guard open", step)
					}
					if aheadPast && (g.Allows() || testutil.ToFloat64(until) != 0) {
						t.Fatalf("a witness ahead past the allowance armed a bound at +%v", step)
					}
				}
				if !aheadPast && !g.Allows() {
					t.Fatal("a usable witness left the guard up 30m on")
				}
			})
		}
	}
}

func TestASecondRestoreWhileGuardedRetakesTheBound(t *testing.T) {
	g, now, _, _, until := boundGuard(t)
	setNow(g, now)
	g.Saw(12)
	at1 := now.Add(-2 * time.Minute)
	judgeNow(g, etcdstore.RestoreRead{Witness: 12, Header: 30, WitnessAt: at1}, nil)
	if g.Allows() {
		t.Fatal("not guarded by the first drop")
	}
	at2 := now.Add(-time.Minute)
	judgeNow(g, etcdstore.RestoreRead{Witness: 8, Header: 35, WitnessAt: at2}, nil)
	if g.Allows() || testutil.ToFloat64(until) != float64(at2.Add(20*time.Minute).Unix()) {
		t.Fatalf("the bound was not retaken from the second snapshot")
	}
	judgeNow(g, etcdstore.RestoreRead{Witness: 9, Purged: 35, Header: 36, WitnessAt: at2}, nil)
	if g.Allows() {
		t.Fatal("a purge at the second drop's header lifted it")
	}
	judgeNow(g, etcdstore.RestoreRead{Witness: 9, Purged: 37, Header: 38, WitnessAt: at2}, nil)
	if !g.Allows() {
		t.Fatal("a purge after the second drop did not lift it")
	}
}

// A witness followed while a read is in flight is newer than the read, not a
// second restore: it must not move dropAt past the runner's one purge (F2).
func TestAWitnessFollowedDuringAGuardedReadIsNoSecondRestore(t *testing.T) {
	g, now, _, _, _ := boundGuard(t)
	setNow(g, now)
	judgeNow(g, etcdstore.RestoreRead{Witness: 12, Header: 30}, nil) // guarded, purge-only
	high, seen, guardHigh := g.recorded()
	g.Saw(50) // followed while the next read is in flight
	g.judge(etcdstore.RestoreRead{Witness: 31, Header: 40}, nil, high, seen, guardHigh)
	if g.Allows() {
		t.Fatal("lifted by a plain witness")
	}
	judgeNow(g, etcdstore.RestoreRead{Witness: 51, Purged: 35, Header: 46}, nil)
	if !g.Allows() {
		t.Fatal("the purge above the original drop did not lift it: dropAt moved")
	}
}

func TestTheGuardLineSaysWhenItLifts(t *testing.T) {
	g, now, out, _, _ := boundGuard(t)
	setNow(g, now)
	at := now.Add(-time.Minute)
	judgeNow(g, etcdstore.RestoreRead{Witness: 12, Header: 30, WitnessAt: at}, nil)
	line := out.String()
	for _, want := range []string{at.Add(20 * time.Minute).UTC().Format(time.RFC3339), "15m0s", "5m0s"} {
		if !strings.Contains(line, want) {
			t.Errorf("the line lacks %q: %q", want, line)
		}
	}
	if strings.Contains(line, `{"`) || strings.Contains(line, `"who"`) {
		t.Errorf("the line holds a witness body: %q", line)
	}
}
