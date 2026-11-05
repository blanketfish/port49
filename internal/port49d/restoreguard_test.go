package port49d

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/blanketfish/port49/internal/policy"
	"github.com/blanketfish/port49/internal/store"
	etcdstore "github.com/blanketfish/port49/internal/store/etcd"
)

// judgeNow is one read as keep takes it: the record, then the read.
func judgeNow(g *restoreGuard, r etcdstore.RestoreRead, err error) {
	judgeScan(g, r, err, scanResult{})
}

// judgeScan is judgeNow with the scan of the token family the read called for.
func judgeScan(g *restoreGuard, r etcdstore.RestoreRead, err error, sc scanResult) {
	high, seen, guardHigh := g.recorded()
	g.judge(r, err, high, seen, guardHigh, sc)
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
	g.judge(etcdstore.RestoreRead{Witness: 100, Header: 150}, nil, high, seen, guardHigh, scanResult{})
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
	}, nil)
	if !g.Allows() {
		t.Fatalf("a routine witness write followed during a read guarded port49d: %q", out.String())
	}
	// A real drop is still caught by the same pass.
	g.pass(context.Background(), time.Second, func(context.Context) (etcdstore.RestoreRead, error) {
		return etcdstore.RestoreRead{Witness: 40, Header: 200}, nil
	}, nil)
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

// The time bound (plan 12c, Task 9a): the guard lifts on its own once port49d's
// clock passes the largest ExpiresAt among the token records, scanned at the
// drop and again on every guarded read, judged as redemption judges a token.

var guardClock = time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)

// boundGuard is a begun guard on a test clock that followed witness 20.
type bound struct {
	g      *restoreGuard
	now    time.Time
	out    *bytes.Buffer
	guard  prometheus.Gauge
	until  prometheus.Gauge
	header uint64
}

func newBound(t *testing.T) *bound {
	t.Helper()
	b := &bound{now: guardClock, out: &bytes.Buffer{}, header: 30,
		guard: prometheus.NewGauge(prometheus.GaugeOpts{Name: "g"}),
		until: prometheus.NewGauge(prometheus.GaugeOpts{Name: "u"})}
	b.g = newRestoreGuard(b.out)
	b.g.now = func() time.Time { return b.now }
	b.g.begin(b.guard, b.until, nil)
	b.g.Saw(20)
	return b
}

// read is one judged read at the witness w and the latest expiry latest, as a
// scan of the token family answers; the header rises with each.
func (b *bound) read(w, purged uint64, latest time.Time) {
	b.header++
	judgeScan(b.g, etcdstore.RestoreRead{Witness: w, Purged: purged, Header: b.header}, nil,
		scanResult{ran: true, max: latest})
}

func (b *bound) readSc(w uint64, sc scanResult) {
	b.header++
	judgeScan(b.g, etcdstore.RestoreRead{Witness: w, Header: b.header}, nil, sc)
}

func (b *bound) gauges() (guard, until float64) {
	return testutil.ToFloat64(b.guard), testutil.ToFloat64(b.until)
}

// A quiet store's witness can be hours older than the snapshot's last mint, so
// the bound is the tokens' own: the guard holds until the latest ExpiresAt, to
// the second, whatever the witness says (review C1).
func TestAQuietStoreRestoreStaysGuardedUntilTheLastTokenExpires(t *testing.T) {
	b := newBound(t)
	latest := b.now.Add(9 * time.Minute)
	b.read(12, 0, latest)
	if g, u := b.gauges(); b.g.Allows() || g != 1 || u != float64(latest.Unix()) {
		t.Fatalf("not guarded to the latest expiry: %v %v %q", g, u, b.out.String())
	}
	b.now = latest.Add(-time.Second)
	b.read(12, 0, latest)
	if b.g.Allows() {
		t.Fatal("lifted a second before the latest expiry")
	}
	b.now = latest
	b.read(12, 0, latest)
	if g, u := b.gauges(); !b.g.Allows() || g != 0 || u != 0 || !strings.Contains(b.out.String(), "has now expired") {
		t.Fatalf("not lifted at the latest expiry: %v %v %q", g, u, b.out.String())
	}
}

// A scan that finds every token already expired guards nothing, said once; the
// floor still refuses them (the next test).
func TestAScanThatProvesEveryTokenExpiredGuardsNothing(t *testing.T) {
	for name, latest := range map[string]time.Time{"none": {}, "all expired": guardClock.Add(-time.Second),
		"expiring now": guardClock} {
		t.Run(name, func(t *testing.T) {
			b := newBound(t)
			b.read(12, 0, latest)
			if !b.g.Allows() {
				t.Fatalf("guarded for a read: %q", b.out.String())
			}
			b.read(12, 0, latest)
			if g, u := b.gauges(); !b.g.Allows() || g != 0 || u != 0 || strings.Count(b.out.String(), "meta/witness is at revision 12") != 1 {
				t.Fatalf("guarded, or said more than once: %q", b.out.String())
			}
		})
	}
}

// A newer restore while guarded brings tokens that expire later: a re-scan
// raises the bound, it never lowers it (review C2).
func TestANewerRestoreWhileGuardedExtendsTheBound(t *testing.T) {
	b := newBound(t)
	first, second := b.now.Add(5*time.Minute), b.now.Add(14*time.Minute)
	b.read(12, 0, first)
	b.read(15, 0, second) // the snapshot restored over it, its witness above the first's
	if _, u := b.gauges(); u != float64(second.Unix()) {
		t.Fatalf("the bound did not rise: %v", u)
	}
	b.now = first.Add(time.Second)
	b.read(15, 0, second)
	if b.g.Allows() {
		t.Fatal("lifted at the first snapshot's bound")
	}
	b.read(15, 0, first) // a scan that shows less never lowers it
	if _, u := b.gauges(); u != float64(second.Unix()) {
		t.Fatalf("a smaller scan lowered the bound: %v", u)
	}
	b.now = second
	b.read(15, 0, second)
	if !b.g.Allows() {
		t.Fatal("not lifted at the second bound")
	}
}

// After a drop is judged, the witness at the drop is the baseline: a read below
// it is a second restore and guards again if live tokens came back with it
// (review C2, variant; final review I2).
func TestARestoreAfterATimeLiftIsDetected(t *testing.T) {
	b := newBound(t)
	first := b.now.Add(5 * time.Minute)
	b.read(12, 0, first)
	b.now = first
	b.read(12, 0, first)
	if !b.g.Allows() {
		t.Fatal("not lifted")
	}
	second := b.now.Add(10 * time.Minute)
	b.read(10, 0, second) // a second restore: its witness is below the first drop's baseline of 12
	if b.g.Allows() {
		t.Fatalf("a restore after a time lift was not guarded: %q", b.out.String())
	}
	if _, u := b.gauges(); u != float64(second.Unix()) {
		t.Fatalf("the bound is %v", u)
	}
	b.now = second
	b.read(10, 0, second)
	if !b.g.Allows() {
		t.Fatal("not lifted at the second bound")
	}
}

// A second restore after an all-expired drop re-arms too: the baseline is the
// witness at that drop, not the pre-restore record.
func TestASecondRestoreAfterAnAllExpiredDropIsDetected(t *testing.T) {
	b := newBound(t)
	b.read(12, 0, b.now.Add(-2*time.Hour))
	if !b.g.Allows() {
		t.Fatal("guarded for an all-expired snapshot")
	}
	b.read(9, 0, b.now.Add(4*time.Minute)) // below the drop's 12, with live tokens
	if b.g.Allows() {
		t.Fatalf("a second restore was not guarded: %q", b.out.String())
	}
}

// A restore without --bump-revision from an old snapshot leaves the witness
// below the old record while brokers mint: the drop was judged, so a fresh
// token never arms the guard (final review I2).
func TestAFreshMintAfterAnAllExpiredDropNeverArmsTheGuard(t *testing.T) {
	b := newBound(t)
	t0 := b.now
	f := &fakeTokens{recs: []fakeTok{{minted: t0.Add(-3 * time.Hour), expires: t0.Add(-2 * time.Hour)}}}
	b.passAt(12, 100, f)
	b.now = t0.Add(restoreSkew + time.Second)
	for i := 0; i < 3; i++ {
		b.now = b.now.Add(scanEvery) // a broker mints; the witness is still below the old 20
		f.recs = append(f.recs, fakeTok{minted: b.now, expires: b.now.Add(10 * time.Minute)})
		b.passAt(12+uint64(i), 101+uint64(i), f)
		if !b.g.Allows() {
			t.Fatalf("pass %d: a fresh mint guarded: %q", i, b.out.String())
		}
	}
}

// fakeTokens is the token family as the guard's scan reads it.
type fakeTokens struct {
	recs []fakeTok
}

type fakeTok struct{ minted, expires time.Time }

// latest is the store's answer: only records minted by the cutoff count.
func (f *fakeTokens) latest(_ context.Context, mintedBy time.Time) (time.Time, error) {
	var m time.Time
	for _, r := range f.recs {
		if !r.minted.After(mintedBy) {
			m = laterOf(m, r.expires)
		}
	}
	return m, nil
}

// A token minted after the drop never extends the bound past the restored
// tokens' latest expiry (final review I2).
func TestAMintAfterTheDropDoesNotExtendTheBound(t *testing.T) {
	b := newBound(t)
	restored := b.now.Add(8 * time.Minute)
	f := &fakeTokens{recs: []fakeTok{{minted: b.now.Add(-9 * time.Minute), expires: restored}}}
	pass := func(w uint64) {
		b.header++
		b.g.pass(context.Background(), time.Second, func(context.Context) (etcdstore.RestoreRead, error) {
			return etcdstore.RestoreRead{Witness: w, Header: b.header}, nil
		}, f.latest)
	}
	pass(12)
	if _, u := b.gauges(); u != float64(restored.Unix()) {
		t.Fatalf("the bound is %v, want the restored expiry", u)
	}
	b.now = b.now.Add(restoreSkew + time.Second)                                          // a mint within the skew of the read still counts, by design
	f.recs = append(f.recs, fakeTok{minted: b.now, expires: b.now.Add(15 * time.Minute)}) // a running broker's mint
	pass(12)
	pass(13)
	if _, u := b.gauges(); u != float64(restored.Unix()) {
		t.Fatalf("a mint after the drop moved the bound to %v", u)
	}
}

// Once lifted, a token expiring at or before the bound stays refused, whatever
// port49d's clock then says, until a purge (review C3).
func TestAClockStepBackAfterALiftStillRefusesARestoredToken(t *testing.T) {
	b := newBound(t)
	latest := b.now.Add(5 * time.Minute)
	b.read(12, 0, latest)
	b.now = latest.Add(time.Second)
	b.read(12, 0, latest)
	if !b.g.Allows() || !b.g.RedeemFloor().Equal(latest) {
		t.Fatalf("lifted %v with floor %v, want %v", b.g.Allows(), b.g.RedeemFloor(), latest)
	}
	// NTP steps port49d back 8m: a token expiring at the bound is live on its
	// clock again, and the floor still refuses it. The witness caught up, so no
	// re-scan is called for.
	b.now = latest.Add(-8 * time.Minute)
	b.read(40, 0, latest)
	if !b.g.RedeemFloor().Equal(latest) {
		t.Fatalf("the floor moved: %v", b.g.RedeemFloor())
	}
	if exp := latest; !(exp.After(b.now) && !exp.After(b.g.RedeemFloor())) {
		t.Fatal("the restored token is neither live on the stepped clock nor under the floor")
	}
	b.read(41, 50, time.Time{}) // a purge after the drop clears it
	if !b.g.RedeemFloor().IsZero() {
		t.Fatalf("a purge left the floor %v", b.g.RedeemFloor())
	}
}

// Every way the bound cannot be trusted leaves only the purge: the gauge reads
// 0, a day later it holds, and a purge lifts it.
func TestABoundThatCannotBeTrustedGuardsUntilThePurge(t *testing.T) {
	cases := map[string]scanResult{
		"the scan failed":          {ran: true, err: errors.New("down")},
		"a record does not decode": {ran: true, err: etcdstore.ErrTokenRecord},
		"no scan taken":            {},
		"an expiry far ahead":      {ran: true, max: guardClock.Add(policy.MaxTokenTTL + restoreSkew + time.Second)},
	}
	for name, sc := range cases {
		t.Run(name, func(t *testing.T) {
			b := newBound(t)
			b.readSc(12, sc)
			if g, u := b.gauges(); b.g.Allows() || g != 1 || u != 0 || !strings.Contains(b.out.String(), "only the purge lifts it") {
				t.Fatalf("no bound should be armed: %q", b.out.String())
			}
			b.now = b.now.Add(24 * time.Hour)
			b.readSc(12, scanResult{ran: true, max: b.now.Add(-time.Hour)}) // a later good scan arms nothing
			if g, u := b.gauges(); b.g.Allows() || g != 1 || u != 0 {
				t.Fatal("a day later it lifted without a purge")
			}
			b.read(40, b.header, time.Time{})
			if !b.g.Allows() {
				t.Fatal("a purge after the drop did not lift it")
			}
		})
	}
	// Exactly token_ttl + 5m ahead is trusted.
	b := newBound(t)
	edge := b.now.Add(policy.MaxTokenTTL + restoreSkew)
	b.read(12, 0, edge)
	if _, u := b.gauges(); b.g.Allows() || u != float64(edge.Unix()) {
		t.Fatalf("the edge expiry was not trusted: %v", u)
	}
}

// A witness followed while a read is in flight is newer than the read, not a
// second restore: it must not move dropAt past the runner's one purge (F2).
func TestAWitnessFollowedDuringAGuardedReadIsNoSecondRestore(t *testing.T) {
	g := newRestoreGuard(&bytes.Buffer{})
	g.Saw(20)
	judgeNow(g, etcdstore.RestoreRead{Witness: 12, Header: 30}, nil) // guarded, purge-only
	high, seen, guardHigh := g.recorded()
	g.Saw(50) // followed while the next read is in flight
	g.judge(etcdstore.RestoreRead{Witness: 31, Header: 40}, nil, high, seen, guardHigh, scanResult{})
	if g.Allows() {
		t.Fatal("lifted by a plain witness")
	}
	judgeNow(g, etcdstore.RestoreRead{Witness: 51, Purged: 35, Header: 46}, nil)
	if !g.Allows() {
		t.Fatal("the purge above the original drop did not lift it: dropAt moved")
	}
}

func TestTheGuardLineSaysWhenItLifts(t *testing.T) {
	b := newBound(t)
	latest := b.now.Add(7 * time.Minute)
	b.read(12, 0, latest)
	line := b.out.String()
	if !strings.Contains(line, latest.UTC().Format(time.RFC3339)) || strings.Contains(line, `{"`) || strings.Contains(line, `"who"`) {
		t.Fatalf("the line lacks the lift time, or holds a body: %q", line)
	}
}

// pass scans the token family only when the read calls for it, and judges what
// it answered: a drop with a live token guards to its expiry, and a scan that
// fails guards to the purge.
func TestAPassScansWhenAReadCallsForIt(t *testing.T) {
	b := newBound(t)
	latest := b.now.Add(3 * time.Minute)
	scans := 0
	read := func(context.Context) (etcdstore.RestoreRead, error) {
		return etcdstore.RestoreRead{Witness: 12, Header: 99}, nil
	}
	b.g.pass(context.Background(), time.Second, read, func(context.Context, time.Time) (time.Time, error) { scans++; return latest, nil })
	if scans != 1 || b.g.Allows() {
		t.Fatalf("scans %d, allows %v", scans, b.g.Allows())
	}
	if _, u := b.gauges(); u != float64(latest.Unix()) {
		t.Fatalf("the bound %v", u)
	}
	noDrop := newRestoreGuard(&bytes.Buffer{})
	noDrop.Saw(5)
	noDrop.pass(context.Background(), time.Second, func(context.Context) (etcdstore.RestoreRead, error) {
		return etcdstore.RestoreRead{Witness: 5, Header: 9}, nil
	}, func(context.Context, time.Time) (time.Time, error) { scans++; return latest, nil })
	if scans != 1 {
		t.Fatal("scanned with nothing restored")
	}
}

// A second restore whose witness is above the first drop's but below the old
// record brings back live tokens redeemed before the first restore: the record
// still catches it (re-review R1).
func TestASecondRestoreAboveTheFirstDropsBaselineStillGuards(t *testing.T) {
	b := newBound(t) // the record is 20
	b.read(12, 0, b.now.Add(-2*time.Hour))
	if !b.g.Allows() {
		t.Fatal("setup: the first, old snapshot guarded")
	}
	b.read(15, 0, b.now.Add(10*time.Minute)) // the right snapshot: live restored tokens
	if b.g.Allows() {
		t.Fatalf("a second restore (witness 15, below the record 20) with live tokens was served: %q", b.out.String())
	}
}

// passAt is one pass at the witness w, header h, the scan answering what f holds.
func (b *bound) passAt(w, h uint64, f *fakeTokens) {
	b.g.pass(context.Background(), time.Second, func(context.Context) (etcdstore.RestoreRead, error) {
		return etcdstore.RestoreRead{Witness: w, Header: h}, nil
	}, f.latest)
}

// A guarded re-read still takes in tokens a second restore brought, even when
// the store's own revisions say nothing changed (re-review R2: a ModRevision
// compares only within one timeline).
func TestAGuardedRereadAfterACrossTimelineRestoreKeepsTheLaterBound(t *testing.T) {
	b := newBound(t)
	f := &fakeTokens{recs: []fakeTok{{minted: b.now.Add(-time.Minute), expires: b.now.Add(5 * time.Minute)}}}
	b.passAt(12, 100, f)
	f.recs = append(f.recs, fakeTok{minted: b.now.Add(-time.Minute), expires: b.now.Add(12 * time.Minute)})
	b.now = b.now.Add(scanEvery + time.Second)
	b.passAt(15, 120, f) // restore #2: an old-timeline snapshot
	if _, u := b.gauges(); u != float64(b.now.Add(12*time.Minute-scanEvery-time.Second).Unix()) {
		t.Fatalf("the bound stayed %v, want the second snapshot's", u)
	}
}

// The pass that would lift scans first, however recent the last scan: a token
// the cheaper passes missed cannot be lifted over.
func TestThePassThatWouldLiftScansFirst(t *testing.T) {
	b := newBound(t)
	t0 := b.now
	f := &fakeTokens{recs: []fakeTok{{minted: t0.Add(-time.Minute), expires: t0.Add(5 * time.Minute)}}}
	b.passAt(12, 100, f)
	b.now = t0.Add(5*time.Minute - 2*time.Second)
	b.passAt(12, 101, f) // a scan: its last
	f.recs = append(f.recs, fakeTok{minted: t0.Add(-time.Minute), expires: t0.Add(12 * time.Minute)})
	b.now = t0.Add(5 * time.Minute) // 2 s on: inside the rate limit, but the bound is reached
	b.passAt(12, 102, f)
	if b.g.Allows() {
		t.Fatalf("lifted over a token the last scans had not seen: %q", b.out.String())
	}
}

// A restored token minted a few minutes after port49d's read, by a broker whose
// clock runs ahead (within restoreSkew), is still counted: the cutoff is the
// read plus the skew (re-review R4).
func TestARestoredTokenFromAClockAheadBrokerHoldsTheBound(t *testing.T) {
	b := newBound(t)
	restored := b.now.Add(14 * time.Minute)
	f := &fakeTokens{recs: []fakeTok{{minted: b.now.Add(3 * time.Minute), expires: restored}}}
	b.passAt(12, 100, f)
	if g, u := b.gauges(); b.g.Allows() || g != 1 || u != float64(restored.Unix()) {
		t.Fatalf("a restored token from a clock 3m ahead was left out: %v %v", g, u)
	}
}

// While the witness stays below the old record, after an all-expired drop, a
// pass keeps scanning with the first drop's cutoff: a broker's mint after it
// never guards, a token minted before it that is live does (re-review R1 with
// I2).
func TestAPassAfterAnAllExpiredDropScansWithTheDropsCutoff(t *testing.T) {
	b := newBound(t) // the record is 20
	t0 := b.now
	f := &fakeTokens{recs: []fakeTok{{minted: t0.Add(-3 * time.Hour), expires: t0.Add(-2 * time.Hour)}}}
	b.passAt(12, 100, f)
	if !b.g.Allows() {
		t.Fatalf("guarded for an all-expired snapshot: %q", b.out.String())
	}
	b.now = t0.Add(restoreSkew + time.Minute)
	f.recs = append(f.recs, fakeTok{minted: b.now, expires: b.now.Add(15 * time.Minute)}) // a running broker
	b.passAt(13, 101, f)
	if !b.g.Allows() {
		t.Fatalf("a mint after the drop's cutoff guarded: %q", b.out.String())
	}
	b.now = b.now.Add(scanEvery)
	f.recs = append(f.recs, fakeTok{minted: t0.Add(-time.Hour), expires: b.now.Add(10 * time.Minute)}) // old timeline, live
	b.passAt(15, 102, f)
	if b.g.Allows() {
		t.Fatalf("a second restore above the first drop's witness, with a live token, was served: %q", b.out.String())
	}
}

// A re-read of the same drop scans at most every scanEvery.
func TestARereadOfTheSameDropScansAtMostEveryFiveSeconds(t *testing.T) {
	b := newBound(t)
	t0 := b.now
	scans := 0
	f := &fakeTokens{recs: []fakeTok{{minted: t0.Add(-time.Minute), expires: t0.Add(10 * time.Minute)}}}
	count := func(ctx context.Context, m time.Time) (time.Time, error) { scans++; return f.latest(ctx, m) }
	pass := func() {
		b.g.pass(context.Background(), time.Second, func(context.Context) (etcdstore.RestoreRead, error) {
			return etcdstore.RestoreRead{Witness: 12, Header: 100}, nil
		}, count)
	}
	pass()
	for i := 0; i < 4; i++ {
		b.now = b.now.Add(time.Second)
		pass()
	}
	if scans != 1 {
		t.Fatalf("%d scans in 4 s of re-reads, want the drop's one", scans)
	}
	b.now = t0.Add(scanEvery)
	pass()
	if scans != 2 {
		t.Fatalf("%d scans after scanEvery, want 2", scans)
	}
}
