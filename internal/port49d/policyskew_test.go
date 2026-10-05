package port49d

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/policy"
	"github.com/rhwendt/port49/internal/store"
	etcdstore "github.com/rhwendt/port49/internal/store/etcd"
)

// A replica's first record of the bundle it serves lands before it serves
// anything that mints, tried again while the store is unavailable and
// said at each wait; an error waiting does not mend, or a stop, ends the
// start with nothing recorded (Task 15a review M-1).
func TestTheFirstBundleRecordLandsBeforeAnythingIsServed(t *testing.T) {
	var out syncBuffer
	st := &fakeBundles{fail: 2, failErr: store.ErrUnavailable}
	if err := firstBundle(context.Background(), st, "replica-b", "b1", time.Minute, time.Second,
		10*time.Millisecond, &out); err != nil {
		t.Fatal(err)
	}
	if st.put("replica-b") != "b1" || st.puts != 3 ||
		strings.Count(out.String(), "port49-broker: policy: recording the bundle this replica serves (b1): ") != 1 ||
		!strings.Contains(out.String(), "nothing that mints is served until it lands") {
		t.Fatalf("%d put(s), recorded %q; said %q", st.puts, st.put("replica-b"), out.String())
	}
	refused := errors.New("the record is refused")
	st = &fakeBundles{fail: 1, failErr: refused}
	if err := firstBundle(context.Background(), st, "replica-b", "b1", time.Minute, time.Second,
		10*time.Millisecond, &out); !errors.Is(err, refused) || st.put("replica-b") != "" || st.puts != 1 {
		t.Fatalf("an error waiting does not mend: %v, %d put(s)", err, st.puts)
	}
	st = &fakeBundles{fail: 1 << 30, failErr: store.ErrUnavailable}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := firstBundle(ctx, st, "replica-b", "b1", time.Minute, time.Second, 10*time.Millisecond,
		&out); err == nil || st.put("replica-b") != "" {
		t.Fatalf("a stop while the store is unavailable: %v", err)
	}
}

// A start marks the bundle last judged in doubt only when it is not the
// replica's own, after the replica's record lands; a mark the store did
// not answer is tried again and said, and one refused otherwise ends the
// start (Task 15a re-review 1, I-2).
func TestAStartMarksTheJudgedBundleOnlyWhenItIsAnother(t *testing.T) {
	var out syncBuffer
	st := &fakeBundles{judged: "b1"}
	if err := recordAtStart(context.Background(), st, "replica-b", "b1", time.Minute, time.Second,
		10*time.Millisecond, &out); err != nil || st.inDoubt || st.put("replica-b") != "b1" {
		t.Fatalf("a start on the bundle judged: %v, in doubt %v", err, st.inDoubt)
	}
	st = &fakeBundles{judged: "b1", markFail: 2, failErr: store.ErrUnavailable}
	if err := recordAtStart(context.Background(), st, "replica-b", "b2", time.Minute, time.Second,
		10*time.Millisecond, &out); err != nil || !st.inDoubt || st.put("replica-b") != "b2" {
		t.Fatalf("a start on another bundle: %v, in doubt %v", err, st.inDoubt)
	}
	if strings.Count(out.String(), "port49-broker: policy: marking the bundle last judged in doubt against this "+
		"replica's (b2): ") != 1 || !strings.Contains(out.String(), "port49-broker: policy: this replica serves "+
		"bundle b2 and the bundle last judged is b1: marked it in doubt, so the next takeover purges the unspent "+
		"tokens") {
		t.Fatalf("said: %s", out.String())
	}
	refused := errors.New("the mark is refused")
	st = &fakeBundles{judged: "b1", markFail: 1, failErr: refused}
	if err := recordAtStart(context.Background(), st, "replica-b", "b2", time.Minute, time.Second,
		10*time.Millisecond, &out); !errors.Is(err, refused) || st.inDoubt {
		t.Fatalf("a mark refused: %v", err)
	}
}

// A swap opens the gate to mints under its bundle only once the bundle
// last judged is marked in doubt, or names it (Task 15a re-review 1, I-2).
// A mark the store did not answer, or refused (a role edited, then fixed),
// is tried again until it lands, each distinct error said once; until then,
// or until the replica stops, the gate stays shut (re-review 2, M-8).
func TestASwapMintsOnlyOnceItsSkewIsFlagged(t *testing.T) {
	var out syncBuffer
	b1, b2 := policyWithBundle(t, "b1"), policyWithBundle(t, "b2")
	gate := &skewGate{}
	gate.flag("b1")
	closed := prometheus.NewGauge(prometheus.GaugeOpts{Name: "port49_broker_mint_gate_closed"})
	if gate.allow(b1) != nil || gate.allow(b2) == nil {
		t.Fatal("the gate is open only to the bundle flagged")
	}
	st := &fakeBundles{judged: "b1", markFail: 3, failErr: store.ErrUnavailable}
	flagSwap(context.Background(), st, gate, "replica-b", "b2", time.Minute, time.Second, 10*time.Millisecond, closed, &out)
	if gate.allow(b2) != nil || gate.allow(b1) == nil || !st.inDoubt {
		t.Fatalf("a swap flagged: in doubt %v; said %s", st.inDoubt, out.String())
	}
	if n := strings.Count(out.String(), "marking the bundle last judged in doubt against this replica's (b2): "+
		"store: unavailable"); n != 1 {
		t.Fatalf("one error said %d times: %s", n, out.String())
	}
	b4 := policyWithBundle(t, "b4")
	st = &fakeBundles{judged: "b3", markFail: 1, failErr: store.ErrRefused}
	flagSwap(context.Background(), st, gate, "replica-b", "b4", time.Minute, time.Second, 10*time.Millisecond, closed, &out)
	if gate.allow(b4) != nil || !st.inDoubt || !strings.Contains(out.String(), "(b4): store: refused this identity") {
		t.Fatalf("a refused mark, then one that lands: in doubt %v; said %s", st.inDoubt, out.String())
	}
	b5 := policyWithBundle(t, "b5")
	st = &fakeBundles{judged: "b3", markFail: 1 << 30, failErr: store.ErrRefused}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	flagSwap(ctx, st, gate, "replica-b", "b5", time.Minute, time.Second, 10*time.Millisecond, closed, &out)
	if gate.allow(b5) == nil || st.inDoubt || testutil.ToFloat64(closed) != 1 {
		t.Fatalf("a mark that never lands opened the gate (gauge %v)", testutil.ToFloat64(closed))
	}
	b3 := policyWithBundle(t, "b3")
	st = &fakeBundles{judged: "b3"}
	flagSwap(context.Background(), st, gate, "replica-b", "b3", time.Minute, time.Second, 10*time.Millisecond, closed, &out)
	if gate.allow(b3) != nil || st.inDoubt || testutil.ToFloat64(closed) != 0 {
		t.Fatalf("a swap onto the bundle judged: in doubt %v, gauge %v", st.inDoubt, testutil.ToFloat64(closed))
	}
}

// markOrder is a recorder that notes what its record named when the mark
// landed.
type markOrder struct {
	*fakeBundles
	who, atMark string
}

func (m *markOrder) JudgeInDoubt(ctx context.Context, unless string) (string, bool, error) {
	m.atMark = m.put(m.who)
	return m.fakeBundles.JudgeInDoubt(ctx, unless)
}

// A swap records its bundle before it marks meta/judged in doubt, as the
// start does: a runner whose PutJudgedSince read the records before the
// record landed is refused, and one that read after it declines. Marked
// first, the runner could clear the mark with the record still on the old
// bundle (final review 7e-2 M-1).
func TestASwapRecordsItsBundleBeforeItMarks(t *testing.T) {
	var out syncBuffer
	gate := &skewGate{}
	closed := prometheus.NewGauge(prometheus.GaugeOpts{Name: "port49_broker_mint_gate_closed"})
	st := &markOrder{fakeBundles: &fakeBundles{judged: "b1"}, who: "replica-b"}
	st.set("replica-b", "b1")
	flagSwap(context.Background(), st, gate, "replica-b", "b2", time.Minute, time.Second, 10*time.Millisecond, closed,
		&out)
	if st.atMark != "b2" || !st.inDoubt {
		t.Fatalf("the record named %q when the mark landed (in doubt %v)", st.atMark, st.inDoubt)
	}
}

// A replica whose bundle is not the runner's gauges 0 and says so once per
// pair; matching, it gauges 1 (pre-flight I3).
func TestAReplicaServingAnotherBundleSaysSo(t *testing.T) {
	var out syncBuffer
	m := metrics.New(prometheus.NewRegistry())
	st := &fakeBundles{holder: "runner-a", recs: []etcdstore.BundleRecord{{Who: "runner-a", Bundle: "b-new"}}}
	live := policy.NewLive(policyWithBundle(t, "b-old"))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go keepBundle(ctx, st, "replica-b", live, 300*time.Millisecond, nil, m, &out)
	waitFor(t, &out, "this replica serves bundle b-old and the runner")
	if v := testutil.ToFloat64(m.PolicyBundleMatchesRunner); v != 0 {
		t.Fatalf("gauge %v with another bundle", v)
	}
	time.Sleep(time.Second) // several rounds: the line is said once
	if n := strings.Count(out.String(), "this replica serves bundle b-old"); n != 1 {
		t.Fatalf("said %d times", n)
	}
	st.set("runner-a", "b-old")
	waitUntil(t, "the gauge to match the runner", func() bool { return testutil.ToFloat64(m.PolicyBundleMatchesRunner) == 1 })
	if got := st.put("replica-b"); got != "b-old" {
		t.Fatalf("the replica recorded %q", got)
	}
	cancel() // a graceful stop deletes the record (pre-flight 7e-2 P-5)
	waitUntil(t, "the stopped replica's record is deleted", func() bool { return st.put("replica-b") == "" })
}

// A swap is recorded at once, not at the next third of the ttl.
func TestASwapIsRecordedAtOnce(t *testing.T) {
	m := metrics.New(prometheus.NewRegistry())
	st := &fakeBundles{holder: "replica-b"}
	live := policy.NewLive(policyWithBundle(t, "b-old"))
	swapped := make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go keepBundle(ctx, st, "replica-b", live, time.Hour, swapped, m, &syncBuffer{})
	waitUntil(t, "the first record", func() bool { return st.put("replica-b") == "b-old" })
	live.Swap(policyWithBundle(t, "b-new"))
	swapped <- struct{}{}
	waitUntil(t, "the swap's record", func() bool { return st.put("replica-b") == "b-new" })
}

// A full pass is owed once every token a mismatched replica could have
// minted has expired.
func TestAFullPassIsOwedATokenLifeAfterTheLastMismatch(t *testing.T) {
	at := time.Unix(1_000_000, 0)
	if got := owedFullPassAt(at); !got.Equal(at.Add(policy.MaxTokenTTL)) {
		t.Fatalf("%v", got)
	}
}

// A port49d whose policy is not the bundle last judged gauges 0 and says
// so once per pair; with no record it gauges 1 and says nothing; matching,
// 1 (re-check R5). The daemon's role cannot write meta/, so it reads the
// runner's judged record.
func TestADaemonServingAnotherBundleThanTheJudgedSaysSo(t *testing.T) {
	var out syncBuffer
	m := metrics.New(prometheus.NewRegistry())
	j := &judgedVar{}
	live := policy.NewLive(policyWithBundle(t, "b-old"))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m.PolicyBundleMatchesRunner.Set(0)
	go keepDaemonBundle(ctx, j, live, 100*time.Millisecond, m, &out)
	waitUntil(t, "the daemon's gauge to match the judged bundle", func() bool { return testutil.ToFloat64(m.PolicyBundleMatchesRunner) == 1 })
	if out.String() != "" {
		t.Fatalf("with no judged record: %q", out.String())
	}
	j.set(etcdstore.JudgedRecord{Bundle: "b-new"}, true)
	waitFor(t, &out, "this port49d serves bundle b-old and the bundle last judged by the runner is b-new")
	if v := testutil.ToFloat64(m.PolicyBundleMatchesRunner); v != 0 {
		t.Fatalf("gauge %v with another bundle judged", v)
	}
	time.Sleep(500 * time.Millisecond) // several rounds: the line is said once
	if n := strings.Count(out.String(), "this port49d serves bundle b-old"); n != 1 {
		t.Fatalf("said %d times", n)
	}
	j.set(etcdstore.JudgedRecord{Bundle: "b-old"}, true)
	waitUntil(t, "the daemon's gauge to match the judged bundle", func() bool { return testutil.ToFloat64(m.PolicyBundleMatchesRunner) == 1 })
}

// judgedVar is a judgedReader whose record the test changes.
type judgedVar struct {
	mu  sync.Mutex
	rec etcdstore.JudgedRecord
	ok  bool
}

func (j *judgedVar) Judged(context.Context) (etcdstore.JudgedRecord, bool, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.rec, j.ok, nil
}

func (j *judgedVar) JudgedBundle(ctx context.Context) (string, bool, error) {
	rec, ok, err := j.Judged(ctx)
	return rec.Bundle, ok, err
}

func (j *judgedVar) set(rec etcdstore.JudgedRecord, ok bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.rec, j.ok = rec, ok
}

// fakeBundles is a bundleStore in memory: each replica's record, and the
// holder's who.
type fakeBundles struct {
	mu     sync.Mutex
	holder string
	recs   []etcdstore.BundleRecord
	// fail is how many puts fail next, with failErr.
	fail    int
	failErr error
	puts    int
	// judged is meta/judged's bundle, inDoubt its mark; markFail is how
	// many marks fail next, with failErr.
	judged   string
	inDoubt  bool
	markFail int
}

func (f *fakeBundles) JudgeInDoubt(_ context.Context, unless string) (string, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.markFail > 0 {
		f.markFail--
		return "", false, f.failErr
	}
	if f.judged == "" || f.inDoubt || f.judged == unless {
		return f.judged, false, nil
	}
	f.inDoubt = true
	return f.judged, true, nil
}

func (f *fakeBundles) PutBundle(_ context.Context, who, bundle string, ttl time.Duration) error {
	f.mu.Lock()
	f.puts++
	if f.fail > 0 {
		f.fail--
		f.mu.Unlock()
		return f.failErr
	}
	f.mu.Unlock()
	f.set(who, bundle)
	return nil
}

func (f *fakeBundles) DeleteBundle(_ context.Context, who string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, r := range f.recs {
		if r.Who == who {
			f.recs = append(f.recs[:i], f.recs[i+1:]...)
			return nil
		}
	}
	return nil
}

func (f *fakeBundles) Bundles(context.Context) ([]etcdstore.BundleRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]etcdstore.BundleRecord(nil), f.recs...), nil
}

func (f *fakeBundles) Holder(context.Context) (string, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.holder, f.holder != "", nil
}

// set records bundle as who's.
func (f *fakeBundles) set(who, bundle string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, r := range f.recs {
		if r.Who == who {
			f.recs[i].Bundle = bundle
			return
		}
	}
	f.recs = append(f.recs, etcdstore.BundleRecord{Who: who, Bundle: bundle})
}

// put is the bundle who last recorded, "" once deleted.
func (f *fakeBundles) put(who string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range f.recs {
		if r.Who == who {
			return r.Bundle
		}
	}
	return ""
}

// policyWithBundle is minimalPolicy loaded into the named bundle.
func policyWithBundle(t *testing.T, bundle string) *policy.Policy {
	t.Helper()
	cfg := brokerConfig(t, minimalPolicy)
	pol, err := parseBundle(cfg, []byte(minimalPolicy), cfg.Inventory)
	if err != nil {
		t.Fatal(err)
	}
	pol.Bundle = bundle
	return pol
}
