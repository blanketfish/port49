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
		strings.Count(out.String(), "port49-broker: policy: recording the bundle this replica serves (b1): ") != 2 ||
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
