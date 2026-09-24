package acct

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/decision"
)

// flakySink refuses every record while down, and records what it took.
type flakySink struct {
	mu    sync.Mutex
	down  bool
	got   []string
	tries int
}

func (f *flakySink) Emit(r decision.Record) { _ = f.Write(r) }

func (f *flakySink) setDown(down bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.down = down
}

func (f *flakySink) Write(r decision.Record) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tries++
	if f.down {
		return errors.New("sink: connection refused")
	}
	f.got = append(f.got, r.TaskID)
	return nil
}

// The spool's at-least-once contract reaches across the sink (roadmap, plan
// 4): a record the sink refuses is neither deleted nor skipped. The pass stops
// at it, the depth still counts it, and the next pass after the sink recovers
// delivers it, and everything after it, exactly once and in order.
func TestARefusedRecordIsOfferedAgain(t *testing.T) {
	sink := &flakySink{}
	m := metrics.New(prometheus.NewRegistry())
	sp, err := NewSpool(4, filepath.Join(t.TempDir(), "o.jsonl"), sink, m)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"a", "b", "c"} {
		if err := sp.Offer(decision.Record{Event: decision.EventAccount, TaskID: id}); err != nil {
			t.Fatal(err)
		}
	}
	sink.setDown(true)
	if ok, n := sp.drainOnce(); ok || n != 0 {
		t.Fatalf("a refused first record is no progress: ok=%v forwarded=%d", ok, n)
	}
	if d := testutil.ToFloat64(m.SpoolDepth); d != 3 {
		t.Fatalf("depth after a refusal: %v, want 3", d)
	}
	sink.setDown(false)
	if ok, n := sp.drainOnce(); !ok || n != 3 {
		t.Fatalf("after recovery: ok=%v forwarded=%d", ok, n)
	}
	if len(sink.got) != 3 || sink.got[0] != "a" || sink.got[2] != "c" {
		t.Fatalf("delivered %q, want a b c once each", sink.got)
	}
	if d := testutil.ToFloat64(m.SpoolDepth); d != 0 {
		t.Fatalf("depth after the drain: %v", d)
	}
}

// A refusal part-way through a file keeps what was already delivered
// delivered: the next pass resumes at the refused record, not at the start.
func TestARefusalMidFileResumesAtTheRefusedRecord(t *testing.T) {
	sink := &flakySink{}
	m := metrics.New(prometheus.NewRegistry())
	sp, err := NewSpool(4, filepath.Join(t.TempDir(), "o.jsonl"), &refuseAfter{next: sink, n: 1}, m)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"a", "b", "c"} {
		if err := sp.Offer(decision.Record{Event: decision.EventAccount, TaskID: id}); err != nil {
			t.Fatal(err)
		}
	}
	if ok, n := sp.drainOnce(); ok || n != 1 {
		t.Fatalf("one delivered, then a refusal: ok=%v forwarded=%d", ok, n)
	}
	if d := testutil.ToFloat64(m.SpoolDepth); d != 2 {
		t.Fatalf("depth after delivering one of three: %v, want 2", d)
	}
	if ok, n := sp.drainOnce(); !ok || n != 2 {
		t.Fatalf("the rest: ok=%v forwarded=%d", ok, n)
	}
	if d := testutil.ToFloat64(m.SpoolDepth); d != 0 {
		t.Fatalf("depth after the drain: %v", d)
	}
	if len(sink.got) != 3 || sink.got[0] != "a" || sink.got[1] != "b" || sink.got[2] != "c" {
		t.Fatalf("delivered %q, want a b c once each", sink.got)
	}
}

// A sink that is down for good never gets a file quarantined: the records are
// fine, and quarantine is for a file the spool cannot read.
func TestARefusingSinkNeverQuarantines(t *testing.T) {
	sink := &flakySink{down: true}
	m := metrics.New(prometheus.NewRegistry())
	sp, err := NewSpool(4, filepath.Join(t.TempDir(), "o.jsonl"), sink, m)
	if err != nil {
		t.Fatal(err)
	}
	if err := sp.Offer(decision.Record{Event: decision.EventAccount, TaskID: "a"}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		sp.drainOnce()
	}
	if q := testutil.ToFloat64(m.SpoolQuarantines); q != 0 {
		t.Fatalf("quarantined %v files over a sink outage", q)
	}
	sink.setDown(false)
	if ok, n := sp.drainOnce(); !ok || n != 1 || len(sink.got) != 1 {
		t.Fatalf("after the outage: ok=%v forwarded=%d got=%q", ok, n, sink.got)
	}
}

// A sink that keeps refusing is retried at a pace, not every tick: each
// refused write is a counted failure and a log line in the decision package,
// so a spool hammering a full disk ten times a second would bury stderr and
// make port49_decision_log_write_failures_total climb as if records were
// being lost, while every one of them is still in the spool.
func TestARefusingSinkIsRetriedAtAPace(t *testing.T) {
	sink := &flakySink{down: true}
	sp, err := NewSpool(4, filepath.Join(t.TempDir(), "o.jsonl"), sink,
		metrics.New(prometheus.NewRegistry()))
	if err != nil {
		t.Fatal(err)
	}
	if err := sp.Offer(decision.Record{Event: decision.EventAccount, TaskID: "a"}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { sp.Run(ctx); close(done) }()
	time.Sleep(600 * time.Millisecond)
	sink.mu.Lock()
	tries := sink.tries
	sink.mu.Unlock()
	if tries > 2 {
		t.Fatalf("%d writes to a refusing sink in 600ms, want at most 2", tries)
	}
	// Recovery is still picked up: the paced retry delivers the record.
	sink.setDown(false)
	deadline := time.Now().Add(3 * sinkRetryInterval)
	for {
		sink.mu.Lock()
		n := len(sink.got)
		sink.mu.Unlock()
		if n == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the record was not delivered after the sink recovered")
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-done
}

// refuseAfter passes n records to next, then refuses exactly one, then passes
// everything.
type refuseAfter struct {
	next    decision.Sink
	n       int
	refused bool
}

func (r *refuseAfter) Emit(rec decision.Record) { _ = r.Write(rec) }

func (r *refuseAfter) Write(rec decision.Record) error {
	if r.n > 0 {
		r.n--
		return r.next.Write(rec)
	}
	if !r.refused {
		r.refused = true
		return errors.New("sink: refused once")
	}
	return r.next.Write(rec)
}
