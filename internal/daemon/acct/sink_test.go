package acct

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
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

// unencodable refuses one task's record as the decision log refuses a record
// it can never encode, and passes the rest.
type unencodable struct {
	next decision.Sink
	bad  string
}

func (u *unencodable) Emit(rec decision.Record) { _ = u.Write(rec) }

func (u *unencodable) Write(rec decision.Record) error {
	if rec.TaskID == u.bad {
		return fmt.Errorf("%w: json: unsupported value", decision.ErrUnencodable)
	}
	return u.next.Write(rec)
}

// A record the decision log can never encode is set aside, never retried
// forever: it would hold every accounting record behind it. It goes to a file
// beside the spool for an operator, counted and logged, and the drain goes on.
// A transient refusal is still retried (TestARefusedRecordIsOfferedAgain).
func TestAnUnencodableRecordIsSetAside(t *testing.T) {
	sink := &flakySink{}
	m := metrics.New(prometheus.NewRegistry())
	path := filepath.Join(t.TempDir(), "o.jsonl")
	sp, err := NewSpool(4, path, &unencodable{next: sink, bad: "b"}, m)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"a", "b", "c"} {
		if err := sp.Offer(decision.Record{Event: decision.EventAccount, TaskID: id}); err != nil {
			t.Fatal(err)
		}
	}
	if ok, n := sp.drainOnce(); !ok || n != 3 {
		t.Fatalf("ok=%v forwarded=%d", ok, n)
	}
	if len(sink.got) != 2 || sink.got[0] != "a" || sink.got[1] != "c" {
		t.Fatalf("delivered %q, want a c", sink.got)
	}
	aside, err := os.ReadFile(path + ".unencodable")
	if err != nil || strings.Count(string(aside), "\n") != 1 || !strings.Contains(string(aside), `"task_id":"b"`) {
		t.Fatalf("set aside %q, %v", aside, err)
	}
	if n := testutil.ToFloat64(m.SpoolDrops.WithLabelValues(dropDrainSetAside)); n != 1 {
		t.Fatalf("set aside counted %v", n)
	}
	if d := testutil.ToFloat64(m.SpoolDepth); d != 0 {
		t.Fatalf("depth %v", d)
	}
}

// A sink that keeps refusing is retried with a backoff from
// sinkRetryInterval, doubling to sinkRetryMax, and the refusal is logged at
// most once a minute with how many refusals it stands for.
func TestARefusingSinkBacksOffAndLogsACount(t *testing.T) {
	var want []time.Duration
	for d := sinkRetryInterval; len(want) < 10; d = min(2*d, sinkRetryMax) {
		want = append(want, d)
	}
	for i, w := range want {
		if got := sinkBackoff(i + 1); got != w {
			t.Errorf("refusal %d: %v, want %v", i+1, got, w)
		}
	}
	if sinkRetryMax != time.Minute {
		t.Errorf("cap %v", sinkRetryMax)
	}
	var logged strings.Builder
	defer log.SetOutput(log.Writer())
	log.SetOutput(&logged)
	sink := &flakySink{down: true}
	sp, err := NewSpool(4, filepath.Join(t.TempDir(), "o.jsonl"), sink, metrics.New(prometheus.NewRegistry()))
	if err != nil {
		t.Fatal(err)
	}
	if err := sp.Offer(decision.Record{Event: decision.EventAccount, TaskID: "a"}); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		sp.drainOnce()
	}
	if n := strings.Count(logged.String(), "sink refused"); n != 1 {
		t.Fatalf("%d refusal lines in a minute:\n%s", n, logged.String())
	}
	sp.lastSinkLog = time.Now().Add(-time.Minute)
	sp.drainOnce()
	if !strings.Contains(logged.String(), "3 refusals since the last line") {
		t.Fatalf("log:\n%s", logged.String())
	}
}

// The set-aside file is on disk like the spool and never takes a secret: a
// record an earlier build spooled unredacted is redacted before it is set
// aside, and a line that cannot be read back as a record is kept only as its
// length and sha256 (spec §5.8; task 11 re-review).
func TestTheSetAsideFileNeverHoldsASecret(t *testing.T) {
	sink := &flakySink{}
	path := filepath.Join(t.TempDir(), "o.jsonl")
	sp, err := NewSpool(4, path, &unencodable{next: sink, bad: "b"}, metrics.New(prometheus.NewRegistry()))
	if err != nil {
		t.Fatal(err)
	}
	dev := &decision.Device{NAS: "10.20.0.7", Name: "leaf-01", Platform: "arista_eos"}
	if err := sp.Offer(decision.Record{Event: decision.EventAccount, TaskID: "b", Device: dev,
		AcctRecord: &decision.AcctRecord{Raw: []string{"cmd=username", "cmd-arg=bob", "cmd-arg=secret", "cmd-arg=Hunter2"},
			Vector: []string{"username", "bob", "secret", "Hunter2"}}}); err != nil {
		t.Fatal(err)
	}
	if ok, n := sp.drainOnce(); !ok || n != 1 {
		t.Fatalf("ok=%v forwarded=%d", ok, n)
	}
	aside, err := os.ReadFile(path + ".unencodable")
	if err != nil || strings.Contains(string(aside), "Hunter2") || !strings.Contains(string(aside), `"task_id":"b"`) ||
		!strings.Contains(string(aside), `"redacted":true`) {
		t.Fatalf("set aside %q, %v", aside, err)
	}
	line := []byte(`{"event":"account","record":{"raw":["cmd=username","cmd-arg=Hunter2"`)
	if got := string(sp.setAsideForm(line)); strings.Contains(got, "Hunter2") || !strings.Contains(got, `"sha256":"`) ||
		!strings.Contains(got, fmt.Sprintf(`"length":%d`, len(line))) {
		t.Fatalf("an unreadable line: %s", got)
	}
}
