package acct

import (
	"bytes"
	"context"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/decision"
)

func TestSpoolDrainsInOrder(t *testing.T) {
	out := &bytes.Buffer{}
	sp, err := NewSpool(4, filepath.Join(t.TempDir(), "overflow.jsonl"), decision.NewJSONLines(out), metrics.New(prometheus.NewRegistry()))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { sp.Run(ctx); close(done) }()
	for i := 0; i < 3; i++ {
		if err := sp.Offer(decision.Record{Event: decision.EventAccount, TaskID: string(rune('a' + i))}); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(150 * time.Millisecond)
	cancel()
	<-done
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 3 || !strings.Contains(lines[0], `"task_id":"a"`) || !strings.Contains(lines[2], `"task_id":"c"`) {
		t.Fatalf("%q", out.String())
	}
}

func TestSpoolOverflowsToDiskNotToError(t *testing.T) {
	out := &bytes.Buffer{}
	path := filepath.Join(t.TempDir(), "overflow.jsonl")
	sp, _ := NewSpool(2, path, decision.NewJSONLines(out), metrics.New(prometheus.NewRegistry()))
	// Every offer is a durable disk append now, whether or not Run is draining.
	for i := 0; i < 5; i++ {
		if err := sp.Offer(decision.Record{Event: decision.EventAccount, TaskID: "x"}); err != nil {
			t.Fatalf("offer %d: %v", i, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { sp.Run(ctx); close(done) }()
	time.Sleep(200 * time.Millisecond)
	cancel()
	<-done
	if n := strings.Count(out.String(), "\n"); n != 5 {
		t.Fatalf("drained %d of 5", n)
	}
}

// brokenSpool points a Spool at a path that cannot be written, bypassing
// NewSpool's start-time probe. It models the disk that goes bad while the
// daemon is running — the case the probe cannot catch and the ERROR reply
// exists for.
func brokenSpool(path string, m *metrics.Metrics) *Spool {
	return &Spool{path: path, sink: decision.NewJSONLines(&bytes.Buffer{}), metrics: m, capacity: 1, signal: make(chan struct{}, 1)}
}

func TestSpoolFullWhenDiskUnwritable(t *testing.T) {
	sp := brokenSpool("/proc/port49-cannot-write-here/overflow.jsonl", metrics.New(prometheus.NewRegistry()))
	if err := sp.Offer(decision.Record{Event: decision.EventAccount}); err != ErrSpoolFull {
		t.Fatalf("want ErrSpoolFull, got %v", err)
	}
	if err := sp.Offer(decision.Record{Event: decision.EventAccount}); err != ErrSpoolFull {
		t.Fatalf("want ErrSpoolFull, got %v", err)
	}
}

// TestNewSpoolRefusesAPathItCannotWrite covers the most likely accounting
// misconfiguration there is: spool_path points somewhere the daemon cannot
// write, usually because /var/lib/port49 was never created. main.go's rule is
// that everything which can fail on a typo fails before the listener opens,
// so this must be an error at construction, not a per-record ERROR reply
// discovered at 3am.
func TestNewSpoolRefusesAPathItCannotWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent-directory", "overflow.jsonl")
	_, err := NewSpool(4, path, decision.NewJSONLines(&bytes.Buffer{}), metrics.New(prometheus.NewRegistry()))
	if err == nil {
		t.Fatal("NewSpool must refuse a spool path it cannot create or append to")
	}
	if !strings.Contains(err.Error(), path) {
		t.Fatalf("the error must name the path an operator has to fix, got %v", err)
	}
}

// TestNewSpoolLeavesAnExistingFileAlone guards the probe against damaging
// what it is probing: records already on disk must survive it byte for byte.
func TestNewSpoolLeavesAnExistingFileAlone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "overflow.jsonl")
	b, err := decision.Record{Event: decision.EventAccount, TaskID: "pre-existing"}.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(b, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewSpool(4, path, decision.NewJSONLines(&bytes.Buffer{}), metrics.New(prometheus.NewRegistry())); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(append(b, '\n')) {
		t.Fatalf("the probe must not alter an existing spool file, got %q", got)
	}
}

// TestOfferLogsWhyItFailedWithoutTheRecord covers what the operator sees when
// the spool stops accepting: without the underlying error, spool_drops_total
// and requests_total{acct,error} climb together and ENOSPC, EACCES and a
// missing directory are indistinguishable. The record itself must never reach
// the log -- it is device accounting, and an unspooled record is no more
// loggable than a spooled one.
func TestOfferLogsWhyItFailedWithoutTheRecord(t *testing.T) {
	var logged bytes.Buffer
	log.SetOutput(&logged)
	log.SetFlags(0)
	t.Cleanup(func() { log.SetOutput(os.Stderr); log.SetFlags(log.LstdFlags) })

	path := filepath.Join(t.TempDir(), "absent-directory", "overflow.jsonl")
	sp := brokenSpool(path, metrics.New(prometheus.NewRegistry()))

	if err := sp.Offer(decision.Record{Event: decision.EventAccount, TaskID: "never-log-me"}); err != ErrSpoolFull {
		t.Fatalf("want ErrSpoolFull, got %v", err)
	}
	if !strings.Contains(logged.String(), path) {
		t.Fatalf("the log must name the spool path, got %q", logged.String())
	}
	if !strings.Contains(logged.String(), "no such file or directory") {
		t.Fatalf("the log must carry the underlying OS error, got %q", logged.String())
	}
	if strings.Contains(logged.String(), "never-log-me") {
		t.Fatalf("the record must never reach the log, got %q", logged.String())
	}

	// A disk that stays full fails every offer; the log must not follow it.
	before := strings.Count(logged.String(), path)
	for i := 0; i < 5; i++ {
		sp.Offer(decision.Record{Event: decision.EventAccount})
	}
	if after := strings.Count(logged.String(), path); after != before {
		t.Fatalf("the offer-failure log must be throttled: %d lines, want %d", after, before)
	}
}

func TestSpoolSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "overflow.jsonl")
	sp, err := NewSpool(4, path, decision.NewJSONLines(&bytes.Buffer{}), metrics.New(prometheus.NewRegistry()))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := sp.Offer(decision.Record{Event: decision.EventAccount, TaskID: string(rune('a' + i))}); err != nil {
			t.Fatal(err)
		}
	}
	// No Run on sp: the records sit durably on disk, unforwarded.

	out := &bytes.Buffer{}
	sp2, err := NewSpool(4, path, decision.NewJSONLines(out), metrics.New(prometheus.NewRegistry()))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { sp2.Run(ctx); close(done) }()
	time.Sleep(200 * time.Millisecond)
	cancel()
	<-done
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 3 || !strings.Contains(lines[0], `"task_id":"a"`) || !strings.Contains(lines[1], `"task_id":"b"`) || !strings.Contains(lines[2], `"task_id":"c"`) {
		t.Fatalf("%q", out.String())
	}
}

func TestSpoolResumesDrainingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "overflow.jsonl")
	draining := path + ".draining"
	rec := decision.Record{Event: decision.EventAccount, TaskID: "resumed"}
	b, err := rec.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(draining, append(b, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}

	out := &bytes.Buffer{}
	sp, err := NewSpool(4, path, decision.NewJSONLines(out), metrics.New(prometheus.NewRegistry()))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { sp.Run(ctx); close(done) }()
	time.Sleep(200 * time.Millisecond)
	cancel()
	<-done

	if !strings.Contains(out.String(), `"task_id":"resumed"`) {
		t.Fatalf("%q", out.String())
	}
	if _, err := os.Stat(draining); !os.IsNotExist(err) {
		t.Fatalf("draining file should be removed, stat err: %v", err)
	}
}

// TestDrainDoesNotReemitWhenRemoveFails covers the case where a pass fully
// forwards .draining but the directory it lives in won't allow the removal
// (for example, permissions). A prior version of drainOnce silently retried
// the whole rename-and-forward cycle every pass, re-emitting the same
// records forever. It must instead remember that .draining was already
// fully delivered and retry only the removal.
func TestDrainDoesNotReemitWhenRemoveFails(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory write permission checks")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "overflow.jsonl")
	draining := path + ".draining"

	var data []byte
	for i := 0; i < 3; i++ {
		rec := decision.Record{Event: decision.EventAccount, TaskID: string(rune('a' + i))}
		b, err := rec.MarshalJSON()
		if err != nil {
			t.Fatal(err)
		}
		data = append(append(data, b...), '\n')
	}
	if err := os.WriteFile(draining, data, 0o600); err != nil {
		t.Fatal(err)
	}

	out := &bytes.Buffer{}
	sp, err := NewSpool(4, path, decision.NewJSONLines(out), metrics.New(prometheus.NewRegistry()))
	if err != nil {
		t.Fatal(err)
	}

	// Block removal (unlink needs write permission on the directory) while
	// leaving the file itself readable, so forwarding still succeeds and
	// only the removal fails.
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0o700)

	for i := 0; i < 3; i++ {
		sp.drainOnce()
	}

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("want each of 3 records forwarded exactly once across 3 passes, got %d lines: %q", len(lines), out.String())
	}
}

// TestDrainStreamsLargeBacklog guards against the drain path going quadratic
// (repeatedly reading and rewriting the whole backlog per batch): 500
// records must all arrive, in order, and the drain itself — Run reading and
// forwarding what Offer already wrote — must finish well within a generous
// time bound. Offer's own cost (one fsync per record) is not timed here: on
// a slow filesystem that dominates wall time regardless of drain algorithm
// and is not what this test guards against. 500 is enough to discriminate: a
// reintroduced write-back would rewrite+fsync the shrinking remainder on
// every 100ms pass, on the order of 500^2/2 ~= 125k line-writes, against 500
// for a single streamed pass.
func TestDrainStreamsLargeBacklog(t *testing.T) {
	if testing.Short() {
		t.Skip("large-backlog timing test; skipped in -short")
	}
	path := filepath.Join(t.TempDir(), "overflow.jsonl")
	out := &bytes.Buffer{}
	sp, err := NewSpool(4, path, decision.NewJSONLines(out), metrics.New(prometheus.NewRegistry()))
	if err != nil {
		t.Fatal(err)
	}

	const n = 500
	for i := 0; i < n; i++ {
		if err := sp.Offer(decision.Record{Event: decision.EventAccount, TaskID: strconv.Itoa(i)}); err != nil {
			t.Fatalf("offer %d: %v", i, err)
		}
	}

	start := time.Now()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { sp.Run(ctx); close(done) }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	<-done
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("drain took %v for %d records, want well under 5s (possible quadratic drain)", elapsed, n)
	}

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != n {
		t.Fatalf("want %d records, got %d", n, len(lines))
	}
	for i, line := range lines {
		want := `"task_id":"` + strconv.Itoa(i) + `"`
		if !strings.Contains(line, want) {
			t.Fatalf("line %d out of order or wrong: %q", i, line)
		}
	}
}

// TestShutdownQuarantinesUnreadableDrainingFile covers the shutdown drain:
// if .draining can never be read (here, because it is a directory, not a
// file), the per-offset failure counter quarantines it (renames it aside)
// after three consecutive failures, and Run then finds nothing left to do
// and returns cleanly -- well within a bounded number of attempts, never
// spinning forever.
func TestShutdownQuarantinesUnreadableDrainingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "overflow.jsonl")
	draining := path + ".draining"
	if err := os.Mkdir(draining, 0o700); err != nil {
		t.Fatal(err)
	}

	sp, err := NewSpool(4, path, decision.NewJSONLines(&bytes.Buffer{}), metrics.New(prometheus.NewRegistry()))
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { sp.Run(ctx); close(done) }()
	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return within 2s despite a persistent read error")
	}
}

// TestShutdownGivesUpAfterThreeStrikes covers Run's bounded give-up path
// directly: with drainOnce forced to fail on every call (via the forceFail
// test hook, so the outcome does not depend on any real filesystem
// behavior or on the quarantine mechanism resolving things), the shutdown
// drain must still return within a bounded time, leaving the still-durable
// record on disk rather than losing it.
func TestShutdownGivesUpAfterThreeStrikes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "overflow.jsonl")
	sp, err := NewSpool(4, path, decision.NewJSONLines(&bytes.Buffer{}), metrics.New(prometheus.NewRegistry()))
	if err != nil {
		t.Fatal(err)
	}
	if err := sp.Offer(decision.Record{Event: decision.EventAccount, TaskID: "stuck-in-file"}); err != nil {
		t.Fatal(err)
	}
	sp.forceFail = true

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { sp.Run(ctx); close(done) }()
	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not give up within 2s despite drainOnce always failing")
	}

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the offered record should remain on disk after giving up, stat err: %v", err)
	}
}

// TestOversizedLineIsDroppedNotFatal covers a line over maxLineBytes: it
// must be dropped and skipped, not treated as a read error, so drainOnce
// makes it through the whole file (including the records after the
// oversized line) in one streamed pass without re-forwarding anything it
// already emitted, and depth is not left over- or under-reported.
func TestOversizedLineIsDroppedNotFatal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "overflow.jsonl")
	draining := path + ".draining"

	line := func(taskID string) []byte {
		rec := decision.Record{Event: decision.EventAccount, TaskID: taskID}
		b, err := rec.MarshalJSON()
		if err != nil {
			t.Fatal(err)
		}
		return append(b, '\n')
	}
	oversized := append(bytes.Repeat([]byte("x"), 2*1024*1024), '\n') // > maxLineBytes, no embedded newline

	var data []byte
	data = append(data, line("1")...)
	data = append(data, line("2")...)
	data = append(data, oversized...)
	data = append(data, line("4")...)
	data = append(data, line("5")...)
	if err := os.WriteFile(draining, data, 0o600); err != nil {
		t.Fatal(err)
	}

	out := &bytes.Buffer{}
	m := metrics.New(prometheus.NewRegistry())
	sp, err := NewSpool(4, path, decision.NewJSONLines(out), m)
	if err != nil {
		t.Fatal(err)
	}

	// A handful of passes is enough regardless of exactly how many the
	// implementation needs; extra passes on an already-empty spool are
	// no-ops.
	for i := 0; i < 3; i++ {
		sp.drainOnce()
	}

	want := []string{`"task_id":"1"`, `"task_id":"2"`, `"task_id":"4"`, `"task_id":"5"`}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != len(want) {
		t.Fatalf("want %d records (1,2,4,5; 3 dropped as oversized), got %d: %q", len(want), len(lines), out.String())
	}
	for _, w := range want {
		if n := strings.Count(out.String(), w); n != 1 {
			t.Fatalf("want %s forwarded exactly once, got %d: %q", w, n, out.String())
		}
	}
	if got := testutil.ToFloat64(m.SpoolDrops); got != 1 {
		t.Fatalf("want SpoolDrops == 1 (the oversized line), got %v", got)
	}
	if got := testutil.ToFloat64(m.SpoolDepth); got != 0 {
		t.Fatalf("want SpoolDepth == 0 once the drain has caught up, got %v", got)
	}
	if _, err := os.Stat(draining); !os.IsNotExist(err) {
		t.Fatalf("draining file should be removed, stat err: %v", err)
	}
}

// TestStuckClearsWhenFileVanishes covers a stuck spool (fully forwarded,
// removal failed) whose .draining file then disappears out from under it:
// os.Remove reports IsNotExist, which must clear stuck rather than wedge it
// permanently, since there is nothing left to remove.
func TestStuckClearsWhenFileVanishes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "overflow.jsonl")
	out := &bytes.Buffer{}
	sp, err := NewSpool(4, path, decision.NewJSONLines(out), metrics.New(prometheus.NewRegistry()))
	if err != nil {
		t.Fatal(err)
	}

	sp.stuck = true // simulate a prior pass that forwarded everything but couldn't remove .draining
	// No .draining file exists here, simulating it having vanished (e.g. an
	// operator cleaned it up) since the pass that set stuck.

	ok, forwarded := sp.drainOnce()
	if !ok || forwarded != 0 {
		t.Fatalf("want ok=true forwarded=0 when the stuck file has vanished, got ok=%v forwarded=%d", ok, forwarded)
	}
	if sp.stuck {
		t.Fatal("stuck should clear once .draining no longer exists")
	}

	if err := sp.Offer(decision.Record{Event: decision.EventAccount, TaskID: "after"}); err != nil {
		t.Fatal(err)
	}
	sp.drainOnce()

	if !strings.Contains(out.String(), `"task_id":"after"`) {
		t.Fatalf("an offer after stuck clears should be forwarded normally: %q", out.String())
	}
}

// TestTornTailDoesNotSwallowTheNextRecord covers the full-disk case: a short
// write (ENOSPC mid-record) or a crash mid-append leaves the file ending
// without a newline. The device that offered that record was told ERROR and
// will retry, so losing the fragment is correct. What must not happen is the
// *next* Offer appending onto the same line: that offer returns nil, its
// device is told SUCCESS, and at drain the glued line fails to unmarshal and
// is dropped — a record lost after SUCCESS, which is the one thing the spool's
// durability contract forbids.
func TestTornTailDoesNotSwallowTheNextRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "overflow.jsonl")
	b, err := decision.Record{Event: decision.EventAccount, TaskID: "torn"}.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	// A record that was cut off mid-write: no trailing newline.
	if err := os.WriteFile(path, b[:len(b)/2], 0o600); err != nil {
		t.Fatal(err)
	}

	out := &bytes.Buffer{}
	m := metrics.New(prometheus.NewRegistry())
	sp, err := NewSpool(4, path, decision.NewJSONLines(out), m)
	if err != nil {
		t.Fatal(err)
	}
	if err := sp.Offer(decision.Record{Event: decision.EventAccount, TaskID: "acked"}); err != nil {
		t.Fatalf("the offer after a torn tail must succeed: %v", err)
	}
	sp.drainOnce()

	if !strings.Contains(out.String(), `"task_id":"acked"`) {
		t.Fatalf("a record acknowledged with SUCCESS must reach the sink, got %q", out.String())
	}
	if got := testutil.ToFloat64(m.SpoolDrops); got != 1 {
		t.Fatalf("want exactly 1 drop (the torn fragment alone), got %v", got)
	}
}

// TestTornTailWithinOneProcessIsSeparated covers the same hazard when the
// failing write and the next offer happen in one process: Offer must remember
// that its last write left the file in an unknown state, not only notice a
// torn tail at construction.
func TestTornTailWithinOneProcessIsSeparated(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "overflow.jsonl")
	out := &bytes.Buffer{}
	m := metrics.New(prometheus.NewRegistry())
	sp, err := NewSpool(4, path, decision.NewJSONLines(out), m)
	if err != nil {
		t.Fatal(err)
	}
	if err := sp.Offer(decision.Record{Event: decision.EventAccount, TaskID: "first"}); err != nil {
		t.Fatal(err)
	}
	// Simulate the write that failed partway: the bytes are on disk, the
	// newline is not, and Offer knows its write did not complete.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`{"ts":"2026-09-20T00:00:00.00`); err != nil {
		t.Fatal(err)
	}
	f.Close()
	sp.mu.Lock()
	sp.needNewline = true
	sp.mu.Unlock()

	if err := sp.Offer(decision.Record{Event: decision.EventAccount, TaskID: "second"}); err != nil {
		t.Fatal(err)
	}
	sp.drainOnce()

	for _, want := range []string{`"task_id":"first"`, `"task_id":"second"`} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("want %s forwarded, got %q", want, out.String())
		}
	}
}

// fiveLines writes 5 small, distinct JSON lines and returns each one's raw
// bytes (including its trailing newline) alongside the concatenated whole,
// so a test can both write a .draining file by hand and compute exact byte
// offsets into it.
func fiveLines(t *testing.T) (lines [5][]byte, all []byte) {
	t.Helper()
	for i := range lines {
		rec := decision.Record{Event: decision.EventAccount, TaskID: strconv.Itoa(i + 1)}
		b, err := rec.MarshalJSON()
		if err != nil {
			t.Fatal(err)
		}
		lines[i] = append(b, '\n')
		all = append(all, lines[i]...)
	}
	return lines, all
}

// TestDrainResumesAtOffsetWithoutDuplicates is the real resume-at-offset
// test TestOversizedLineIsDroppedNotFatal was mistaken for: that test never
// makes drainOnce fail, so drainOffset never leaves zero. This one exercises
// drainOffset directly, both as a starting point and as state that survives
// a failed pass.
func TestDrainResumesAtOffsetWithoutDuplicates(t *testing.T) {
	t.Run("starts mid-file and delivers only what's left", func(t *testing.T) {
		lines, all := fiveLines(t)
		path := filepath.Join(t.TempDir(), "overflow.jsonl")
		draining := path + ".draining"
		if err := os.WriteFile(draining, all, 0o600); err != nil {
			t.Fatal(err)
		}

		out := &bytes.Buffer{}
		m := metrics.New(prometheus.NewRegistry())
		sp, err := NewSpool(4, path, decision.NewJSONLines(out), m)
		if err != nil {
			t.Fatal(err)
		}
		// Simulate a prior pass (within the same process) having already
		// forwarded records 1 and 2: set drainOffset past them and bring
		// depth down to match, exactly as applyForwarded would have left
		// them after that pass.
		sp.mu.Lock()
		sp.drainOffset = int64(len(lines[0]) + len(lines[1]))
		sp.depth -= 2
		m.SpoolDepth.Set(float64(sp.depth))
		sp.mu.Unlock()

		ok, forwarded := sp.drainOnce()
		if !ok || forwarded != 3 {
			t.Fatalf("want ok=true forwarded=3, got ok=%v forwarded=%d", ok, forwarded)
		}

		got := strings.Split(strings.TrimSpace(out.String()), "\n")
		if len(got) != 3 {
			t.Fatalf("want exactly records 3,4,5, got %d lines: %q", len(got), out.String())
		}
		for i, want := range []string{`"task_id":"3"`, `"task_id":"4"`, `"task_id":"5"`} {
			if !strings.Contains(got[i], want) {
				t.Fatalf("line %d: want %s, got %q", i, want, got[i])
			}
		}
		for _, unwanted := range []string{`"task_id":"1"`, `"task_id":"2"`} {
			if strings.Contains(out.String(), unwanted) {
				t.Fatalf("record %s should not have been re-delivered: %q", unwanted, out.String())
			}
		}
		if sp.drainOffset != 0 {
			t.Fatalf("want drainOffset == 0 after a full drain, got %d", sp.drainOffset)
		}
		if _, err := os.Stat(draining); !os.IsNotExist(err) {
			t.Fatalf("draining file should be removed, stat err: %v", err)
		}
		if got := testutil.ToFloat64(m.SpoolDepth); got != 0 {
			t.Fatalf("want SpoolDepth == 0, got %v", got)
		}
	})

	t.Run("offset survives a failed pass and the next pass resumes cleanly", func(t *testing.T) {
		lines, all := fiveLines(t)
		path := filepath.Join(t.TempDir(), "overflow.jsonl")
		draining := path + ".draining"
		if err := os.WriteFile(draining, all, 0o600); err != nil {
			t.Fatal(err)
		}

		out := &bytes.Buffer{}
		m := metrics.New(prometheus.NewRegistry())
		sp, err := NewSpool(4, path, decision.NewJSONLines(out), m)
		if err != nil {
			t.Fatal(err)
		}

		wantOffset := int64(len(lines[0]) + len(lines[1]))
		sp.failAfterBytes = wantOffset
		ok, forwarded := sp.drainOnce()
		if ok || forwarded != 2 {
			t.Fatalf("want ok=false forwarded=2 on the injected failure, got ok=%v forwarded=%d", ok, forwarded)
		}
		if sp.drainOffset != wantOffset {
			t.Fatalf("want drainOffset == %d after the failed pass, got %d", wantOffset, sp.drainOffset)
		}
		got := strings.Split(strings.TrimSpace(out.String()), "\n")
		if len(got) != 2 || !strings.Contains(got[0], `"task_id":"1"`) || !strings.Contains(got[1], `"task_id":"2"`) {
			t.Fatalf("want records 1,2 delivered once each, got %q", out.String())
		}

		sp.failAfterBytes = 0
		ok, forwarded = sp.drainOnce()
		if !ok || forwarded != 3 {
			t.Fatalf("want ok=true forwarded=3 on the resumed pass, got ok=%v forwarded=%d", ok, forwarded)
		}
		got = strings.Split(strings.TrimSpace(out.String()), "\n")
		if len(got) != 5 {
			t.Fatalf("want all 5 records total, got %d: %q", len(got), out.String())
		}
		for _, want := range []string{`"task_id":"1"`, `"task_id":"2"`, `"task_id":"3"`, `"task_id":"4"`, `"task_id":"5"`} {
			if n := strings.Count(out.String(), want); n != 1 {
				t.Fatalf("want %s delivered exactly once, got %d: %q", want, n, out.String())
			}
		}
		if sp.drainOffset != 0 {
			t.Fatalf("want drainOffset == 0 after the resumed pass completes, got %d", sp.drainOffset)
		}
		if _, err := os.Stat(draining); !os.IsNotExist(err) {
			t.Fatalf("draining file should be removed, stat err: %v", err)
		}
		if got := testutil.ToFloat64(m.SpoolDepth); got != 0 {
			t.Fatalf("want SpoolDepth == 0, got %v", got)
		}
	})
}
