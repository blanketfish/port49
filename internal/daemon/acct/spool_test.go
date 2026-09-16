package acct

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

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

func TestSpoolFullWhenDiskUnwritable(t *testing.T) {
	sp, _ := NewSpool(1, "/proc/port49-cannot-write-here/overflow.jsonl", decision.NewJSONLines(&bytes.Buffer{}), metrics.New(prometheus.NewRegistry()))
	if err := sp.Offer(decision.Record{Event: decision.EventAccount}); err != ErrSpoolFull {
		t.Fatalf("want ErrSpoolFull, got %v", err)
	}
	if err := sp.Offer(decision.Record{Event: decision.EventAccount}); err != ErrSpoolFull {
		t.Fatalf("want ErrSpoolFull, got %v", err)
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

// TestShutdownGivesUpOnPersistentReadError covers the shutdown drain: if
// .draining can never be read (here, because it is a directory, not a
// file), Run must give up after a bounded number of attempts rather than
// spin forever.
func TestShutdownGivesUpOnPersistentReadError(t *testing.T) {
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
