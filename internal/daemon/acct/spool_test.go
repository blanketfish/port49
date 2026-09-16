package acct

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
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
	// Every offer is a durable disk append now; capacity only bounds the drain batch size.
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
