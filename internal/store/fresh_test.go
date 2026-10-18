package store

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestFreshnessConfirmsOnlyWhileTheFeedRuns(t *testing.T) {
	now := time.Date(2026, 10, 17, 9, 0, 0, 0, time.UTC)
	var confirmed []time.Time
	var reach []bool
	f := NewFreshness(func() time.Time { return now })
	f.Tell(func(at time.Time) { confirmed = append(confirmed, at) }, func(r bool) { reach = append(reach, r) })
	if _, ok := f.Age(); ok {
		t.Fatal("a copy never confirmed has an age")
	}
	if tr := f.Checked(nil); tr != Steady {
		t.Fatalf("a first answer: %v", tr)
	}
	if _, ok := f.Age(); ok {
		t.Fatal("confirmed with the feed down")
	}
	f.FeedUp(true)
	f.Checked(nil)
	now = now.Add(2 * time.Second)
	if age, ok := f.Age(); !ok || age != 2*time.Second {
		t.Fatalf("age %v %v", age, ok)
	}
	if tr := f.Checked(errors.New("store: unavailable: deadline")); tr != Stopped {
		t.Fatalf("a failed read: %v", tr)
	}
	if ok, why := f.Reachable(); ok || why != "store: unavailable: deadline" {
		t.Fatalf("%v %q", ok, why)
	}
	if tr := f.Checked(errors.New("again")); tr != Steady {
		t.Fatalf("a second failure: %v", tr)
	}
	now = now.Add(time.Second)
	if tr := f.Checked(nil); tr != Resumed {
		t.Fatalf("the answer after a stop: %v", tr)
	}
	// Reachability is told when first known (true), at the stop (false) and
	// at the resume (true); a confirmation only while the feed ran.
	if len(confirmed) != 2 || !confirmed[1].Equal(now) || len(reach) != 3 || !reach[0] || reach[1] || !reach[2] {
		t.Fatalf("confirmed %v, reach %v", confirmed, reach)
	}
}

// A first read that fails is a stop: the line says the directory is not
// answering from the start.
func TestFreshnessFirstFailureIsAStop(t *testing.T) {
	f := NewFreshness(time.Now)
	if tr := f.Checked(errors.New("no")); tr != Stopped {
		t.Fatalf("%v", tr)
	}
}

// Tell tells a run's metrics the state at once: a port49d run after a store
// gone keeps the process's copy, and its new registry must not read absent
// or zero (plan 11a, R19).
func TestFreshnessTellsANewRunAtOnce(t *testing.T) {
	now := time.Date(2026, 10, 17, 9, 0, 0, 0, time.UTC)
	f := NewFreshness(func() time.Time { return now })
	f.FeedUp(true)
	f.Checked(nil)
	var at time.Time
	var reach []bool
	f.Tell(func(t time.Time) { at = t }, func(r bool) { reach = append(reach, r) })
	if !at.Equal(now) || len(reach) != 1 || !reach[0] {
		t.Fatalf("told %v %v", at, reach)
	}
}

// R19: a copy seeded from a snapshot counts its age from the snapshot's
// confirmed time, and is a snapshot until a live read confirms it.
func TestASeededCopyIsASnapshotUntilConfirmed(t *testing.T) {
	now := time.Date(2026, 10, 17, 9, 0, 0, 0, time.UTC)
	f := NewFreshness(func() time.Time { return now })
	f.Seed(now.Add(-time.Hour))
	if age, ok := f.Age(); !ok || age != time.Hour || !f.Snapshot() {
		t.Fatalf("age %v %v, snapshot %v", age, ok, f.Snapshot())
	}
	f.Checked(nil) // the feed is not up: no confirmation
	if !f.Snapshot() {
		t.Fatal("a read with the feed down confirmed the snapshot")
	}
	f.FeedUp(true) // a load from 0 succeeded (N5)
	f.Checked(nil)
	if age, _ := f.Age(); age != 0 || f.Snapshot() {
		t.Fatalf("after a live confirmation: age %v, snapshot %v", age, f.Snapshot())
	}
	if at, ok := f.Confirmed(); !ok || !at.Equal(now) {
		t.Fatalf("confirmed %v %v", at, ok)
	}
}

// loadFailFeed (the brief's flakyFeed; marks_test.go has one) fails every load while fail is set, and watches until ctx ends.
type loadFailFeed struct {
	mu   sync.Mutex
	fail bool
}

func (f *loadFailFeed) Revocations(context.Context) (uint64, []Revocation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail {
		return 0, nil, ErrUnavailable
	}
	return 7, nil, nil
}

func (f *loadFailFeed) WatchRevocations(ctx context.Context, _ uint64, _ func(Revocation, bool, uint64), _ func(uint64)) error {
	<-ctx.Done()
	return ctx.Err()
}

// N5: a snapshot's ceiling stays until a load of the directory succeeds; a
// directory that answers reads while its load fails does not clear it.
func TestAFailedLoadKeepsTheSnapshot(t *testing.T) {
	f := NewFreshness(time.Now)
	f.Seed(time.Now().Add(-time.Hour))
	feed := &loadFailFeed{fail: true}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go FollowMarks(ctx, feed, NewMarks(), 0, nil, f.FeedUp, func() error { return nil }, func(string, ...any) {})
	time.Sleep(1500 * time.Millisecond)
	f.Checked(nil) // the directory answers a read
	if !f.Snapshot() {
		t.Fatal("the snapshot was cleared while the load failed")
	}
	feed.mu.Lock()
	feed.fail = false
	feed.mu.Unlock()
	for deadline := time.Now().Add(5 * time.Second); f.Snapshot(); time.Sleep(50 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("a successful load did not clear the snapshot")
		}
	}
}
