package store

import (
	"errors"
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
