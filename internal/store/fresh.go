package store

import (
	"sync"
	"time"
)

// Freshness is how current a process's copy of the directory store is
// (plan 11a; spec §13 decision 51): whether its marks feed runs, and the
// last time a read of the directory answered while it did. A watch that
// runs and a store that answers a linearizable read leave the copy at most
// one check and one delivery behind. It is safe for concurrent use.
type Freshness struct {
	mu        sync.Mutex
	now       func() time.Time
	feedUp    bool
	confirmed time.Time
	snapshot  bool // the copy is a snapshot's, not yet reloaded from the directory
	checked   bool
	reachable bool
	why       string
	onConfirm func(time.Time)
	onReach   func(bool)
}

// Transition is what a check changed: nothing, the directory stopped
// answering, or it answered again after it had stopped.
type Transition int

const (
	Steady Transition = iota
	Stopped
	Resumed
)

// NewFreshness is a copy never confirmed, telling nothing until Tell.
func NewFreshness(now func() time.Time) *Freshness { return &Freshness{now: now} }

// Tell has onConfirm told each confirmation's time, and onReach each
// check's reachability when it changes or is first known (nil tells
// nothing): a run's metrics. Each is told what is known now, at once.
// The hooks are called under the lock, so their calls are in the checks'
// order: they must not call back into f.
func (f *Freshness) Tell(onConfirm func(time.Time), onReach func(bool)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.onConfirm, f.onReach = onConfirm, onReach
	if onConfirm != nil && !f.confirmed.IsZero() {
		onConfirm(f.confirmed)
	}
	if onReach != nil && f.checked {
		onReach(f.reachable)
	}
}

// FeedUp is the marks feed's up hook (FollowMarks).
func (f *Freshness) FeedUp(up bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.feedUp = up
	if up {
		f.snapshot = false
	}
}

// Checked is a directory read's answer: nil confirms the copy while the
// feed runs. It returns Stopped when the directory stops answering (a
// first check that fails included), Resumed when it answers after a stop,
// and Steady otherwise.
func (f *Freshness) Checked(err error) Transition {
	f.mu.Lock()
	defer f.mu.Unlock()
	was, first := f.reachable, !f.checked
	f.checked, f.reachable = true, err == nil
	f.why = ""
	if err != nil {
		f.why = err.Error()
	}
	if err == nil && f.feedUp {
		f.confirmed = f.now()
		if f.onConfirm != nil {
			f.onConfirm(f.confirmed)
		}
	}
	if (first || was != f.reachable) && f.onReach != nil {
		f.onReach(f.reachable)
	}
	switch {
	case !f.reachable && (first || was):
		return Stopped
	case f.reachable && !first && !was:
		return Resumed
	}
	return Steady
}

// Age is how long since the copy was last confirmed, and false before
// the first confirmation.
func (f *Freshness) Age() (time.Duration, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.confirmed.IsZero() {
		return 0, false
	}
	return f.now().Sub(f.confirmed), true
}

// Reachable is whether the last read answered, and its error's text when
// it did not.
func (f *Freshness) Reachable() (bool, string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.reachable, f.why
}

// Seed is a copy loaded from a snapshot confirmed at at (plan 11a, R19):
// Age counts from at, and Snapshot reports true until the marks feed's
// load from the directory succeeds (FeedUp). It tells onConfirm, as a
// confirmation does.
func (f *Freshness) Seed(at time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.confirmed, f.snapshot = at, true
	if f.onConfirm != nil {
		f.onConfirm(at)
	}
}

// Snapshot reports whether the copy is a snapshot's, not yet reloaded from
// the directory.
func (f *Freshness) Snapshot() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.snapshot
}

// Confirmed is when the copy was last confirmed (a snapshot's time while it
// is one), and false before the first.
func (f *Freshness) Confirmed() (time.Time, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.confirmed, !f.confirmed.IsZero()
}
