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
