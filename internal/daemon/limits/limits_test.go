package limits

import (
	"net/netip"
	"testing"
	"time"
)

func cfg() Config {
	return Config{PerNASConnections: 2, IdleTimeout: time.Second,
		MalformedBackoffBase: 100 * time.Millisecond, MalformedBackoffMax: time.Second, MalformedWindow: time.Minute,
		AuthFailureDelayBase: 200 * time.Millisecond, AuthFailureDelayMax: 2 * time.Second, AuthFailureWindow: time.Minute}
}

func TestPerNASCapIsPerSource(t *testing.T) {
	l := New(cfg(), time.Now)
	a, b := netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2")
	r1, ok1 := l.Acquire(a)
	r2, ok2 := l.Acquire(a)
	_, ok3 := l.Acquire(a)
	_, okB := l.Acquire(b)
	if !ok1 || !ok2 || ok3 || !okB {
		t.Fatalf("cap: %v %v %v other=%v", ok1, ok2, ok3, okB)
	}
	r1()
	if _, ok := l.Acquire(a); !ok {
		t.Fatal("release must free a slot")
	}
	r2()
}

func TestMalformedBackoffGrowsAndCaps(t *testing.T) {
	l := New(cfg(), time.Now)
	a := netip.MustParseAddr("10.0.0.1")
	d1, d2, d3 := l.Malformed(a), l.Malformed(a), l.Malformed(a)
	if !(d1 < d2 && d2 < d3) {
		t.Fatalf("not growing: %v %v %v", d1, d2, d3)
	}
	var last time.Duration
	for i := 0; i < 20; i++ {
		last = l.Malformed(a)
	}
	if last != time.Second {
		t.Fatalf("cap: %v", last)
	}
}

func TestAuthFailureDelaysButNeverLocks(t *testing.T) {
	now := time.Unix(1000, 0)
	l := New(cfg(), func() time.Time { return now })
	d1 := l.AuthFailure("leaf-01", "alice")
	var last time.Duration
	for i := 0; i < 100; i++ {
		last = l.AuthFailure("leaf-01", "alice")
	}
	if d1 >= last || last != 2*time.Second {
		t.Fatalf("delays: first %v last %v", d1, last)
	}
	// Past the window the counter resets; nothing is ever "locked".
	now = now.Add(2 * time.Minute)
	if d := l.AuthFailure("leaf-01", "alice"); d != d1 {
		t.Fatalf("window reset: %v vs %v", d, d1)
	}
}

func TestSweepEvictsIdleEntries(t *testing.T) {
	now := time.Unix(1000, 0)
	l := New(cfg(), func() time.Time { return now })

	// Strike a few sources and (nas, user) keys.
	a := netip.MustParseAddr("10.0.0.1")
	b := netip.MustParseAddr("10.0.0.2")
	l.Malformed(a)
	l.Malformed(b)
	l.Decline(a)
	l.AuthFailure("leaf-01", "alice")
	l.AuthFailure("leaf-02", "bob")

	// Verify maps have entries.
	if len(l.bad) != 2 || len(l.declined) != 1 || len(l.auth) != 2 {
		t.Fatalf("before: bad=%d declined=%d auth=%d", len(l.bad), len(l.declined), len(l.auth))
	}

	// Advance past both windows and sweep.
	now = now.Add(2 * time.Minute)
	l.sweepLocked(now)

	// All maps should be empty.
	if len(l.bad) != 0 || len(l.declined) != 0 || len(l.auth) != 0 {
		t.Fatalf("after sweep: bad=%d declined=%d auth=%d", len(l.bad), len(l.declined), len(l.auth))
	}

	// A fresh strike after the window starts the count over.
	d1 := l.Malformed(a)
	d2 := l.Malformed(a)
	if d1 >= d2 {
		t.Fatalf("restart: first %v should be less than second %v", d1, d2)
	}
}

// A decline opens a window on the strike's schedule: the backoff base, then
// doubling (spec §10, "A declined source is refused at Accept").
func TestADeclineOpensAWindowOnTheStrikesSchedule(t *testing.T) {
	now := time.Unix(1000, 0)
	l := New(cfg(), func() time.Time { return now })
	a, b := netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2")
	if l.Declined(a) {
		t.Fatal("declined before any decline")
	}
	l.Decline(a)
	if !l.Declined(a) || l.Declined(b) {
		t.Fatalf("after one decline of a: a %v, b %v", l.Declined(a), l.Declined(b))
	}
	now = now.Add(99 * time.Millisecond)
	if !l.Declined(a) {
		t.Fatal("the first window is the backoff base, 100ms")
	}
	now = now.Add(2 * time.Millisecond)
	if l.Declined(a) {
		t.Fatal("the first window outlasted the backoff base")
	}
	l.Decline(a)
	now = now.Add(150 * time.Millisecond)
	if !l.Declined(a) {
		t.Fatal("the second window did not double to 200ms")
	}
}

// The window is capped at MalformedBackoffMax, and the count starts over once
// MalformedWindow has passed with no decline (decision 1's other two halves).
func TestADeclineWindowIsCappedAndStartsOver(t *testing.T) {
	now := time.Unix(1000, 0)
	l := New(cfg(), func() time.Time { return now })
	a := netip.MustParseAddr("10.0.0.1")
	for i := 0; i < 10; i++ {
		l.Decline(a)
	}
	now = now.Add(time.Second - time.Millisecond)
	if !l.Declined(a) {
		t.Fatal("the capped window is MalformedBackoffMax, 1s")
	}
	now = now.Add(2 * time.Millisecond)
	if l.Declined(a) {
		t.Fatal("the window outlasted MalformedBackoffMax")
	}
	now = now.Add(2 * time.Minute) // past MalformedWindow
	l.Decline(a)
	now = now.Add(101 * time.Millisecond)
	if l.Declined(a) {
		t.Fatal("the count did not start over after MalformedWindow: the window was longer than the base")
	}
}

// A decline is not a strike: it puts the source in no strike's backoff and
// does not lengthen the next strike's.
func TestADeclineIsNotAStrike(t *testing.T) {
	now := time.Unix(1000, 0)
	l := New(cfg(), func() time.Time { return now })
	a := netip.MustParseAddr("10.0.0.1")
	for i := 0; i < 5; i++ {
		l.Decline(a)
	}
	if l.Holding(a) {
		t.Fatal("a decline put the source in a strike's backoff")
	}
	if d := l.Malformed(a); d != 100*time.Millisecond {
		t.Fatalf("declines lengthened the first strike's backoff to %v", d)
	}
}

// Undecline drops the window and the count: a source declined again after it
// starts from the base.
func TestUndeclineDropsTheWindowAndTheCount(t *testing.T) {
	now := time.Unix(1000, 0)
	l := New(cfg(), func() time.Time { return now })
	a := netip.MustParseAddr("10.0.0.1")
	for i := 0; i < 5; i++ {
		l.Decline(a)
	}
	l.Undecline(a)
	if l.Declined(a) {
		t.Fatal("still declined after Undecline")
	}
	l.Decline(a)
	now = now.Add(101 * time.Millisecond)
	if l.Declined(a) {
		t.Fatal("the count survived Undecline: the next window was longer than the base")
	}
}

// The declined map holds one entry per declined source and no more: Undecline
// deletes the entry, and Declines alone drive the periodic sweep that evicts
// an idle one.
func TestTheDeclinedMapIsBoundedAndSwept(t *testing.T) {
	now := time.Unix(1000, 0)
	l := New(cfg(), func() time.Time { return now })
	a, b := netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2")
	l.Decline(a)
	l.Decline(a)
	l.Decline(b)
	if len(l.declined) != 2 {
		t.Fatalf("declined=%d, want one entry per source", len(l.declined))
	}
	l.Undecline(b)
	if len(l.declined) != 1 {
		t.Fatalf("declined=%d after Undecline, want 1", len(l.declined))
	}
	now = now.Add(2 * time.Minute) // a is past MalformedWindow
	for l.writes%1024 != 0 {
		l.Decline(b)
	}
	if _, ok := l.declined[a]; ok || len(l.declined) != 1 {
		t.Fatalf("the sweep a Decline triggered left declined=%d (a kept: %v)", len(l.declined), ok)
	}
}
