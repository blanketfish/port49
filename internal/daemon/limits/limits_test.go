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
	l.AuthFailure("leaf-01", "alice")
	l.AuthFailure("leaf-02", "bob")

	// Verify maps have entries.
	if len(l.bad) != 2 || len(l.auth) != 2 {
		t.Fatalf("before: bad=%d auth=%d", len(l.bad), len(l.auth))
	}

	// Advance past both windows and sweep.
	now = now.Add(2 * time.Minute)
	l.sweepLocked(now)

	// Both maps should be empty.
	if len(l.bad) != 0 || len(l.auth) != 0 {
		t.Fatalf("after sweep: bad=%d auth=%d", len(l.bad), len(l.auth))
	}

	// A fresh strike after the window starts the count over.
	d1 := l.Malformed(a)
	d2 := l.Malformed(a)
	if d1 >= d2 {
		t.Fatalf("restart: first %v should be less than second %v", d1, d2)
	}
}
