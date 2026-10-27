package server

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// A slot is taken without waiting, released once however often release is
// called, and a full pool says no at once: the cap sheds, it never queues
// (design §11; decision 53 ruling 8).
func TestSlots(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	s := NewSlots(1, func() time.Time { return now })
	if s.InUse() != 0 {
		t.Fatal("a new pool holds a slot")
	}
	r1, ok := s.TryAcquire()
	if !ok || s.InUse() != 1 {
		t.Fatal("the first slot")
	}
	if _, ok := s.TryAcquire(); ok {
		t.Fatal("a full pool gave a slot")
	}
	// Twice frees once: a second release that freed a slot it did not hold
	// would block on the empty pool, so it is waited for, not trusted.
	released := make(chan struct{})
	go func() { r1(); r1(); close(released) }()
	select {
	case <-released:
	case <-time.After(2 * time.Second):
		t.Fatal("a second release freed a slot it did not hold")
	}
	if s.InUse() != 0 {
		t.Fatal("a double release freed two, or none")
	}
	var none *Slots
	if r, ok := none.TryAcquire(); !ok {
		t.Fatal("a nil Slots is no cap")
	} else {
		r()
	}
}

// The first shed after a quiet minute is said at once; more within the
// minute are counted and said once a minute after, with their number.
func TestTheShedLineIsSaidWhenSheddingBeginsAndThenOncePerMinute(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	s := NewSlots(2, func() time.Time { return now })
	if l := s.Shed(); !strings.Contains(l, "shedding: all 2 TACACS+ connection slots") {
		t.Fatalf("the first shed: %q", l)
	}
	now = now.Add(10 * time.Second)
	if l := s.Shed(); l != "" {
		t.Fatalf("a second shed inside the minute was said: %q", l)
	}
	now = now.Add(55 * time.Second) // 65s after the run began
	if l := s.Shed(); !strings.Contains(l, "still shedding: 2 connections reset at Accept in the last minute") {
		t.Fatalf("a minute on: %q", l)
	}
	now = now.Add(2 * time.Minute)
	if l := s.Shed(); !strings.Contains(l, "shedding: all 2") {
		t.Fatalf("after a quiet minute shedding begins again: %q", l)
	}
}

// Hammered by many goroutines past the cap, the pool never holds more than
// its cap, every attempt is a slot or a refusal, and it ends empty: no
// release is lost and none counted twice (run under -race).
func TestSlotsHoldExactlyUnderConcurrentAcquireAndRelease(t *testing.T) {
	const cap, workers, rounds = 8, 64, 2000
	s := NewSlots(cap, time.Now)
	var held, over, got, refused atomic.Int64
	// Reaching the cap is not left to the workers overlapping: cap slots are
	// taken, the next attempt must be refused, and all are freed before the
	// hammer (a second release of each frees nothing).
	var releases []func()
	for range cap {
		release, ok := s.TryAcquire()
		if !ok {
			t.Fatal("a slot under the cap was refused")
		}
		releases = append(releases, release)
	}
	if _, ok := s.TryAcquire(); ok || s.InUse() != cap {
		t.Fatalf("at the cap: acquired %v, %d in use, want a refusal at %d", ok, s.InUse(), cap)
	}
	// A second release of the same slot frees nothing: the other cap-1 holders
	// keep theirs, whether a wrong release would block or take another's.
	releases[0]()
	releases[0]()
	if s.InUse() != cap-1 {
		t.Fatalf("one slot released twice: %d in use, want %d", s.InUse(), cap-1)
	}
	for _, release := range releases {
		release()
		release()
	}
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range rounds {
				release, ok := s.TryAcquire()
				if !ok {
					refused.Add(1)
					continue
				}
				got.Add(1)
				if held.Add(1) > cap || s.InUse() > cap {
					over.Add(1)
				}
				held.Add(-1)
				release()
				release() // a second call must free nothing
			}
		}()
	}
	finished := make(chan struct{})
	go func() { wg.Wait(); close(finished) }()
	select {
	case <-finished:
	case <-time.After(30 * time.Second):
		t.Fatal("a release blocked: one freed a slot it did not hold")
	}
	if over.Load() != 0 {
		t.Fatalf("the pool held more than its cap %d times", over.Load())
	}
	if got.Load()+refused.Load() != workers*rounds {
		t.Fatalf("%d slots + %d refusals != %d attempts", got.Load(), refused.Load(), workers*rounds)
	}
	if s.InUse() != 0 {
		t.Fatalf("%d slots held at the end", s.InUse())
	}
}

// pending is the sheds counted since the last line said (the test reads it
// once every goroutine has returned).
func pending(s *Slots) int { s.mu.Lock(); defer s.mu.Unlock(); return s.sinceSaid }

// A wall clock stepped back an hour (NTP correcting a clock that ran ahead, a
// VM resumed) must not silence the line: shedding that goes on is still said
// within a minute, never silently (design §11).
func TestAWallClockStepBackStillLetsTheLineThrough(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	s := NewSlots(2, func() time.Time { return now })
	if l := s.Shed(); !strings.Contains(l, "shedding: all 2") {
		t.Fatalf("the first shed: %q", l)
	}
	now = now.Add(-time.Hour)
	lines := 0
	for range 60 { // ten minutes of sheds, one every 10s, on the stepped-back clock
		if s.Shed() != "" {
			lines++
		}
		now = now.Add(10 * time.Second)
	}
	if lines < 8 {
		t.Fatalf("%d lines said in ten minutes of shedding after the clock stepped back an hour", lines)
	}
}

// Many Accepts shed in the same instant as shedding begins: exactly one says
// the onset line, and it is the onset line, not "still shedding". A minute
// on, many more shed at once: exactly one says "still shedding", and what it
// says plus what waits for the next line is every shed since the onset's.
func TestConcurrentOnsetIsOneLineAndTheCountsAreExact(t *testing.T) {
	const workers = 16
	burst := func(s *Slots) (lines []string) {
		var mu sync.Mutex
		var ready atomic.Int64
		start := make(chan struct{})
		var wg sync.WaitGroup
		for range workers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				ready.Add(1)
				<-start
				if l := s.Shed(); l != "" {
					mu.Lock()
					lines = append(lines, l)
					mu.Unlock()
				}
			}()
		}
		for ready.Load() < workers {
			time.Sleep(time.Microsecond)
		}
		close(start)
		wg.Wait()
		return lines
	}
	for round := range 200 {
		now := time.Unix(1_800_000_000, 0)
		var mu sync.Mutex
		s := NewSlots(2, func() time.Time { mu.Lock(); defer mu.Unlock(); return now })
		onset := burst(s)
		if len(onset) != 1 || !strings.Contains(onset[0], "port49d: shedding: all 2") {
			t.Fatalf("round %d: onset said %q", round, onset)
		}
		if n := pending(s); n != workers-1 {
			t.Fatalf("round %d: %d counted after the onset, want %d", round, n, workers-1)
		}
		mu.Lock()
		now = now.Add(30 * time.Second)
		mu.Unlock()
		if l := s.Shed(); l != "" { // shedding goes on, inside the minute
			t.Fatalf("round %d: a shed 30s on said %q", round, l)
		}
		mu.Lock()
		now = now.Add(35 * time.Second) // 65s into the run, 35s after the last shed
		mu.Unlock()
		later := burst(s)
		if len(later) != 1 || !strings.Contains(later[0], "port49d: still shedding: ") {
			t.Fatalf("round %d: a minute on said %q", round, later)
		}
		var n int
		if _, err := fmt.Sscanf(later[0], "port49d: still shedding: %d connections", &n); err != nil {
			t.Fatalf("round %d: %q", round, later[0])
		}
		if got := n + pending(s); got != (workers-1)+1+workers {
			t.Fatalf("round %d: the line says %d and %d wait: %d of %d sheds counted", round, n, pending(s), got,
				(workers-1)+1+workers)
		}
	}
}
