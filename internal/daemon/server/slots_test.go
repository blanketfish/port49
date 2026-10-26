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
	if refused.Load() == 0 {
		t.Fatal("the hammer never reached the cap")
	}
	if s.InUse() != 0 {
		t.Fatalf("%d slots held at the end", s.InUse())
	}
}

// Shedding runs on, a minute passes, and many Accepts shed in the same
// instant: exactly one says the line, and it counts every shed since the last
// one said (the others returned nothing and lost nothing).
func TestOneOfManyConcurrentShedsSaysTheMinuteLine(t *testing.T) {
	for round := range 300 {
		var clock atomic.Int64
		clock.Store(time.Unix(1_800_000_000, 0).UnixNano())
		s := NewSlots(2, func() time.Time { return time.Unix(0, clock.Load()) })
		s.Shed() // shedding begins and is said
		clock.Add(int64(10 * time.Second))
		s.Shed()
		clock.Add(int64(55 * time.Second)) // 65s into the run, 55s after the last shed
		const workers = 16
		var lines, ready atomic.Int64
		var said atomic.Value
		start := make(chan struct{})
		var wg sync.WaitGroup
		for range workers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				ready.Add(1)
				<-start
				if l := s.Shed(); l != "" {
					lines.Add(1)
					said.Store(l)
				}
			}()
		}
		for ready.Load() < workers {
			time.Sleep(time.Microsecond)
		}
		close(start)
		wg.Wait()
		if lines.Load() != 1 {
			t.Fatalf("round %d: %d lines said for one minute of shedding", round, lines.Load())
		}
		// A shed that lands after the claim is counted toward the next line,
		// so what the line says plus what waits for the next is every shed
		// since the last line: the 1 at +10s and the 16 at once.
		var n int
		if _, err := fmt.Sscanf(said.Load().(string), "port49d: still shedding: %d connections", &n); err != nil {
			t.Fatalf("round %d: %q", round, said.Load())
		}
		if got := int64(n) + s.sinceSaid.Load(); got != 1+workers {
			t.Fatalf("round %d: the line says %d and %d wait: sheds were lost", round, n, s.sinceSaid.Load())
		}
	}
}
