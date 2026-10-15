package storetest

import (
	"context"
	"sync"
	"testing"
	"time"
)

// SignInAttemptsCountInAFixedWindow: the window starts at the first attempt,
// a later attempt does not move its end, and past the end the count starts
// again; undo never goes below zero; clear returns what it held.
func SignInAttemptsCountInAFixedWindow(t *testing.T, b Backend) {
	ctx := context.Background()
	var mu sync.Mutex
	now := t0
	s := b.New(t, func() time.Time { mu.Lock(); defer mu.Unlock(); return now })
	const k = "principal:user:alice@example.com"
	for i := 1; i <= 3; i++ {
		n, end, err := s.NoteSignInAttempt(ctx, k, 15*time.Minute)
		if err != nil || n != i || !end.Equal(t0.Add(15*time.Minute)) {
			t.Fatalf("attempt %d: %d %s %v", i, n, end, err)
		}
		mu.Lock()
		now = now.Add(time.Minute)
		mu.Unlock()
	}
	if err := s.UndoSignInAttempt(ctx, k); err != nil {
		t.Fatal(err)
	}
	if n, err := s.ClearSignInAttempts(ctx, k); err != nil || n != 2 {
		t.Fatalf("cleared %d %v", n, err)
	}
	if err := s.UndoSignInAttempt(ctx, k); err != nil {
		t.Fatalf("undo with none: %v", err)
	}
	if n, _, _ := s.NoteSignInAttempt(ctx, k, 15*time.Minute); n != 1 {
		t.Fatalf("after clear: %d", n)
	}
	mu.Lock()
	now = now.Add(16 * time.Minute)
	mu.Unlock()
	if n, end, _ := s.NoteSignInAttempt(ctx, k, 15*time.Minute); n != 1 || !end.Equal(now.Add(15*time.Minute)) {
		t.Fatalf("a new window: %d %s", n, end)
	}
}

// SignInAttemptsCountEveryRacer: fifty attempts at once are fifty counts,
// each racer told a distinct count (Review Focus 3).
func SignInAttemptsCountEveryRacer(t *testing.T, b Backend) {
	ctx := context.Background()
	s := b.New(t, func() time.Time { return t0 })
	const k = "source:192.0.2.0/32"
	var wg sync.WaitGroup
	seen := make(chan int, 50)
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			n, _, err := s.NoteSignInAttempt(ctx, k, time.Minute)
			if err != nil {
				t.Error(err)
			}
			seen <- n
		}()
	}
	wg.Wait()
	close(seen)
	got := map[int]bool{}
	for n := range seen {
		if got[n] {
			t.Fatalf("two racers told %d", n)
		}
		got[n] = true
	}
	if len(got) != 50 || !got[50] {
		t.Fatalf("%d distinct counts", len(got))
	}
}
