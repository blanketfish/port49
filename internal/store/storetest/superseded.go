package storetest

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/store"
)

// SupersededIsTheLaterAndExpires: a key's superseded instant is the later
// of every one written, the all-keys instant reaches every key, and both
// are gone SupersededFor after they were written (plan 7e, Ruling 9). An
// unknown key is zero, never ErrNotFound.
func SupersededIsTheLaterAndExpires(t *testing.T, b Backend) {
	ctx := context.Background()
	var mu sync.Mutex
	now := t0
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	advance := func(d time.Duration) { mu.Lock(); now = now.Add(d); mu.Unlock() }
	s := b.New(t, clock)
	k := store.TokenKey{NAS: "leaf-01", Username: "alice"}
	other := store.TokenKey{NAS: "leaf-02", Username: "alice"}
	if at, err := s.SupersededAt(ctx, k); err != nil || !at.IsZero() {
		t.Fatalf("an unknown key: %v %v", at, err)
	}
	if err := s.SupersedeTokens(ctx, k, t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := s.SupersedeTokens(ctx, k, t0); err != nil { // earlier: the later stands
		t.Fatal(err)
	}
	if at, _ := s.SupersededAt(ctx, k); !at.Equal(t0.Add(time.Minute)) {
		t.Fatalf("the later did not stand: %v", at)
	}
	if at, _ := s.SupersededAt(ctx, other); !at.IsZero() {
		t.Fatalf("another key was superseded: %v", at)
	}
	if err := s.SupersedeAll(ctx, t0.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	for _, key := range []store.TokenKey{k, other} {
		if at, _ := s.SupersededAt(ctx, key); !at.Equal(t0.Add(2 * time.Minute)) {
			t.Fatalf("the all-keys instant did not reach %v: %v", key, at)
		}
	}
	advance(store.SupersededFor + 3*time.Minute)
	if at, err := s.SupersededAt(ctx, k); err != nil || !at.IsZero() {
		t.Fatalf("past SupersededFor: %v %v", at, err)
	}
}
