package memory

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/store"
)

func TestTokenLifecycle(t *testing.T) {
	now := time.Unix(1_000, 0)
	s := New(func() time.Time { return now })
	ctx := context.Background()
	k := store.TokenKey{NAS: "leaf-01", Username: "alice"}

	n, err := s.PutToken(ctx, k, store.Token{Secret: []byte("t1"), Kind: "login", ExpiresAt: now.Add(time.Minute)})
	if err != nil || n != 1 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	n, _ = s.PutToken(ctx, k, store.Token{Secret: []byte("t2"), Kind: "login", ExpiresAt: now.Add(time.Second)})
	if n != 2 {
		t.Fatalf("second put count %d", n)
	}
	c, _ := s.Candidates(ctx, k)
	if len(c) != 2 {
		t.Fatalf("candidates %d", len(c))
	}

	now = now.Add(2 * time.Second) // t2 expires
	c, _ = s.Candidates(ctx, k)
	if len(c) != 1 || !bytes.Equal(c[0].Secret, []byte("t1")) {
		t.Fatalf("after expiry %+v", c)
	}

	rk := store.ReceiptKey{NAS: "leaf-01", Port: "vty0", Username: "alice"}
	r := store.Receipt{Status: 1, CtxID: "01J", ExpiresAt: now.Add(30 * time.Second)}
	if err := s.RedeemAndReceipt(ctx, k, []byte("t1"), rk, r); err != nil {
		t.Fatal(err)
	}
	if err := s.RedeemAndReceipt(ctx, k, []byte("t1"), rk, r); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("second redeem must lose: %v", err)
	}
	got, err := s.GetReceipt(ctx, rk)
	if err != nil || got.CtxID != "01J" {
		t.Fatalf("receipt %+v %v", got, err)
	}
	if c, _ := s.Candidates(ctx, k); len(c) != 0 {
		t.Fatal("token still present after redemption")
	}
}

func TestRedeemIsAtomicUnderRace(t *testing.T) {
	s := New(time.Now)
	ctx := context.Background()
	k := store.TokenKey{NAS: "n", Username: "u"}
	s.PutToken(ctx, k, store.Token{Secret: []byte("x"), ExpiresAt: time.Now().Add(time.Minute)})
	rk := store.ReceiptKey{NAS: "n", Port: "p", Username: "u"}
	var wg sync.WaitGroup
	wins := 0
	var mu sync.Mutex
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.RedeemAndReceipt(ctx, k, []byte("x"), rk, store.Receipt{ExpiresAt: time.Now().Add(time.Minute)}); err == nil {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("exactly one redeemer must win, got %d", wins)
	}
}

func TestContextTTL(t *testing.T) {
	now := time.Unix(1_000, 0)
	s := New(func() time.Time { return now })
	ctx := context.Background()
	k := store.ContextKey{NAS: "n", Port: "vty0"}
	if err := s.PutContext(ctx, k, store.Context{CtxID: "c1"}, time.Minute); err != nil {
		t.Fatal(err)
	}
	if c, err := s.GetContext(ctx, k); err != nil || c.CtxID != "c1" {
		t.Fatalf("%+v %v", c, err)
	}
	now = now.Add(2 * time.Minute)
	if _, err := s.GetContext(ctx, k); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expired context still readable: %v", err)
	}
}
