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

func TestSecretsAreNotAliased(t *testing.T) {
	now := time.Unix(1_000, 0)
	s := New(func() time.Time { return now })
	ctx := context.Background()
	k := store.TokenKey{NAS: "n", Username: "u"}

	// Put a token with a mutable secret
	secret := []byte("mysecret")
	_, err := s.PutToken(ctx, k, store.Token{Secret: secret, Kind: "login", ExpiresAt: now.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}

	// Mutate the caller's secret after putting
	secret[0] = 'X'

	// Candidates should still return the original secret
	c, _ := s.Candidates(ctx, k)
	if len(c) != 1 || !bytes.Equal(c[0].Secret, []byte("mysecret")) {
		t.Fatalf("secret was aliased, got %q", c[0].Secret)
	}

	// Mutate the returned secret
	c[0].Secret[0] = 'Y'

	// A second Candidates call should return the original secret unchanged
	c2, _ := s.Candidates(ctx, k)
	if len(c2) != 1 || !bytes.Equal(c2[0].Secret, []byte("mysecret")) {
		t.Fatalf("returned secret was not copied, got %q", c2[0].Secret)
	}
}

func TestSweepDropsExpiredKeys(t *testing.T) {
	now := time.Unix(1_000, 0)
	s := New(func() time.Time { return now })
	ctx := context.Background()

	// Write tokens, receipts, contexts under distinct keys with short TTLs
	for i := 0; i < 3; i++ {
		tk := store.TokenKey{NAS: "n", Username: "u" + string(rune(i))}
		s.PutToken(ctx, tk, store.Token{Secret: []byte("s"), ExpiresAt: now.Add(time.Second)})

		rk := store.ReceiptKey{NAS: "n", Port: "p", Username: "u" + string(rune(i))}
		s.receipts[rk] = store.Receipt{ExpiresAt: now.Add(time.Second)}

		ck := store.ContextKey{NAS: "n", Port: "p" + string(rune(i))}
		s.contexts[ck] = ctxEntry{c: store.Context{CtxID: "c"}, exp: now.Add(time.Second)}
	}

	// Verify entries exist
	if len(s.tokens) != 3 || len(s.receipts) != 3 || len(s.contexts) != 3 {
		t.Fatalf("setup failed: tokens=%d receipts=%d contexts=%d", len(s.tokens), len(s.receipts), len(s.contexts))
	}

	// Advance time past expiry
	now = now.Add(2 * time.Second)

	// Call sweepLocked directly while holding the lock
	s.mu.Lock()
	s.sweepLocked()
	s.mu.Unlock()

	// Verify all expired entries are gone
	if len(s.tokens) != 0 || len(s.receipts) != 0 || len(s.contexts) != 0 {
		t.Fatalf("sweep failed: tokens=%d receipts=%d contexts=%d", len(s.tokens), len(s.receipts), len(s.contexts))
	}
}

func TestReusableTokenRedeem(t *testing.T) {
	now := time.Unix(1_000, 0)
	s := New(func() time.Time { return now })
	ctx := context.Background()
	k := store.TokenKey{NAS: "n", Username: "u"}

	// Put a reusable token
	_, err := s.PutToken(ctx, k, store.Token{
		Secret:    []byte("reusable_secret"),
		Kind:      "login",
		Reusable:  true,
		ExpiresAt: now.Add(time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}

	// First redeem: should succeed and write receipt
	rk := store.ReceiptKey{NAS: "n", Port: "vty0", Username: "u"}
	r1 := store.Receipt{Status: 1, CtxID: "ctx1", ExpiresAt: now.Add(time.Minute)}
	if err := s.RedeemAndReceipt(ctx, k, []byte("reusable_secret"), rk, r1); err != nil {
		t.Fatal(err)
	}

	// Verify receipt was written
	got, err := s.GetReceipt(ctx, rk)
	if err != nil || got.CtxID != "ctx1" {
		t.Fatalf("receipt not written: %+v %v", got, err)
	}

	// Verify token still present (Reusable: true)
	c, _ := s.Candidates(ctx, k)
	if len(c) != 1 {
		t.Fatalf("token was removed but Reusable: true, have %d tokens", len(c))
	}

	// Second redeem with same secret: should succeed again
	r2 := store.Receipt{Status: 1, CtxID: "ctx2", ExpiresAt: now.Add(time.Minute)}
	if err := s.RedeemAndReceipt(ctx, k, []byte("reusable_secret"), rk, r2); err != nil {
		t.Fatalf("second redeem of reusable token failed: %v", err)
	}

	// Verify receipt was updated
	got, err = s.GetReceipt(ctx, rk)
	if err != nil || got.CtxID != "ctx2" {
		t.Fatalf("receipt not updated: %+v %v", got, err)
	}
}

func TestDeleteContext(t *testing.T) {
	now := time.Unix(1_000, 0)
	s := New(func() time.Time { return now })
	ctx := context.Background()
	k := store.ContextKey{NAS: "n", Port: "vty0"}

	// Put a context
	if err := s.PutContext(ctx, k, store.Context{CtxID: "c1"}, time.Minute); err != nil {
		t.Fatal(err)
	}

	// Verify it exists
	c, err := s.GetContext(ctx, k)
	if err != nil || c.CtxID != "c1" {
		t.Fatalf("context not found after put: %+v %v", c, err)
	}

	// Delete the context
	if err := s.DeleteContext(ctx, k); err != nil {
		t.Fatal(err)
	}

	// Verify it's gone
	if _, err := s.GetContext(ctx, k); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("context still present after delete: %v", err)
	}

	// Delete a missing key: verify it returns same as GetContext (should not error)
	missingKey := store.ContextKey{NAS: "missing", Port: "missing"}
	if err := s.DeleteContext(ctx, missingKey); err != nil {
		t.Fatalf("delete of missing key returned error: %v", err)
	}
}
