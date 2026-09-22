package memory

import (
	"bytes"
	"context"
	"crypto/sha256"
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

	n, err := s.PutToken(ctx, k, store.Token{ID: "t1", Secret: []byte("t1"), Kind: "login", ExpiresAt: now.Add(time.Minute)})
	if err != nil || n != 1 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	n, _ = s.PutToken(ctx, k, store.Token{ID: "t2", Secret: []byte("t2"), Kind: "login", ExpiresAt: now.Add(time.Second)})
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

	rk := store.ReceiptKey{NAS: "leaf-01", Username: "alice", CredentialSHA256: sha256.Sum256([]byte("t1"))}
	r := store.Receipt{Status: 1, CtxID: "01J", FirstRedeemedAt: now, IdleExpiresAt: now.Add(30 * time.Second), RetainUntil: now.Add(30 * time.Second)}
	if err := s.RedeemAndReceipt(ctx, k, "t1", rw(rk, r, "user:alice")); err != nil {
		t.Fatal(err)
	}
	if err := s.RedeemAndReceipt(ctx, k, "t1", rw(rk, r, "user:alice")); !errors.Is(err, store.ErrNotFound) {
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
	s.PutToken(ctx, k, store.Token{ID: "x", Secret: []byte("x"), ExpiresAt: time.Now().Add(time.Minute)})
	rk := store.ReceiptKey{NAS: "n", Username: "u", CredentialSHA256: sha256.Sum256([]byte("x"))}
	var wg sync.WaitGroup
	wins := 0
	var mu sync.Mutex
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := store.Receipt{FirstRedeemedAt: time.Now(), IdleExpiresAt: time.Now().Add(time.Minute), RetainUntil: time.Now().Add(time.Minute)}
			if err := s.RedeemAndReceipt(ctx, k, "x", rw(rk, r, "user:u")); err == nil {
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
	k := store.ContextKey{NAS: "n", Username: "u"}
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
	_, err := s.PutToken(ctx, k, store.Token{ID: "t1", Secret: secret, Kind: "login", ExpiresAt: now.Add(time.Minute)})
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
		s.PutToken(ctx, tk, store.Token{ID: "t", Secret: []byte("s"), ExpiresAt: now.Add(time.Second)})

		rk := store.ReceiptKey{NAS: "n", Username: "u" + string(rune(i))}
		s.receipts[rk] = store.Receipt{RetainUntil: now.Add(time.Second)}
		s.receiptsByPrincipal["user:u"+string(rune(i))] = map[store.ReceiptKey]time.Time{rk: now.Add(time.Second)}

		ck := store.ContextKey{NAS: "n", Username: "u" + string(rune(i))}
		s.contexts[ck] = ctxEntry{c: store.Context{CtxID: "c"}, exp: now.Add(time.Second)}
	}

	// Verify entries exist
	if len(s.tokens) != 3 || len(s.receipts) != 3 || len(s.contexts) != 3 || len(s.receiptsByPrincipal) != 3 {
		t.Fatalf("setup failed: tokens=%d receipts=%d contexts=%d index=%d",
			len(s.tokens), len(s.receipts), len(s.contexts), len(s.receiptsByPrincipal))
	}

	// Advance time past expiry
	now = now.Add(2 * time.Second)

	// Call sweepLocked directly while holding the lock
	s.mu.Lock()
	s.sweepLocked()
	s.mu.Unlock()

	// Verify all expired entries are gone. The principal index matters as much
	// as the records: a daemon that sweeps records but keeps their index
	// entries grows one map entry per login for as long as it runs.
	if len(s.tokens) != 0 || len(s.receipts) != 0 || len(s.contexts) != 0 || len(s.receiptsByPrincipal) != 0 {
		t.Fatalf("sweep failed: tokens=%d receipts=%d contexts=%d index=%d",
			len(s.tokens), len(s.receipts), len(s.contexts), len(s.receiptsByPrincipal))
	}
}

func TestDeleteContext(t *testing.T) {
	now := time.Unix(1_000, 0)
	s := New(func() time.Time { return now })
	ctx := context.Background()
	k := store.ContextKey{NAS: "n", Username: "u"}

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
	missingKey := store.ContextKey{NAS: "missing", Username: "missing"}
	if err := s.DeleteContext(ctx, missingKey); err != nil {
		t.Fatalf("delete of missing key returned error: %v", err)
	}
}

// TestCompactionZeroesTheTail covers what in-place compaction leaves behind.
// live() and sweepLocked() rewrite the slice over its own backing array, so
// the elements past the new length still hold Token values -- Secret headers
// included -- for tokens that have been evicted. They are unreachable through
// the map but very much still in the process, for as long as the array lives.
func TestCompactionZeroesTheTail(t *testing.T) {
	now := time.Now()
	s := New(func() time.Time { return now })
	k := store.TokenKey{NAS: "leaf-01", Username: "alice"}
	if _, err := s.PutToken(context.Background(), k, store.Token{ID: "stays", Secret: []byte("p49_stays"), Kind: store.KindLogin, ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	// The expiring token is last, so compaction drops it from the tail rather
	// than overwriting it with a live one.
	if _, err := s.PutToken(context.Background(), k, store.Token{ID: "expires", Secret: []byte("p49_expires"), Kind: store.KindLogin, ExpiresAt: now.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}

	now = now.Add(2 * time.Minute)
	if cands, err := s.Candidates(context.Background(), k); err != nil || len(cands) != 1 {
		t.Fatalf("want only the live token, got %d, %v", len(cands), err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	set := s.tokens[k]
	for i, tok := range set[len(set):cap(set)] {
		if tok.Secret != nil {
			t.Fatalf("tail entry %d still holds an evicted token's secret: %q", i, tok.Secret)
		}
	}
}

func rw(rk store.ReceiptKey, r store.Receipt, principal string) store.ReceiptWrite {
	return store.ReceiptWrite{Key: rk, Receipt: r, Principal: principal, IndexTTL: time.Hour}
}

func TestRedeemByID(t *testing.T) {
	s := New(time.Now)
	ctx := context.Background()
	k := store.TokenKey{NAS: "n", Username: "u"}
	s.PutToken(ctx, k, store.Token{ID: "t1", Secret: []byte("same"), ExpiresAt: time.Now().Add(time.Minute)})
	s.PutToken(ctx, k, store.Token{ID: "t2", Secret: []byte("same"), ExpiresAt: time.Now().Add(time.Minute)})
	rk := store.ReceiptKey{NAS: "n", Username: "u"}
	r := store.Receipt{FirstRedeemedAt: time.Now(), IdleExpiresAt: time.Now().Add(time.Minute), RetainUntil: time.Now().Add(time.Hour)}
	if err := s.RedeemAndReceipt(ctx, k, "t2", rw(rk, r, "user:u")); err != nil {
		t.Fatal(err)
	}
	c, _ := s.Candidates(ctx, k)
	if len(c) != 1 || c[0].ID != "t1" {
		t.Fatalf("%+v", c)
	}
	if err := s.RedeemAndReceipt(ctx, k, "gone", rw(rk, r, "user:u")); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("redeeming an unknown id: %v", err)
	}
	if err := s.DeleteTokens(ctx, k); err != nil {
		t.Fatal(err)
	}
	if c, _ := s.Candidates(ctx, k); len(c) != 0 {
		t.Fatal("DeleteTokens left members")
	}
}

func TestReceiptRetainedPastItsSlidingBound(t *testing.T) {
	now := time.Unix(1000, 0)
	s := New(func() time.Time { return now })
	ctx := context.Background()
	k := store.TokenKey{NAS: "n", Username: "u"}
	rk := store.ReceiptKey{NAS: "n", Username: "u"}
	s.PutToken(ctx, k, store.Token{ID: "t", Secret: []byte("s"), ExpiresAt: now.Add(time.Hour)})
	s.RedeemAndReceipt(ctx, k, "t", rw(rk, store.Receipt{
		FirstRedeemedAt: now, IdleExpiresAt: now.Add(time.Minute), RetainUntil: now.Add(time.Hour)}, "user:u"))

	now = now.Add(2 * time.Minute) // past the sliding bound, inside retention
	got, err := s.GetReceipt(ctx, rk)
	if err != nil {
		t.Fatal("a receipt past its sliding bound must still be found, or a late presentation reads as token_not_found")
	}
	if !got.IdleExpiresAt.Equal(now.Add(-time.Minute)) {
		t.Fatalf("%+v", got)
	}
	if err := s.ExtendReceipt(ctx, rk, now.Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetReceipt(ctx, rk); !got.IdleExpiresAt.Equal(now.Add(10*time.Minute)) || !got.FirstRedeemedAt.Equal(time.Unix(1000, 0)) {
		t.Fatalf("extend moved the anchor or missed the bound: %+v", got)
	}
	now = now.Add(2 * time.Hour) // past retention
	if _, err := s.GetReceipt(ctx, rk); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("receipt outlived RetainUntil")
	}
	if err := s.ExtendReceipt(ctx, rk, now.Add(time.Minute)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("extending a reclaimed receipt: %v", err)
	}
}

func TestDeleteReceiptsByPrincipal(t *testing.T) {
	now := time.Unix(1000, 0)
	s := New(func() time.Time { return now })
	ctx := context.Background()
	k := store.TokenKey{NAS: "n", Username: "u"}
	r := store.Receipt{FirstRedeemedAt: now, IdleExpiresAt: now.Add(time.Minute), RetainUntil: now.Add(time.Hour)}
	for i, id := range []string{"a", "b"} {
		s.PutToken(ctx, k, store.Token{ID: id, Secret: []byte(id), ExpiresAt: now.Add(time.Hour)})
		var h [32]byte
		h[0] = byte(i)
		s.RedeemAndReceipt(ctx, k, id, rw(store.ReceiptKey{NAS: "n", Username: "u", CredentialSHA256: h}, r, "user:alice"))
	}
	s.PutToken(ctx, k, store.Token{ID: "c", Secret: []byte("c"), ExpiresAt: now.Add(time.Hour)})
	var other [32]byte
	other[0] = 9
	s.RedeemAndReceipt(ctx, k, "c", rw(store.ReceiptKey{NAS: "n", Username: "u", CredentialSHA256: other}, r, "user:bob"))

	n, err := s.DeleteReceiptsByPrincipal(ctx, "user:alice")
	if err != nil || n != 2 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	var h0 [32]byte
	if _, err := s.GetReceipt(ctx, store.ReceiptKey{NAS: "n", Username: "u", CredentialSHA256: h0}); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("revocation must delete the principal's receipts")
	}
	if _, err := s.GetReceipt(ctx, store.ReceiptKey{NAS: "n", Username: "u", CredentialSHA256: other}); err != nil {
		t.Fatal("another principal's receipt must survive")
	}
}

// The shape TouchContext exists for: extending a TTL must not discard a write
// that landed since the record was read. Revocation is the write that matters —
// an extension that clobbered RevokedAt would un-revoke the session
// permanently, because the receipts are already gone and nothing sets it again.
func TestTouchContextExtendsWithoutClobbering(t *testing.T) {
	now := time.Unix(1000, 0)
	s := New(func() time.Time { return now })
	ctx := context.Background()
	k := store.ContextKey{NAS: "n", Username: "u"}
	s.PutContext(ctx, k, store.Context{CtxID: "c", Username: "u", LastTouchedAt: now}, time.Minute)

	// A revocation lands after the reader took its copy.
	c, _ := s.GetContext(ctx, k)
	c.RevokedAt = now
	s.PutContext(ctx, k, c, time.Minute)

	now = now.Add(30 * time.Second)
	if err := s.TouchContext(ctx, k, time.Minute); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetContext(ctx, k)
	if err != nil || got.RevokedAt.IsZero() {
		t.Fatalf("the extension discarded the revocation: %+v %v", got, err)
	}
	if !got.LastTouchedAt.Equal(now) {
		t.Fatalf("TouchContext must stamp LastTouchedAt, or the half-TTL rule never skips: %+v", got)
	}
	now = now.Add(45 * time.Second) // past the original expiry, inside the extended one
	if _, err := s.GetContext(ctx, k); err != nil {
		t.Fatal("TouchContext did not extend the expiry")
	}
	now = now.Add(2 * time.Minute)
	if err := s.TouchContext(ctx, k, time.Minute); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("touching an expired context must say so, not resurrect it: %v", err)
	}
}
