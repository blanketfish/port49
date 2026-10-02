package memory

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/storetest"
)

func TestSweepDropsExpiredKeys(t *testing.T) {
	now := time.Unix(1_000, 0)
	s := New(func() time.Time { return now })
	ctx := context.Background()

	// Write tokens, receipts, contexts, blobs, idempotency records, and
	// context-index entries under distinct keys with short TTLs. These are
	// written straight into the maps, as the receipt index above already
	// does, because every getter (GetBlob, ReserveIdempotency, the Contexts*
	// readers) self-checks expiry and so cannot tell a swept map from an
	// unswept one whose entry it happens to skip: only reaching the map
	// directly, after sweepLocked, catches a sweep branch that was never
	// wired up.
	for i := 0; i < 3; i++ {
		tk := store.TokenKey{NAS: "n", Username: "u" + string(rune(i))}
		s.PutToken(ctx, tk, store.Token{ID: "t", Secret: []byte("s"), ExpiresAt: now.Add(time.Second)})

		rk := store.ReceiptKey{NAS: "n", Username: "u" + string(rune(i))}
		s.receipts[rk] = store.Receipt{RetainUntil: now.Add(time.Second)}
		s.receiptsByPrincipal["user:u"+string(rune(i))] = map[store.ReceiptKey]time.Time{rk: now.Add(time.Second)}

		ck := store.ContextKey{NAS: "n", Username: "u" + string(rune(i))}
		s.contexts[ck] = ctxEntry{c: store.Context{CtxID: "c"}, exp: now.Add(time.Second)}

		s.blobs["sha256:"+string(rune(i))] = blobEntry{body: []byte("b"), exp: now.Add(time.Second)}
		s.idem[idemKey("user:u"+string(rune(i)), "k")] = store.Idempotency{ExpiresAt: now.Add(time.Second)}

		ref := store.ContextRef{NAS: "n", Username: "u" + string(rune(i))}
		exp := now.Add(time.Second)
		s.byPrincipal["user:u"+string(rune(i))] = map[store.ContextRef]time.Time{ref: exp}
		s.bySid["sid"+string(rune(i))] = map[store.ContextRef]time.Time{ref: exp}
		s.byCert["cert"+string(rune(i))] = map[store.ContextRef]time.Time{ref: exp}

		s.tokensByPrincipal["user:u"+string(rune(i))] = map[store.TokenKey]time.Time{tk: exp}
		s.tokensByCert["cert"+string(rune(i))] = map[store.TokenKey]time.Time{tk: exp}
	}

	// Verify entries exist
	if len(s.tokens) != 3 || len(s.receipts) != 3 || len(s.contexts) != 3 || len(s.receiptsByPrincipal) != 3 ||
		len(s.blobs) != 3 || len(s.idem) != 3 || len(s.byPrincipal) != 3 || len(s.bySid) != 3 || len(s.byCert) != 3 ||
		len(s.tokensByPrincipal) != 3 || len(s.tokensByCert) != 3 {
		t.Fatalf("setup failed: tokens=%d receipts=%d contexts=%d index=%d blobs=%d idem=%d byPrincipal=%d bySid=%d byCert=%d tokensByPrincipal=%d tokensByCert=%d",
			len(s.tokens), len(s.receipts), len(s.contexts), len(s.receiptsByPrincipal),
			len(s.blobs), len(s.idem), len(s.byPrincipal), len(s.bySid), len(s.byCert),
			len(s.tokensByPrincipal), len(s.tokensByCert))
	}

	// Advance time past expiry
	now = now.Add(2 * time.Second)

	// Call sweepLocked directly while holding the lock
	s.mu.Lock()
	s.sweepLocked()
	s.mu.Unlock()

	// Verify all expired entries are gone. The principal index matters as much
	// as the records: a daemon that sweeps records but keeps their index
	// entries grows one map entry per login for as long as it runs. Same for
	// the blob, idempotency, and context-index maps Task 3 added, and the
	// token indexes of plan 7a.
	if len(s.tokens) != 0 || len(s.receipts) != 0 || len(s.contexts) != 0 || len(s.receiptsByPrincipal) != 0 ||
		len(s.blobs) != 0 || len(s.idem) != 0 || len(s.byPrincipal) != 0 || len(s.bySid) != 0 || len(s.byCert) != 0 ||
		len(s.tokensByPrincipal) != 0 || len(s.tokensByCert) != 0 {
		t.Fatalf("sweep failed: tokens=%d receipts=%d contexts=%d index=%d blobs=%d idem=%d byPrincipal=%d bySid=%d byCert=%d tokensByPrincipal=%d tokensByCert=%d",
			len(s.tokens), len(s.receipts), len(s.contexts), len(s.receiptsByPrincipal),
			len(s.blobs), len(s.idem), len(s.byPrincipal), len(s.bySid), len(s.byCert),
			len(s.tokensByPrincipal), len(s.tokensByCert))
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
			t.Fatalf("tail entry %d still holds an evicted token's secret (%d bytes)", i, len(tok.Secret))
		}
	}
}

// SetPrivilege is TouchContext's sibling and exists for the same reason: the
// authorization path has to record the level it just granted without writing
// back a record it read a moment ago, because the writer it would race is
// revocation (spec §5.3).
func TestSetPrivilegeWritesTheLevelAndNothingElse(t *testing.T) {
	now := time.Unix(1000, 0)
	s := New(func() time.Time { return now })
	ctx := context.Background()
	k := store.ContextKey{NAS: "n", Username: "u"}
	s.PutContext(ctx, k, store.Context{CtxID: "c", Username: "u", PrivLvl: 1}, time.Minute)

	// A revocation lands after the authorization path took its copy.
	c, _ := s.GetContext(ctx, k)
	c.RevokedAt = now
	s.PutContext(ctx, k, c, time.Minute)

	stamped := now
	now = now.Add(30 * time.Second)
	if err := s.SetPrivilege(ctx, k, 15); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetContext(ctx, k)
	if err != nil {
		t.Fatal(err)
	}
	if got.PrivLvl != 15 {
		t.Fatalf("SetPrivilege did not record the granted level: %+v", got)
	}
	if got.RevokedAt.IsZero() {
		t.Fatalf("SetPrivilege discarded the revocation: %+v", got)
	}
	if got.CtxID != "c" {
		t.Fatalf("SetPrivilege must keep the same ctx_id (spec §7): %+v", got)
	}
	// It is not an extension: the TTL and its stamp are TouchContext's to move,
	// and a device that only ever authorizes sessions must not keep a context
	// alive by being granted the same level over and over.
	if !got.LastTouchedAt.Equal(stamped) {
		t.Fatalf("SetPrivilege must not stamp LastTouchedAt: %+v", got)
	}
	now = now.Add(31 * time.Second) // past the original expiry
	if _, err := s.GetContext(ctx, k); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("SetPrivilege extended the expiry; only TouchContext may")
	}
	if err := s.SetPrivilege(ctx, k, 15); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("setting a level on an expired context must say so, not resurrect it: %v", err)
	}
}

// A redeemed token's Secret must not survive in the backing array. The removal
// in RedeemAndReceipt clips the capacity to the spent token's index, so when it
// is the last member of the set nothing reallocates and its entry stays
// reachable from the very allocation the map still holds -- invisible through
// s.tokens[k], whose cap is clipped, but alive for as long as the key is.
// TestCompactionZeroesTheTail cannot see this one for exactly that reason.
func TestRedeemZeroesTheSpentToken(t *testing.T) {
	now := time.Now()
	s := New(func() time.Time { return now })
	ctx := context.Background()
	k := store.TokenKey{NAS: "n", Username: "u"}
	// The spent token is last, so the removal takes the non-reallocating path.
	s.PutToken(ctx, k, store.Token{ID: "keep", Secret: []byte("p49_keeps"), ExpiresAt: now.Add(time.Hour)})
	s.PutToken(ctx, k, store.Token{ID: "spend", Secret: []byte("p49_spent"), ExpiresAt: now.Add(time.Hour)})

	// Taken before the redemption, this aliases the same array the map holds,
	// over its full capacity rather than the clipped length left behind.
	s.mu.Lock()
	arr := s.tokens[k][:cap(s.tokens[k])]
	s.mu.Unlock()

	rk := store.ReceiptKey{NAS: "n", Username: "u"}
	r := store.Receipt{FirstRedeemedAt: now, IdleExpiresAt: now.Add(time.Minute), RetainUntil: now.Add(time.Hour)}
	if err := s.RedeemAndReceipt(ctx, k, "spend", storetest.Rw(rk, r, "user:u")); err != nil {
		t.Fatal(err)
	}

	s.mu.Lock()
	for i, tok := range arr {
		if tok.ID == "spend" || bytes.Equal(tok.Secret, []byte("p49_spent")) {
			s.mu.Unlock()
			t.Fatalf("backing array entry %d still holds the spent token: id=%q, %d secret bytes", i, tok.ID, len(tok.Secret))
		}
	}
	s.mu.Unlock()

	// And the survivor came through the zeroing intact: clearTail clears the
	// entries, never the secret bytes a surviving token still points at.
	c, _ := s.Candidates(ctx, k)
	if len(c) != 1 || c[0].ID != "keep" || !bytes.Equal(c[0].Secret, []byte("p49_keeps")) {
		t.Fatalf("the surviving token was damaged: %+v", c)
	}
}

// planting is the memory store with a way to write an idempotency record
// whole, which no store.Store method has: storetest.IdempotencyReservesOnce
// plants a holderless one through it.
type planting struct{ *Store }

func (p planting) PlantIdempotency(_ context.Context, principal, key string, rec store.Idempotency) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.idem[idemKey(principal, key)] = rec
	return nil
}

// Every storetest property, against the memory store; a planting store, so
// IdempotencyReservesOnce plants its holderless record.
func TestTheMemoryStoreHoldsEveryProperty(t *testing.T) {
	storetest.Run(t, storetest.Backend{New: func(_ *testing.T, clock func() time.Time) store.Store {
		return planting{New(clock)}
	}})
}

// Each whole-context write returns the revision it committed at, which is
// the Rev the next read sees, and a refused one returns zero
// (store.RevStore; plan 7d Task 6b).
func TestAContextWriteReturnsItsRevision(t *testing.T) {
	ctx := context.Background()
	s := New(func() time.Time { return time.Unix(1_000, 0) })
	k := store.ContextKey{NAS: "leaf-01", Username: "alice"}
	c := store.Context{CtxID: "c", Principal: "p", Username: "alice", PrivLvl: 1}
	check := func(what string, rev uint64, err error) store.Context {
		t.Helper()
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		got, err := s.GetContext(ctx, k)
		if err != nil || got.Rev != rev || rev == 0 {
			t.Fatalf("%s committed at %d, and a read sees Rev %d (%v)", what, rev, got.Rev, err)
		}
		return got
	}
	rev, err := s.PutContextRev(ctx, k, c, time.Hour)
	got := check("a put", rev, err)
	rev, err = s.SwapLoginRev(ctx, k, got.Rev, c, time.Hour, store.LoginWrite{Principal: "p", Sid: "s", IndexTTL: time.Hour})
	got = check("a login", rev, err)
	rev, err = s.SwapContextRev(ctx, k, got.Rev, c, time.Hour)
	got = check("a swap", rev, err)
	got.PrivLvl = 7
	rev, err = s.RewriteContextRev(ctx, k, got.Rev, got, 0, true)
	got = check("a rewrite", rev, err)
	if rev, err := s.SwapLoginRev(ctx, k, got.Rev-1, c, time.Hour, store.LoginWrite{}); rev != 0 || !errors.Is(err, store.ErrConflict) {
		t.Fatalf("a login on a stale revision: %d %v, want 0 and ErrConflict", rev, err)
	}
	if rev, err := s.RewriteContextRev(ctx, k, got.Rev-1, got, 0, false); rev != 0 || !errors.Is(err, store.ErrConflict) {
		t.Fatalf("a rewrite on a stale revision: %d %v, want 0 and ErrConflict", rev, err)
	}
}
