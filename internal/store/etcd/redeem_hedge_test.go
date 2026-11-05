package etcd

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"

	"github.com/blanketfish/port49/internal/store"
	"github.com/blanketfish/port49/internal/store/etcd/etcdtest"
	"github.com/blanketfish/port49/internal/store/storetest"
)

// dupKV makes every transaction run twice, as a hedge does: copy 1 applies,
// and the answer the caller gets is copy 2's, which finds copy 1's effects.
type dupKV struct{ clientv3.KV }

func (d dupKV) Txn(ctx context.Context) clientv3.Txn { return &dupTxn{kv: d.KV, ctx: ctx} }

type dupTxn struct {
	kv           clientv3.KV
	ctx          context.Context
	cmps         []clientv3.Cmp
	thens, elses []clientv3.Op
}

func (t *dupTxn) If(c ...clientv3.Cmp) clientv3.Txn  { t.cmps = append(t.cmps, c...); return t }
func (t *dupTxn) Then(o ...clientv3.Op) clientv3.Txn { t.thens = append(t.thens, o...); return t }
func (t *dupTxn) Else(o ...clientv3.Op) clientv3.Txn { t.elses = append(t.elses, o...); return t }
func (t *dupTxn) Commit() (*clientv3.TxnResponse, error) {
	run := func() (*clientv3.TxnResponse, error) {
		return t.kv.Txn(t.ctx).If(t.cmps...).Then(t.thens...).Else(t.elses...).Commit()
	}
	if _, err := run(); err != nil {
		return nil, err
	}
	return run()
}

func redeemFixture(t *testing.T) (*Store, []*etcdtest.Proxy, store.TokenKey, store.ReceiptKey, store.Receipt) {
	t.Helper()
	s, _, ps := threeBehindProxies(t)
	k := store.TokenKey{NAS: "leaf-01", Username: "alice"}
	rk := store.ReceiptKey{NAS: "leaf-01", Username: "alice", CredentialSHA256: sha256.Sum256([]byte("t1"))}
	now := time.Now()
	r := store.Receipt{Status: 1, CtxID: "01J", CredentialSHA256: rk.CredentialSHA256, FirstRedeemedAt: now,
		IdleExpiresAt: now.Add(time.Minute), RetainUntil: now.Add(time.Minute)}
	return s, ps, k, rk, r
}

func putToken(t *testing.T, s *Store, k store.TokenKey, id string) {
	t.Helper()
	if _, err := s.PutToken(context.Background(), k, store.Token{ID: id, Secret: []byte(id), Kind: store.KindLogin,
		ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
}

// A hedged redemption whose first copy applied and whose second answered
// first, compare failed, is this request's own success: it is never the
// ErrNotFound that authen reads as a replay.
func TestAHedgedRedemptionsOwnEarlierCopyIsNotAReplay(t *testing.T) {
	s, _, k, rk, r := redeemFixture(t)
	putToken(t, s, k, "t1")
	tokenKV = func(kv clientv3.KV) clientv3.KV { return dupKV{kv} }
	t.Cleanup(func() { tokenKV = func(kv clientv3.KV) clientv3.KV { return kv } })
	if err := s.RedeemAndReceipt(context.Background(), k, "t1", storetest.Rw(rk, r, "user:alice")); err != nil {
		t.Fatalf("the redemption whose own first copy applied: %v, want success", err)
	}
	if _, err := s.GetReceipt(context.Background(), rk); err != nil {
		t.Fatalf("the receipt: %v", err)
	}
	if c, _ := s.Candidates(context.Background(), k); len(c) != 0 {
		t.Fatal("the token is still there")
	}
}

// A different request's redemption that lost the compare is token_spent, as
// ever: another request's nonce in the receipt is not this one's.
func TestAnotherRequestsRedemptionOfASpentTokenIsStillRefused(t *testing.T) {
	s, _, k, rk, r := redeemFixture(t)
	putToken(t, s, k, "t1")
	ctx := context.Background()
	// B reads the token, then A redeems it, then B's transaction runs.
	identity := func(kv clientv3.KV) clientv3.KV { return kv }
	t.Cleanup(func() { tokenKV = identity })
	tokenKV = func(kv clientv3.KV) clientv3.KV {
		return raceKV{KV: kv, before: func() {
			tokenKV = identity
			if err := s.RedeemAndReceipt(ctx, k, "t1", storetest.Rw(rk, r, "user:alice")); err != nil {
				t.Errorf("request A: %v", err)
			}
		}}
	}
	if err := s.RedeemAndReceipt(ctx, k, "t1", storetest.Rw(rk, r, "user:alice")); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a second request's redemption of a token the first spent: %v, want ErrNotFound", err)
	}
}

type raceKV struct {
	clientv3.KV
	before func()
}

func (r raceKV) Txn(ctx context.Context) clientv3.Txn {
	return &raceTxn{Txn: r.KV.Txn(ctx), before: r.before}
}

type raceTxn struct {
	clientv3.Txn
	before func()
}

func (r *raceTxn) If(c ...clientv3.Cmp) clientv3.Txn  { r.Txn = r.Txn.If(c...); return r }
func (r *raceTxn) Then(o ...clientv3.Op) clientv3.Txn { r.Txn = r.Txn.Then(o...); return r }
func (r *raceTxn) Else(o ...clientv3.Op) clientv3.Txn { r.Txn = r.Txn.Else(o...); return r }
func (r *raceTxn) Commit() (*clientv3.TxnResponse, error) {
	r.before()
	return r.Txn.Commit()
}

// One member of three dark, a redemption's transaction sent to its stalled
// connection is sent again on the next, inside the call's own deadline: no
// login in a dozen fails (the matrix's one_member_dark).
func TestARedemptionSucceedsWhileOneMemberIsDark(t *testing.T) {
	s, ps, k, _, r := redeemFixture(t)
	for i := 0; i < 30; i++ { // warm round-robin, as the lift test does
		putToken(t, s, k, fmt.Sprintf("w%d", i))
	}
	const logins = 12             // inside keepalive's 10s + 2s, which would drop the dark connection
	for i := 0; i < logins; i++ { // minted while every member answers: the mint's Txn is not hedged
		putToken(t, s, k, fmt.Sprintf("r%d", i))
	}
	ps[2].Hang(true)
	failed := 0
	for i := 0; i < logins; i++ {
		id := fmt.Sprintf("r%d", i)
		for range i % 3 { // each connection meets the Txn in turn
			ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			if _, err := s.tok.Get(ctx, "rotate"); err != nil {
				t.Fatalf("a hedged read failed: %v", err)
			}
			cancel()
		}
		rk := store.ReceiptKey{NAS: k.NAS, Username: k.Username, CredentialSHA256: sha256.Sum256([]byte(id))}
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		start := time.Now()
		if err := s.RedeemAndReceipt(ctx, k, id, storetest.Rw(rk, r, "user:alice")); err != nil {
			failed++
			t.Logf("redemption %d: %v after %v", i, err, time.Since(start))
		}
		cancel()
	}
	if failed != 0 {
		t.Fatalf("%d of %d redemptions failed with one of three members dark", failed, logins)
	}
}

func swapFixture(t *testing.T) (*Store, []*etcdtest.Proxy, store.ContextKey) {
	t.Helper()
	s, _, ps := threeBehindProxies(t)
	return s, ps, store.ContextKey{NAS: "leaf-01", Username: "alice"}
}

func loginContext(id string) store.Context {
	return store.Context{CtxID: id, Principal: "user:alice", Username: "alice", PrivLvl: 1,
		AuthTime: time.Now(), SessionExpires: time.Now().Add(time.Hour)}
}

// The login's context swap, hedged: a copy whose first copy applied is this
// swap's own success, not the ErrConflict a lost race is.
func TestAHedgedContextSwapsOwnEarlierCopyIsNotAConflict(t *testing.T) {
	s, _, k := swapFixture(t)
	s.ctxKV = dupKV{s.ctxKV}
	if err := s.SwapLogin(context.Background(), k, 0, loginContext("c1"), time.Hour, store.LoginWrite{}); err != nil {
		t.Fatalf("the swap whose own first copy applied: %v, want success", err)
	}
	if c, err := s.GetContext(context.Background(), k); err != nil || c.CtxID != "c1" {
		t.Fatalf("context %+v %v", c, err)
	}
}

// Another login's swap that lost the compare is a conflict, as ever.
func TestAnotherLoginsSwapThatLostTheCompareIsStillAConflict(t *testing.T) {
	s, _, k := swapFixture(t)
	if err := s.SwapLogin(context.Background(), k, 0, loginContext("c1"), time.Hour, store.LoginWrite{}); err != nil {
		t.Fatal(err)
	}
	if err := s.SwapLogin(context.Background(), k, 0, loginContext("c2"), time.Hour, store.LoginWrite{}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("a swap from a stale read: %v, want ErrConflict", err)
	}
}

// One member dark: the swap's transaction on the stalled connection is sent
// again on the next.
func TestAContextSwapSucceedsWhileOneMemberIsDark(t *testing.T) {
	s, ps, k := swapFixture(t)
	ctx := context.Background()
	for i := 0; i < 30; i++ {
		if err := s.SwapLogin(ctx, k, 0, loginContext("w"), time.Hour, store.LoginWrite{}); err != nil && !errors.Is(err, store.ErrConflict) {
			t.Fatal(err)
		}
		s.DeleteContext(ctx, k)
	}
	ps[2].Hang(true)
	failed := 0
	const logins = 12
	for i := 0; i < logins; i++ {
		var rev uint64
		if cur, err := s.GetContext(ctx, k); err == nil {
			rev = cur.Rev
		}
		for range i % 3 {
			c, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
			s.tok.Get(c, "rotate")
			cancel()
		}
		c, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		if err := s.SwapLogin(c, k, rev, loginContext(fmt.Sprintf("c%d", i)), time.Hour, store.LoginWrite{}); err != nil {
			failed++
			t.Logf("swap %d: %v", i, err)
		}
		cancel()
	}
	if failed != 0 {
		t.Fatalf("%d of %d swaps failed with one of three members dark", failed, logins)
	}
}
