package storetest

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/store"
)

// The read-modify-writes of the token family, raced. On memory each is one
// critical section; on a network backend each is a read and a write bound
// to the revision read, and a backend that drops that bind loses one of two
// racing writes in about half the rounds (plan 7d Task 5 review I1). Each
// runs the backend's RaceRounds.

// race runs fs at once and waits for all of them.
func race(fs ...func()) {
	start := make(chan struct{})
	var wg sync.WaitGroup
	for _, f := range fs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			f()
		}()
	}
	close(start)
	wg.Wait()
}

// IndexTokenKeepsTheLongestUnderARace is IndexToken's "keeping the later
// expiry", raced: two mints under one key, an hour and two hours out,
// leave the entry naming the key until the later. A shorter write landing
// last would drop the entry while the longer token lives, and a revocation
// by that principal or certificate would miss the token: revocation
// failing open.
func IndexTokenKeepsTheLongestUnderARace(t *testing.T, b Backend) {
	k := store.TokenKey{NAS: "leaf-01", Username: "svc"}
	const alice = "spiffe://example.com/alice"
	cert := store.CertKey("CN=Corp CA", "0a")
	for round := 0; round < b.raceRounds(); round++ {
		var mu sync.Mutex
		now := t0
		s := b.New(t, func() time.Time { mu.Lock(); defer mu.Unlock(); return now })
		ctx := context.Background()
		var errs [2]error
		race(func() { errs[0] = s.IndexToken(ctx, alice, cert, k, time.Hour) },
			func() { errs[1] = s.IndexToken(ctx, alice, cert, k, 2*time.Hour) })
		if err := errors.Join(errs[:]...); err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
		mu.Lock()
		now = t0.Add(90 * time.Minute)
		mu.Unlock()
		byP, err1 := s.TokensByPrincipal(ctx, alice)
		byC, err2 := s.TokensByCert(ctx, cert)
		if err := errors.Join(err1, err2); err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
		if len(byP) != 1 || len(byC) != 1 {
			t.Fatalf("round %d: at 90m the two-hour entry is gone: by principal %v, by cert %v", round, byP, byC)
		}
	}
}

// FailReceiptSurvivesARacingExtend is FailReceipt and ExtendReceipt raced
// on one receipt: both writes stand. An extension that read before the
// fail and wrote after it would put the receipt back unfailed, and a
// retransmission of the refused login would replay its PASS.
func FailReceiptSurvivesARacingExtend(t *testing.T, b Backend) {
	k := store.TokenKey{NAS: "leaf-01", Username: "svc"}
	rk := store.ReceiptKey{NAS: k.NAS, Username: k.Username, Kind: store.KindLogin, CredentialSHA256: [32]byte{1}}
	for round := 0; round < b.raceRounds(); round++ {
		s := b.New(t, func() time.Time { return t0 })
		ctx := context.Background()
		if _, err := s.PutToken(ctx, k, store.Token{ID: "a", Secret: []byte("a"), Kind: store.KindLogin,
			ExpiresAt: t0.Add(time.Minute)}); err != nil {
			t.Fatal(err)
		}
		r := store.Receipt{Status: 1, CtxID: "ctx1", FirstRedeemedAt: t0, IdleExpiresAt: t0.Add(time.Minute),
			RetainUntil: t0.Add(time.Hour)}
		if err := s.RedeemAndReceipt(ctx, k, "a", Rw(rk, r, "user:svc")); err != nil {
			t.Fatal(err)
		}
		var errs [2]error
		race(func() { errs[0] = s.FailReceipt(ctx, rk) },
			func() { errs[1] = s.ExtendReceipt(ctx, rk, t0.Add(10*time.Minute)) })
		if err := errors.Join(errs[:]...); err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
		got, err := s.GetReceipt(ctx, rk)
		if err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
		if !got.Failed || !got.IdleExpiresAt.Equal(t0.Add(10*time.Minute)) {
			t.Fatalf("round %d: a racing write was lost: failed %v, idle bound %v", round, got.Failed, got.IdleExpiresAt)
		}
	}
}

// RedeemOrDeleteNotBoth is DeleteToken and RedeemAndReceipt raced on one
// token: of a redeemer and four deleters, exactly one takes it and every
// other is ErrNotFound. A delete that is not bound to the token it read
// reports success for a token a redeemer already spent, and a principal
// ending its sessions is told a token was ended that had in fact logged
// in. Four deleters, not one, so a round has many pairs that can both read
// before either writes.
func RedeemOrDeleteNotBoth(t *testing.T, b Backend) {
	k := store.TokenKey{NAS: "leaf-01", Username: "svc"}
	w := Rw(store.ReceiptKey{NAS: k.NAS, Username: k.Username, Kind: store.KindLogin, CredentialSHA256: [32]byte{1}},
		store.Receipt{FirstRedeemedAt: t0, IdleExpiresAt: t0.Add(time.Minute), RetainUntil: t0.Add(time.Hour)}, "user:svc")
	for round := 0; round < b.raceRounds(); round++ {
		s := b.New(t, func() time.Time { return t0 })
		ctx := context.Background()
		if _, err := s.PutToken(ctx, k, store.Token{ID: "a", Secret: []byte("a"), Kind: store.KindLogin,
			ExpiresAt: t0.Add(time.Minute)}); err != nil {
			t.Fatal(err)
		}
		errs := make([]error, 5)
		fs := []func(){func() { errs[0] = s.RedeemAndReceipt(ctx, k, "a", w) }}
		for i := 1; i < len(errs); i++ {
			fs = append(fs, func() { errs[i] = s.DeleteToken(ctx, k, "a") })
		}
		race(fs...)
		took := 0
		for _, err := range errs {
			switch {
			case err == nil:
				took++
			case !errors.Is(err, store.ErrNotFound):
				t.Fatalf("round %d: %v", round, err)
			}
		}
		if took != 1 {
			t.Fatalf("round %d: redeem %v, deletes %v; want exactly one nil and the rest ErrNotFound",
				round, errs[0], errs[1:])
		}
	}
}
