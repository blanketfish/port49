package storetest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/store"
)

// lifted are the properties the memory store's own tests held until plan
// 7d, each now run against every backend (Run).
var lifted = []struct {
	name string
	run  func(*testing.T, Backend)
}{
	{"TokenLifecycle", TokenLifecycle},
	{"RedeemIsAtomic", RedeemIsAtomic},
	{"ContextExpires", ContextExpires},
	{"SecretsAreNotAliased", SecretsAreNotAliased},
	{"DeleteContextRemovesIt", DeleteContextRemovesIt},
	{"RedeemByID", RedeemByID},
	{"ReceiptRetainedPastItsSlidingBound", ReceiptRetainedPastItsSlidingBound},
	{"FailReceiptMarksOnly", FailReceiptMarksOnly},
	{"DeleteReceiptsByPrincipal", DeleteReceiptsByPrincipal},
	{"TouchExtendsWithoutClobbering", TouchExtendsWithoutClobbering},
	{"AnnotateKeepsARacingRevocation", AnnotateKeepsARacingRevocation},
	{"SetRevokedAtMarksOneField", SetRevokedAtMarksOneField},
	{"RefreshMovesTheWindow", RefreshMovesTheWindow},
	{"ExtendingCarriesIndexEntries", ExtendingCarriesIndexEntries},
	{"ExtendingNeverShortensOrCreates", ExtendingNeverShortensOrCreates},
	{"ExtendingFollowsARotatedSid", ExtendingFollowsARotatedSid},
	{"RefreshWithoutCeiling", RefreshWithoutCeiling},
	{"AnnotateSetRules", AnnotateSetRules},
	{"AnnotateDoesNotEditAReadersSlice", AnnotateDoesNotEditAReadersSlice},
	{"BlobBump", BlobBump},
	{"Indexes", Indexes},
	{"Idempotency", Idempotency},
	{"SwapIsACompareAndSet", SwapIsACompareAndSet},
	{"EveryWriteMovesTheRevision", EveryWriteMovesTheRevision},
	{"ExtendingCarriesEveryJoinedCredential", ExtendingCarriesEveryJoinedCredential},
	{"SetPrivilegeIsRaiseOnly", SetPrivilegeIsRaiseOnly},
	{"BlankKeysAreNeverIndexed", BlankKeysAreNeverIndexed},
	{"UnindexRefClearsEveryKey", UnindexRefClearsEveryKey},
	{"SetContextPolicyBindsToTheRead", SetContextPolicyBindsToTheRead},
	{"TokenIndexExpiresWithItsLongestToken", TokenIndexExpiresWithItsLongestToken},
	{"RevocationMarkNeverExpires", RevocationMarkNeverExpires},
}

// Rw is the write RedeemAndReceipt takes: r under rk, indexed under
// principal for an hour.
func Rw(rk store.ReceiptKey, r store.Receipt, principal string) store.ReceiptWrite {
	return store.ReceiptWrite{Key: rk, Receipt: r, Principal: principal, IndexTTL: time.Hour}
}

func TokenLifecycle(t *testing.T, b Backend) {
	now := time.Unix(1_000, 0)
	s := b.New(t, func() time.Time { return now })
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
	if err := s.RedeemAndReceipt(ctx, k, "t1", Rw(rk, r, "user:alice")); err != nil {
		t.Fatal(err)
	}
	if err := s.RedeemAndReceipt(ctx, k, "t1", Rw(rk, r, "user:alice")); !errors.Is(err, store.ErrNotFound) {
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

func RedeemIsAtomic(t *testing.T, b Backend) {
	s := b.New(t, func() time.Time { return t0 })
	ctx := context.Background()
	k := store.TokenKey{NAS: "n", Username: "u"}
	s.PutToken(ctx, k, store.Token{ID: "x", Secret: []byte("x"), ExpiresAt: t0.Add(time.Minute)})
	rk := store.ReceiptKey{NAS: "n", Username: "u", CredentialSHA256: sha256.Sum256([]byte("x"))}
	var wg sync.WaitGroup
	wins := 0
	var mu sync.Mutex
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := store.Receipt{FirstRedeemedAt: t0, IdleExpiresAt: t0.Add(time.Minute), RetainUntil: t0.Add(time.Minute)}
			if err := s.RedeemAndReceipt(ctx, k, "x", Rw(rk, r, "user:u")); err == nil {
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

func ContextExpires(t *testing.T, b Backend) {
	now := time.Unix(1_000, 0)
	s := b.New(t, func() time.Time { return now })
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

func SecretsAreNotAliased(t *testing.T, b Backend) {
	now := time.Unix(1_000, 0)
	s := b.New(t, func() time.Time { return now })
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
		t.Fatal("secret was aliased: Candidates returned another secret")
	}

	// Mutate the returned secret
	c[0].Secret[0] = 'Y'

	// A second Candidates call should return the original secret unchanged
	c2, _ := s.Candidates(ctx, k)
	if len(c2) != 1 || !bytes.Equal(c2[0].Secret, []byte("mysecret")) {
		t.Fatal("returned secret was not copied: a caller's write reached the store")
	}
}

func DeleteContextRemovesIt(t *testing.T, b Backend) {
	now := time.Unix(1_000, 0)
	s := b.New(t, func() time.Time { return now })
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

func RedeemByID(t *testing.T, b Backend) {
	s := b.New(t, func() time.Time { return t0 })
	ctx := context.Background()
	k := store.TokenKey{NAS: "n", Username: "u"}
	s.PutToken(ctx, k, store.Token{ID: "t1", Secret: []byte("same"), ExpiresAt: t0.Add(time.Minute)})
	s.PutToken(ctx, k, store.Token{ID: "t2", Secret: []byte("same"), ExpiresAt: t0.Add(time.Minute)})
	rk := store.ReceiptKey{NAS: "n", Username: "u"}
	r := store.Receipt{FirstRedeemedAt: t0, IdleExpiresAt: t0.Add(time.Minute), RetainUntil: t0.Add(time.Hour)}
	if err := s.RedeemAndReceipt(ctx, k, "t2", Rw(rk, r, "user:u")); err != nil {
		t.Fatal(err)
	}
	c, _ := s.Candidates(ctx, k)
	if len(c) != 1 || c[0].ID != "t1" {
		t.Fatalf("%+v", c)
	}
	if err := s.RedeemAndReceipt(ctx, k, "gone", Rw(rk, r, "user:u")); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("redeeming an unknown id: %v", err)
	}
	if err := s.DeleteTokens(ctx, k); err != nil {
		t.Fatal(err)
	}
	if c, _ := s.Candidates(ctx, k); len(c) != 0 {
		t.Fatal("DeleteTokens left members")
	}
}

func ReceiptRetainedPastItsSlidingBound(t *testing.T, b Backend) {
	now := time.Unix(1000, 0)
	s := b.New(t, func() time.Time { return now })
	ctx := context.Background()
	k := store.TokenKey{NAS: "n", Username: "u"}
	rk := store.ReceiptKey{NAS: "n", Username: "u"}
	s.PutToken(ctx, k, store.Token{ID: "t", Secret: []byte("s"), ExpiresAt: now.Add(time.Hour)})
	s.RedeemAndReceipt(ctx, k, "t", Rw(rk, store.Receipt{
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
	// Both anchors, not just one: sliding RetainUntil on every re-presentation
	// would let a spent token's receipt answer replays indefinitely, which is
	// the unbounded window the three timestamps exist to remove.
	if got, _ := s.GetReceipt(ctx, rk); !got.IdleExpiresAt.Equal(now.Add(10*time.Minute)) ||
		!got.FirstRedeemedAt.Equal(time.Unix(1000, 0)) || !got.RetainUntil.Equal(time.Unix(1000, 0).Add(time.Hour)) {
		t.Fatalf("extend moved an anchor or missed the bound: %+v", got)
	}
	now = now.Add(2 * time.Hour) // past retention
	if _, err := s.GetReceipt(ctx, rk); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("receipt outlived RetainUntil")
	}
	if err := s.ExtendReceipt(ctx, rk, now.Add(time.Minute)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("extending a reclaimed receipt: %v", err)
	}
}

// FailReceipt marks the receipt refused and touches nothing else: not the
// sealed status it was written with, not either bound, not retention.
func FailReceiptMarksOnly(t *testing.T, b Backend) {
	now := time.Unix(1000, 0)
	s := b.New(t, func() time.Time { return now })
	ctx := context.Background()
	k := store.TokenKey{NAS: "n", Username: "u"}
	rk := store.ReceiptKey{NAS: "n", Username: "u"}
	s.PutToken(ctx, k, store.Token{ID: "t", Secret: []byte("s"), ExpiresAt: now.Add(time.Hour)})
	want := store.Receipt{Status: 1, CtxID: "ctx1", FirstRedeemedAt: now,
		IdleExpiresAt: now.Add(time.Minute), RetainUntil: now.Add(time.Hour)}
	s.RedeemAndReceipt(ctx, k, "t", Rw(rk, want, "user:u"))
	if err := s.FailReceipt(ctx, rk); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetReceipt(ctx, rk); !got.Failed || got.Status != want.Status || got.CtxID != want.CtxID ||
		!got.FirstRedeemedAt.Equal(want.FirstRedeemedAt) || !got.IdleExpiresAt.Equal(want.IdleExpiresAt) ||
		!got.RetainUntil.Equal(want.RetainUntil) {
		t.Fatalf("FailReceipt moved more than Failed: %+v", got)
	}
	now = now.Add(2 * time.Hour) // past retention
	if err := s.FailReceipt(ctx, rk); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("failing a reclaimed receipt: %v", err)
	}
}

func DeleteReceiptsByPrincipal(t *testing.T, b Backend) {
	now := time.Unix(1000, 0)
	s := b.New(t, func() time.Time { return now })
	ctx := context.Background()
	k := store.TokenKey{NAS: "n", Username: "u"}
	r := store.Receipt{FirstRedeemedAt: now, IdleExpiresAt: now.Add(time.Minute), RetainUntil: now.Add(time.Hour)}
	for i, id := range []string{"a", "b"} {
		s.PutToken(ctx, k, store.Token{ID: id, Secret: []byte(id), ExpiresAt: now.Add(time.Hour)})
		var h [32]byte
		h[0] = byte(i)
		s.RedeemAndReceipt(ctx, k, id, Rw(store.ReceiptKey{NAS: "n", Username: "u", CredentialSHA256: h}, r, "user:alice"))
	}
	s.PutToken(ctx, k, store.Token{ID: "c", Secret: []byte("c"), ExpiresAt: now.Add(time.Hour)})
	var other [32]byte
	other[0] = 9
	s.RedeemAndReceipt(ctx, k, "c", Rw(store.ReceiptKey{NAS: "n", Username: "u", CredentialSHA256: other}, r, "user:bob"))

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
func TouchExtendsWithoutClobbering(t *testing.T, b Backend) {
	now := time.Unix(1000, 0)
	s := b.New(t, func() time.Time { return now })
	ctx := context.Background()
	k := store.ContextKey{NAS: "n", Username: "u"}
	// The seeded stamp is stale on purpose: the write is an extension too, so
	// PutContext stamps the clock rather than storing what the caller passed.
	// A zero or stale value here is what makes Task 10's half-TTL rule extend
	// on every command, which is the store write that rule exists to avoid.
	s.PutContext(ctx, k, store.Context{CtxID: "c", Username: "u", LastTouchedAt: time.Unix(1, 0)}, time.Minute)
	if got, _ := s.GetContext(ctx, k); !got.LastTouchedAt.Equal(now) {
		t.Fatalf("PutContext must stamp LastTouchedAt, or Task 10's half-TTL rule reads a stale clock: %+v", got)
	}

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

// AnnotateContext is the third of the narrow setters, and store.Store's
// comment on TouchContext names accounting's annotation as one of the three
// writers that lose a revocation by re-putting a record they read earlier in
// the request. This is that scenario run: the revocation lands after
// accounting took its copy, and the annotation must not carry it away.
func AnnotateKeepsARacingRevocation(t *testing.T, b Backend) {
	now := time.Unix(1000, 0)
	s := b.New(t, func() time.Time { return now })
	ctx := context.Background()
	k := store.ContextKey{NAS: "n", Username: "u"}
	s.PutContext(ctx, k, store.Context{CtxID: "c", Username: "u", PrivLvl: 15}, time.Minute)

	// Accounting reads the context at the top of its request. It will not use
	// this copy to write, and that is the whole point of the setter.
	accountingsCopy, _ := s.GetContext(ctx, k)

	// A revocation lands while the accounting record is being spooled.
	c, _ := s.GetContext(ctx, k)
	c.RevokedAt = now
	s.PutContext(ctx, k, c, time.Minute)

	stamped := now
	now = now.Add(30 * time.Second)
	hash := store.HashDiscriminator("31050")
	if err := s.AnnotateContext(ctx, k, hash, store.AccountingStateOpen); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetContext(ctx, k)
	if err != nil {
		t.Fatal(err)
	}
	if got.RevokedAt.IsZero() {
		t.Fatalf("the annotation discarded the revocation — a re-put of %+v would: %+v", accountingsCopy, got)
	}
	if len(got.SessionDiscriminators) != 1 || got.SessionDiscriminators[0] != hash ||
		got.AccountingState != store.AccountingStateOpen {
		t.Fatalf("the annotation did not land: %+v", got)
	}
	if got.CtxID != "c" || got.PrivLvl != 15 {
		t.Fatalf("AnnotateContext wrote a field that is not its own: %+v", got)
	}
	// Accounting is not activity for the idle TTL: a device sending only STOPs
	// must not be able to hold a context open (spec §5.8).
	if !got.LastTouchedAt.Equal(stamped) {
		t.Fatalf("AnnotateContext must not stamp LastTouchedAt: %+v", got)
	}
	now = now.Add(31 * time.Second) // past the original expiry
	if _, err := s.GetContext(ctx, k); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("AnnotateContext extended the expiry; only TouchContext may")
	}
	if err := s.AnnotateContext(ctx, k, hash, ""); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("annotating an expired context must say so, not resurrect it: %v", err)
	}
}

// SetRevokedAt is the write every other setter's doc comment names as the one
// that must not be raced away, so it is held to the same rule itself: one
// field, no extension. Row 6 of spec §5.6 reclaims a revoked context on the
// idle TTL it was already on.
func SetRevokedAtMarksOneField(t *testing.T, b Backend) {
	now := time.Unix(1000, 0)
	s := b.New(t, func() time.Time { return now })
	ctx := context.Background()
	k := store.ContextKey{NAS: "n", Username: "u"}
	s.PutContext(ctx, k, store.Context{CtxID: "c", Username: "u", PrivLvl: 15,
		AccountingState: store.AccountingStateOpen}, time.Minute)

	stamped := now
	now = now.Add(30 * time.Second)
	if err := s.SetRevokedAt(ctx, k, now); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetContext(ctx, k)
	if err != nil || !got.RevokedAt.Equal(now) {
		t.Fatalf("the mark did not land: %+v %v", got, err)
	}
	if got.CtxID != "c" || got.PrivLvl != 15 || got.AccountingState != store.AccountingStateOpen {
		t.Fatalf("SetRevokedAt wrote a field that is not its own: %+v", got)
	}
	if !got.LastTouchedAt.Equal(stamped) {
		t.Fatalf("SetRevokedAt must not stamp LastTouchedAt: %+v", got)
	}
	now = now.Add(31 * time.Second) // past the original expiry
	if _, err := s.GetContext(ctx, k); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("SetRevokedAt extended the expiry; a revoked context must age out on its own clock")
	}
	if err := s.SetRevokedAt(ctx, k, now); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("revoking an expired context must say so, not resurrect it: %v", err)
	}
}

// RefreshContext is the broker's setter. The window it recomputes is read by
// the store from the record's own pair, not from a copy the broker took,
// and everything outside its closed list is left as whoever wrote it last left
// it — a revocation mark included, which is why the seed carries one.
func RefreshMovesTheWindow(t *testing.T, b Backend) {
	now := time.Unix(1000, 0)
	s := b.New(t, func() time.Time { return now })
	ctx := context.Background()
	k := store.ContextKey{NAS: "n", Username: "u"}
	s.PutContext(ctx, k, store.Context{CtxID: "c", Username: "u", PrivLvl: 15, BlobHash: "sha256:old",
		AuthTime: now.Add(-time.Hour), SessionExpires: now.Add(7 * time.Hour),
		RevokedAt: now, AccountingState: store.AccountingStateOpen}, time.Minute)

	now = now.Add(30 * time.Second)
	if err := s.RefreshContext(ctx, k, store.ContextRefresh{AuthTime: now, RefreshedAt: now, BlobHash: "sha256:new"}, time.Minute); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetContext(ctx, k)
	if err != nil {
		t.Fatal(err)
	}
	if !got.AuthTime.Equal(now) || !got.RefreshedAt.Equal(now) || got.BlobHash != "sha256:new" {
		t.Fatalf("the refresh did not land: %+v", got)
	}
	if !got.SessionExpires.Equal(now.Add(8 * time.Hour)) {
		t.Fatalf("the ceiling must move with auth_time and keep the window: %+v", got)
	}
	if got.RevokedAt.IsZero() {
		t.Fatalf("RefreshContext must leave a revocation in place; only §5.6 row 6 reclaims it: %+v", got)
	}
	if got.CtxID != "c" || got.PrivLvl != 15 || got.AccountingState != store.AccountingStateOpen {
		t.Fatalf("RefreshContext wrote a field that is not its own: %+v", got)
	}
	// A refresh is activity: unlike the annotation, it extends.
	if !got.LastTouchedAt.Equal(now) {
		t.Fatalf("RefreshContext must stamp LastTouchedAt: %+v", got)
	}
	now = now.Add(45 * time.Second) // past the original expiry, inside the extended one
	if _, err := s.GetContext(ctx, k); err != nil {
		t.Fatal("RefreshContext did not extend the expiry")
	}

	// An empty blob hash leaves the hash alone: a refresh that did not
	// recompute policy must not erase what the authorizer reads.
	if err := s.RefreshContext(ctx, k, store.ContextRefresh{AuthTime: now, RefreshedAt: now}, time.Minute); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetContext(ctx, k); got.BlobHash != "sha256:new" {
		t.Fatalf("an empty blob hash must leave the hash alone: %+v", got)
	}

	// A recorded proof lands with the agent that made it and survives a
	// refresh that names none.
	if err := s.RefreshContext(ctx, k, store.ContextRefresh{AuthTime: now, RefreshedAt: now,
		MFAMethod: "hardware_key_touch", MFAAt: now, MFAAgentSHA256: "ab12"}, time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := s.RefreshContext(ctx, k, store.ContextRefresh{AuthTime: now, RefreshedAt: now}, time.Minute); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetContext(ctx, k); got.Credential.MFAMethod != "hardware_key_touch" ||
		!got.Credential.MFAAt.Equal(now) || got.Credential.MFAAgentSHA256 != "ab12" {
		t.Fatalf("the recorded proof and its agent must persist: %+v", got.Credential)
	}

	now = now.Add(2 * time.Minute)
	if err := s.RefreshContext(ctx, k, store.ContextRefresh{AuthTime: now, RefreshedAt: now}, time.Minute); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("refreshing an expired context must say so, not resurrect it: %v", err)
	}
}

// Design §12: an index entry carries the context's TTL. The dangerous
// direction is a context outliving the entries that name it — an 8-to-16 hour
// session kept alive by activity, whose revocation by principal or by
// certificate then finds zero refs while the session is still authorizing.
// Every writer that moves a context's expiry must move its index entries with
// it.
func ExtendingCarriesIndexEntries(t *testing.T, b Backend) {
	now := time.Unix(1000, 0)
	s := b.New(t, func() time.Time { return now })
	ctx := context.Background()
	k := store.ContextKey{NAS: "n", Username: "u"}
	ref := store.ContextRef{NAS: "n", Username: "u"}
	certKey := store.CertKey("ca", "01")
	s.PutContext(ctx, k, store.Context{CtxID: "c", Username: "u",
		AuthTime: now, SessionExpires: now.Add(8 * time.Hour)}, time.Minute)
	if err := s.IndexContext(ctx, "user:alice", "s1", certKey, ref, time.Minute); err != nil {
		t.Fatal(err)
	}

	// Activity keeps the context alive well past the minute the indexes were
	// given at login.
	for i := 0; i < 4; i++ {
		now = now.Add(30 * time.Second)
		if err := s.TouchContext(ctx, k, time.Minute); err != nil {
			t.Fatalf("touch %d: %v", i, err)
		}
	}
	if _, err := s.GetContext(ctx, k); err != nil {
		t.Fatalf("the context should still be live: %v", err)
	}
	for _, tc := range []struct {
		name string
		get  func() ([]store.ContextRef, error)
	}{
		{"principal", func() ([]store.ContextRef, error) { return s.ContextsByPrincipal(ctx, "user:alice") }},
		{"sid", func() ([]store.ContextRef, error) { return s.ContextsBySid(ctx, "s1") }},
		{"cert", func() ([]store.ContextRef, error) { return s.ContextsByCert(ctx, certKey) }},
	} {
		refs, err := tc.get()
		if err != nil || len(refs) != 1 {
			t.Fatalf("%s index lost a live context: refs=%v err=%v", tc.name, refs, err)
		}
	}

	// RefreshContext extends too, and so does a re-put of an indexed ref
	// (spec §5.6 row 1's unconditional overwrite).
	now = now.Add(45 * time.Second)
	if err := s.RefreshContext(ctx, k, store.ContextRefresh{AuthTime: now, RefreshedAt: now}, time.Minute); err != nil {
		t.Fatal(err)
	}
	now = now.Add(45 * time.Second)
	if err := s.PutContext(ctx, k, store.Context{CtxID: "c2", Username: "u"}, time.Minute); err != nil {
		t.Fatal(err)
	}
	now = now.Add(30 * time.Second)
	if refs, _ := s.ContextsByPrincipal(ctx, "user:alice"); len(refs) != 1 {
		t.Fatalf("RefreshContext or PutContext left the principal index behind: %v", refs)
	}

	// An extension must not resurrect an index entry that was removed, and
	// the reverse record must not outlive what it points at.
	if err := s.UnindexContext(ctx, "user:alice", "s1", certKey, ref); err != nil {
		t.Fatal(err)
	}
	now = now.Add(20 * time.Second)
	if err := s.TouchContext(ctx, k, time.Minute); err != nil {
		t.Fatal(err)
	}
	if refs, _ := s.ContextsByPrincipal(ctx, "user:alice"); len(refs) != 0 {
		t.Fatalf("an extension resurrected an unindexed ref: %v", refs)
	}
}

// An extension's two guards on the index are the whole of what it may not
// do there, and neither is reachable down the everyday path: a ref that was
// fully unindexed is stopped before the store re-stamps anything at all, which
// is what ExtendingCarriesIndexEntries exercises. So the guards need the two
// states that do reach them, or a future reader simplifying the store's
// re-stamp has nothing to stop them. Both are about revocation's reach.
func ExtendingNeverShortensOrCreates(t *testing.T, b Backend) {
	now := time.Unix(1000, 0)
	s := b.New(t, func() time.Time { return now })
	ctx := context.Background()

	// Never shortens, matching PutBlob. The index was given an hour of reach;
	// the context lives and is extended in minutes. An extension that wrote its
	// own shorter expiry over the entry would pull revocation's reach in to the
	// context's TTL, and a revocation of alice a quarter of an hour later would
	// report zero contexts touched on a session that is still authorizing.
	kA := store.ContextKey{NAS: "n1", Username: "u"}
	refA := store.ContextRef{NAS: "n1", Username: "u"}
	s.PutContext(ctx, kA, store.Context{CtxID: "a", Username: "u"}, time.Minute)
	if err := s.IndexContext(ctx, "user:alice", "", "", refA, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := s.TouchContext(ctx, kA, time.Minute); err != nil {
		t.Fatal(err)
	}
	now = now.Add(15 * time.Minute)
	if refs, _ := s.ContextsByPrincipal(ctx, "user:alice"); len(refs) != 1 || refs[0] != refA {
		t.Fatalf("the extension shortened the index entry to the context's TTL: %v", refs)
	}

	// Never creates. bob holds two devices; the short entry expires and is
	// dropped on the next read, leaving the principal's set alive under the
	// other one — so the store re-stamps a key it still has for a ref it no
	// longer holds there, which is the state the everyday check cannot catch. An
	// extension that recreated the entry would put a swept ref back in front of
	// revocation, naming a context the index was done with.
	kShort := store.ContextKey{NAS: "n2", Username: "u"}
	refShort := store.ContextRef{NAS: "n2", Username: "u"}
	refLong := store.ContextRef{NAS: "n3", Username: "u"}
	s.PutContext(ctx, kShort, store.Context{CtxID: "s", Username: "u"}, time.Hour)
	if err := s.IndexContext(ctx, "user:bob", "", "", refShort, time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := s.IndexContext(ctx, "user:bob", "", "", refLong, time.Hour); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Minute)
	if refs, _ := s.ContextsByPrincipal(ctx, "user:bob"); len(refs) != 1 || refs[0] != refLong {
		t.Fatalf("the short entry should have aged out, leaving the long one: %v", refs)
	}
	if err := s.TouchContext(ctx, kShort, time.Hour); err != nil {
		t.Fatal(err)
	}
	if refs, _ := s.ContextsByPrincipal(ctx, "user:bob"); len(refs) != 1 || refs[0] != refLong {
		t.Fatalf("the extension resurrected a swept index entry: %v", refs)
	}
}

// A rotated sid moves the reverse record with it, or the next extension
// re-stamps the entry the rotation removed and lets the live one expire
// underneath it.
func ExtendingFollowsARotatedSid(t *testing.T, b Backend) {
	now := time.Unix(1000, 0)
	s := b.New(t, func() time.Time { return now })
	ctx := context.Background()
	k := store.ContextKey{NAS: "n", Username: "u"}
	ref := store.ContextRef{NAS: "n", Username: "u"}
	s.PutContext(ctx, k, store.Context{CtxID: "c", Username: "u"}, time.Minute)
	if err := s.IndexContext(ctx, "user:alice", "s1", "", ref, time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := s.ReindexSid(ctx, "s1", "s2", ref, time.Minute); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		now = now.Add(30 * time.Second)
		if err := s.TouchContext(ctx, k, time.Minute); err != nil {
			t.Fatal(err)
		}
	}
	if refs, _ := s.ContextsBySid(ctx, "s2"); len(refs) != 1 {
		t.Fatalf("the rotated sid index expired under a live context: %v", refs)
	}
}

// A context with no ceiling must not gain one: HasCeiling is false when either
// half of the pair is zero, and the refresh leaves SessionExpires alone.
func RefreshWithoutCeiling(t *testing.T, b Backend) {
	now := time.Unix(1000, 0)
	s := b.New(t, func() time.Time { return now })
	ctx := context.Background()
	k := store.ContextKey{NAS: "n", Username: "u"}
	s.PutContext(ctx, k, store.Context{CtxID: "c", Username: "u"}, time.Minute)
	if err := s.RefreshContext(ctx, k, store.ContextRefresh{AuthTime: now, RefreshedAt: now}, time.Minute); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetContext(ctx, k); !got.SessionExpires.IsZero() {
		t.Fatalf("a context with no ceiling must not gain one: %+v", got)
	}
}

// The set's two rules: an empty argument writes nothing, a repeat adds
// nothing, and the ninth entry evicts the oldest rather than the newest — the
// newest is the session still running (store.MaxSessionDiscriminators).
func AnnotateSetRules(t *testing.T, b Backend) {
	now := time.Unix(1000, 0)
	s := b.New(t, func() time.Time { return now })
	ctx := context.Background()
	k := store.ContextKey{NAS: "n", Username: "u"}
	s.PutContext(ctx, k, store.Context{CtxID: "c", Username: "u",
		AccountingState: store.AccountingStateClosing}, time.Minute)

	// An empty discriminator adds nothing; an empty state leaves the field
	// alone, which is how a STOP annotates without touching the set.
	if err := s.AnnotateContext(ctx, k, "", ""); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetContext(ctx, k); len(got.SessionDiscriminators) != 0 ||
		got.AccountingState != store.AccountingStateClosing {
		t.Fatalf("empty arguments must write nothing: %+v", got)
	}

	first := store.HashDiscriminator("s0")
	for i := 0; i < store.MaxSessionDiscriminators; i++ {
		if err := s.AnnotateContext(ctx, k, store.HashDiscriminator(fmt.Sprintf("s%d", i)), ""); err != nil {
			t.Fatal(err)
		}
	}
	// A device retransmitting a START must not consume a slot.
	if err := s.AnnotateContext(ctx, k, first, ""); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetContext(ctx, k)
	if len(got.SessionDiscriminators) != store.MaxSessionDiscriminators {
		t.Fatalf("a repeat added a duplicate: %+v", got.SessionDiscriminators)
	}
	if got.SessionDiscriminators[0] != first {
		t.Fatalf("a repeat reordered the set: %+v", got.SessionDiscriminators)
	}

	ninth := store.HashDiscriminator("s8")
	if err := s.AnnotateContext(ctx, k, ninth, ""); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetContext(ctx, k)
	if len(got.SessionDiscriminators) != store.MaxSessionDiscriminators {
		t.Fatalf("the cap did not hold: %d entries", len(got.SessionDiscriminators))
	}
	if got.SessionDiscriminators[0] == first {
		t.Fatalf("the cap evicted nothing: %+v", got.SessionDiscriminators)
	}
	if got.SessionDiscriminators[store.MaxSessionDiscriminators-1] != ninth {
		t.Fatalf("the cap evicted the newest instead of the oldest: %+v", got.SessionDiscriminators)
	}
}

// A caller that read the context before an annotation must not see its own
// slice change underneath it: the set is rewritten, never appended in place.
func AnnotateDoesNotEditAReadersSlice(t *testing.T, b Backend) {
	s := b.New(t, func() time.Time { return t0 })
	ctx := context.Background()
	k := store.ContextKey{NAS: "n", Username: "u"}
	s.PutContext(ctx, k, store.Context{CtxID: "c", Username: "u",
		SessionDiscriminators: []string{store.HashDiscriminator("a")}}, time.Minute)
	before, _ := s.GetContext(ctx, k)
	if err := s.AnnotateContext(ctx, k, store.HashDiscriminator("b"), ""); err != nil {
		t.Fatal(err)
	}
	if len(before.SessionDiscriminators) != 1 {
		t.Fatalf("the annotation grew a slice a caller was already holding: %+v", before.SessionDiscriminators)
	}
}

func BlobBump(t *testing.T, b Backend) {
	now := time.Unix(1000, 0)
	s := b.New(t, func() time.Time { return now })
	ctx := context.Background()
	s.PutBlob(ctx, "sha256:a", []byte("blob"), time.Minute)
	s.BumpBlob(ctx, "sha256:a", time.Hour)
	now = now.Add(30 * time.Minute)
	if b, err := s.GetBlob(ctx, "sha256:a"); err != nil || string(b) != "blob" {
		t.Fatalf("%s %v", b, err)
	}
	s.BumpBlob(ctx, "sha256:a", time.Minute) // must not shorten
	now = now.Add(20 * time.Minute)
	if _, err := s.GetBlob(ctx, "sha256:a"); err != nil {
		t.Fatal("bump shortened the blob's life")
	}
	now = now.Add(time.Hour)
	if _, err := s.GetBlob(ctx, "sha256:a"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("blob outlived its TTL")
	}
}

func Indexes(t *testing.T, b Backend) {
	now := time.Unix(1000, 0)
	s := b.New(t, func() time.Time { return now })
	ctx := context.Background()
	ref := store.ContextRef{NAS: "leaf-01", Username: "alice"}
	s.IndexContext(ctx, "user:alice", "sid1", store.CertKey("ca", "01"), ref, time.Hour)
	if r, _ := s.ContextsByPrincipal(ctx, "user:alice"); len(r) != 1 || r[0] != ref {
		t.Fatalf("%v", r)
	}
	if r, _ := s.ContextsBySid(ctx, "sid1"); len(r) != 1 {
		t.Fatalf("%v", r)
	}
	if r, _ := s.ContextsByCert(ctx, store.CertKey("ca", "01")); len(r) != 1 {
		t.Fatalf("%v", r)
	}
	if p, _ := s.ActivePrincipals(ctx); len(p) != 1 || p[0] != "user:alice" {
		t.Fatalf("%v", p)
	}
	s.ReindexSid(ctx, "sid1", "sid2", ref, time.Hour)
	if r, _ := s.ContextsBySid(ctx, "sid1"); len(r) != 0 {
		t.Fatal("old sid still indexed")
	}
	if r, _ := s.ContextsBySid(ctx, "sid2"); len(r) != 1 {
		t.Fatal("new sid not indexed")
	}
	s.UnindexContext(ctx, "user:alice", "sid2", store.CertKey("ca", "01"), ref)
	if p, _ := s.ActivePrincipals(ctx); len(p) != 0 {
		t.Fatalf("still active: %v", p)
	}
	s.IndexContext(ctx, "user:bob", "", "", ref, time.Minute)
	now = now.Add(2 * time.Minute)
	if p, _ := s.ActivePrincipals(ctx); len(p) != 0 {
		t.Fatal("expired index entry still active")
	}
}

func Idempotency(t *testing.T, b Backend) {
	s := b.New(t, func() time.Time { return t0 })
	ctx := context.Background()
	if _, ok, err := s.ReserveIdempotency(ctx, "user:alice", "k1", store.Idempotency{BodyHash: "h", Holder: "x",
		Pending: true, ExpiresAt: t0.Add(time.Minute)}); err != nil || !ok {
		t.Fatalf("%v %v", ok, err)
	}
	if err := s.CompleteIdempotency(ctx, "user:alice", "k1", "x", store.Idempotency{BodyHash: "h", Holder: "x",
		Response: []byte("resp"), ExpiresAt: t0.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if r, ok := Peek(t, s, t0, "user:alice", "k1"); !ok || string(r.Response) != "resp" {
		t.Fatalf("%+v %v", r, ok)
	}
	if _, ok := Peek(t, s, t0, "user:bob", "k1"); ok {
		t.Fatal("idempotency is per principal")
	}
}

// SwapContext is a compare-and-set, and each of its refusals is a state a
// read-merge-write can meet: someone wrote since the read, the record expired
// under it, or a record appeared where the read found none. Every refusal
// writes nothing.
func SwapIsACompareAndSet(t *testing.T, backend Backend) {
	now := time.Unix(1000, 0)
	s := backend.New(t, func() time.Time { return now })
	ctx := context.Background()
	k := store.ContextKey{NAS: "n", Username: "u"}

	// Absent: only rev 0 writes.
	if err := s.SwapContext(ctx, k, 7, store.Context{CtxID: "x", Username: "u"}, time.Minute); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("a revision for a record that does not exist must conflict: %v", err)
	}
	if err := s.SwapContext(ctx, k, 0, store.Context{CtxID: "a", Username: "u"}, time.Minute); err != nil {
		t.Fatal(err)
	}
	a, _ := s.GetContext(ctx, k)
	if a.CtxID != "a" || a.Rev == 0 {
		t.Fatalf("a written record must carry a revision: %+v", a)
	}

	// Present: rev 0 and a stale revision both conflict, and write nothing.
	if err := s.SwapContext(ctx, k, 0, store.Context{CtxID: "b", Username: "u"}, time.Minute); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("rev 0 over a live record must conflict: %v", err)
	}
	if err := s.SwapContext(ctx, k, a.Rev+1, store.Context{CtxID: "b", Username: "u"}, time.Minute); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("a revision the record does not carry must conflict: %v", err)
	}
	if got, _ := s.GetContext(ctx, k); got.CtxID != "a" || got.Rev != a.Rev {
		t.Fatalf("a refused swap wrote: %+v", got)
	}

	// The revision it was read at writes, stamps like PutContext, and moves it.
	now = now.Add(30 * time.Second)
	if err := s.SwapContext(ctx, k, a.Rev, store.Context{CtxID: "b", Username: "u", Rev: 12345}, time.Minute); err != nil {
		t.Fatal(err)
	}
	b, _ := s.GetContext(ctx, k)
	if b.CtxID != "b" || b.Rev == a.Rev || b.Rev == 12345 || !b.LastTouchedAt.Equal(now) {
		t.Fatalf("the swap must write, stamp LastTouchedAt, and take a fresh revision whatever the caller passed: %+v", b)
	}

	// Expired: the old revision conflicts; rev 0 writes.
	now = now.Add(2 * time.Minute)
	if err := s.SwapContext(ctx, k, b.Rev, store.Context{CtxID: "c", Username: "u"}, time.Minute); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("a revision of an expired record must conflict, not resurrect it: %v", err)
	}
	if err := s.SwapContext(ctx, k, 0, store.Context{CtxID: "c", Username: "u"}, time.Minute); err != nil {
		t.Fatalf("an expired record is absent: %v", err)
	}
	if c, _ := s.GetContext(ctx, k); c.CtxID != "c" || c.Rev <= b.Rev {
		t.Fatalf("a record written again must never repeat a revision: %+v (previous %d)", c, b.Rev)
	}
}

// Every writer moves the revision, the narrow setters included. A setter that
// did not would be a write a read-merge-write cannot see, and SetRevokedAt is
// the one that matters: a join that read before the revocation and swapped
// after it would put back a RevokedAt of zero (store.Context.Rev).
func EveryWriteMovesTheRevision(t *testing.T, b Backend) {
	now := time.Unix(1000, 0)
	s := b.New(t, func() time.Time { return now })
	ctx := context.Background()
	k := store.ContextKey{NAS: "n", Username: "u"}
	s.PutContext(ctx, k, store.Context{CtxID: "c", Username: "u", PrivLvl: 1,
		AuthTime: now, SessionExpires: now.Add(time.Hour)}, time.Hour)
	for _, w := range []struct {
		name  string
		write func() error
	}{
		{"PutContext", func() error { return s.PutContext(ctx, k, store.Context{CtxID: "c", Username: "u"}, time.Hour) }},
		{"TouchContext", func() error { return s.TouchContext(ctx, k, time.Hour) }},
		{"SetPrivilege", func() error { return s.SetPrivilege(ctx, k, 15) }},
		{"AnnotateContext", func() error { return s.AnnotateContext(ctx, k, "h", store.AccountingStateOpen) }},
		{"RefreshContext", func() error {
			return s.RefreshContext(ctx, k, store.ContextRefresh{AuthTime: now, RefreshedAt: now}, time.Hour)
		}},
		{"SetRevokedAt", func() error { return s.SetRevokedAt(ctx, k, now) }},
		{"SetContextPolicy", func() error {
			c, _ := s.GetContext(ctx, k)
			return s.SetContextPolicy(ctx, k, c.PolicyRev, store.ContextPolicy{BlobHash: "sha256:b", Enable: "none"})
		}},
	} {
		before, _ := s.GetContext(ctx, k)
		if err := w.write(); err != nil {
			t.Fatalf("%s: %v", w.name, err)
		}
		if err := s.SwapContext(ctx, k, before.Rev, before, time.Hour); !errors.Is(err, store.ErrConflict) {
			t.Fatalf("%s did not move the revision: a copy read before it swapped over it (%v)", w.name, err)
		}
	}
}

// A context a second login joined is indexed under both logins' credentials,
// and revocation by either has to reach it for as long as it lives (spec §5.6).
// The reverse record used to hold one sid and one cert, so the second
// IndexContext overwrote the first login's and every extension after it
// re-stamped only the newest: the first login's entries aged out at index_ttl
// under a context still authorizing, and a back-channel logout for that sid
// reported zero contexts.
func ExtendingCarriesEveryJoinedCredential(t *testing.T, b Backend) {
	now := time.Unix(1000, 0)
	s := b.New(t, func() time.Time { return now })
	ctx := context.Background()
	k := store.ContextKey{NAS: "n", Username: "u"}
	ref := store.ContextRef{NAS: "n", Username: "u"}
	certA, certB := store.CertKey("ca", "01"), store.CertKey("ca", "02")
	s.PutContext(ctx, k, store.Context{CtxID: "c", Username: "u"}, time.Minute)
	if err := s.IndexContext(ctx, "user:alice", "sA", certA, ref, time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := s.IndexContext(ctx, "user:alice", "sB", certB, ref, time.Minute); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		now = now.Add(30 * time.Second)
		if err := s.TouchContext(ctx, k, time.Minute); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name string
		get  func() ([]store.ContextRef, error)
	}{
		{"first login's sid", func() ([]store.ContextRef, error) { return s.ContextsBySid(ctx, "sA") }},
		{"second login's sid", func() ([]store.ContextRef, error) { return s.ContextsBySid(ctx, "sB") }},
		{"first login's cert", func() ([]store.ContextRef, error) { return s.ContextsByCert(ctx, certA) }},
		{"second login's cert", func() ([]store.ContextRef, error) { return s.ContextsByCert(ctx, certB) }},
	} {
		if refs, err := tc.get(); err != nil || len(refs) != 1 {
			t.Fatalf("%s aged out under a live context: %v %v", tc.name, refs, err)
		}
	}

	// Unindexing one login's keys leaves the other's reaching the context.
	if err := s.UnindexContext(ctx, "", "sA", certA, ref); err != nil {
		t.Fatal(err)
	}
	now = now.Add(45 * time.Second)
	if err := s.TouchContext(ctx, k, time.Minute); err != nil {
		t.Fatal(err)
	}
	now = now.Add(30 * time.Second)
	if refs, _ := s.ContextsBySid(ctx, "sA"); len(refs) != 0 {
		t.Fatalf("an extension resurrected an unindexed sid: %v", refs)
	}
	if refs, _ := s.ContextsBySid(ctx, "sB"); len(refs) != 1 {
		t.Fatalf("unindexing one login's sid lost the other's: %v", refs)
	}
	if refs, _ := s.ContextsByCert(ctx, certB); len(refs) != 1 {
		t.Fatalf("unindexing one login's cert lost the other's: %v", refs)
	}
}

// The stored level is the highest port49 has granted this user on this device,
// bounded by the ceiling (spec §5.3). A second window's session authorization
// granting a lower level must not take window A's enable away, and zero
// MaxPrivilege is no ceiling (store.Context.PrivilegeCeiling).
func SetPrivilegeIsRaiseOnly(t *testing.T, b Backend) {
	for _, tt := range []struct {
		name             string
		held, max, level uint8
		want             uint8
	}{
		{"a raise is recorded", 1, 15, 15, 15},
		{"a lower grant keeps the held level", 15, 15, 1, 15},
		{"a raise past the ceiling stops at it", 1, 7, 15, 7},
		{"no ceiling bounds nothing", 1, 0, 15, 15},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := b.New(t, func() time.Time { return t0 })
			ctx := context.Background()
			k := store.ContextKey{NAS: "n", Username: "u"}
			s.PutContext(ctx, k, store.Context{CtxID: "c", Username: "u", PrivLvl: tt.held, MaxPrivilege: tt.max}, time.Minute)
			if err := s.SetPrivilege(ctx, k, tt.level); err != nil {
				t.Fatal(err)
			}
			if got, _ := s.GetContext(ctx, k); got.PrivLvl != tt.want {
				t.Fatalf("level %d, want %d", got.PrivLvl, tt.want)
			}
		})
	}
}

// Ruling P8. An empty sid and a certificate key with no issuer or no serial
// name nobody: every certificate login has sid "", and every OIDC login has
// cert key "|". Indexed, each would be one bucket holding every such
// operator's context on the fleet, and a revocation that reached it would
// revoke them all. They are never indexed, and an extension has nothing of
// theirs to carry.
func BlankKeysAreNeverIndexed(t *testing.T, b Backend) {
	now := time.Unix(1000, 0)
	s := b.New(t, func() time.Time { return now })
	ctx := context.Background()
	for i, certKey := range []string{store.CertKey("", ""), store.CertKey("ca", ""), store.CertKey("", "01")} {
		ref := store.ContextRef{NAS: "leaf-01", Username: fmt.Sprintf("user%d", i)}
		if err := s.PutContext(ctx, store.ContextKey{NAS: ref.NAS, Username: ref.Username},
			store.Context{CtxID: ref.Username, Principal: "user:" + ref.Username}, time.Hour); err != nil {
			t.Fatal(err)
		}
		if err := s.IndexContext(ctx, "user:"+ref.Username, "", certKey, ref, time.Hour); err != nil {
			t.Fatal(err)
		}
		if err := s.TouchContext(ctx, store.ContextKey{NAS: ref.NAS, Username: ref.Username}, time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	for _, certKey := range []string{"|", "ca|", "|01"} {
		if r, _ := s.ContextsByCert(ctx, certKey); len(r) != 0 {
			t.Fatalf("cert key %q is indexed: %v", certKey, r)
		}
	}
	if r, _ := s.ContextsBySid(ctx, ""); len(r) != 0 {
		t.Fatalf("the empty sid is indexed: %v", r)
	}
	// The principal index is untouched by the skip.
	if r, _ := s.ContextsByPrincipal(ctx, "user:user0"); len(r) != 1 {
		t.Fatalf("principal index: %v", r)
	}
	// Unindexing with the same empty keys is a no-op, not an error, and does
	// not disturb what is indexed.
	if err := s.UnindexContext(ctx, "", "", "|", store.ContextRef{NAS: "leaf-01", Username: "user0"}); err != nil {
		t.Fatal(err)
	}
	if r, _ := s.ContextsByPrincipal(ctx, "user:user0"); len(r) != 1 {
		t.Fatalf("principal index after a blank unindex: %v", r)
	}
}

// Ruling P10. A context another principal replaces must stop answering every
// key the displaced context was indexed under — not only its last login's,
// which is all the replace can read off the record. UnindexRef clears every
// key recorded for the ref and leaves other refs under the same keys alone,
// and an extension afterwards does not bring any of them back.
func UnindexRefClearsEveryKey(t *testing.T, b Backend) {
	now := time.Unix(1000, 0)
	s := b.New(t, func() time.Time { return now })
	ctx := context.Background()
	ref := store.ContextRef{NAS: "leaf-01", Username: "alice"}
	other := store.ContextRef{NAS: "leaf-02", Username: "alice"}
	ck := store.ContextKey{NAS: ref.NAS, Username: ref.Username}
	if err := s.PutContext(ctx, ck, store.Context{CtxID: "ctxL", Principal: "user:alice"}, time.Hour); err != nil {
		t.Fatal(err)
	}
	// Two joined logins on leaf-01, and the first login's sid on leaf-02 too.
	s.IndexContext(ctx, "user:alice", "sid-1", store.CertKey("ca", "01"), ref, time.Hour)
	s.IndexContext(ctx, "user:alice", "sid-2", store.CertKey("ca", "02"), ref, time.Hour)
	s.IndexContext(ctx, "user:alice", "sid-1", "", other, time.Hour)
	if err := s.UnindexRef(ctx, ref); err != nil {
		t.Fatal(err)
	}
	now = now.Add(30 * time.Minute)
	if err := s.TouchContext(ctx, ck, 2*time.Hour); err != nil {
		t.Fatal(err)
	}
	for _, sid := range []string{"sid-1", "sid-2"} {
		if r, _ := s.ContextsBySid(ctx, sid); len(r) > 1 || (len(r) == 1 && r[0] != other) {
			t.Fatalf("%s still reaches the unindexed ref: %v", sid, r)
		}
	}
	for _, certKey := range []string{store.CertKey("ca", "01"), store.CertKey("ca", "02")} {
		if r, _ := s.ContextsByCert(ctx, certKey); len(r) != 0 {
			t.Fatalf("%s still reaches the unindexed ref: %v", certKey, r)
		}
	}
	if r, _ := s.ContextsByPrincipal(ctx, "user:alice"); len(r) != 1 || r[0] != other {
		t.Fatalf("the principal index must keep only the other ref: %v", r)
	}
	if r, _ := s.ContextsBySid(ctx, "sid-1"); len(r) != 1 || r[0] != other {
		t.Fatalf("another ref under the same sid must be left alone: %v", r)
	}
}

// SetContextPolicy is the refresher's setter (spec §5.1.3): a compare-and-set
// on the policy revision the refresher read, writing its closed list and
// nothing else. The seed carries a field of every other writer's — the annotation,
// the discriminators, the clocks — so a write that strayed shows.
func SetContextPolicyBindsToTheRead(t *testing.T, b Backend) {
	now := time.Unix(1000, 0)
	s := b.New(t, func() time.Time { return now })
	ctx := context.Background()
	k := store.ContextKey{NAS: "n", Username: "u"}
	seed := store.Context{CtxID: "c", Principal: "p", Username: "u", PrivLvl: 15, MaxPrivilege: 15,
		Enable: "token", BlobHash: "sha256:old", AuthTime: now.Add(-time.Hour),
		SessionExpires: now.Add(7 * time.Hour), RefreshedAt: now.Add(-time.Hour),
		SessionDiscriminators: []string{"h"}, AccountingState: store.AccountingStateOpen}
	s.PutContext(ctx, k, seed, time.Minute)
	read, _ := s.GetContext(ctx, k)

	// A replace that lands between the read and the refresh moves the policy
	// revision, and the refresh is refused with nothing written.
	s.PutContext(ctx, k, seed, time.Minute)
	if err := s.SetContextPolicy(ctx, k, read.PolicyRev, store.ContextPolicy{BlobHash: "sha256:new", Enable: "none"}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("a policy revision that moved must conflict: %v", err)
	}
	if got, _ := s.GetContext(ctx, k); got.BlobHash != "sha256:old" {
		t.Fatalf("a refused refresh wrote: %+v", got)
	}

	// Read again; accounting lands in between and does not make the refresh
	// lose. The three fields land, and a held level above the new ceiling
	// comes down to it.
	stamped := now
	now = now.Add(30 * time.Second)
	read, _ = s.GetContext(ctx, k)
	if err := s.AnnotateContext(ctx, k, "", store.AccountingStateClosing); err != nil {
		t.Fatal(err)
	}
	if err := s.SetContextPolicy(ctx, k, read.PolicyRev, store.ContextPolicy{BlobHash: "sha256:new", MaxPrivilege: 7, Enable: "none"}); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetContext(ctx, k)
	if err != nil {
		t.Fatal(err)
	}
	if got.BlobHash != "sha256:new" || got.MaxPrivilege != 7 || got.Enable != "none" || got.PrivLvl != 7 {
		t.Fatalf("the refresh did not land, or did not clamp: %+v", got)
	}
	if got.CtxID != "c" || got.Principal != "p" || !got.AuthTime.Equal(seed.AuthTime) ||
		!got.SessionExpires.Equal(seed.SessionExpires) || !got.RefreshedAt.Equal(seed.RefreshedAt) ||
		!got.RevokedAt.IsZero() || len(got.SessionDiscriminators) != 1 || got.AccountingState != store.AccountingStateClosing {
		t.Fatalf("SetContextPolicy wrote a field that is not its own: %+v", got)
	}
	// Not activity: the expiry and its stamp stay where they were.
	if !got.LastTouchedAt.Equal(stamped) {
		t.Fatalf("SetContextPolicy must not stamp LastTouchedAt: %+v", got)
	}

	// A ceiling lifted does not raise the held level: a level is granted at a
	// session authorization or an enable, never by a refresh.
	if err := s.SetContextPolicy(ctx, k, got.PolicyRev, store.ContextPolicy{BlobHash: "sha256:wide", Enable: "token"}); err != nil {
		t.Fatal(err)
	}
	if got, _ = s.GetContext(ctx, k); got.PrivLvl != 7 || got.MaxPrivilege != 0 {
		t.Fatalf("a lifted ceiling must leave the level alone: %+v", got)
	}

	// A revocation writes RevokedAt and nothing else.
	if err := s.SetContextPolicy(ctx, k, got.PolicyRev, store.ContextPolicy{RevokedAt: now, BlobHash: "sha256:ignored",
		MaxPrivilege: 1, Enable: "auto"}); err != nil {
		t.Fatal(err)
	}
	if got, _ = s.GetContext(ctx, k); !got.RevokedAt.Equal(now) || got.BlobHash != "sha256:wide" ||
		got.MaxPrivilege != 0 || got.Enable != "token" || got.PrivLvl != 7 {
		t.Fatalf("a revoking refresh must write the mark and only the mark: %+v", got)
	}

	now = now.Add(31 * time.Second) // past the original expiry: nothing extended it
	if err := s.SetContextPolicy(ctx, k, got.PolicyRev, store.ContextPolicy{BlobHash: "sha256:x"}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("an expired context must be ErrNotFound, not resurrected: %v", err)
	}
}

// An index entry lives as long as the longest token written under it, and
// then drops out: a principal's keys do not accumulate for good.
func TokenIndexExpiresWithItsLongestToken(t *testing.T, b Backend) {
	now := time.Unix(1_757_041_495, 0)
	s := b.New(t, func() time.Time { return now })
	ctx := context.Background()
	k := store.TokenKey{NAS: "leaf-01", Username: "alice"}
	_ = s.IndexToken(ctx, "user:alice", "", k, 10*time.Minute)
	_ = s.IndexToken(ctx, "user:alice", "", k, time.Minute) // never shortens it
	now = now.Add(5 * time.Minute)
	if got, _ := s.TokensByPrincipal(ctx, "user:alice"); len(got) != 1 {
		t.Fatalf("at 5m: %v", got)
	}
	now = now.Add(5 * time.Minute)
	if got, _ := s.TokensByPrincipal(ctx, "user:alice"); len(got) != 0 {
		t.Fatalf("at 10m: %v", got)
	}
}

// A mark does not expire however far the clock moves: only a delete lifts
// it (spec §13, decision 32).
func RevocationMarkNeverExpires(t *testing.T, b Backend) {
	now := time.Unix(1_757_041_495, 0)
	s := b.New(t, func() time.Time { return now })
	ctx := context.Background()
	if err := s.PutRevocation(ctx, store.Revocation{Kind: store.RevocationPrincipal, Key: "user:alice", At: now}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 1024; i++ { // through a sweep, on a store that sweeps
		_ = s.PutBlob(ctx, fmt.Sprintf("b%d", i), []byte("x"), time.Second)
	}
	now = now.Add(10 * 365 * 24 * time.Hour)
	if _, err := s.GetRevocation(ctx, store.RevocationPrincipal, "user:alice"); err != nil {
		t.Fatalf("a mark expired: %v", err)
	}
}
