package memory

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/storetest"
)

// The context key is (nas, username): two usernames on one device are two
// slots, and one username on two devices is two slots.
func TestContextKeySeparatesUsersAndDevices(t *testing.T) {
	now := time.Unix(1_000, 0)
	s := New(func() time.Time { return now })
	ctx := context.Background()

	for _, tc := range []struct{ nas, user, id string }{
		{"leaf-01", "alice", "c1"}, {"leaf-01", "bob", "c2"}, {"leaf-02", "alice", "c3"},
	} {
		if err := s.PutContext(ctx, store.ContextKey{NAS: tc.nas, Username: tc.user},
			store.Context{CtxID: tc.id, Username: tc.user, Port: "vty4"}, time.Minute); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct{ nas, user, id string }{
		{"leaf-01", "alice", "c1"}, {"leaf-01", "bob", "c2"}, {"leaf-02", "alice", "c3"},
	} {
		c, err := s.GetContext(ctx, store.ContextKey{NAS: tc.nas, Username: tc.user})
		if err != nil || c.CtxID != tc.id {
			t.Fatalf("(%s,%s): %+v %v", tc.nas, tc.user, c, err)
		}
	}
	// Deleting one leaves the others alone.
	if err := s.DeleteContext(ctx, store.ContextKey{NAS: "leaf-01", Username: "bob"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetContext(ctx, store.ContextKey{NAS: "leaf-01", Username: "bob"}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("%v", err)
	}
	if _, err := s.GetContext(ctx, store.ContextKey{NAS: "leaf-01", Username: "alice"}); err != nil {
		t.Fatalf("alice's context went with bob's: %v", err)
	}
}

// The receipt key carries the credential hash and the token kind, so a
// different credential is a miss rather than a collision — and so is the same
// credential presented at enable, which is a different question than the login
// this receipt answered.
func TestReceiptKeyCarriesTheCredentialHash(t *testing.T) {
	now := time.Unix(1_000, 0)
	s := New(func() time.Time { return now })
	ctx := context.Background()

	k := store.TokenKey{NAS: "leaf-01", Username: "alice"}
	if _, err := s.PutToken(ctx, k, store.Token{ID: "t1", Secret: []byte("p49_tok1"), Kind: store.KindLogin, ExpiresAt: now.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	h1 := sha256.Sum256([]byte("p49_tok1"))
	rk := store.ReceiptKey{NAS: "leaf-01", Username: "alice", Kind: store.KindLogin, CredentialSHA256: h1}
	r := store.Receipt{CredentialSHA256: h1, CtxID: "ctx1", FirstRedeemedAt: now, IdleExpiresAt: now.Add(time.Minute), RetainUntil: now.Add(time.Minute)}
	if err := s.RedeemAndReceipt(ctx, k, "t1", storetest.Rw(rk, r, "user:alice@example.com")); err != nil {
		t.Fatal(err)
	}
	if got, err := s.GetReceipt(ctx, rk); err != nil || got.CtxID != "ctx1" {
		t.Fatalf("%+v %v", got, err)
	}
	h2 := sha256.Sum256([]byte("p49_tok2"))
	for _, miss := range []store.ReceiptKey{
		{NAS: "leaf-01", Username: "alice", Kind: store.KindLogin, CredentialSHA256: h2},
		{NAS: "leaf-01", Username: "bob", Kind: store.KindLogin, CredentialSHA256: h1},
		{NAS: "leaf-02", Username: "alice", Kind: store.KindLogin, CredentialSHA256: h1},
		// The same credential on the same device, asked as an enable question.
		{NAS: "leaf-01", Username: "alice", Kind: store.KindEnable, CredentialSHA256: h1},
	} {
		if _, err := s.GetReceipt(ctx, miss); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("%+v resolved to a receipt: %v", miss, err)
		}
	}
}
