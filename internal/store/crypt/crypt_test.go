package crypt

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/memory"
)

func keys() Keys {
	var a, b [32]byte
	copy(a[:], "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	copy(b[:], "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	return Keys{Current: Key{ID: "v2", Bytes: a}, Previous: &Key{ID: "v1", Bytes: b}}
}

func TestSealOpenRoundTripAndRotation(t *testing.T) {
	k := keys()
	sealed, err := k.Seal([]byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte("secret")) {
		t.Fatal("plaintext visible")
	}
	if got, _ := k.Open(sealed); string(got) != "secret" {
		t.Fatalf("%q", got)
	}
	old := Keys{Current: *k.Previous}
	s2, _ := old.Seal([]byte("old"))
	if got, err := k.Open(s2); err != nil || string(got) != "old" {
		t.Fatalf("sealed under the previous key: %q %v", got, err)
	}
	var c [32]byte
	copy(c[:], "cccccccccccccccccccccccccccccccc")
	s3, _ := Keys{Current: Key{ID: "v0", Bytes: c}}.Seal([]byte("gone"))
	if _, err := k.Open(s3); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("retired key: %v", err)
	}
	sealed[len(sealed)-1] ^= 1
	if _, err := k.Open(sealed); err == nil {
		t.Fatal("tampered ciphertext opened")
	}

	// A fresh nonce on every seal, so identical plaintext never produces
	// identical bytes. Without this assertion a refactor that derived the nonce
	// from the plaintext — reusing it across every record holding the same
	// secret, which is the one thing GCM must never do — passes every other
	// check in this file.
	n1, err := k.Seal([]byte("same"))
	if err != nil {
		t.Fatal(err)
	}
	n2, err := k.Seal([]byte("same"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(n1, n2) {
		t.Fatal("identical ciphertext for identical plaintext: the nonce is not fresh")
	}

	// The key id is the AAD, so a record cannot be re-labelled into another
	// key's generation. Both ids here carry the same key bytes deliberately:
	// the bytes cannot be what rejects the re-labelled record, so only the AAD
	// can, and dropping the AAD argument fails this and nothing else.
	twin := Keys{Current: Key{ID: "v2", Bytes: k.Current.Bytes}, Previous: &Key{ID: "v1", Bytes: k.Current.Bytes}}
	relabel, err := Keys{Current: *twin.Previous}.Seal([]byte("v1 payload"))
	if err != nil {
		t.Fatal(err)
	}
	relabel[1], relabel[2] = 'v', '2' // "v1" -> "v2", same length, same key bytes
	if _, err := twin.Open(relabel); err == nil {
		t.Fatal("a record re-labelled with another key's id opened: the id is not bound as AAD")
	}
}

func TestWrappedStoreHoldsNoPlaintext(t *testing.T) {
	inner := memory.New(time.Now)
	s := Wrap(inner, keys(), nil)
	ctx := context.Background()
	k := store.TokenKey{NAS: "leaf-01", Username: "alice"}
	tok := store.Token{ID: "t1", Secret: []byte("p49_secret"), Kind: store.KindLogin,
		Principal: "user:alice@example.com", Username: "alice",
		Credential: store.Credential{Method: "oidc", Sub: "a7f3"}, ExpiresAt: time.Now().Add(time.Minute), BlobHash: "sha256:x"}
	if _, err := s.PutToken(ctx, k, tok); err != nil {
		t.Fatal(err)
	}
	raw, _ := inner.Candidates(ctx, k)
	if len(raw) != 1 || raw[0].Secret != nil || raw[0].Principal != "" || raw[0].Credential.Sub != "" || raw[0].Sealed == nil {
		t.Fatalf("inner holds plaintext: %+v", raw[0])
	}
	if raw[0].ID != "t1" || raw[0].Kind != store.KindLogin || raw[0].BlobHash != "sha256:x" || raw[0].ExpiresAt.IsZero() {
		t.Fatalf("keying fields must stay plaintext: %+v", raw[0])
	}
	got, _ := s.Candidates(ctx, k)
	if len(got) != 1 || string(got[0].Secret) != "p49_secret" || got[0].Principal != "user:alice@example.com" || got[0].Sealed != nil {
		t.Fatalf("wrapped read: %+v", got[0])
	}

	var h [32]byte
	copy(h[:], "hash")
	rk := store.ReceiptKey{NAS: "leaf-01", Username: "alice", CredentialSHA256: h}
	now := time.Now()
	w := store.ReceiptWrite{Key: rk, Principal: "user:alice@example.com", IndexTTL: time.Hour,
		Receipt: store.Receipt{CredentialSHA256: h, Status: 1, CtxID: "ctx1",
			FirstRedeemedAt: now, IdleExpiresAt: now.Add(time.Minute), RetainUntil: now.Add(time.Hour)}}
	if err := s.RedeemAndReceipt(ctx, k, "t1", w); err != nil {
		t.Fatal(err)
	}
	inr, _ := inner.GetReceipt(ctx, rk)
	if inr.CtxID != "" || inr.CredentialSHA256 != ([32]byte{}) || inr.Sealed == nil || inr.FirstRedeemedAt.IsZero() {
		t.Fatalf("receipt plaintext: %+v", inr)
	}
	if r, _ := s.GetReceipt(ctx, rk); r.CtxID != "ctx1" || r.CredentialSHA256 != h || !r.IdleExpiresAt.Equal(w.Receipt.IdleExpiresAt) {
		t.Fatalf("receipt read: %+v", r)
	}
	// The principal index is written by the inner store, in the clear, and is
	// what revocation walks (the ruling in this task).
	if n, _ := inner.DeleteReceiptsByPrincipal(ctx, "user:alice@example.com"); n != 1 {
		t.Fatalf("receipt not indexed by principal in the clear: %d", n)
	}

	ck := store.ContextKey{NAS: "leaf-01", Username: "alice"}
	if err := s.PutContext(ctx, ck, store.Context{CtxID: "ctx1", Principal: "user:alice@example.com", Username: "alice",
		Port: "ssh", RemAddr: "198.51.100.4", PrivLvl: 15, SessionDiscriminator: "14656"}, time.Hour); err != nil {
		t.Fatal(err)
	}
	if c, _ := inner.GetContext(ctx, ck); c.Principal != "" || c.RemAddr != "" || c.SessionDiscriminator != "" || c.PrivLvl != 15 {
		t.Fatalf("context plaintext: %+v", c)
	}
	if c, _ := s.GetContext(ctx, ck); c.Principal != "user:alice@example.com" || c.RemAddr != "198.51.100.4" || c.SessionDiscriminator != "14656" {
		t.Fatalf("context read: %+v", c)
	}

	// SetPrivilege and TouchContext pass straight through: both write only
	// plaintext bookkeeping, so the inner store changes a record it cannot
	// read, and the sealed fields it never touched still open afterwards.
	if err := s.SetPrivilege(ctx, ck, 1); err != nil {
		t.Fatal(err)
	}
	if err := s.TouchContext(ctx, ck, time.Hour); err != nil {
		t.Fatal(err)
	}
	if c, _ := inner.GetContext(ctx, ck); c.PrivLvl != 1 {
		t.Fatalf("SetPrivilege must reach the inner store in the clear: %+v", c)
	}
	if c, _ := s.GetContext(ctx, ck); c.PrivLvl != 1 || c.Principal != "user:alice@example.com" || c.SessionDiscriminator != "14656" {
		t.Fatalf("a narrow write must leave the sealed fields readable: %+v", c)
	}

	if err := s.PutIdempotency(ctx, "user:alice", "k", store.Idempotency{BodyHash: "b", Response: []byte(`{"login":"p49_x"}`), ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if r, _ := inner.GetIdempotency(ctx, "user:alice", "k"); r.Response != nil || r.BodyHash != "b" {
		t.Fatalf("idempotency plaintext: %+v", r)
	}
	if r, _ := s.GetIdempotency(ctx, "user:alice", "k"); string(r.Response) != `{"login":"p49_x"}` {
		t.Fatalf("idempotency read: %+v", r)
	}

	if err := s.PutBlob(ctx, "sha256:x", []byte("blob"), time.Minute); err != nil {
		t.Fatal(err)
	}
	if b, _ := inner.GetBlob(ctx, "sha256:x"); string(b) != "blob" {
		t.Fatal("blobs are not encrypted; they hold no identity")
	}
}

// A token sealed under a key that has since been retired is unreadable, and
// therefore unredeemable. It must not be returned as a candidate with a zero
// secret, which would match a zero-length credential.
func TestTokenUnderRetiredKeyIsDroppedNotReturned(t *testing.T) {
	inner := memory.New(time.Now)
	var c [32]byte
	copy(c[:], "cccccccccccccccccccccccccccccccc")
	retired := Wrap(inner, Keys{Current: Key{ID: "v0", Bytes: c}}, nil)
	ctx := context.Background()
	k := store.TokenKey{NAS: "leaf-01", Username: "alice"}
	if _, err := retired.PutToken(ctx, k, store.Token{ID: "t", Secret: []byte("s"), Kind: store.KindLogin, ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	// Without this the test passes vacuously: a write that failed leaves an
	// empty inner store, and an empty candidate set is what the assertion
	// below is looking for.
	if raw, err := inner.Candidates(ctx, k); err != nil || len(raw) != 1 {
		t.Fatalf("the inner store must hold the sealed token: %+v %v", raw, err)
	}

	failures := prometheus.NewCounterVec(prometheus.CounterOpts{Name: "t"}, []string{"record"})
	got, err := Wrap(inner, keys(), failures).Candidates(ctx, k)
	if err != nil || len(got) != 0 {
		t.Fatalf("%+v %v", got, err)
	}
	// The dropped token is invisible in the return value — this is the one read
	// that deliberately does not fail the call — so the counter is the only
	// signal an operator gets that a key, not an expiry, emptied this set.
	if n := testutil.ToFloat64(failures.WithLabelValues("token")); n != 1 {
		t.Fatalf(`crypt_open_failures_total{record="token"} = %v, want 1`, n)
	}
}

// A record that will not open is not an absent record, and the difference is
// the whole value of the rotation window. Reported as ErrNotFound, an operator
// who retires the previous key one rotation early sees every session on the
// fleet answered "this session was not authenticated by port49", every
// redemption `token_not_found`, and store_ops{outcome="not_found"} climbing —
// exactly what an expired session looks like, with nothing anywhere naming the
// key they just changed.
func TestUnopenableRecordIsNotReportedAsMissing(t *testing.T) {
	inner := memory.New(time.Now)
	ctx := context.Background()
	ck := store.ContextKey{NAS: "leaf-01", Username: "alice"}
	var c [32]byte
	copy(c[:], "cccccccccccccccccccccccccccccccc")
	Wrap(inner, Keys{Current: Key{ID: "v0", Bytes: c}}, nil).PutContext(ctx, ck,
		store.Context{CtxID: "ctx1", Username: "alice"}, time.Hour)

	failures := prometheus.NewCounterVec(prometheus.CounterOpts{Name: "t"}, []string{"record"})
	_, err := Wrap(inner, keys(), failures).GetContext(ctx, ck)
	if err == nil || errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a record sealed under a retired key must not read as absent: %v", err)
	}
	if !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("%v", err)
	}
	if got := testutil.ToFloat64(failures.WithLabelValues("context")); got != 1 {
		t.Fatalf("crypt_open_failures_total{record=\"context\"} = %v", got)
	}
}
