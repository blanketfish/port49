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
	"github.com/rhwendt/port49/internal/store/storetest"
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
	// FailReceipt writes a plaintext mark and reseals nothing: it works under
	// any key, and the sealed status stays what the login sent.
	if err := s.FailReceipt(ctx, rk); err != nil {
		t.Fatal(err)
	}
	if r, _ := s.GetReceipt(ctx, rk); !r.Failed || r.Status != 1 || r.CtxID != "ctx1" {
		t.Fatalf("failed receipt read: %+v", r)
	}
	// The principal index is written by the inner store, in the clear, and is
	// what revocation walks (the ruling in this task).
	if n, _ := inner.DeleteReceiptsByPrincipal(ctx, "user:alice@example.com"); n != 1 {
		t.Fatalf("receipt not indexed by principal in the clear: %d", n)
	}

	ck := store.ContextKey{NAS: "leaf-01", Username: "alice"}
	if err := s.PutContext(ctx, ck, store.Context{CtxID: "ctx1", Principal: "user:alice@example.com", Username: "alice",
		Port: "ssh", RemAddr: "198.51.100.4", PrivLvl: 1}, time.Hour); err != nil {
		t.Fatal(err)
	}
	if c, _ := inner.GetContext(ctx, ck); c.Principal != "" || c.RemAddr != "" || c.PrivLvl != 1 {
		t.Fatalf("context plaintext: %+v", c)
	}
	if c, _ := s.GetContext(ctx, ck); c.Principal != "user:alice@example.com" || c.RemAddr != "198.51.100.4" {
		t.Fatalf("context read: %+v", c)
	}

	// SetPrivilege, TouchContext and AnnotateContext pass straight through:
	// all three write only plaintext bookkeeping, so the inner store changes a
	// record it cannot read, and the sealed fields it never touched still open
	// afterwards.
	if err := s.SetPrivilege(ctx, ck, 15); err != nil {
		t.Fatal(err)
	}
	if err := s.TouchContext(ctx, ck, time.Hour); err != nil {
		t.Fatal(err)
	}
	hash := store.HashDiscriminator("31050")
	if err := s.AnnotateContext(ctx, ck, hash, store.AccountingStateClosing); err != nil {
		t.Fatal(err)
	}
	if c, _ := inner.GetContext(ctx, ck); c.PrivLvl != 15 {
		t.Fatalf("SetPrivilege must reach the inner store in the clear: %+v", c)
	}
	// The discriminator set is the point of the hashing: the INNER store, which
	// cannot open a sealed field, can both write and read it. Were it sealed,
	// AnnotateContext could only be a read-unseal-modify-reseal-write, which is
	// the read-modify-write the setter exists to avoid (spec §5.8).
	if c, _ := inner.GetContext(ctx, ck); len(c.SessionDiscriminators) != 1 || c.SessionDiscriminators[0] != hash ||
		c.AccountingState != store.AccountingStateClosing {
		t.Fatalf("AnnotateContext must reach the inner store in the clear: %+v", c)
	}
	// And the value itself is not in the store: a store dump must not be able
	// to enumerate `172.100.100.1@pts/3`-shaped discriminators, which carry the
	// client's source address (store.Context.SessionDiscriminators).
	if c, _ := inner.GetContext(ctx, ck); c.SessionDiscriminators[0] == "31050" {
		t.Fatal("the discriminator is stored in the clear, not hashed")
	}
	if c, _ := s.GetContext(ctx, ck); c.PrivLvl != 15 || c.Principal != "user:alice@example.com" ||
		len(c.SessionDiscriminators) != 1 || c.SessionDiscriminators[0] != hash {
		t.Fatalf("a narrow write must leave the sealed fields readable: %+v", c)
	}

	if _, ok, err := s.ReserveIdempotency(ctx, "user:alice", "k", store.Idempotency{BodyHash: "b", Holder: "h",
		Pending: true, ExpiresAt: time.Now().Add(time.Minute)}); err != nil || !ok {
		t.Fatalf("%v %v", ok, err)
	}
	if err := s.CompleteIdempotency(ctx, "user:alice", "k", "h", store.Idempotency{BodyHash: "b", Holder: "h",
		Response: []byte(`{"login":"p49_x"}`), ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if r, _ := storetest.Peek(t, inner, "user:alice", "k"); r.Response != nil || r.BodyHash != "b" {
		t.Fatalf("idempotency plaintext: %+v", r)
	}
	if r, _ := storetest.Peek(t, s, "user:alice", "k"); string(r.Response) != `{"login":"p49_x"}` {
		t.Fatalf("idempotency read: %+v", r)
	}

	if err := s.PutBlob(ctx, "sha256:x", []byte("blob"), time.Minute); err != nil {
		t.Fatal(err)
	}
	if b, _ := inner.GetBlob(ctx, "sha256:x"); string(b) != "blob" {
		t.Fatal("blobs are not encrypted; they hold no identity")
	}
}

// MintedAt is what a join's minted-after rule compares against a revocation
// (store.JoinContext). If the seal/open round trip dropped it, every token would
// read as minted before any revocation: fail-closed, but a relogin could never
// lift one.
func TestTokenMintedAtSurvivesTheSealingLayer(t *testing.T) {
	inner := memory.New(time.Now)
	s := Wrap(inner, keys(), nil)
	ctx := context.Background()
	k := store.TokenKey{NAS: "leaf-01", Username: "alice"}
	minted := time.Unix(1_757_041_495, 0)
	if _, err := s.PutToken(ctx, k, store.Token{ID: "t1", Secret: []byte("p49_secret"), Kind: store.KindLogin,
		Principal: "user:alice@example.com", Username: "alice", ExpiresAt: time.Now().Add(time.Minute),
		MintedAt: minted}); err != nil {
		t.Fatal(err)
	}
	got, err := s.Candidates(ctx, k)
	if err != nil || len(got) != 1 || !got[0].MintedAt.Equal(minted) {
		t.Fatalf("MintedAt lost through the sealing layer: %+v %v", got, err)
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

// SwapContext seals exactly what PutContext seals and hands the revision
// through: Rev is plaintext, so the inner store can hold the precondition on a
// record it cannot read, and a revision read through this layer is the one the
// inner store compares.
func TestSwapContextSealsAndKeepsTheRevision(t *testing.T) {
	inner := memory.New(time.Now)
	s := Wrap(inner, keys(), nil)
	ctx := context.Background()
	ck := store.ContextKey{NAS: "leaf-01", Username: "alice"}
	c := store.Context{CtxID: "ctx1", Principal: "user:alice@example.com", Username: "alice",
		Port: "ssh", RemAddr: "198.51.100.4", PrivLvl: 15}
	if err := s.SwapContext(ctx, ck, 0, c, time.Hour); err != nil {
		t.Fatal(err)
	}
	if raw, _ := inner.GetContext(ctx, ck); raw.Principal != "" || raw.RemAddr != "" || raw.CtxID != "" || raw.Sealed == nil {
		t.Fatalf("SwapContext wrote plaintext: %+v", raw)
	}
	got, err := s.GetContext(ctx, ck)
	if err != nil || got.Principal != "user:alice@example.com" || got.Rev == 0 {
		t.Fatalf("%+v %v", got, err)
	}
	// A narrow setter lands between the read and the swap, through this layer.
	if err := s.SetRevokedAt(ctx, ck, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := s.SwapContext(ctx, ck, got.Rev, got, time.Hour); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("a revision read through the sealing layer must be the one the inner store compares: %v", err)
	}
	if after, _ := s.GetContext(ctx, ck); after.RevokedAt.IsZero() {
		t.Fatalf("the refused swap erased the revocation: %+v", after)
	}
}

// A pending reservation has nothing sealed in it, so reading one back is
// not a record that will not open: no open failure is counted, and no
// decryption error reaches the caller.
func TestAPendingReservationReadsBackWithoutOpening(t *testing.T) {
	ctx := context.Background()
	failures := prometheus.NewCounterVec(prometheus.CounterOpts{Name: "t"}, []string{"record"})
	s := Wrap(memory.New(time.Now), keys(), failures)
	if _, ok, err := s.ReserveIdempotency(ctx, "user:alice", "k",
		store.Idempotency{BodyHash: "b", Holder: "h", Pending: true, ExpiresAt: time.Now().Add(time.Minute)}); err != nil || !ok {
		t.Fatalf("%v %v", ok, err)
	}
	r, ok := storetest.Peek(t, s, "user:alice", "k")
	if !ok || !r.Pending || r.Holder != "h" {
		t.Fatalf("reading a pending reservation: %+v %v", r, ok)
	}
	if n := testutil.ToFloat64(failures.WithLabelValues("idempotency")); n != 0 {
		t.Fatalf("a pending reservation counted %v open failures", n)
	}
}

// A completed record holds the minted tokens, so the inner store sees it
// sealed; a reservation holds no response, and one that tries to carry one
// is refused rather than written in clear.
func TestACompletedReservationIsSealed(t *testing.T) {
	ctx := context.Background()
	inner := memory.New(time.Now)
	s := Wrap(inner, keys(), nil)
	exp := time.Now().Add(time.Hour)
	if _, ok, err := s.ReserveIdempotency(ctx, "user:alice", "k",
		store.Idempotency{BodyHash: "b", Holder: "h", Pending: true, ExpiresAt: exp}); err != nil || !ok {
		t.Fatalf("%v %v", ok, err)
	}
	if err := s.CompleteIdempotency(ctx, "user:alice", "k", "h",
		store.Idempotency{BodyHash: "b", Holder: "h", Response: []byte(`{"login":"p49_x"}`), ExpiresAt: exp}); err != nil {
		t.Fatal(err)
	}
	if r, _ := storetest.Peek(t, inner, "user:alice", "k"); r.Response != nil || len(r.Sealed) == 0 {
		t.Fatalf("the inner store holds the response in clear: %+v", r)
	}
	cur, ok, err := s.ReserveIdempotency(ctx, "user:alice", "k",
		store.Idempotency{BodyHash: "b", Holder: "h2", Pending: true, ExpiresAt: exp})
	if err != nil || ok || string(cur.Response) != `{"login":"p49_x"}` {
		t.Fatalf("a reservation must find the completed record opened: %+v %v %v", cur, ok, err)
	}
	if _, _, err := s.ReserveIdempotency(ctx, "user:alice", "k2",
		store.Idempotency{BodyHash: "b", Holder: "h", Pending: true, Response: []byte("x"), ExpiresAt: exp}); err == nil {
		t.Fatal("a reservation carrying a response was written")
	}
}

// A renewal of a pending hold is a pending record: nothing is sealed into
// it, so it reads back without opening, and one carrying a response is
// refused rather than written in clear.
func TestARenewedHoldIsNotSealed(t *testing.T) {
	ctx := context.Background()
	inner := memory.New(time.Now)
	s := Wrap(inner, keys(), nil)
	exp := time.Now().Add(time.Minute)
	if _, ok, err := s.ReserveIdempotency(ctx, "user:alice", "k",
		store.Idempotency{BodyHash: "b", Holder: "h", Pending: true, ExpiresAt: exp}); err != nil || !ok {
		t.Fatalf("%v %v", ok, err)
	}
	if err := s.CompleteIdempotency(ctx, "user:alice", "k", "h",
		store.Idempotency{BodyHash: "b", Holder: "h", Pending: true, ExpiresAt: exp.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if r, _ := storetest.Peek(t, inner, "user:alice", "k"); !r.Pending || len(r.Sealed) != 0 || !r.ExpiresAt.Equal(exp.Add(time.Minute)) {
		t.Fatalf("the renewed hold: %+v", r)
	}
	if err := s.CompleteIdempotency(ctx, "user:alice", "k", "h",
		store.Idempotency{BodyHash: "b", Holder: "h", Pending: true, Response: []byte("x"), ExpiresAt: exp}); err == nil {
		t.Fatal("a pending record carrying a response was written")
	}
}

// Ruling R1 through the real sealing layer: a context sealed under a key that
// has left the two-key window, and revoked, is replaced by the next login
// rather than refusing it, and the revocation carries. What makes it possible
// is that GetContext hands up the plaintext Rev and RevokedAt of a record it
// cannot open, in a store.UnreadableContextError that still unwraps to
// ErrUnknownKey — so every other caller still reads it as the key failure it
// is (TestUnopenableRecordIsNotReportedAsMissing).
func TestAContextUnderARetiredKeyIsReplacedCarryingItsRevocation(t *testing.T) {
	now := time.Unix(1_757_041_495, 0)
	inner := memory.New(func() time.Time { return now })
	ctx := context.Background()
	ck := store.ContextKey{NAS: "leaf-01", Username: "alice"}
	var c [32]byte
	copy(c[:], "cccccccccccccccccccccccccccccccc")
	retired := Wrap(inner, Keys{Current: Key{ID: "v0", Bytes: c}}, nil)
	if err := retired.PutContext(ctx, ck, store.Context{CtxID: "ctx_old", Principal: "user:alice@example.com",
		Username: "alice", PrivLvl: 15}, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := retired.SetRevokedAt(ctx, ck, now.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}

	s := Wrap(inner, keys(), nil)
	_, err := s.GetContext(ctx, ck)
	var u *store.UnreadableContextError
	if !errors.As(err, &u) || u.Rev == 0 || !u.RevokedAt.Equal(now.Add(-time.Minute)) || !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("an unopenable context must hand up its plaintext revision and revocation: %v", err)
	}
	login := store.Context{CtxID: "ctx_new", Principal: "user:alice@example.com", Username: "alice", PrivLvl: 1}
	res, err := store.JoinContext(ctx, s, ck, login, now.Add(-2*time.Minute), now, time.Hour)
	if err != nil || !res.ReplacedUnreadable || res.Joined {
		t.Fatalf("%+v %v", res, err)
	}
	got, err := s.GetContext(ctx, ck)
	if err != nil || got.CtxID != "ctx_new" || got.PrivLvl != 1 || !got.RevokedAt.Equal(now.Add(-time.Minute)) {
		t.Fatalf("the replace must be readable under the current key and keep the revocation: %+v %v", got, err)
	}
}

// UnindexRef passes through to the inner store, as the other index writes do.
func TestUnindexRefPassesThrough(t *testing.T) {
	inner := memory.New(time.Now)
	s := Wrap(inner, keys(), nil)
	ctx := context.Background()
	ref := store.ContextRef{NAS: "leaf-01", Username: "alice"}
	if err := s.IndexContext(ctx, "user:alice@example.com", "sid-1", store.CertKey("ca", "01"), ref, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := s.UnindexRef(ctx, ref); err != nil {
		t.Fatal(err)
	}
	if r, _ := inner.ContextsBySid(ctx, "sid-1"); len(r) != 0 {
		t.Fatalf("UnindexRef did not reach the inner store: %v", r)
	}
}

// SetContextPolicy's compare-and-set survives the sealing layer: the
// policy revision read through GetContext, with the principal opened, is the
// one the inner store compares, and the fields it writes are plaintext, so the sealed
// ones are untouched.
func TestSetContextPolicyThroughTheSealingLayer(t *testing.T) {
	inner := memory.New(time.Now)
	s := Wrap(inner, keys(), nil)
	ctx := context.Background()
	ck := store.ContextKey{NAS: "leaf-01", Username: "alice"}
	if err := s.PutContext(ctx, ck, store.Context{CtxID: "ctx1", Principal: "user:alice@example.com",
		Username: "alice", PrivLvl: 15, BlobHash: "sha256:old"}, time.Hour); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetContext(ctx, ck)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetRevokedAt(ctx, ck, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := s.SetContextPolicy(ctx, ck, got.PolicyRev, store.ContextPolicy{BlobHash: "sha256:new"}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("the revision read through the sealing layer must be the one compared: %v", err)
	}
	got, _ = s.GetContext(ctx, ck)
	if err := s.SetContextPolicy(ctx, ck, got.PolicyRev, store.ContextPolicy{BlobHash: "sha256:new", MaxPrivilege: 1}); err != nil {
		t.Fatal(err)
	}
	after, err := s.GetContext(ctx, ck)
	if err != nil || after.Principal != "user:alice@example.com" || after.CtxID != "ctx1" ||
		after.BlobHash != "sha256:new" || after.PrivLvl != 1 {
		t.Fatalf("%+v %v", after, err)
	}
}

// Every storetest property through the sealing layer over memory: what the
// layer passes through, it must not change.
func TestTheSealingLayerHoldsEveryProperty(t *testing.T) {
	storetest.Run(t, storetest.Backend{New: func(_ *testing.T, clock func() time.Time) store.Store {
		return Wrap(memory.New(clock), keys(), nil)
	}})
}
