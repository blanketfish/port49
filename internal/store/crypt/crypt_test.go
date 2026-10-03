package crypt

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
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
	// The ID and the expiry alone stay in the clear, for the backend to
	// address and expire the record; the kind and the policy blob are sealed
	// with the secret now (plan 7d; re-check CA1).
	if raw[0].ID != "t1" || raw[0].ExpiresAt.IsZero() || raw[0].Kind != "" || raw[0].BlobHash != "" {
		t.Fatalf("only the ID and the expiry stay plaintext: %+v", raw[0])
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
			FirstRedeemedAt: now, IdleExpiresAt: now.Add(time.Minute), RetainUntil: now.Add(time.Hour),
			Principal: "user:alice@example.com", Sid: "sid-1", CertKey: store.CertKey("ca", "0a")}}
	if err := s.RedeemAndReceipt(ctx, k, "t1", w); err != nil {
		t.Fatal(err)
	}
	inr, _ := inner.GetReceipt(ctx, rk)
	if inr.CtxID != "" || inr.CredentialSHA256 != ([32]byte{}) || inr.Sealed == nil || inr.FirstRedeemedAt.IsZero() ||
		inr.Principal != "" || inr.Sid != "" || inr.CertKey != "" {
		t.Fatalf("receipt plaintext: %+v", inr)
	}
	// The credential the receipt was written for comes back from the seal:
	// a replay checks the marks and the index for it (plan 7d).
	if r, _ := s.GetReceipt(ctx, rk); r.CtxID != "ctx1" || r.CredentialSHA256 != h || !r.IdleExpiresAt.Equal(w.Receipt.IdleExpiresAt) ||
		r.Principal != "user:alice@example.com" || r.Sid != "sid-1" || r.CertKey != store.CertKey("ca", "0a") {
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
		Port: "ssh", RemAddr: "198.51.100.4", PrivLvl: 1, Logins: []string{store.LoginWitness(h)}}, time.Hour); err != nil {
		t.Fatal(err)
	}
	// The login witness is sealed: a store write cannot add a login that
	// did not commit (Task 4b review I1).
	if c, _ := inner.GetContext(ctx, ck); c.Principal != "" || c.RemAddr != "" || c.PrivLvl != 0 || c.Logins != nil {
		t.Fatalf("context plaintext: %+v", c)
	}
	if c, _ := s.GetContext(ctx, ck); c.Principal != "user:alice@example.com" || c.RemAddr != "198.51.100.4" ||
		len(c.Logins) != 1 || c.Logins[0] != store.LoginWitness(h) {
		t.Fatalf("context read: %+v", c)
	}

	// TouchContext and AnnotateContext pass straight through: both write only
	// plaintext bookkeeping, so the inner store changes a record it cannot
	// read, and the sealed fields it never touched still open afterwards.
	// SetPrivilege is a rewrite now: the level is sealed (plan 7d).
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
	if c, _ := inner.GetContext(ctx, ck); c.PrivLvl != 0 {
		t.Fatalf("SetPrivilege wrote the level in the clear: %+v", c)
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
	if r, _ := storetest.Peek(t, inner, time.Now(), "user:alice", "k"); r.Response != nil || r.BodyHash != "b" {
		t.Fatalf("idempotency plaintext: %+v", r)
	}
	if r, _ := storetest.Peek(t, s, time.Now(), "user:alice", "k"); string(r.Response) != `{"login":"p49_x"}` {
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
	r, ok := storetest.Peek(t, s, time.Now(), "user:alice", "k")
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
	if r, _ := storetest.Peek(t, inner, time.Now(), "user:alice", "k"); r.Response != nil || len(r.Sealed) == 0 {
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
	if r, _ := storetest.Peek(t, inner, time.Now(), "user:alice", "k"); !r.Pending || len(r.Sealed) != 0 || !r.ExpiresAt.Equal(exp.Add(time.Minute)) {
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
	res, err := store.JoinContext(ctx, s, ck, login, now.Add(-2*time.Minute), now, time.Hour, store.LoginIndex{})
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

// The sealing layer seals every field the authorizer trusts, bound to the
// record's key (plan 7d; Ruling 17; pre-flight I12). A store write that
// zeroes revoked_at, raises the privilege, swaps the blob or removes the
// ceiling changes nothing the layer returns, and a record moved to another
// (nas, username) does not open.
func TestTheSealCoversWhatAuthorizationTrusts(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_000_000, 0).UTC()
	inner := memory.New(func() time.Time { return now })
	s := Wrap(inner, keys(), nil)
	k := store.ContextKey{NAS: "leaf-01", Username: "alice"}
	if err := s.PutContext(ctx, k, store.Context{CtxID: "c1", Principal: "user:alice@example.com", Username: "alice",
		PrivLvl: 1, MaxPrivilege: 1, BlobHash: "sha256:narrow", Enable: "none", AuthTime: now, RefreshedAt: now,
		SessionExpires: now.Add(time.Hour)}, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := s.SetRevokedAt(ctx, k, now); err != nil {
		t.Fatal(err)
	}
	raw, err := inner.GetContext(ctx, k)
	if err != nil {
		t.Fatal(err)
	}
	// What the backend holds names none of it in the clear, the revocation
	// aside, which is written both ways.
	if raw.PrivLvl != 0 || raw.MaxPrivilege != 0 || raw.BlobHash != "" || raw.Enable != "" ||
		!raw.SessionExpires.IsZero() || !raw.AuthTime.IsZero() || !raw.RevokedAt.Equal(now) {
		t.Fatalf("the backend holds a trusted field in the clear: %+v", raw)
	}
	// Each edit writes a plaintext value the seal must outrank: a field
	// already blank in the clear, set blank, would test nothing (re-check
	// MA5).
	for name, edit := range map[string]func(*store.Context){
		"a zeroed revoked_at": func(r *store.Context) { r.RevokedAt = time.Time{} },
		"a raised privilege":  func(r *store.Context) { r.PrivLvl, r.MaxPrivilege = 15, 15 },
		"a swapped blob":      func(r *store.Context) { r.BlobHash = "sha256:wide" },
		"a later ceiling": func(r *store.Context) {
			r.SessionExpires, r.AuthTime = now.Add(100*time.Hour), now.Add(99*time.Hour)
		},
	} {
		r := raw
		edit(&r)
		if err := inner.PutContext(ctx, k, r, time.Hour); err != nil {
			t.Fatal(err)
		}
		got, err := s.GetContext(ctx, k)
		if err != nil || !got.RevokedAt.Equal(now) || got.PrivLvl != 1 || got.MaxPrivilege != 1 ||
			got.BlobHash != "sha256:narrow" || !got.SessionExpires.Equal(now.Add(time.Hour)) {
			t.Fatalf("%s reached the reader: %+v %v", name, got, err)
		}
	}
	// Moved to another key, the record does not open: unreadable, never
	// another device's session.
	other := store.ContextKey{NAS: "leaf-02", Username: "alice"}
	if err := inner.PutContext(ctx, other, raw, time.Hour); err != nil {
		t.Fatal(err)
	}
	var u *store.UnreadableContextError
	if _, err := s.GetContext(ctx, other); !errors.As(err, &u) {
		t.Fatalf("a transplanted record opened: %v", err)
	}
	// One sealed byte flipped: the record does not open (re-check MA5).
	flipped := raw
	flipped.Sealed = append([]byte(nil), raw.Sealed...)
	flipped.Sealed[len(flipped.Sealed)-1] ^= 1
	if err := inner.PutContext(ctx, k, flipped, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetContext(ctx, k); !errors.As(err, &u) {
		t.Fatalf("a record with a flipped sealed byte opened: %v", err)
	}
}

// A revocation needs no key: on a record the layer cannot open, the
// plaintext mark still lands, and a read of it is the unreadable error
// carrying that mark (plan 7d; Ruling 17). A regression guard, not a
// failing test: it passes before this task too, since SetRevokedAt was
// already a plaintext pass-through (re-check MA4).
func TestARevocationOfAnUnopenableContextNeedsNoKey(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_000_000, 0).UTC()
	inner := memory.New(func() time.Time { return now })
	k := store.ContextKey{NAS: "leaf-01", Username: "alice"}
	old := Wrap(inner, Keys{Current: Key{ID: "gone", Bytes: [32]byte{9}}}, nil)
	if err := old.PutContext(ctx, k, store.Context{CtxID: "c", Principal: "p", Username: "alice"}, time.Hour); err != nil {
		t.Fatal(err)
	}
	s := Wrap(inner, keys(), nil)
	if err := s.SetRevokedAt(ctx, k, now); err != nil {
		t.Fatalf("a keyless revocation: %v", err)
	}
	var u *store.UnreadableContextError
	if _, err := s.GetContext(ctx, k); !errors.As(err, &u) || !u.RevokedAt.Equal(now) {
		t.Fatalf("the unopenable record: %v", err)
	}
}

// A token's every field a redemption or a login trusts is sealed, bound to
// its key and ID (plan 7d; Ruling 17; re-check CA1). A store write that
// changes one reads back as minted, and the login copies what this layer
// returns (authen.go:705-724), so its context carries the minted value. A
// token moved to another key or ID, or whose plaintext expiry moved, is
// dropped and counted. A deleted token put back opens: the replay Ruling 17
// states, bounded by its sealed expiry.
func TestTheTokensTrustedFieldsAreSealed(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_000_000, 0).UTC()
	inner := memory.New(func() time.Time { return now })
	failures := prometheus.NewCounterVec(prometheus.CounterOpts{Name: "t"}, []string{"record"})
	s := Wrap(inner, keys(), failures)
	k := store.TokenKey{NAS: "leaf-01", Username: "alice"}
	minted := store.Token{ID: "t1", Secret: []byte("p49_secret"), Kind: store.KindLogin, ExpiresAt: now.Add(time.Minute),
		Principal: "user:alice@example.com", Username: "alice", BlobHash: "sha256:narrow", MaxSessionAge: time.Hour,
		Enable: "token", MaxPrivilege: 1, AuthTime: now, MintedAt: now}
	if _, err := s.PutToken(ctx, k, minted); err != nil {
		t.Fatal(err)
	}
	raws, err := inner.Candidates(ctx, k)
	if err != nil || len(raws) != 1 {
		t.Fatalf("%v %v", raws, err)
	}
	raw := raws[0]
	if raw.Kind != "" || raw.BlobHash != "" || raw.MaxSessionAge != 0 || raw.Enable != "" || raw.MaxPrivilege != 0 ||
		!raw.AuthTime.IsZero() || !raw.MintedAt.IsZero() || !raw.ExpiresAt.Equal(minted.ExpiresAt) {
		t.Fatalf("the backend holds a trusted token field in the clear: %+v", raw)
	}
	putRaw := func(k store.TokenKey, r store.Token) {
		t.Helper()
		if err := inner.DeleteTokens(ctx, k); err != nil {
			t.Fatal(err)
		}
		if _, err := inner.PutToken(ctx, k, r); err != nil {
			t.Fatal(err)
		}
	}
	asMinted := func(got store.Token) bool {
		return got.Kind == minted.Kind && got.BlobHash == minted.BlobHash && got.MaxSessionAge == minted.MaxSessionAge &&
			got.Enable == minted.Enable && got.MaxPrivilege == minted.MaxPrivilege && got.AuthTime.Equal(minted.AuthTime) &&
			got.MintedAt.Equal(minted.MintedAt) && got.ExpiresAt.Equal(minted.ExpiresAt) &&
			got.Principal == minted.Principal && string(got.Secret) == string(minted.Secret)
	}
	for name, edit := range map[string]func(*store.Token){
		"a raised privilege":   func(r *store.Token) { r.MaxPrivilege = 15 },
		"enable auto":          func(r *store.Token) { r.Enable = "auto" },
		"a longer session age": func(r *store.Token) { r.MaxSessionAge = 1000 * time.Hour },
		"another blob":         func(r *store.Token) { r.BlobHash = "sha256:wide" },
		"a later auth time":    func(r *store.Token) { r.AuthTime = now.Add(time.Hour) },
		"a later mint":         func(r *store.Token) { r.MintedAt = now.Add(time.Hour) },
		"the enable kind":      func(r *store.Token) { r.Kind = store.KindEnable },
	} {
		r := raw
		edit(&r)
		putRaw(k, r)
		got, err := s.Candidates(ctx, k)
		if err != nil || len(got) != 1 || !asMinted(got[0]) {
			t.Fatalf("%s reached the reader: %+v %v", name, got, err)
		}
	}
	// Dropped and counted: an extended plaintext expiry, another key,
	// another ID.
	dropped := func(what string, k store.TokenKey) {
		t.Helper()
		before := testutil.ToFloat64(failures.WithLabelValues("token"))
		if got, err := s.Candidates(ctx, k); err != nil || len(got) != 0 {
			t.Fatalf("%s opened: %+v %v", what, got, err)
		}
		if testutil.ToFloat64(failures.WithLabelValues("token")) != before+1 {
			t.Fatalf("%s was not counted", what)
		}
	}
	later := raw
	later.ExpiresAt = now.Add(time.Hour)
	putRaw(k, later)
	dropped("an extended plaintext expiry", k)
	other := store.TokenKey{NAS: "leaf-02", Username: "alice"}
	putRaw(other, raw)
	dropped("a token moved to another key", other)
	renamed := raw
	renamed.ID = "t2"
	putRaw(k, renamed)
	dropped("a token moved to another ID", k)
	// The replay: a deleted token put back opens, until its sealed expiry.
	putRaw(k, raw)
	if got, err := s.Candidates(ctx, k); err != nil || len(got) != 1 || !asMinted(got[0]) {
		t.Fatalf("a token put back as it was: %+v %v (the residual, Ruling 17)", got, err)
	}
}

// A receipt is sealed bound to its whole key (re-check CA1): a login
// receipt copied to the enable key does not open, so it can never replay
// an escalation; and the cap's anchor is the sealed first redemption,
// whatever the plaintext copy says.
func TestAReceiptIsBoundToItsKey(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_000_000, 0).UTC()
	inner := memory.New(func() time.Time { return now })
	s := Wrap(inner, keys(), nil)
	tk := store.TokenKey{NAS: "leaf-01", Username: "alice"}
	spend := func(id string) {
		t.Helper()
		if _, err := inner.PutToken(ctx, tk, store.Token{ID: id, ExpiresAt: now.Add(time.Minute)}); err != nil {
			t.Fatal(err)
		}
	}
	var h [32]byte
	copy(h[:], "hash")
	login := store.ReceiptKey{NAS: "leaf-01", Username: "alice", Kind: store.KindLogin, CredentialSHA256: h}
	spend("t1")
	if err := s.RedeemAndReceipt(ctx, tk, "t1", store.ReceiptWrite{Key: login, Principal: "user:alice@example.com",
		IndexTTL: time.Hour, Receipt: store.Receipt{CredentialSHA256: h, Status: 1, CtxID: "ctx1", FirstRedeemedAt: now,
			IdleExpiresAt: now.Add(time.Minute), RetainUntil: now.Add(time.Hour)}}); err != nil {
		t.Fatal(err)
	}
	raw, err := inner.GetReceipt(ctx, login)
	if err != nil {
		t.Fatal(err)
	}
	enable := login
	enable.Kind = store.KindEnable
	spend("t2")
	if err := inner.RedeemAndReceipt(ctx, tk, "t2", store.ReceiptWrite{Key: enable, Principal: "user:alice@example.com",
		IndexTTL: time.Hour, Receipt: raw}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetReceipt(ctx, enable); err == nil || errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a login receipt copied to the enable key opened: %v", err)
	}
	moved := raw
	moved.FirstRedeemedAt = now.Add(time.Hour)
	spend("t3")
	if err := inner.RedeemAndReceipt(ctx, tk, "t3", store.ReceiptWrite{Key: login, Principal: "user:alice@example.com",
		IndexTTL: time.Hour, Receipt: moved}); err != nil {
		t.Fatal(err)
	}
	if got, err := s.GetReceipt(ctx, login); err != nil || !got.FirstRedeemedAt.Equal(now) {
		t.Fatalf("the cap's anchor came from the clear: %+v %v", got, err)
	}
}

// The ledger (re-check IA1; plan 7e, Ruling 3): another login's context
// written back at a key is denied ErrNotLastWritten, through either Wrap
// sharing the ledger, and so is an earlier version of the same context,
// since each write is sealed at a sequence above the last (Ruling T12-g).
// A fresh process with a base of zero takes the first record it reads as
// the key's, the restart residual, and denies an earlier one after it.
func TestTheLedgerDeniesAnotherLoginsContext(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_000_000, 0).UTC()
	inner := memory.New(func() time.Time { return now })
	l := NewLedger()
	daemon := Wrap(inner, keys(), nil, WithLedger(l))
	broker := Wrap(inner, keys(), nil, WithLedger(l))
	k := store.ContextKey{NAS: "leaf-01", Username: "netops"}
	if err := daemon.PutContext(ctx, k, store.Context{CtxID: "alice-1", Principal: "user:alice@example.com",
		Username: "netops", PrivLvl: 15}, time.Hour); err != nil {
		t.Fatal(err)
	}
	alice, _ := inner.GetContext(ctx, k)
	if err := daemon.PutContext(ctx, k, store.Context{CtxID: "bob-1", Principal: "user:bob@example.com",
		Username: "netops", PrivLvl: 1}, time.Hour); err != nil {
		t.Fatal(err)
	}
	bob, _ := inner.GetContext(ctx, k)
	if err := broker.SetPrivilege(ctx, k, 5); err != nil {
		t.Fatal(err)
	}
	if err := inner.PutContext(ctx, k, alice, time.Hour); err != nil { // Alice's, written back
		t.Fatal(err)
	}
	var u *store.UnreadableContextError
	for name, s := range map[string]store.Store{"daemon": daemon, "broker": broker} {
		if _, err := s.GetContext(ctx, k); !errors.As(err, &u) || !errors.Is(err, ErrNotLastWritten) {
			t.Fatalf("%s read another login's context written back: %v", name, err)
		}
	}
	if err := inner.PutContext(ctx, k, bob, time.Hour); err != nil { // Bob's own, before the raise
		t.Fatal(err)
	}
	for name, s := range map[string]store.Store{"daemon": daemon, "broker": broker} {
		if got, err := s.GetContext(ctx, k); !errors.As(err, &u) || !errors.Is(err, ErrNotLastWritten) {
			t.Fatalf("%s read an earlier version of the same context: %+v %v", name, got, err)
		}
	}
	// A record sealed above the first one read is a later write, whichever
	// process made it (Ruling 3), so the residual's check is an earlier one
	// after it: Bob's first, then Alice's.
	fresh := Wrap(inner, keys(), nil) // a restart: its own, empty ledger
	if got, err := fresh.GetContext(ctx, k); err != nil || got.CtxID != "bob-1" {
		t.Fatalf("a fresh process's first read: %+v %v (the restart residual)", got, err)
	}
	if err := inner.PutContext(ctx, k, alice, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := fresh.GetContext(ctx, k); !errors.Is(err, ErrNotLastWritten) {
		t.Fatalf("after its first read, a fresh process read another login's: %v", err)
	}
}

// An earlier version of the same context, put back after a later write
// at its key landed, is denied ErrNotLastWritten: each sealed write
// carries a sequence above the last, and the ledger admits the highest,
// not every write under its ctx_id (Ruling T12-g; Task 12 re-review,
// "Context-ID rollback"; plan 7e, Ruling 3). Put back, it would undo a
// self revocation that leaves no mark, a policy narrowing a refresh
// wrote, or drop a login's witness. A fresh process still takes the
// first record it reads, the restart residual.
func TestTheLedgerDeniesAnEarlierVersionOfTheSameContext(t *testing.T) {
	now := time.Unix(1_000_000, 0).UTC()
	login := func(blob string) store.Context {
		return store.Context{CtxID: "alice-1", Principal: "user:alice@example.com", Username: "netops", PrivLvl: 15,
			BlobHash: blob, AuthTime: now, CreatedAt: now}
	}
	for name, later := range map[string]func(ctx context.Context, s store.Store, k store.ContextKey) error{
		"a second login joining": func(ctx context.Context, s store.Store, k store.ContextKey) error {
			res, err := store.JoinContext(ctx, s, k, login("wide"), now, now, time.Hour, store.LoginIndex{})
			if err == nil && (!res.Joined || res.Context.CtxID != "alice-1") {
				t.Fatalf("the second login did not join: %+v", res)
			}
			return err
		},
		"a self revocation": func(ctx context.Context, s store.Store, k store.ContextKey) error {
			return s.SetRevokedAt(ctx, k, now)
		},
		"a refresh narrowing the policy": func(ctx context.Context, s store.Store, k store.ContextKey) error {
			return s.RefreshContext(ctx, k, store.ContextRefresh{AuthTime: now, RefreshedAt: now, BlobHash: "narrow"},
				time.Hour)
		},
	} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			inner := memory.New(func() time.Time { return now })
			l := NewLedger()
			daemon := Wrap(inner, keys(), nil, WithLedger(l))
			broker := Wrap(inner, keys(), nil, WithLedger(l))
			k := store.ContextKey{NAS: "leaf-01", Username: "netops"}
			if _, err := store.JoinContext(ctx, daemon, k, login("wide"), now, now, time.Hour,
				store.LoginIndex{}); err != nil {
				t.Fatal(err)
			}
			l.SetBase(inner.Seen() + 1)
			earlier, err := inner.GetContext(ctx, k)
			if err != nil {
				t.Fatal(err)
			}
			if err := later(ctx, broker, k); err != nil {
				t.Fatal(err)
			}
			if _, err := daemon.GetContext(ctx, k); err != nil {
				t.Fatalf("the later write: %v", err)
			}
			if err := inner.PutContext(ctx, k, earlier, time.Hour); err != nil { // put back
				t.Fatal(err)
			}
			var u *store.UnreadableContextError
			for name, s := range map[string]store.Store{"daemon": daemon, "broker": broker} {
				if got, err := s.GetContext(ctx, k); !errors.As(err, &u) || !errors.Is(err, ErrNotLastWritten) {
					t.Fatalf("%s read an earlier version of the same context: %+v %v", name, got, err)
				}
			}
			fresh := Wrap(inner, keys(), nil) // a restart: its own, empty ledger
			if got, err := fresh.GetContext(ctx, k); err != nil || got.CtxID != "alice-1" {
				t.Fatalf("a fresh process's first read: %+v %v (the restart residual)", got, err)
			}
		})
	}
}

// twoProcesses is one memory store with two sealing layers over it, each
// with its own ledger, as two port49d processes on one etcd keyspace are;
// each set its base when the store was empty.
func twoProcesses(t *testing.T) (*memory.Store, store.Store, store.Store, *Ledger, *Ledger) {
	t.Helper()
	inner := memory.New(time.Now)
	la, lb := NewLedger(), NewLedger()
	la.SetBase(inner.Seen() + 1)
	lb.SetBase(inner.Seen() + 1)
	return inner, Wrap(inner, keys(), nil, WithLedger(la)), Wrap(inner, keys(), nil, WithLedger(lb)), la, lb
}

var ka = store.ContextKey{NAS: "leaf-01", Username: "netops"}

func login(t *testing.T, s store.Store, ctxID, principal string) {
	t.Helper()
	cur, err := s.GetContext(context.Background(), ka)
	var rev uint64
	switch {
	case err == nil:
		rev = cur.Rev
	case errors.Is(err, store.ErrNotFound):
	default:
		var u *store.UnreadableContextError
		if !errors.As(err, &u) {
			t.Fatal(err)
		}
		rev = u.Rev
	}
	if err := s.SwapLogin(context.Background(), ka, rev, store.Context{CtxID: ctxID, Principal: principal,
		Username: "netops", BlobHash: "b-" + ctxID, PrivLvl: 1}, time.Hour, store.LoginWrite{}); err != nil {
		t.Fatal(err)
	}
}

// A login on one process is admitted on another: the record's sequence is
// above the other's base, and above any mark it knows at the key (Review
// Focus 1; Ruling 3). Neither ledger here follows a feed, so the fence
// (Task 8a) passes at once; Task 8a's test covers the wait. A per-process
// ledger, sealed, denied it (re-check IA1).
func TestAnotherProcesssWriteIsAdmittedWithNoFeedBetween(t *testing.T) {
	_, a, b, _, _ := twoProcesses(t)
	login(t, a, "ctx-alice", "user:alice")
	if c, err := b.GetContext(context.Background(), ka); err != nil || c.CtxID != "ctx-alice" {
		t.Fatalf("the other process: %v %v", c.CtxID, err)
	}
	login(t, a, "ctx-bob", "user:bob") // a later login, again on a
	if c, err := b.GetContext(context.Background(), ka); err != nil || c.CtxID != "ctx-bob" {
		t.Fatalf("the other process, after a later login: %v %v", c.CtxID, err)
	}
}

// Bob's context, written on a, read on b, and Alice's earlier one put
// back by a store writer: b denies it, as a does, since both have seen a
// later sequence at the key (Ruling 3).
func TestAnEarlierRecordIsDeniedOnEveryProcessThatSawALater(t *testing.T) {
	inner, a, b, _, _ := twoProcesses(t)
	login(t, a, "ctx-alice", "user:alice")
	saved, err := inner.GetContext(context.Background(), ka)
	if err != nil {
		t.Fatal(err)
	}
	login(t, b, "ctx-bob", "user:bob") // on b this time
	if _, err := a.GetContext(context.Background(), ka); err != nil {
		t.Fatal(err) // a reads bob's, raising its mark
	}
	if err := inner.PutContext(context.Background(), ka, saved, time.Hour); err != nil {
		t.Fatal(err)
	}
	for name, s := range map[string]store.Store{"a": a, "b": b} {
		_, err := s.GetContext(context.Background(), ka)
		if !errors.Is(err, ErrNotLastWritten) {
			t.Fatalf("process %s took alice's context put back over bob's: %v", name, err)
		}
	}
}

// A write in flight leaves the record before it admitted, and a write
// whose outcome is unknown is admitted once read if it landed, and leaves
// the record before it admitted if it did not (Ruling 3; 7d's three
// in-flight and unknown-outcome tests).
func TestAWriteInFlightOrOfUnknownOutcomeIsAdmittedWhicheverLanded(t *testing.T) {
	for _, landed := range []bool{true, false} {
		inner := &lossy{RevStore: memory.New(time.Now), commit: landed}
		l := NewLedger()
		l.SetBase(inner.Seen() + 1)
		s := Wrap(inner, keys(), nil, WithLedger(l))
		login(t, s, "ctx-1", "user:alice")
		inner.lose = true // the next swap's reply is lost: ErrUnavailable, committed or not
		cur, _ := s.GetContext(context.Background(), ka)
		err := s.SwapContext(context.Background(), ka, cur.Rev, store.Context{CtxID: "ctx-1", Principal: "user:alice",
			Username: "netops", BlobHash: "b-2", PrivLvl: 1}, time.Hour)
		if !errors.Is(err, store.ErrUnavailable) {
			t.Fatalf("landed=%v: %v", landed, err)
		}
		inner.lose = false
		c, err := s.GetContext(context.Background(), ka)
		want := map[bool]string{true: "b-2", false: "b-ctx-1"}[landed]
		if err != nil || c.BlobHash != want {
			t.Fatalf("landed=%v: read %q, %v; want %q", landed, c.BlobHash, err, want)
		}
	}
}

// lossy commits a SwapContextRev (or not) and reports ErrUnavailable while
// lose is set.
type lossy struct {
	store.RevStore
	lose, commit bool
}

func (l *lossy) SwapContextRev(ctx context.Context, k store.ContextKey, rev uint64, c store.Context, ttl time.Duration) (uint64, error) {
	if !l.lose {
		return l.RevStore.SwapContextRev(ctx, k, rev, c, ttl)
	}
	if l.commit {
		l.RevStore.SwapContextRev(ctx, k, rev, c, ttl)
	}
	return 0, store.ErrUnavailable
}

// Two writes at a key in either order of ending: whichever the store
// holds is admitted, because it is the one whose compare-and-set landed
// last, and a writer that read the other's record seals above it.
func TestTheStoresLastWriteIsAdmittedWhateverOrderWritesEnd(t *testing.T) {
	_, a, b, _, _ := twoProcesses(t)
	login(t, a, "ctx-1", "user:alice")
	login(t, b, "ctx-1", "user:alice") // b read a's, so seals above it
	for name, s := range map[string]store.Store{"a": a, "b": b} {
		if _, err := s.GetContext(context.Background(), ka); err != nil {
			t.Fatalf("%s: the store's last write was denied: %v", name, err)
		}
	}
}

// After the store's revisions went back (a restore without
// --bump-revision) or jumped (with it), a login seals above every record
// this process knew, because Seen never goes back: it is admitted, and a
// record the restore brought back, below the mark, is denied (Ruling 3;
// L35's restore, measured).
//
// With two processes (pre-flight I12): q starts after the restore, so its
// Seen is the restored store's. With the bump, q's login seals above
// everything p knew, and p admits it. Without it, q seals below p's mark,
// and p denies it until p writes at the key. The runbook (design §13)
// says to bump, or to restart every process: the second half pins why.
func TestALoginAfterARestoreIsAdmitted(t *testing.T) {
	for _, bump := range []bool{false, true} {
		inner := newRewinding(memory.New(time.Now))
		l := NewLedger()
		l.SetBase(inner.Seen() + 1)
		p := Wrap(inner, keys(), nil, WithLedger(l))
		login(t, p, "ctx-old", "user:alice")
		old, _ := inner.RevStore.GetContext(context.Background(), ka)
		for i := 0; i < 5; i++ { // p's mark well past the snapshot's revisions
			login(t, p, fmt.Sprintf("ctx-new-%d", i), "user:alice")
		}
		inner.restore(old, bump) // the store now holds ctx-old, its revisions back or bumped
		if _, err := p.GetContext(context.Background(), ka); !errors.Is(err, ErrNotLastWritten) {
			t.Fatalf("bump=%v: a restored record below the mark was admitted: %v", bump, err)
		}
		// q: a process started after the restore, with a view of its own.
		qv := inner.view()
		lq := NewLedger()
		lq.SetBase(qv.Seen() + 1)
		q := Wrap(qv, keys(), nil, WithLedger(lq))
		login(t, q, "ctx-on-q", "user:alice")
		c, err := p.GetContext(context.Background(), ka)
		switch {
		case bump && (err != nil || c.CtxID != "ctx-on-q"):
			t.Fatalf("with the bump, p did not admit q's login: %v %v", c.CtxID, err)
		case !bump && !errors.Is(err, ErrNotLastWritten):
			t.Fatalf("without the bump, p admitted a login sealed below its mark (%v %v): the runbook's "+
				"restart is no longer needed, so say so in design §13", c.CtxID, err)
		}
		login(t, p, "ctx-after", "user:alice") // p's own write after the restore
		for name, s := range map[string]store.Store{"p": p, "q": q} {
			if c, err := s.GetContext(context.Background(), ka); err != nil || c.CtxID != "ctx-after" {
				t.Fatalf("bump=%v, %s: the login after the restore: %v %v", bump, name, c.CtxID, err)
			}
		}
	}
}

// rewinding is a store whose revisions can be put back to before a
// record's, as a restore without --bump-revision does, or bumped by a
// billion, as one with it does. Each view's Seen is its own and never goes
// back, as an etcd client's is; the offset is the store's, shared by every
// view.
type rewinding struct {
	store.RevStore
	shared *rewindState
	mu     sync.Mutex
	seen   uint64
}

type rewindState struct {
	mu     sync.Mutex
	offset int64 // added to every revision the inner store reports
}

func newRewinding(inner store.RevStore) *rewinding {
	return &rewinding{RevStore: inner, shared: &rewindState{}}
}

// view is another client of the same store, which has seen nothing yet:
// a process started now.
func (r *rewinding) view() *rewinding { return &rewinding{RevStore: r.RevStore, shared: r.shared} }

func (r *rewinding) offset() int64 {
	r.shared.mu.Lock()
	defer r.shared.mu.Unlock()
	return r.shared.offset
}

// out is an inner revision as the store reports it; in is the reverse.
func (r *rewinding) out(rev uint64) uint64 {
	if rev == 0 {
		return 0
	}
	v := uint64(int64(rev) + r.offset())
	r.mu.Lock()
	r.seen = max(r.seen, v)
	r.mu.Unlock()
	return v
}

func (r *rewinding) in(rev uint64) uint64 {
	if rev == 0 {
		return 0
	}
	return uint64(int64(rev) - r.offset())
}

func (r *rewinding) Seen() uint64 {
	r.out(r.RevStore.Seen())
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.seen
}

func (r *rewinding) GetContext(ctx context.Context, k store.ContextKey) (store.Context, error) {
	c, err := r.RevStore.GetContext(ctx, k)
	c.Rev, c.PolicyRev = r.out(c.Rev), r.out(c.PolicyRev)
	return c, err
}

func (r *rewinding) SwapLoginRev(ctx context.Context, k store.ContextKey, rev uint64, c store.Context,
	ttl time.Duration, w store.LoginWrite) (uint64, error) {
	got, err := r.RevStore.SwapLoginRev(ctx, k, r.in(rev), c, ttl, w)
	return r.out(got), err
}

// SwapContextRev, PutContextRev and RewriteContextRev are SwapLoginRev's
// shape: in on the way down, out on the way up.
func (r *rewinding) SwapContextRev(ctx context.Context, k store.ContextKey, rev uint64, c store.Context,
	ttl time.Duration) (uint64, error) {
	got, err := r.RevStore.SwapContextRev(ctx, k, r.in(rev), c, ttl)
	return r.out(got), err
}

func (r *rewinding) PutContextRev(ctx context.Context, k store.ContextKey, c store.Context,
	ttl time.Duration) (uint64, error) {
	got, err := r.RevStore.PutContextRev(ctx, k, c, ttl)
	return r.out(got), err
}

func (r *rewinding) RewriteContextRev(ctx context.Context, k store.ContextKey, rev uint64, c store.Context,
	ttl time.Duration, policyMoved bool) (uint64, error) {
	got, err := r.RevStore.RewriteContextRev(ctx, k, r.in(rev), c, ttl, policyMoved)
	return r.out(got), err
}

// restore puts old back at ka as the store's, and moves the revisions the
// store reports: back to just above 1 (no bump), below everything written
// since, or up by a billion (bump).
func (r *rewinding) restore(old store.Context, bump bool) {
	cur := r.RevStore.Seen()
	r.shared.mu.Lock()
	if bump {
		r.shared.offset = 1_000_000_000
	} else {
		r.shared.offset = 1 - int64(cur)
	}
	r.shared.mu.Unlock()
	old.Rev, old.PolicyRev = 0, 0
	r.RevStore.PutContext(context.Background(), ka, old, time.Hour)
}

// A record sealed before this process's base, at a key it has no mark
// for, is a put-back: denied. One sealed after the base, by any process,
// is admitted (7d's sealed ledger, on the new rule).
func TestARecordSealedBeforeTheBaseIsDeniedAtAnUnseenKey(t *testing.T) {
	inner, a, _, _, _ := twoProcesses(t)
	login(t, a, "ctx-1", "user:alice")
	saved, _ := inner.GetContext(context.Background(), ka)
	if err := inner.DeleteContext(context.Background(), ka); err != nil {
		t.Fatal(err)
	}
	late := NewLedger()
	late.SetBase(inner.Seen() + 1) // a process started now, finding the key empty
	c := Wrap(inner, keys(), nil, WithLedger(late))
	if err := inner.PutContext(context.Background(), ka, saved, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetContext(context.Background(), ka); !errors.Is(err, ErrNotLastWritten) {
		t.Fatalf("a record sealed before the base was admitted at an unseen key: %v", err)
	}
	login(t, a, "ctx-2", "user:alice")
	if _, err := c.GetContext(context.Background(), ka); err != nil {
		t.Fatalf("a record sealed after the base was denied: %v", err)
	}
}

// A delete forgets nothing: a record put back after one is still below the
// key's mark (stronger than 7d's forget).
func TestADeletedKeyKeepsItsMark(t *testing.T) {
	inner, a, _, _, _ := twoProcesses(t)
	login(t, a, "ctx-1", "user:alice")
	saved, _ := inner.GetContext(context.Background(), ka)
	login(t, a, "ctx-2", "user:bob")
	if err := a.DeleteContext(context.Background(), ka); err != nil {
		t.Fatal(err)
	}
	inner.PutContext(context.Background(), ka, saved, time.Hour)
	if _, err := a.GetContext(context.Background(), ka); !errors.Is(err, ErrNotLastWritten) {
		t.Fatalf("a put-back after a delete was admitted: %v", err)
	}
}

// A mark is kept past the latest sealed ceiling seen at its key by the
// ledger's keep, then pruned; a context with no ceiling (never) is kept.
func TestTheLedgerPrunesAKeyPastItsKeep(t *testing.T) {
	l := NewLedger()
	now := time.Unix(2_000_000, 0)
	l.Observe(ka, 10, 10, time.Time{}, now.Add(time.Hour))
	never := store.ContextKey{NAS: "leaf-02", Username: "svc"}
	l.Observe(never, 11, 11, time.Time{}, time.Time{})
	if n := l.Prune(now.Add(time.Hour + DefaultLedgerKeep - time.Second)); n != 0 {
		t.Fatalf("pruned %d before its keep", n)
	}
	if n := l.Prune(now.Add(time.Hour + DefaultLedgerKeep + time.Second)); n != 1 || l.Len() != 1 {
		t.Fatalf("pruned %d, %d left: the never context's mark must stay", n, l.Len())
	}
	// A key pruned since its mark was handed out is owed nothing again
	// (Task 7 review M-4).
	l.Dirty()
	l.Redirty([]store.LedgerMark{{Key: ka, Seq: 10}})
	if n := l.Pending(); n != 0 {
		t.Fatalf("a pruned key is owed again: %d pending", n)
	}
}

// The sequence a write seals is above the revision it compares on, above
// everything the store has told this process, and above the key's mark:
// each term wins once (pre-flight M4: the Seen term is exercised too).
func TestTheSequenceIsAboveEverythingKnown(t *testing.T) {
	inner := &seenAt{RevStore: memory.New(time.Now), seen: 10}
	l := NewLedger()
	l.Observe(ka, 1000, 1000, time.Time{}, time.Time{})
	w := Wrap(inner, keys(), nil, WithLedger(l)).(*wrapped)
	if got := w.seqFor(ka, 5); got != 1001 {
		t.Fatalf("the mark's term: %d", got)
	}
	if got := w.seqFor(ka, 5000); got != 5000 {
		t.Fatalf("the compare revision's term: %d", got)
	}
	inner.seen = 9000
	if got := w.seqFor(ka, 5000); got != 9000 {
		t.Fatalf("the Seen term: %d", got)
	}
}

// seenAt is a store whose Seen is whatever the test sets.
type seenAt struct {
	store.RevStore
	seen uint64
}

func (s *seenAt) Seen() uint64 { return s.seen }

// A form-3 (7d) or form-2 context does not open: denied, and replaced at
// the next login (Ruling 3, the migration).
func TestAContextOfFormThreeDoesNotOpen(t *testing.T) {
	for _, v := range []int{2, 3} {
		inner := memory.New(time.Now)
		l := NewLedger()
		l.SetBase(inner.Seen() + 1)
		s := Wrap(inner, keys(), nil, WithLedger(l))
		body, _ := json.Marshal(map[string]any{"v": v, "write_id": "00", "ctx_id": "c-old", "principal": "user:alice",
			"username": "netops"})
		sealed, err := keys().SealBound(body, contextAAD(ka))
		if err != nil {
			t.Fatal(err)
		}
		if err := inner.PutContext(context.Background(), ka, store.Context{Sealed: sealed}, time.Hour); err != nil {
			t.Fatal(err)
		}
		var u *store.UnreadableContextError
		if _, err := s.GetContext(context.Background(), ka); !errors.As(err, &u) {
			t.Fatalf("form %d opened: %v", v, err)
		}
		login(t, s, "ctx-new", "user:alice") // the next login replaces it
		if c, err := s.GetContext(context.Background(), ka); err != nil || c.CtxID != "ctx-new" {
			t.Fatalf("form %d: the login after it: %v %v", v, c.CtxID, err)
		}
	}
}

// An earlier form is ErrEarlierForm, both in the read's error and in what
// OnUnopenable is told, so the operator's line names the upgrade rather
// than tampering; a later form, and a put-back, are not it (pre-flight I10).
func TestAnEarlierFormIsNamedAsOne(t *testing.T) {
	for _, c := range []struct {
		v       int
		earlier bool
	}{{3, true}, {2, true}, {5, false}} {
		inner := memory.New(time.Now)
		var told error
		s := Wrap(inner, keys(), nil, OnUnopenable(func(_, _ string, why error) { told = why }))
		body, _ := json.Marshal(map[string]any{"v": c.v, "ctx_id": "c-old", "principal": "user:alice",
			"username": "netops"})
		sealed, _ := keys().SealBound(body, contextAAD(ka))
		inner.PutContext(context.Background(), ka, store.Context{Sealed: sealed}, time.Hour)
		_, err := s.GetContext(context.Background(), ka)
		if errors.Is(err, ErrEarlierForm) != c.earlier || errors.Is(told, ErrEarlierForm) != c.earlier {
			t.Fatalf("form %d: read %v, told %v", c.v, err, told)
		}
	}
	// A put-back is told as one, never as an earlier form.
	inner := memory.New(time.Now)
	l := NewLedger()
	l.SetBase(inner.Seen() + 1)
	var told error
	s := Wrap(inner, keys(), nil, WithLedger(l), OnUnopenable(func(_, _ string, why error) { told = why }))
	login(t, s, "ctx-alice", "user:alice")
	saved, _ := inner.GetContext(context.Background(), ka)
	login(t, s, "ctx-bob", "user:bob")
	inner.PutContext(context.Background(), ka, saved, time.Hour)
	s.GetContext(context.Background(), ka)
	if !errors.Is(told, ErrNotLastWritten) || errors.Is(told, ErrEarlierForm) {
		t.Fatalf("a put-back was told as %v", told)
	}
}

// sealFailsStore lands SetRevokedAt's plaintext mark and then answers
// every GetContext ErrUnavailable while down, so the seal that follows the
// mark sends nothing.
type sealFailsStore struct {
	store.RevStore
	down atomic.Bool
}

func (s *sealFailsStore) SetRevokedAt(ctx context.Context, k store.ContextKey, at time.Time) error {
	if err := s.RevStore.SetRevokedAt(ctx, k, at); err != nil {
		return err
	}
	s.down.Store(true)
	return nil
}

func (s *sealFailsStore) GetContext(ctx context.Context, k store.ContextKey) (store.Context, error) {
	if s.down.Load() {
		return store.Context{}, store.ErrUnavailable
	}
	return s.RevStore.GetContext(ctx, k)
}

// A self or key revocation whose plaintext mark landed and whose seal sent
// nothing is not undone by the record before it put back: the ledger keeps
// the mark as k's revocation floor, and every read takes the latest of the
// sealed time, the plaintext time and the floor, through either Wrap. A
// write this process sends after the floor, landed, chose its own sealed
// fields and clears it (final review 7d-2 I-1).
func TestARevocationWhoseSealFailedIsNotUndoneByAPutBack(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_000_000, 0).UTC()
	inner := memory.New(func() time.Time { return now })
	fails := &sealFailsStore{RevStore: inner}
	l := NewLedger()
	daemon := Wrap(inner, keys(), nil, WithLedger(l))
	broker := Wrap(fails, keys(), nil, WithLedger(l))
	k := store.ContextKey{NAS: "leaf-01", Username: "netops"}
	alice := store.Context{CtxID: "alice-1", Principal: "user:alice@example.com", Username: "netops", PrivLvl: 15}
	if err := daemon.PutContext(ctx, k, alice, time.Hour); err != nil {
		t.Fatal(err)
	}
	l.SetBase(inner.Seen() + 1)
	earlier, err := inner.GetContext(ctx, k)
	if err != nil {
		t.Fatal(err)
	}
	if err := broker.SetRevokedAt(ctx, k, now); !errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("a revocation whose seal failed: %v", err)
	}
	fails.down.Store(false)
	if err := inner.PutContext(ctx, k, earlier, time.Hour); err != nil { // put back
		t.Fatal(err)
	}
	for name, s := range map[string]store.Store{"daemon": daemon, "broker": broker} {
		if got, err := s.GetContext(ctx, k); err != nil || !got.RevokedAt.Equal(now) {
			t.Fatalf("%s read the record before a revocation whose seal failed: %+v %v", name, got, err)
		}
	}
	if err := daemon.PutContext(ctx, k, store.Context{CtxID: "alice-2", Principal: "user:alice@example.com",
		Username: "netops", PrivLvl: 15}, time.Hour); err != nil {
		t.Fatal(err)
	}
	if got, err := daemon.GetContext(ctx, k); err != nil || !got.RevokedAt.IsZero() {
		t.Fatalf("a login after the floor: %+v %v", got, err)
	}
}

// The floor is cleared only by a later sequence: a record at or below the
// sequence it holds through, read or written, keeps it, and so does a
// write that failed, which tells the ledger nothing. Set at a key with no
// mark, it holds through every sequence below the revision this process
// had seen when the plaintext mark landed, which a write sent after it
// seals above. A plaintext revocation read at the mark sets it too; and it
// is the latest revocation (final review 7d-2 I-1; plan 7e, Ruling 3).
func TestTheRevocationFloorIsClearedOnlyByALaterWrite(t *testing.T) {
	now := time.Unix(1_000_000, 0).UTC()
	k := store.ContextKey{NAS: "leaf-01", Username: "netops"}
	l := NewLedger()
	l.revoked(k, now, 6)                          // no mark at k; the plaintext mark landed by revision 6
	l.Observe(k, 5, 10, time.Time{}, time.Time{}) // a record sealed before it, put back
	if got := l.floor(k); !got.Equal(now) {
		t.Fatalf("a record sealed before the revocation cleared the floor: %v", got)
	}
	l.Observe(k, 5, 11, time.Time{}, time.Time{}) // the same record, read again
	l.Observe(k, 3, 12, time.Time{}, time.Time{}) // an earlier one
	if got := l.floor(k); !got.Equal(now) {
		t.Fatalf("a record at or below the floor's sequence cleared it: %v", got)
	}
	l.wrote(k, 6, 13, time.Time{}) // sealed at the revision seen: sent after
	if got := l.floor(k); !got.IsZero() {
		t.Fatalf("a later sequence kept the floor: %v", got)
	}
	l.revoked(k, now, 2) // at the mark, 6, whatever was seen
	l.Observe(k, 6, 14, time.Time{}, time.Time{})
	if got := l.floor(k); !got.Equal(now) {
		t.Fatalf("the record the revocation landed on cleared the floor: %v", got)
	}
	l.Observe(k, 7, 15, time.Time{}, time.Time{})
	if got := l.floor(k); !got.IsZero() {
		t.Fatalf("a later sequence, read, kept the floor: %v", got)
	}
	l.Observe(k, 7, 16, now, time.Time{}) // a plaintext revocation at the mark
	if got := l.floor(k); !got.Equal(now) {
		t.Fatalf("a plaintext revocation read at the mark is not the floor: %v", got)
	}
	l.revoked(k, now.Add(-time.Minute), 0)
	l.revoked(k, now, 0)
	l.revoked(k, now.Add(-time.Minute), 0)
	if got := l.floor(k); !got.Equal(now) {
		t.Fatalf("the floor is not the latest revocation: %v", got)
	}
	// A plaintext revocation read at the mark does not lower a floor held
	// through the revision seen: a record sealed before the revocation,
	// above the mark, still keeps it (Task 7 review M-3).
	l = NewLedger()
	l.Observe(k, 7, 7, time.Time{}, time.Time{})
	l.revoked(k, now, 101) // through 100
	l.Observe(k, 7, 8, now.Add(time.Minute), time.Time{})
	l.Observe(k, 50, 50, time.Time{}, time.Time{}) // sealed before the revocation
	if got := l.floor(k); got.IsZero() {
		t.Fatal("a plaintext revocation at the mark lowered the floor's sequence")
	}
}

// A context this process cannot open (a form-3 record at the 7e upgrade)
// is revoked by the start's refresh, at a key the ledger has no mark for,
// and the user's next login replaces it: that login is not read as
// revoked (Task 7 self-review: a floor that took the next sequence as its
// own held every first login after the upgrade revoked).
func TestALoginAfterRevokingAnUnopenableContextIsNotRevoked(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_000_000, 0).UTC()
	inner := memory.New(func() time.Time { return now })
	l := NewLedger()
	l.SetBase(inner.Seen() + 1)
	s := Wrap(inner, keys(), nil, WithLedger(l))
	body, _ := json.Marshal(map[string]any{"v": 3, "ctx_id": "c-old", "principal": "user:alice",
		"username": "netops"})
	sealed, _ := keys().SealBound(body, contextAAD(ka))
	if err := inner.PutContext(ctx, ka, store.Context{Sealed: sealed}, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := s.SetRevokedAt(ctx, ka, now); err != nil {
		t.Fatal(err)
	}
	login(t, s, "ctx-new", "user:alice")
	if c, err := s.GetContext(ctx, ka); err != nil || !c.RevokedAt.IsZero() {
		t.Fatalf("the login after the revocation reads as revoked: %v %v", c.RevokedAt, err)
	}
}

// readHoldingStore holds the first GetContext after the store has read
// the record, before it returns, so the sealing layer has not yet asked
// the ledger.
type readHoldingStore struct {
	store.RevStore
	read, release chan struct{}
	held          atomic.Bool
}

func (h *readHoldingStore) GetContext(ctx context.Context, k store.ContextKey) (store.Context, error) {
	c, err := h.RevStore.GetContext(ctx, k)
	if h.held.CompareAndSwap(false, true) {
		close(h.read)
		<-h.release
	}
	return c, err
}

// A read that races a write of the same context, landing and ending
// between the store's read and the ledger's check, read the write before
// the last: its revision is below the last's, so it is stale, not put
// back, and the layer reads again and is answered from the last. Through
// either Wrap, whichever wrote (Task 13b review I-1).
func TestAReadRacingAWriteOfTheSameContextReadsAgain(t *testing.T) {
	for _, reader := range []string{"daemon", "broker"} {
		t.Run(reader, func(t *testing.T) {
			ctx := context.Background()
			now := time.Unix(1_000_000, 0).UTC()
			h := &readHoldingStore{RevStore: memory.New(func() time.Time { return now }), read: make(chan struct{}),
				release: make(chan struct{})}
			l := NewLedger()
			wraps := map[string]store.Store{"daemon": Wrap(h, keys(), nil, WithLedger(l)),
				"broker": Wrap(h, keys(), nil, WithLedger(l))}
			writer := wraps["daemon"]
			if reader == "daemon" {
				writer = wraps["broker"]
			}
			k := store.ContextKey{NAS: "leaf-01", Username: "netops"}
			l.SetBase(h.Seen() + 1)
			if err := writer.PutContext(ctx, k, store.Context{CtxID: "alice-1", Principal: "user:alice@example.com",
				Username: "netops", PrivLvl: 1}, time.Hour); err != nil {
				t.Fatal(err)
			}
			type got struct {
				c   store.Context
				err error
			}
			done := make(chan got)
			go func() {
				c, err := wraps[reader].GetContext(ctx, k)
				done <- got{c, err}
			}()
			<-h.read
			if err := writer.SetPrivilege(ctx, k, 15); err != nil {
				t.Fatal(err)
			}
			close(h.release)
			if g := <-done; g.err != nil || g.c.PrivLvl != 15 {
				t.Fatalf("a read racing a write of the same context: %+v %v", g.c, g.err)
			}
		})
	}
}

// holdingStore holds the first SwapContext after it has landed, before it
// returns, so the sealing layer has not yet told the ledger it ended.
type holdingStore struct {
	store.RevStore
	landed, release chan struct{}
	held            atomic.Bool
}

func (h *holdingStore) SwapContextRev(ctx context.Context, k store.ContextKey, rev uint64, c store.Context,
	ttl time.Duration) (uint64, error) {
	committed, err := h.RevStore.SwapContextRev(ctx, k, rev, c, ttl)
	if h.held.CompareAndSwap(false, true) {
		close(h.landed)
		<-h.release
	}
	return committed, err
}

// Two first logins racing on a key no context holds, which is every first
// login to a device and username, and every login after a context
// expired. Alice's write lands on no record and is held before it ends;
// Bob's reads it, swaps on its revision, sealing above it, and ends first.
// The store holds Bob's, and it is admitted whatever order the writes end
// in; Alice's written back is still another login's (Task 4b fix 2 review
// I2; Task 6b; plan 7e, Ruling 3).
func TestFirstLoginsRacingOnAnEmptyKey(t *testing.T) {
	s, inner, k, aliceSealed := twoLoginsEndOutOfOrder(t)
	if got, err := s.GetContext(context.Background(), k); err != nil || got.CtxID != "bob-1" {
		t.Fatalf("the write the store committed last: %q %v", got.CtxID, err)
	}
	if err := inner.PutContext(context.Background(), k, aliceSealed, time.Hour); err != nil { // Alice's, written back
		t.Fatal(err)
	}
	if _, err := s.GetContext(context.Background(), k); !errors.Is(err, ErrNotLastWritten) {
		t.Fatalf("the write the store committed first, written back: %v", err)
	}
}

// twoLoginsEndOutOfOrder races Alice's write and Bob's at k, on no
// record, so that Bob's swaps on Alice's and ends first. It returns the
// sealing layer, the store under it, and Alice's sealed record.
func twoLoginsEndOutOfOrder(t *testing.T) (store.Store, store.Store, store.ContextKey, store.Context) {
	t.Helper()
	ctx := context.Background()
	now := time.Unix(1_000_000, 0).UTC()
	inner := memory.New(func() time.Time { return now })
	h := &holdingStore{RevStore: inner, landed: make(chan struct{}), release: make(chan struct{})}
	l := NewLedger()
	s := Wrap(h, keys(), nil, WithLedger(l))
	k := store.ContextKey{NAS: "leaf-01", Username: "netops"}
	l.SetBase(inner.Seen() + 1)
	done := make(chan error)
	go func() {
		done <- s.SwapContext(ctx, k, 0, store.Context{CtxID: "alice-1", Principal: "user:alice@example.com",
			Username: "netops", PrivLvl: 15}, time.Hour)
	}()
	<-h.landed
	aliceSealed, err := inner.GetContext(ctx, k)
	if err != nil {
		t.Fatal(err)
	}
	alice, err := s.GetContext(ctx, k)
	if err != nil || alice.CtxID != "alice-1" {
		t.Fatalf("a write in flight: %q %v", alice.CtxID, err)
	}
	if err := s.SwapContext(ctx, k, alice.Rev, store.Context{CtxID: "bob-1", Principal: "user:bob@example.com",
		Username: "netops", PrivLvl: 1}, time.Hour); err != nil {
		t.Fatal(err)
	}
	close(h.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	return s, inner, k, aliceSealed
}

// A record that will not open is told to OnUnopenable with its kind and
// the key id its header names, beside the counter; a token among
// candidates is dropped as before (plan 7d; the plan 2 alarm).
func TestAnUnopenableRecordNamesItsKey(t *testing.T) {
	now := time.Unix(1000, 0)
	inner := memory.New(func() time.Time { return now })
	old := Keys{Current: Key{ID: "enc2", Bytes: [32]byte{2}}}
	cur := Keys{Current: Key{ID: "enc3", Bytes: [32]byte{3}}}
	k := store.TokenKey{NAS: "leaf-01", Username: "alice"}
	if _, err := Wrap(inner, old, nil).PutToken(context.Background(), k, store.Token{ID: "t", Secret: []byte("s"),
		ExpiresAt: now.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	var told [][2]string
	s := Wrap(inner, cur, nil, OnUnopenable(func(record, keyID string, _ error) { told = append(told, [2]string{record, keyID}) }))
	if got, err := s.Candidates(context.Background(), k); err != nil || len(got) != 0 {
		t.Fatalf("%v %v", got, err)
	}
	if len(told) != 1 || told[0] != [2]string{"token", "enc2"} {
		t.Fatalf("told %v", told)
	}
	if SealedKeyID(nil) != "" || SealedKeyID([]byte{9, 'a'}) != "" {
		t.Fatal("a short or empty record names no key")
	}
	// A header is the record's, so anyone who can write the store writes
	// it: what it names is echoed only within the key-id charset
	// (pre-flight M44).
	if got := SealedKeyID(append([]byte{5}, "a\nb;c"...)); got != "?" {
		t.Fatalf("a header outside the key-id charset named %q", got)
	}
}
