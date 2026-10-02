package crypt

import (
	"bytes"
	"context"
	"errors"
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

// The ledger (re-check IA1; the controller's ruling): another login's
// context written back at a key is denied ErrNotLastWritten, through
// either Wrap sharing the ledger. An earlier version of the same context
// opens, which is the residual Ruling 17 states. A fresh process takes the
// first record it reads as the key's, the restart residual, and denies
// another after it.
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
	if got, err := daemon.GetContext(ctx, k); err != nil || got.CtxID != "bob-1" || got.PrivLvl != 1 {
		t.Fatalf("an earlier version of the same context: %+v %v (the residual)", got, err)
	}
	fresh := Wrap(inner, keys(), nil) // a restart: its own, empty ledger
	if err := inner.PutContext(ctx, k, alice, time.Hour); err != nil {
		t.Fatal(err)
	}
	if got, err := fresh.GetContext(ctx, k); err != nil || got.CtxID != "alice-1" {
		t.Fatalf("a fresh process's first read: %+v %v (the restart residual)", got, err)
	}
	if err := inner.PutContext(ctx, k, bob, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := fresh.GetContext(ctx, k); !errors.Is(err, ErrNotLastWritten) {
		t.Fatalf("after its first read, a fresh process read another login's: %v", err)
	}
}

// A write in flight is admitted beside the last one, a write that landed
// replaces it, one refused admits nothing, and one whose outcome is
// unknown stays admitted until a later write lands, or until a read finds
// it, which proves it landed (re-check IA1; re-check 2 M-B1).
func TestTheLedgerAdmitsWritesInFlight(t *testing.T) {
	l := NewLedger()
	k := store.ContextKey{NAS: "leaf-01", Username: "netops"}
	if !l.admits(k, "a") {
		t.Fatal("a first read is the key's")
	}
	b := l.begin(k, "b", 0)
	if !l.admits(k, "a") || !l.admits(k, "b") || l.admits(k, "x") {
		t.Fatal("a write in flight")
	}
	l.end(b, 1, nil)
	if l.admits(k, "a") || !l.admits(k, "b") {
		t.Fatal("a write that landed")
	}
	l.end(l.begin(k, "c", 0), 0, store.ErrConflict)
	if l.admits(k, "c") {
		t.Fatal("a conflict wrote nothing")
	}
	l.end(l.begin(k, "d", 0), 0, store.ErrUnavailable)
	if !l.admits(k, "b") || !l.admits(k, "d") {
		t.Fatal("a write whose outcome is unknown may have landed")
	}
	// The read of d is the store holding it: it landed, and b is gone.
	if l.admits(k, "b") || !l.admits(k, "d") {
		t.Fatal("a read of a write whose outcome was unknown did not settle it")
	}
	l.end(l.begin(k, "e", 0), 0, store.ErrUnavailable)
	l.end(l.begin(k, "f", 0), 3, nil)
	if l.admits(k, "e") || l.admits(k, "d") || !l.admits(k, "f") {
		t.Fatal("a later write landed")
	}
}

// A read that finds a write whose outcome was unknown settles every one:
// the store holds that one, so a later write whose outcome is unknown too
// did not land over it, and is not admitted (Task 4b review M4).
func TestAReadSettlesEveryWriteWhoseOutcomeWasUnknown(t *testing.T) {
	l := NewLedger()
	k := store.ContextKey{NAS: "leaf-01", Username: "netops"}
	for _, id := range []string{"d", "e"} {
		l.end(l.begin(k, id, 0), 0, store.ErrUnavailable)
	}
	if !l.admits(k, "d") {
		t.Fatal("a write whose outcome is unknown may have landed")
	}
	if l.admits(k, "e") {
		t.Fatal("a read of d left e admitted")
	}
}

// The ledger forgets a key the store holds nothing at: a delete that
// landed, or after Seal a read that found nothing. A sealed ledger then
// admits nothing there but what this process writes, so forgetting fails
// closed; a write sent since the delete or the read was keeps the entry
// (Task 4b review M5).
func TestTheLedgerForgetsAKeyTheStoreNoLongerHolds(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_000_000, 0).UTC()
	inner := memory.New(func() time.Time { return now })
	l := NewLedger()
	s := Wrap(inner, keys(), nil, WithLedger(l))
	k := store.ContextKey{NAS: "leaf-01", Username: "netops"}
	alice := store.Context{CtxID: "alice-1", Principal: "user:alice@example.com", Username: "netops", PrivLvl: 15}
	// Before Seal a read that finds nothing keeps the entry: forgetting it
	// would let the next read seed the key.
	l.end(l.begin(k, "a", 0), 1, nil)
	if _, err := s.GetContext(ctx, k); !errors.Is(err, store.ErrNotFound) || len(l.m) != 1 {
		t.Fatalf("a read before Seal that found nothing: %v %v", err, l.m)
	}
	l.Seal()
	if err := s.PutContext(ctx, k, alice, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteContext(ctx, k); err != nil {
		t.Fatal(err)
	}
	if len(l.m) != 0 {
		t.Fatalf("a delete that landed kept the entry: %v", l.m)
	}
	// Alice's record put back where it was deleted is not this key's now.
	if err := Wrap(inner, keys(), nil).PutContext(ctx, k, alice, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetContext(ctx, k); !errors.Is(err, ErrNotLastWritten) {
		t.Fatalf("a record put back at a forgotten key: %v", err)
	}
	if err := inner.DeleteContext(ctx, k); err != nil {
		t.Fatal(err)
	}
	if err := s.PutContext(ctx, k, alice, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := inner.DeleteContext(ctx, k); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetContext(ctx, k); !errors.Is(err, store.ErrNotFound) || len(l.m) != 0 {
		t.Fatalf("a read after Seal that found nothing kept the entry: %v %v", err, l.m)
	}
	// A write sent after the read or the delete was keeps the entry.
	at := l.mark()
	l.end(l.begin(k, "b", 0), 100, nil)
	l.forget(k, at, false)
	if !l.admits(k, "b") {
		t.Fatal("a write sent after the delete was is forgotten")
	}
	l.begin(k, "c", 0)
	l.forget(k, l.mark(), false)
	if !l.admits(k, "c") {
		t.Fatal("a write in flight is forgotten")
	}
}

// A sealed ledger admits nothing at a key it has never seen, except what
// this process writes there itself; before Seal, the first record read at
// an unseen key is the key's (re-check 2 I1; decision 35). port49d seals
// it once the start has read every kept context, so a record put back at
// an empty key, after the start, is never taken as that key's.
func TestASealedLedgerAdmitsNoUnseenKey(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_000_000, 0).UTC()
	inner := memory.New(func() time.Time { return now })
	l := NewLedger()
	s := Wrap(inner, keys(), nil, WithLedger(l))
	alice := store.Context{CtxID: "alice-1", Principal: "user:alice@example.com", Username: "netops", PrivLvl: 15}
	kept := store.ContextKey{NAS: "leaf-01", Username: "netops"}
	if err := Wrap(inner, keys(), nil).PutContext(ctx, kept, alice, time.Hour); err != nil {
		t.Fatal(err)
	}
	// Before Seal: the start's read of a kept context seeds the key.
	if got, err := s.GetContext(ctx, kept); err != nil || got.CtxID != "alice-1" {
		t.Fatalf("a first read before Seal: %+v %v", got, err)
	}
	l.Seal()
	if got, err := s.GetContext(ctx, kept); err != nil || got.CtxID != "alice-1" {
		t.Fatalf("a key seeded before Seal: %+v %v", got, err)
	}
	// After Seal: Alice's record put back at a key no one here has read.
	empty := store.ContextKey{NAS: "leaf-02", Username: "netops"}
	other := Wrap(inner, keys(), nil)
	if err := other.PutContext(ctx, empty, alice, time.Hour); err != nil {
		t.Fatal(err)
	}
	var u *store.UnreadableContextError
	for range 2 { // denied, and the denial seeds nothing
		if _, err := s.GetContext(ctx, empty); !errors.As(err, &u) || !errors.Is(err, ErrNotLastWritten) {
			t.Fatalf("an unseen key after Seal: %v", err)
		}
	}
	// This process's own write at an unseen key is admitted.
	own := store.ContextKey{NAS: "leaf-03", Username: "netops"}
	if err := s.PutContext(ctx, own, store.Context{CtxID: "bob-1", Principal: "user:bob@example.com",
		Username: "netops"}, time.Hour); err != nil {
		t.Fatal(err)
	}
	if got, err := s.GetContext(ctx, own); err != nil || got.CtxID != "bob-1" {
		t.Fatalf("its own write after Seal: %+v %v", got, err)
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

// Two logins' writes that end out of the order the store committed them
// in: the store holds the second, and the ledger admits it, not the first
// (Task 4b defect, LoginsRaceToOneIndex). Alice's write lands on Carol's
// context and is held before it ends; Bob's reads it, admitted in flight,
// swaps on its revision and ends. Alice's ends after. The record Bob wrote
// is the key's, and Alice's written back is still another login's.
func TestTheLedgerOrdersWritesByTheStoresCommit(t *testing.T) {
	s, inner, k, aliceSealed := twoLoginsEndOutOfOrder(t, true)
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

// The same race on a key no context holds, which is every first login to
// a device and username, and every login after a context expired. Alice's
// write compared on no record, so only the revision it committed at
// places it: below Bob's, so its late end leaves Bob's the key's, and
// Alice's written back is still another login's (Task 4b fix 2 review I2;
// Task 6b).
func TestFirstLoginsRacingOnAnEmptyKey(t *testing.T) {
	s, inner, k, aliceSealed := twoLoginsEndOutOfOrder(t, false)
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

// twoLoginsEndOutOfOrder races Alice's write and Bob's at k, on Carol's
// context when seeded and on no record otherwise, so that Bob's swaps on
// Alice's and ends first. It returns the sealing layer, the store under
// it, and Alice's sealed record.
func twoLoginsEndOutOfOrder(t *testing.T, seeded bool) (store.Store, store.Store, store.ContextKey, store.Context) {
	t.Helper()
	ctx := context.Background()
	now := time.Unix(1_000_000, 0).UTC()
	inner := memory.New(func() time.Time { return now })
	h := &holdingStore{RevStore: inner, landed: make(chan struct{}), release: make(chan struct{})}
	l := NewLedger()
	s := Wrap(h, keys(), nil, WithLedger(l))
	k := store.ContextKey{NAS: "leaf-01", Username: "netops"}
	l.Seal()
	var rev uint64
	if seeded {
		if err := s.PutContext(ctx, k, store.Context{CtxID: "carol-1", Principal: "user:carol@example.com",
			Username: "netops"}, time.Hour); err != nil {
			t.Fatal(err)
		}
		carol, err := s.GetContext(ctx, k)
		if err != nil {
			t.Fatal(err)
		}
		rev = carol.Rev
	}
	done := make(chan error)
	go func() {
		done <- s.SwapContext(ctx, k, rev, store.Context{CtxID: "alice-1", Principal: "user:alice@example.com",
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

// Each landed write is placed by the revision it committed at, whatever
// order the writes end in. A write that compared on a revision below the
// last's committed before it, if it landed: ending with an unknown outcome
// it is not admitted. A landed write whose revision is unknown leaves the
// key admitting neither it nor the last (Ledger; Task 6b).
func TestTheLedgerPlacesAWriteThatEndsLate(t *testing.T) {
	k := store.ContextKey{NAS: "leaf-01", Username: "netops"}

	// b compared on 5 and committed at 6, the record was deleted, and c
	// landed on no record at 8; b ends last.
	l := NewLedger()
	l.admits(k, "a")
	b := l.begin(k, "b", 5)
	l.end(l.begin(k, "c", 0), 8, nil)
	l.end(b, 6, nil)
	if l.admits(k, "b") || !l.admits(k, "c") {
		t.Fatal("a write committed before the last replaced it")
	}

	// The same, b ending with an unknown outcome: it compared below the
	// last's revision, so the store does not hold it, and a read of it
	// back is not admitted (fix 2 review M1).
	l = NewLedger()
	l.admits(k, "a")
	b = l.begin(k, "b", 5)
	l.end(l.begin(k, "c", 0), 8, nil)
	l.end(b, 0, store.ErrUnavailable)
	if l.admits(k, "b") || !l.admits(k, "c") {
		t.Fatal("a write compared below the last, its outcome unknown, was admitted")
	}

	// b compared on no record and committed at 4, c swapped on it at 6;
	// b ends last. This is the empty-key race (fix 2 review I2).
	l = NewLedger()
	l.admits(k, "a")
	b = l.begin(k, "b", 0)
	l.end(l.begin(k, "c", 4), 6, nil)
	l.end(b, 4, nil)
	if l.admits(k, "b") || !l.admits(k, "c") {
		t.Fatal("a write on no record, committed first and ending last, replaced the last")
	}

	// b compared on no record and committed at 9, after c at 6: it is the
	// last, whichever ends first.
	l = NewLedger()
	l.admits(k, "a")
	b = l.begin(k, "b", 0)
	l.end(l.begin(k, "c", 4), 6, nil)
	l.end(b, 9, nil)
	if l.admits(k, "c") || !l.admits(k, "b") {
		t.Fatal("a write committed after the last did not replace it")
	}

	// b landed, and the store did not say at what revision: it or c is
	// the store's, and neither is admitted until a write lands at a known
	// one.
	l = NewLedger()
	l.admits(k, "a")
	l.end(l.begin(k, "c", 0), 6, nil)
	l.end(l.begin(k, "b", 6), 0, nil)
	if l.admits(k, "b") || l.admits(k, "c") {
		t.Fatal("a write landed at an unknown revision, and a record was admitted")
	}
	l.end(l.begin(k, "d", 0), 7, nil)
	if !l.admits(k, "d") {
		t.Fatal("a write landed at a known revision after one at an unknown")
	}
}

// A read sets the last at no revision, so any write that lands after
// replaces it: a write that compared on 3 and ends after another landed
// and a record whose outcome was unknown was read back is the last, and
// the read one is denied (fix 2 re-review N1).
func TestAReadSetsTheLastAtNoRevision(t *testing.T) {
	k := store.ContextKey{NAS: "leaf-01", Username: "netops"}
	l := NewLedger()
	l.admits(k, "a")
	w := l.begin(k, "w", 3)
	l.end(l.begin(k, "x", 0), 10, nil)
	l.end(l.begin(k, "d", 0), 0, store.ErrUnavailable)
	if !l.admits(k, "d") {
		t.Fatal("a write whose outcome was unknown, read back")
	}
	l.end(w, 4, nil)
	if l.admits(k, "d") || !l.admits(k, "w") {
		t.Fatal("a write that landed after a read did not replace the record read")
	}
}

// A record whose write's outcome was unknown, put back and read while
// another write has landed and not yet ended, is admitted for that read,
// and denied once the other write ends: that write is the last, as it was
// before the ledger placed writes (fix 2 review I1).
func TestAReplayReadBeforeALandedWriteEndsIsDeniedAfter(t *testing.T) {
	k := store.ContextKey{NAS: "leaf-01", Username: "netops"}
	l := NewLedger()
	l.admits(k, "a")
	l.end(l.begin(k, "d", 0), 0, store.ErrUnavailable)
	w := l.begin(k, "w", 3) // lands at 8; d is put back at 9 before w ends
	if !l.admits(k, "d") {
		t.Fatal("a write whose outcome was unknown, read back")
	}
	l.end(w, 8, nil)
	if l.admits(k, "d") || !l.admits(k, "w") {
		t.Fatal("a replay read before a landed write ended outlived its end")
	}
}

// A write sent after the last ended committed after it, so one that
// reports a lower revision is the store's revisions going back, as an etcd
// restore from a snapshot does: it is the last (Task 6b review C1).
func TestTheLedgerPlacesAWriteAfterTheStoresRevisionsWentBack(t *testing.T) {
	k := store.ContextKey{NAS: "leaf-01", Username: "netops"}
	l := NewLedger()
	l.admits(k, "a")
	l.end(l.begin(k, "x", 0), 1000, nil)
	l.end(l.begin(k, "w", 4), 5, nil)
	if l.admits(k, "x") || !l.admits(k, "w") {
		t.Fatal("a write sent after the last ended, at a lower revision, did not replace it")
	}
}

// offsetStore reports every context revision off above the store's, and
// takes them back on a compare: setting off to zero is an etcd restore,
// whose revisions go back.
type offsetStore struct {
	*memory.Store
	off uint64
}

func (o *offsetStore) in(rev uint64) uint64 {
	if rev == 0 {
		return 0
	}
	return rev - o.off
}

func (o *offsetStore) out(rev uint64, err error) (uint64, error) {
	if err != nil {
		return 0, err
	}
	return rev + o.off, nil
}

func (o *offsetStore) GetContext(ctx context.Context, k store.ContextKey) (store.Context, error) {
	c, err := o.Store.GetContext(ctx, k)
	if err == nil {
		c.Rev += o.off
	}
	return c, err
}

func (o *offsetStore) PutContextRev(ctx context.Context, k store.ContextKey, c store.Context, ttl time.Duration) (uint64, error) {
	return o.out(o.Store.PutContextRev(ctx, k, c, ttl))
}

func (o *offsetStore) SwapContextRev(ctx context.Context, k store.ContextKey, rev uint64, c store.Context,
	ttl time.Duration) (uint64, error) {
	return o.out(o.Store.SwapContextRev(ctx, k, o.in(rev), c, ttl))
}

// A port49d running across an etcd restore: Bob's login, made after the
// snapshot, is the ledger's last at a revision the restored store will not
// reach for a while. Carol's login after the restore is admitted, and
// Bob's record, saved and written back over hers, is denied (Task 6b
// review C1).
func TestALoginAfterARestoreIsTheLast(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_000_000, 0).UTC()
	inner := &offsetStore{Store: memory.New(func() time.Time { return now }), off: 1000}
	l := NewLedger()
	s := Wrap(inner, keys(), nil, WithLedger(l))
	k := store.ContextKey{NAS: "leaf-01", Username: "netops"}
	l.Seal()
	login := func(id string, priv uint8) store.Context {
		return store.Context{CtxID: id, Principal: "user:" + id + "@example.com", Username: "netops", PrivLvl: priv}
	}
	if err := s.PutContext(ctx, k, login("alice-1", 1), time.Hour); err != nil {
		t.Fatal(err)
	}
	snapshot, err := inner.Store.GetContext(ctx, k)
	if err != nil {
		t.Fatal(err)
	}
	alice, err := s.GetContext(ctx, k)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SwapContext(ctx, k, alice.Rev, login("bob-1", 15), time.Hour); err != nil {
		t.Fatal(err)
	}
	bobSealed, err := inner.Store.GetContext(ctx, k)
	if err != nil {
		t.Fatal(err)
	}

	inner.off = 0 // the restore
	if err := inner.Store.PutContext(ctx, k, snapshot, time.Hour); err != nil {
		t.Fatal(err)
	}
	var u *store.UnreadableContextError
	if _, err := s.GetContext(ctx, k); !errors.As(err, &u) {
		t.Fatalf("Alice's record, restored: %v", err)
	}
	if err := s.SwapContext(ctx, k, u.Rev, login("carol-1", 1), time.Hour); err != nil {
		t.Fatal(err)
	}
	if got, err := s.GetContext(ctx, k); err != nil || got.CtxID != "carol-1" {
		t.Errorf("Carol's login after the restore: %q %v", got.CtxID, err)
	}
	if err := inner.Store.PutContext(ctx, k, bobSealed, time.Hour); err != nil { // Bob's, written back
		t.Fatal(err)
	}
	if got, err := s.GetContext(ctx, k); !errors.Is(err, ErrNotLastWritten) {
		t.Errorf("Bob's record written back over Carol's: %q %v", got.CtxID, err)
	}
}
