// Package crypt is the encryption-at-rest layer (design §8). It decorates a
// store.Store so that identity and credential fields are sealed before they
// reach any backend, under a current key with one previous key accepted.
//
// What is NOT sealed is deliberate and is argued in plan 2 Task 5: blobs (no
// identity) and the four indexes. A dump of the index reveals principal, device
// and login name; every credential-bearing record (token, receipt, context
// body) stays sealed; the index is protected by store access control rather
// than by encryption, because revocation is the path needed most on a bad day
// and must not depend on the encryption key or its rotation window being
// available.
package crypt

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/rhwendt/port49/internal/store"
)

// ErrUnknownKey is returned when a sealed record names a key id that is neither
// the current key nor the previous one. It is deliberately distinguishable from
// store.ErrNotFound: a record that will not open is a key problem, not a missing
// record.
var ErrUnknownKey = errors.New("crypt: sealed under an unknown key")

// Key is one AES-256 key and the id that travels with every record it seals.
type Key struct {
	ID    string
	Bytes [32]byte
}

// Keys is the rotation window: everything is written under Current, and reads
// accept Previous as well so a rotation does not invalidate live records.
// Previous is nil when no key is being retired.
type Keys struct {
	Current  Key
	Previous *Key
}

// Seal: len(id) ‖ id ‖ nonce ‖ AES-256-GCM(plaintext, aad=id). The key id
// travels with the ciphertext so a read knows which key to try first, and it
// is the AAD so a record cannot be re-labelled with another key's id.
func (k Keys) Seal(plaintext []byte) ([]byte, error) { return seal(k.Current, plaintext) }

func seal(key Key, plaintext []byte) ([]byte, error) {
	if len(key.ID) == 0 || len(key.ID) > 255 {
		return nil, errors.New("crypt: key id must be 1..255 bytes")
	}
	block, err := aes.NewCipher(key.Bytes[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	out := append([]byte{byte(len(key.ID))}, key.ID...)
	out = append(out, nonce...)
	return gcm.Seal(out, nonce, plaintext, []byte(key.ID)), nil
}

// Open reverses Seal under whichever of the two keys the record names. It
// returns ErrUnknownKey when neither matches, and the GCM authentication error
// when the key matched and the bytes did not.
func (k Keys) Open(sealed []byte) ([]byte, error) {
	if len(sealed) < 1 {
		return nil, ErrUnknownKey
	}
	n := int(sealed[0])
	if len(sealed) < 1+n {
		return nil, ErrUnknownKey
	}
	id := string(sealed[1 : 1+n])
	var key *Key
	switch {
	case id == k.Current.ID:
		key = &k.Current
	case k.Previous != nil && id == k.Previous.ID:
		key = k.Previous
	default:
		return nil, ErrUnknownKey
	}
	block, err := aes.NewCipher(key.Bytes[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	rest := sealed[1+n:]
	if len(rest) < gcm.NonceSize() {
		return nil, errors.New("crypt: short ciphertext")
	}
	return gcm.Open(nil, rest[:gcm.NonceSize()], rest[gcm.NonceSize():], []byte(id))
}

// The sealed portions, as JSON before encryption.
type tokenSecret struct {
	Secret     []byte           `json:"secret"`
	Principal  string           `json:"principal"`
	Username   string           `json:"username"`
	Credential store.Credential `json:"credential"`
}

type receiptSecret struct {
	CredentialSHA256 [32]byte `json:"credential_sha256"`
	Status           uint8    `json:"status"`
	CtxID            string   `json:"ctx_id"`
}

type contextSecret struct {
	CtxID      string           `json:"ctx_id"`
	Principal  string           `json:"principal"`
	Username   string           `json:"username"`
	Port       string           `json:"port"`
	RemAddr    string           `json:"rem_addr"`
	Credential store.Credential `json:"credential"`
}

type wrapped struct {
	inner        store.Store
	keys         Keys
	openFailures *prometheus.CounterVec
}

// Wrap decorates inner so every credential-bearing record is sealed under k
// before it reaches the backend. openFailures may be nil; the daemon passes
// metrics.CryptOpenFailures.
func Wrap(inner store.Store, k Keys, openFailures *prometheus.CounterVec) store.Store {
	return &wrapped{inner: inner, keys: k, openFailures: openFailures}
}

// openErr is what every read returns when a record will not open. It is
// deliberately NOT store.ErrNotFound: that is the one store error every handler
// treats as ordinary — authen falls through to the candidate lookup, author
// denies context_missing, and all three packages label the metric "not_found",
// the same label an absent record produces. Collapsing a key failure into it
// makes a mis-set PORT49_ENC_V1 look exactly like every session on the fleet
// expiring at once, with nothing anywhere naming decryption. Handlers take
// their existing non-ErrNotFound branch instead — store_unavailable — which is
// honest: the store is unavailable to this daemon.
func (w *wrapped) openErr(record string, err error) error {
	if w.openFailures != nil {
		w.openFailures.WithLabelValues(record).Inc()
	}
	// err is already ErrUnknownKey when neither key id matched, and a GCM or
	// JSON failure when the key matched and the bytes did not; both are
	// wrapped as they are, so `errors.Is(err, ErrUnknownKey)` distinguishes
	// "wrong key" from "tampered record" at the call site.
	return fmt.Errorf("crypt: opening %s: %w", record, err)
}

func (w *wrapped) sealJSON(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return w.keys.Seal(b)
}

func (w *wrapped) openJSON(sealed []byte, v any) error {
	b, err := w.keys.Open(sealed)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

func (w *wrapped) sealToken(t store.Token) (store.Token, error) {
	s, err := w.sealJSON(tokenSecret{Secret: t.Secret, Principal: t.Principal, Username: t.Username, Credential: t.Credential})
	if err != nil {
		return store.Token{}, err
	}
	t.Secret, t.Principal, t.Username, t.Credential, t.Sealed = nil, "", "", store.Credential{}, s
	return t, nil
}

func (w *wrapped) openToken(t store.Token) (store.Token, error) {
	var ts tokenSecret
	if err := w.openJSON(t.Sealed, &ts); err != nil {
		return store.Token{}, err
	}
	t.Secret, t.Principal, t.Username, t.Credential, t.Sealed = ts.Secret, ts.Principal, ts.Username, ts.Credential, nil
	return t, nil
}

func (w *wrapped) PutToken(ctx context.Context, k store.TokenKey, t store.Token) (int, error) {
	st, err := w.sealToken(t)
	if err != nil {
		return 0, err
	}
	return w.inner.PutToken(ctx, k, st)
}

func (w *wrapped) Candidates(ctx context.Context, k store.TokenKey) ([]store.Token, error) {
	raw, err := w.inner.Candidates(ctx, k)
	if err != nil {
		return nil, err
	}
	out := make([]store.Token, 0, len(raw))
	for _, t := range raw {
		ot, err := w.openToken(t)
		if err != nil {
			// Sealed under a retired key: unreadable, therefore unredeemable.
			// Returning it with a zero Secret would match a zero-length
			// credential, so it is dropped; expiry reclaims the record. This is
			// the one read that must NOT fail the call — one unreadable token
			// in a candidate set of eight must not deny the seven — so the
			// counter is the only place it is visible. That is what
			// crypt_open_failures_total{record="token"} is for.
			_ = w.openErr("token", err)
			continue
		}
		out = append(out, ot)
	}
	return out, nil
}

func (w *wrapped) RedeemAndReceipt(ctx context.Context, k store.TokenKey, tokenID string, wr store.ReceiptWrite) error {
	s, err := w.sealJSON(receiptSecret{CredentialSHA256: wr.Receipt.CredentialSHA256, Status: wr.Receipt.Status, CtxID: wr.Receipt.CtxID})
	if err != nil {
		return err
	}
	wr.Receipt.CredentialSHA256, wr.Receipt.Status, wr.Receipt.CtxID, wr.Receipt.Sealed = [32]byte{}, 0, "", s
	return w.inner.RedeemAndReceipt(ctx, k, tokenID, wr)
}

// DeleteTokens carries no sealed field: the key alone addresses the records.
func (w *wrapped) DeleteTokens(ctx context.Context, k store.TokenKey) error {
	return w.inner.DeleteTokens(ctx, k)
}

func (w *wrapped) GetReceipt(ctx context.Context, rk store.ReceiptKey) (store.Receipt, error) {
	r, err := w.inner.GetReceipt(ctx, rk)
	if err != nil {
		return store.Receipt{}, err
	}
	var rs receiptSecret
	if err := w.openJSON(r.Sealed, &rs); err != nil {
		return store.Receipt{}, w.openErr("receipt", err)
	}
	r.CredentialSHA256, r.Status, r.CtxID, r.Sealed = rs.CredentialSHA256, rs.Status, rs.CtxID, nil
	return r, nil
}

// ExtendReceipt writes one plaintext timestamp and reads nothing sealed, which
// is why the sliding bound can be pushed out by a daemon holding any key.
func (w *wrapped) ExtendReceipt(ctx context.Context, rk store.ReceiptKey, idleExpiresAt time.Time) error {
	return w.inner.ExtendReceipt(ctx, rk, idleExpiresAt)
}

// FailReceipt writes one plaintext flag and reads nothing sealed, for the
// same reason as ExtendReceipt: a refusal has to stick under any key.
func (w *wrapped) FailReceipt(ctx context.Context, rk store.ReceiptKey) error {
	return w.inner.FailReceipt(ctx, rk)
}

// DeleteReceiptsByPrincipal walks the plaintext revocation index. It works with
// no key at all, which is the point of leaving that index unsealed.
func (w *wrapped) DeleteReceiptsByPrincipal(ctx context.Context, principal string) (int, error) {
	return w.inner.DeleteReceiptsByPrincipal(ctx, principal)
}

func (w *wrapped) sealContext(c store.Context) (store.Context, error) {
	s, err := w.sealJSON(contextSecret{CtxID: c.CtxID, Principal: c.Principal, Username: c.Username,
		Port: c.Port, RemAddr: c.RemAddr, Credential: c.Credential})
	if err != nil {
		return store.Context{}, err
	}
	c.CtxID, c.Principal, c.Username, c.Port, c.RemAddr, c.Credential, c.Sealed =
		"", "", "", "", "", store.Credential{}, s
	return c, nil
}

func (w *wrapped) PutContext(ctx context.Context, k store.ContextKey, c store.Context, ttl time.Duration) error {
	sc, err := w.sealContext(c)
	if err != nil {
		return err
	}
	return w.inner.PutContext(ctx, k, sc, ttl)
}

// SwapContext seals as PutContext does and hands the revision through
// untouched. Rev is plaintext, and that is what lets this layer take part in a
// compare-and-set at all: the inner store compares a revision it can read on a
// record it cannot, so the merge happens up here with the fields open and the
// precondition is enforced down there under its own lock (store.Store).
func (w *wrapped) SwapContext(ctx context.Context, k store.ContextKey, rev uint64, c store.Context, ttl time.Duration) error {
	sc, err := w.sealContext(c)
	if err != nil {
		return err
	}
	return w.inner.SwapContext(ctx, k, rev, sc, ttl)
}

func (w *wrapped) GetContext(ctx context.Context, k store.ContextKey) (store.Context, error) {
	c, err := w.inner.GetContext(ctx, k)
	if err != nil {
		return store.Context{}, err
	}
	var cs contextSecret
	if err := w.openJSON(c.Sealed, &cs); err != nil {
		// The record is there and will not open. Its revision and revocation
		// are plaintext, and JoinContext needs both to replace it without
		// racing a revocation or lifting one (store.UnreadableContextError).
		// The wrapped error is openErr's, so errors.Is(err, ErrUnknownKey)
		// still tells a wrong key from a tampered record.
		return store.Context{}, &store.UnreadableContextError{Rev: c.Rev, RevokedAt: c.RevokedAt,
			Err: w.openErr("context", err)}
	}
	c.CtxID, c.Principal, c.Username, c.Port, c.RemAddr, c.Credential, c.Sealed =
		cs.CtxID, cs.Principal, cs.Username, cs.Port, cs.RemAddr, cs.Credential, nil
	return c, nil
}

// TouchContext needs no sealed field, and that is exactly why it exists
// (store.Store): it writes an expiry and LastTouchedAt, both plaintext
// bookkeeping about the extension, so the inner store can extend a record it
// cannot read.
func (w *wrapped) TouchContext(ctx context.Context, k store.ContextKey, ttl time.Duration) error {
	return w.inner.TouchContext(ctx, k, ttl)
}

// SetPrivilege passes through for the same reason TouchContext does: PrivLvl
// is plaintext -- it is a level, not an identity, and PutContext already
// leaves it in the clear -- so the inner store records the granted level on a
// record whose sealed fields it cannot read.
func (w *wrapped) SetPrivilege(ctx context.Context, k store.ContextKey, level uint8) error {
	return w.inner.SetPrivilege(ctx, k, level)
}

// AnnotateContext passes through for the same reason, and that is the whole
// argument for hashing the discriminator: SessionDiscriminators and
// AccountingState are both plaintext -- a truncated hash of a device-local
// identifier and an advisory string -- so the inner store can record what
// accounting concluded on a record whose sealed fields it cannot read. Were
// the discriminator sealed, this could only be a read-unseal-modify-reseal-
// write, which is the read-modify-write the setter exists to avoid
// (store.Store; spec §5.8).
func (w *wrapped) AnnotateContext(ctx context.Context, k store.ContextKey, discHash, state string) error {
	return w.inner.AnnotateContext(ctx, k, discHash, state)
}

// RefreshContext passes through, and the one field it does not carry is the
// reason it can: every field in store.ContextRefresh is plaintext -- two
// timestamps and a policy blob hash -- and the window it recomputes is read
// from SessionExpires and AuthTime, which PutContext also leaves in the clear.
// The credential's sid is the field a refresh would otherwise want to write,
// and it lives inside the sealed Credential; writing it here could only be a
// read-unseal-modify-reseal-write, which is the read-modify-write the setters
// exist to avoid (AnnotateContext above). A rotated sid moves in the plaintext
// index instead, through ReindexSid, which is what revocation by sid reads.
func (w *wrapped) RefreshContext(ctx context.Context, k store.ContextKey, r store.ContextRefresh, ttl time.Duration) error {
	return w.inner.RefreshContext(ctx, k, r, ttl)
}

// SetRevokedAt passes through, and this is the pass-through the package
// comment is about: RevokedAt is a plaintext timestamp, so a daemon holding no
// usable key can still mark every context of a principal the index names.
// Revocation is the path needed most on a bad day and must not depend on the
// encryption key or its rotation window being available. Its keep-the-later
// comparison is on that plaintext timestamp too, so it is made down there.
func (w *wrapped) SetRevokedAt(ctx context.Context, k store.ContextKey, at time.Time) error {
	return w.inner.SetRevokedAt(ctx, k, at)
}

// SetContextPolicy passes through: every field it writes or compares is
// plaintext — a policy revision, a timestamp, a blob hash, a ceiling, an
// enable mechanism and the level it clamps — so the inner store can hold the
// compare-and-set on a record whose sealed fields it cannot read, exactly as
// SwapContext's revision does. The principal the value was computed from is
// read up here, through GetContext, and the policy revision is what binds the
// write to that read.
func (w *wrapped) SetContextPolicy(ctx context.Context, k store.ContextKey, policyRev uint64, p store.ContextPolicy) error {
	return w.inner.SetContextPolicy(ctx, k, policyRev, p)
}

// DeleteContext is addressed by key alone.
func (w *wrapped) DeleteContext(ctx context.Context, k store.ContextKey) error {
	return w.inner.DeleteContext(ctx, k)
}

// PutBlob passes through unsealed. Blobs hold no identity (design §12).
func (w *wrapped) PutBlob(ctx context.Context, hash string, body []byte, ttl time.Duration) error {
	return w.inner.PutBlob(ctx, hash, body, ttl)
}

// GetBlob passes through unsealed, for the same reason as PutBlob.
func (w *wrapped) GetBlob(ctx context.Context, hash string) ([]byte, error) {
	return w.inner.GetBlob(ctx, hash)
}

// BumpBlob touches only an expiry.
func (w *wrapped) BumpBlob(ctx context.Context, hash string, ttl time.Duration) error {
	return w.inner.BumpBlob(ctx, hash, ttl)
}

// IndexContext writes the indexes in the clear; the package comment is the
// argument for why.
func (w *wrapped) IndexContext(ctx context.Context, principal, sid, certKey string, ref store.ContextRef, ttl time.Duration) error {
	return w.inner.IndexContext(ctx, principal, sid, certKey, ref, ttl)
}

// UnindexContext passes through, matching IndexContext.
func (w *wrapped) UnindexContext(ctx context.Context, principal, sid, certKey string, ref store.ContextRef) error {
	return w.inner.UnindexContext(ctx, principal, sid, certKey, ref)
}

// UnindexRef passes through, matching IndexContext.
func (w *wrapped) UnindexRef(ctx context.Context, ref store.ContextRef) error {
	return w.inner.UnindexRef(ctx, ref)
}

// ContextsByPrincipal passes through: the index is plaintext, so revocation
// resolves a principal to its contexts without the encryption key.
func (w *wrapped) ContextsByPrincipal(ctx context.Context, principal string) ([]store.ContextRef, error) {
	return w.inner.ContextsByPrincipal(ctx, principal)
}

// ContextsBySid passes through, matching ContextsByPrincipal.
func (w *wrapped) ContextsBySid(ctx context.Context, sid string) ([]store.ContextRef, error) {
	return w.inner.ContextsBySid(ctx, sid)
}

// ContextsByCert passes through, matching ContextsByPrincipal.
func (w *wrapped) ContextsByCert(ctx context.Context, certKey string) ([]store.ContextRef, error) {
	return w.inner.ContextsByCert(ctx, certKey)
}

// ReindexSid moves a plaintext index entry and touches no record.
func (w *wrapped) ReindexSid(ctx context.Context, oldSid, newSid string, ref store.ContextRef, ttl time.Duration) error {
	return w.inner.ReindexSid(ctx, oldSid, newSid, ref, ttl)
}

// ActivePrincipals reads the plaintext principal index.
func (w *wrapped) ActivePrincipals(ctx context.Context) ([]string, error) {
	return w.inner.ActivePrincipals(ctx)
}

func (w *wrapped) PutIdempotency(ctx context.Context, principal, key string, rec store.Idempotency) error {
	s, err := w.keys.Seal(rec.Response)
	if err != nil {
		return err
	}
	rec.Response, rec.Sealed = nil, s
	return w.inner.PutIdempotency(ctx, principal, key, rec)
}

func (w *wrapped) GetIdempotency(ctx context.Context, principal, key string) (store.Idempotency, error) {
	rec, err := w.inner.GetIdempotency(ctx, principal, key)
	if err != nil {
		return store.Idempotency{}, err
	}
	resp, err := w.keys.Open(rec.Sealed)
	if err != nil {
		return store.Idempotency{}, w.openErr("idempotency", err)
	}
	rec.Response, rec.Sealed = resp, nil
	return rec, nil
}

// ReserveIdempotency passes a reservation through: it holds no response, so
// there is nothing to seal, and one that tries to carry a response is
// refused rather than written in clear. A completed record it finds is
// opened, as GetIdempotency opens one.
func (w *wrapped) ReserveIdempotency(ctx context.Context, principal, key string, rec store.Idempotency) (store.Idempotency, bool, error) {
	if len(rec.Response) != 0 {
		return store.Idempotency{}, false, errors.New("crypt: a reservation carries no response")
	}
	cur, ok, err := w.inner.ReserveIdempotency(ctx, principal, key, rec)
	if err != nil || ok || cur.Pending {
		return cur, ok, err
	}
	resp, err := w.keys.Open(cur.Sealed)
	if err != nil {
		return store.Idempotency{}, false, w.openErr("idempotency", err)
	}
	cur.Response, cur.Sealed = resp, nil
	return cur, false, nil
}

// CompleteIdempotency seals the response, which holds the minted tokens
// (design §17), before the compare-and-set below.
func (w *wrapped) CompleteIdempotency(ctx context.Context, principal, key, expect string, rec store.Idempotency) error {
	s, err := w.keys.Seal(rec.Response)
	if err != nil {
		return err
	}
	rec.Response, rec.Sealed = nil, s
	return w.inner.CompleteIdempotency(ctx, principal, key, expect, rec)
}

// ReleaseIdempotency touches no sealed field.
func (w *wrapped) ReleaseIdempotency(ctx context.Context, principal, key, holder string) error {
	return w.inner.ReleaseIdempotency(ctx, principal, key, holder)
}

var _ store.Store = (*wrapped)(nil)
