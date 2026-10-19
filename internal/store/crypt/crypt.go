// Package crypt is the encryption-at-rest layer (design §8). It decorates a
// store.Store so that what a login and an authorization trust is sealed
// before it reaches any backend, under a current key with one previous key
// accepted, and bound to the key it is stored at (plan 7d; Ruling 17):
//
//   - a context whole: its identity and credential, its privilege, its
//     ceiling, its policy, its clocks and its revocation, bound to its
//     (nas, username);
//   - a token's secret and everything a redemption or a login copies from
//     it, bound to its key and its ID;
//   - a receipt's decision and the credential it was written for, bound to
//     its whole key, kind included.
//
// A store write can then delete, or put back an earlier record sealed for
// the same key, and nothing else: it cannot zero a revocation, raise a
// privilege, swap a blob or move a record to another key, except by putting
// back an earlier version of the same context. The Ledger denies every
// such put-back sealed below the newest write it knows at the key, whichever
// port49 process made that write: another login's context, which would be
// impersonation, and an earlier version of this one, which would undo a
// revocation that leaves no mark (a self or key revocation) or a policy
// narrowing, a clamp included (spec §13, decision 35; Ruling T12-g; plan
// 7e, Ruling 3).
//
// What is NOT sealed is deliberate and is argued in plan 2 Task 5: blobs (no
// identity) and the indexes: the four of plan 2 and the two token indexes of
// plan 7a. A dump of the index reveals principal, device
// and login name; every credential-bearing record (token, receipt, context
// body) stays sealed; the index is protected by store access control rather
// than by encryption, because revocation is the path needed most on a bad day
// and must not depend on the encryption key or its rotation window being
// available. A context's revocation is written in the clear as well as
// sealed, for the same reason, and a read takes the later of the two.
//
// The idle clock (LastTouchedAt and the expiry) is not sealed either, so
// TouchContext extends a record it cannot read. A context kept alive past
// its idle TTL by a store write is still bounded by its sealed ceiling, if
// it has one; under `max_session_age: never` only the refresh and
// revocation bound it (re-check MA1).
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
	"math"
	"slices"
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
func (k Keys) Seal(plaintext []byte) ([]byte, error) { return seal(k.Current, plaintext, nil) }

// SealBound is Seal with bound appended to the additional data, so the
// record opens only where it was sealed for: OpenBound with the same
// bound (plan 7d). Seal is SealBound with none.
func (k Keys) SealBound(plaintext, bound []byte) ([]byte, error) {
	return seal(k.Current, plaintext, bound)
}

func seal(key Key, plaintext, bound []byte) ([]byte, error) {
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
	return gcm.Seal(out, nonce, plaintext, additional(key.ID, bound)), nil
}

// additional is the AEAD's additional data: the key id, then bound. With
// bound nil it is the key id alone, as every record sealed before plan 7d
// was, so those still open where nothing binds them.
func additional(id string, bound []byte) []byte {
	return append([]byte(id), bound...)
}

// Open reverses Seal under whichever of the two keys the record names. It
// returns ErrUnknownKey when neither matches, and the GCM authentication error
// when the key matched and the bytes did not.
func (k Keys) Open(sealed []byte) ([]byte, error) { return k.open(sealed, nil) }

// OpenBound is Open for a record SealBound sealed with bound.
func (k Keys) OpenBound(sealed, bound []byte) ([]byte, error) { return k.open(sealed, bound) }

func (k Keys) open(sealed, bound []byte) ([]byte, error) {
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
	return gcm.Open(nil, rest[:gcm.NonceSize()], rest[gcm.NonceSize():], additional(id, bound))
}

// tokenSecret is everything of a token a redemption or a login trusts,
// sealed (plan 7d; Ruling 17; re-check CA1): the secret and identity, as
// before, and the kind, the expiry, the policy, the ceiling and the
// clocks, which the login copies into its context (authen's loginContext)
// and the join compares with a revocation (MintedAt). Left in the clear
// they would let a store write raise a login's privilege, widen its
// blob, drop its ceiling or outlive a self revocation. ExpiresAt is also
// written in the clear, for the backend's expiry (openToken).
type tokenSecret struct {
	Secret        []byte           `json:"secret"`
	Principal     string           `json:"principal"`
	Username      string           `json:"username"`
	Credential    store.Credential `json:"credential"`
	Kind          string           `json:"kind"`
	ExpiresAt     time.Time        `json:"expires_at"`
	BlobHash      string           `json:"blob_hash"`
	MaxSessionAge time.Duration    `json:"max_session_age"`
	Enable        string           `json:"enable"`
	MaxPrivilege  uint8            `json:"max_privilege"`
	AuthTime      time.Time        `json:"auth_time"`
	MintedAt      time.Time        `json:"minted_at"`
	VerifiedAt    time.Time        `json:"verified_at"`
}

// receiptSecret is a receipt's sealed part. FirstRedeemedAt anchors the
// cap, so it is sealed too; the plaintext copy stays for the backend and
// is never read back (re-check CA1). Principal, Sid and CertKey are the
// credential the receipt was written for, which a replay checks the marks
// and the index for (store.Receipt).
type receiptSecret struct {
	CredentialSHA256 [32]byte  `json:"credential_sha256"`
	Status           uint8     `json:"status"`
	CtxID            string    `json:"ctx_id"`
	FirstRedeemedAt  time.Time `json:"first_redeemed_at"`
	Principal        string    `json:"principal"`
	Sid              string    `json:"sid"`
	CertKey          string    `json:"cert_key"`
}

// contextSealVersion is the form of contextSecret below: 2 is plan 7d's
// whole record, 3 adds the write ID (Ruling T12-g), and 4 replaces it with
// the write sequence (plan 7e, Ruling 3). A context in any other form does
// not open, and is replaced at its next login
// (store.UnreadableContextError): it fails closed. An earlier form is
// ErrEarlierForm, so the operator's line names the upgrade.
const contextSealVersion = 4

// ErrEarlierForm is a context that opens and is sealed in a form below
// contextSealVersion: written by an earlier port49, and replaced at its
// user's next login (pre-flight I10). A form above it is not this error.
var ErrEarlierForm = errors.New("crypt: a context sealed by an earlier port49")

// contextSecret is everything of a context the authorizer trusts,
// sealed whole (plan 7d; Ruling 17): the identity and credential, as
// before, and the privilege, the ceiling, the policy, the clocks, the
// revocation and the login witness (Context.Logins). Only the store's bookkeeping stays outside it: the
// revisions, the idle clock (LastTouchedAt), and accounting's
// annotations, which authorize nothing. RevokedAt is also written in
// the clear (sealContext).
//
// Seq is the write's sequence (Ledger): above every earlier write at the
// key, whichever process made it. Sealed, a store writer can neither forge
// it nor move it. It authorizes nothing by itself and has no operator use,
// so it never leaves this layer: it is not on store.Context, and nothing
// logs it.
type contextSecret struct {
	V              int              `json:"v"`
	Seq            uint64           `json:"seq"`
	CtxID          string           `json:"ctx_id"`
	Principal      string           `json:"principal"`
	Username       string           `json:"username"`
	Port           string           `json:"port"`
	RemAddr        string           `json:"rem_addr"`
	Credential     store.Credential `json:"credential"`
	PrivLvl        uint8            `json:"priv_lvl"`
	BlobHash       string           `json:"blob_hash"`
	MaxPrivilege   uint8            `json:"max_privilege"`
	Enable         string           `json:"enable"`
	AuthTime       time.Time        `json:"auth_time"`
	SessionExpires time.Time        `json:"session_expires"`
	RefreshedAt    time.Time        `json:"refreshed_at"`
	RevokedAt      time.Time        `json:"revoked_at"`
	CreatedAt      time.Time        `json:"created_at"`
	Logins         []string         `json:"logins"`
}

// contextAAD binds a sealed context to the key it is stored at: the
// record kind, the NAS and the username, each length-prefixed, so no two
// keys share an encoding. A record copied to another (nas, username)
// fails authentication there (pre-flight I12).
func contextAAD(k store.ContextKey) []byte {
	return []byte(fmt.Sprintf("|context|%d:%s|%d:%s", len(k.NAS), k.NAS, len(k.Username), k.Username))
}

// tokenAAD binds a sealed token to its key and its ID, each
// length-prefixed: a token copied to another (nas, username) or given
// another ID does not open (re-check CA1).
func tokenAAD(k store.TokenKey, id string) []byte {
	return []byte(fmt.Sprintf("|token|%d:%s|%d:%s|%d:%s", len(k.NAS), k.NAS, len(k.Username), k.Username,
		len(id), id))
}

// receiptAAD binds a sealed receipt to its whole key: a login receipt
// copied to the enable key would otherwise replay an escalation with no
// enable token (re-check CA1).
func receiptAAD(rk store.ReceiptKey) []byte {
	return []byte(fmt.Sprintf("|receipt|%d:%s|%d:%s|%d:%s|%x", len(rk.NAS), rk.NAS, len(rk.Username), rk.Username,
		len(rk.Kind), rk.Kind, rk.CredentialSHA256))
}

type wrapped struct {
	inner        store.RevStore
	keys         Keys
	openFailures *prometheus.CounterVec
	ledger       *Ledger
	onUnopenable func(record, keyID string, why error)
}

// Option configures Wrap.
type Option func(*wrapped)

// WithLedger shares l with every other Wrap given it, so the daemon's and
// the broker's layers in one process agree on each key's mark (re-check
// IA1). Without it each Wrap keeps its own, with a base of zero.
func WithLedger(l *Ledger) Option { return func(w *wrapped) { w.ledger = l } }

// OnUnopenable is told the kind and the key id of every record that will
// not open, beside crypt_open_failures_total. The key id is the sealed
// record's own header, never a secret: it is how an operator learns which
// key a rotation retired too early (plan 2's alarm; plan 7d). why is the
// error the open returned: ErrUnknownKey, ErrEarlierForm,
// ErrNotLastWritten, or an authentication or decode failure.
func OnUnopenable(f func(record, keyID string, why error)) Option {
	return func(w *wrapped) { w.onUnopenable = f }
}

// SealedKeyID is the key id a sealed record's header names, "" when it is
// too short to name one, and "?" when it names one outside the key-id
// charset (LineKeyID): the header is the record's, so whoever can write
// the store writes it, and a line must not echo up to 255 bytes of it
// (pre-flight M44).
func SealedKeyID(sealed []byte) string {
	if len(sealed) < 1 || len(sealed) < 1+int(sealed[0]) {
		return ""
	}
	return LineKeyID(string(sealed[1 : 1+int(sealed[0])]))
}

// LineKeyID is id as a line may echo it: itself within the key-id charset
// ([A-Za-z0-9._-], at most 64 bytes), "?" outside it. An id read from the
// store is whatever its writer put there (pre-flight M44; review I-2).
func LineKeyID(id string) string {
	if len(id) > 64 {
		return "?"
	}
	for _, b := range []byte(id) {
		switch {
		case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9', b == '.', b == '_', b == '-':
		default:
			return "?"
		}
	}
	return id
}

// Wrap decorates inner so every credential-bearing record is sealed under k
// before it reaches the backend. openFailures may be nil; the daemon passes
// metrics.CryptOpenFailures. inner reports the revision each context write
// committed at, and the highest it has seen, which a write's sequence is
// drawn above (store.RevStore; Ledger).
func Wrap(inner store.RevStore, k Keys, openFailures *prometheus.CounterVec, opts ...Option) store.Store {
	w := &wrapped{inner: inner, keys: k, openFailures: openFailures, ledger: NewLedger()}
	for _, o := range opts {
		o(w)
	}
	return w
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
func (w *wrapped) openErr(record string, sealed []byte, err error) error {
	if w.openFailures != nil {
		w.openFailures.WithLabelValues(record).Inc()
	}
	if w.onUnopenable != nil {
		w.onUnopenable(record, SealedKeyID(sealed), err)
	}
	// err is already ErrUnknownKey when neither key id matched, and a GCM or
	// JSON failure when the key matched and the bytes did not; both are
	// wrapped as they are, so `errors.Is(err, ErrUnknownKey)` distinguishes
	// "wrong key" from "tampered record" at the call site.
	return fmt.Errorf("crypt: opening %s: %w", record, err)
}

// errExpiryMoved is a token whose plaintext expiry is not the one sealed
// with it. sealToken writes them equal, so a store write moved it, and an
// extended one would be redeemable past the sealed one: it is dropped as
// a token that will not open.
var errExpiryMoved = errors.New("crypt: a token's plaintext expiry differs from its sealed one")

func (w *wrapped) sealToken(k store.TokenKey, t store.Token) (store.Token, error) {
	b, err := json.Marshal(tokenSecret{Secret: t.Secret, Principal: t.Principal, Username: t.Username,
		Credential: t.Credential, Kind: t.Kind, ExpiresAt: t.ExpiresAt, BlobHash: t.BlobHash,
		MaxSessionAge: t.MaxSessionAge, Enable: t.Enable, MaxPrivilege: t.MaxPrivilege, AuthTime: t.AuthTime,
		MintedAt: t.MintedAt, VerifiedAt: t.VerifiedAt})
	if err != nil {
		return store.Token{}, err
	}
	s, err := w.keys.SealBound(b, tokenAAD(k, t.ID))
	if err != nil {
		return store.Token{}, err
	}
	return store.Token{ID: t.ID, ExpiresAt: t.ExpiresAt, Sealed: s}, nil
}

func (w *wrapped) openToken(k store.TokenKey, t store.Token) (store.Token, error) {
	b, err := w.keys.OpenBound(t.Sealed, tokenAAD(k, t.ID))
	if err != nil {
		return store.Token{}, err
	}
	var ts tokenSecret
	if err := json.Unmarshal(b, &ts); err != nil {
		return store.Token{}, err
	}
	if !ts.ExpiresAt.Equal(t.ExpiresAt) {
		return store.Token{}, errExpiryMoved
	}
	return store.Token{ID: t.ID, Secret: ts.Secret, Kind: ts.Kind, ExpiresAt: ts.ExpiresAt, Principal: ts.Principal,
		Username: ts.Username, BlobHash: ts.BlobHash, MaxSessionAge: ts.MaxSessionAge, Enable: ts.Enable,
		MaxPrivilege: ts.MaxPrivilege, Credential: ts.Credential, AuthTime: ts.AuthTime, MintedAt: ts.MintedAt,
		VerifiedAt: ts.VerifiedAt}, nil
}

func (w *wrapped) PutToken(ctx context.Context, k store.TokenKey, t store.Token) (int, error) {
	st, err := w.sealToken(k, t)
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
		ot, err := w.openToken(k, t)
		if err != nil {
			// Sealed under a retired key, moved from another key or ID, or
			// its plaintext expiry moved: unreadable, therefore unredeemable.
			// Returning it with a zero Secret would match a zero-length
			// credential, so it is dropped; expiry reclaims the record. This
			// is the one read that must NOT fail the call — one unreadable
			// token in a candidate set of eight must not deny the seven — so
			// the counter is the only place it is visible. That is what
			// crypt_open_failures_total{record="token"} is for.
			_ = w.openErr("token", t.Sealed, err)
			continue
		}
		out = append(out, ot)
	}
	return out, nil
}

func (w *wrapped) RedeemAndReceipt(ctx context.Context, k store.TokenKey, tokenID string, wr store.ReceiptWrite) error {
	b, err := json.Marshal(receiptSecret{CredentialSHA256: wr.Receipt.CredentialSHA256, Status: wr.Receipt.Status,
		CtxID: wr.Receipt.CtxID, FirstRedeemedAt: wr.Receipt.FirstRedeemedAt, Principal: wr.Receipt.Principal,
		Sid: wr.Receipt.Sid, CertKey: wr.Receipt.CertKey})
	if err != nil {
		return err
	}
	s, err := w.keys.SealBound(b, receiptAAD(wr.Key))
	if err != nil {
		return err
	}
	wr.Receipt.CredentialSHA256, wr.Receipt.Status, wr.Receipt.CtxID, wr.Receipt.Sealed = [32]byte{}, 0, "", s
	wr.Receipt.Principal, wr.Receipt.Sid, wr.Receipt.CertKey = "", "", ""
	return w.inner.RedeemAndReceipt(ctx, k, tokenID, wr)
}

// DeleteTokens carries no sealed field: the key alone addresses the records.
func (w *wrapped) DeleteTokens(ctx context.Context, k store.TokenKey) error {
	return w.inner.DeleteTokens(ctx, k)
}

// DeleteToken carries no sealed field: the key and the plaintext ID
// address the record.
func (w *wrapped) DeleteToken(ctx context.Context, k store.TokenKey, id string) error {
	return w.inner.DeleteToken(ctx, k, id)
}

// PurgeTokens reads nothing sealed: the backend deletes by key.
func (w *wrapped) PurgeTokens(ctx context.Context) (int, error) { return w.inner.PurgeTokens(ctx) }

// GetReceipt opens the receipt bound to rk, and takes the cap's anchor
// from the sealed copy, whatever the plaintext one says (re-check CA1).
func (w *wrapped) GetReceipt(ctx context.Context, rk store.ReceiptKey) (store.Receipt, error) {
	r, err := w.inner.GetReceipt(ctx, rk)
	if err != nil {
		return store.Receipt{}, err
	}
	b, err := w.keys.OpenBound(r.Sealed, receiptAAD(rk))
	if err != nil {
		return store.Receipt{}, w.openErr("receipt", r.Sealed, err)
	}
	var rs receiptSecret
	if err := json.Unmarshal(b, &rs); err != nil {
		return store.Receipt{}, w.openErr("receipt", r.Sealed, err)
	}
	r.CredentialSHA256, r.Status, r.CtxID, r.FirstRedeemedAt, r.Sealed =
		rs.CredentialSHA256, rs.Status, rs.CtxID, rs.FirstRedeemedAt, nil
	r.Principal, r.Sid, r.CertKey = rs.Principal, rs.Sid, rs.CertKey
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

// sealContext seals c's trusted fields for k, at the write sequence seq
// (contextSecret; seqFor). What the backend holds beside the sealed bytes
// is the bookkeeping and RevokedAt: the revocation stays in the clear
// too, so a revocation needs no key (SetRevokedAt), and a read takes the
// later of the two (openContext).
func (w *wrapped) sealContext(k store.ContextKey, c store.Context, seq uint64) (store.Context, error) {
	b, err := json.Marshal(contextSecret{V: contextSealVersion, Seq: seq, CtxID: c.CtxID,
		Principal: c.Principal, Username: c.Username, Port: c.Port, RemAddr: c.RemAddr, Credential: c.Credential,
		PrivLvl: c.PrivLvl, BlobHash: c.BlobHash, MaxPrivilege: c.MaxPrivilege, Enable: c.Enable, AuthTime: c.AuthTime,
		SessionExpires: c.SessionExpires, RefreshedAt: c.RefreshedAt, RevokedAt: c.RevokedAt, CreatedAt: c.CreatedAt,
		Logins: c.Logins})
	if err != nil {
		return store.Context{}, err
	}
	s, err := w.keys.SealBound(b, contextAAD(k))
	if err != nil {
		return store.Context{}, err
	}
	return store.Context{RevokedAt: c.RevokedAt, LastTouchedAt: c.LastTouchedAt,
		SessionDiscriminators: c.SessionDiscriminators, AccountingState: c.AccountingState,
		Rev: c.Rev, PolicyRev: c.PolicyRev, Sealed: s}, nil
}

// openContext is openContextWith under this layer's keys.
func (w *wrapped) openContext(k store.ContextKey, c store.Context) (store.Context, uint64, error) {
	return openContextWith(w.keys, k, c)
}

// openContextWith is sealContext reversed under keys for the record read
// at k, with the write sequence it was sealed at, for the ledger; it
// needs no wrapped, so the context feed opens what it brings (Task 8).
// Every trusted field is the sealed one; RevokedAt is the later of the
// sealed and the plaintext, so a keyless revocation is in force at once
// and a store write that zeroes the plaintext lifts nothing.
func openContextWith(keys Keys, k store.ContextKey, c store.Context) (store.Context, uint64, error) {
	b, err := keys.OpenBound(c.Sealed, contextAAD(k))
	if err != nil {
		return store.Context{}, 0, err
	}
	var cs contextSecret
	if err := json.Unmarshal(b, &cs); err != nil {
		return store.Context{}, 0, err
	}
	switch {
	case cs.V < contextSealVersion:
		return store.Context{}, 0, fmt.Errorf("%w (form %d, not %d)", ErrEarlierForm, cs.V, contextSealVersion)
	case cs.V != contextSealVersion:
		return store.Context{}, 0, fmt.Errorf("crypt: a context sealed in form %d, not %d", cs.V, contextSealVersion)
	}
	revoked := cs.RevokedAt
	if c.RevokedAt.After(revoked) {
		revoked = c.RevokedAt
	}
	return store.Context{CtxID: cs.CtxID, Principal: cs.Principal, Username: cs.Username, Port: cs.Port,
		RemAddr: cs.RemAddr, Credential: cs.Credential, PrivLvl: cs.PrivLvl, BlobHash: cs.BlobHash,
		MaxPrivilege: cs.MaxPrivilege, Enable: cs.Enable, AuthTime: cs.AuthTime, SessionExpires: cs.SessionExpires,
		RefreshedAt: cs.RefreshedAt, RevokedAt: revoked, CreatedAt: cs.CreatedAt, Logins: cs.Logins,
		LastTouchedAt:         c.LastTouchedAt,
		SessionDiscriminators: c.SessionDiscriminators, AccountingState: c.AccountingState,
		Rev: c.Rev, PolicyRev: c.PolicyRev}, cs.Seq, nil
}

// seqFor is the sequence a write at k compared on rev seals (Ledger):
// above the compare revision, everything the store has told this process,
// and the key's mark.
func (w *wrapped) seqFor(k store.ContextKey, rev uint64) uint64 {
	return max(rev, w.inner.Seen(), w.ledger.next(k))
}

// sent sends one sealed write at k, sealed at seq, and tells the ledger
// when it lands, with the revision it committed at. A write that fails
// tells it nothing: a conflict wrote nothing, and one of unknown outcome
// is admitted by the next read if it landed (Ledger).
func (w *wrapped) sent(k store.ContextKey, seq uint64, ceiling time.Time, send func() (uint64, error)) error {
	committed, err := send()
	if err == nil {
		w.ledger.wrote(k, seq, committed, ceiling)
	}
	return err
}

func (w *wrapped) PutContext(ctx context.Context, k store.ContextKey, c store.Context, ttl time.Duration) error {
	seq := w.seqFor(k, 0)
	sc, err := w.sealContext(k, c, seq)
	if err != nil {
		return err
	}
	return w.sent(k, seq, c.SessionExpires, func() (uint64, error) { return w.inner.PutContextRev(ctx, k, sc, ttl) })
}

// SwapContext seals as PutContext does and hands the revision through
// untouched. Rev is plaintext, and that is what lets this layer take part in a
// compare-and-set at all: the inner store compares a revision it can read on a
// record it cannot, so the merge happens up here with the fields open and the
// precondition is enforced down there under its own lock (store.Store).
func (w *wrapped) SwapContext(ctx context.Context, k store.ContextKey, rev uint64, c store.Context, ttl time.Duration) error {
	seq := w.seqFor(k, rev)
	sc, err := w.sealContext(k, c, seq)
	if err != nil {
		return err
	}
	return w.sent(k, seq, c.SessionExpires, func() (uint64, error) {
		return w.inner.SwapContextRev(ctx, k, rev, sc, ttl)
	})
}

// SwapLogin seals as SwapContext does, and passes the index change and the
// marks through: both are plaintext, as the indexes and the marks are (the
// package comment), so the inner store compares and writes them under the
// same step as the sealed context.
func (w *wrapped) SwapLogin(ctx context.Context, k store.ContextKey, rev uint64, c store.Context, ttl time.Duration,
	lw store.LoginWrite) error {
	seq := w.seqFor(k, rev)
	sc, err := w.sealContext(k, c, seq)
	if err != nil {
		return err
	}
	return w.sent(k, seq, c.SessionExpires, func() (uint64, error) {
		return w.inner.SwapLoginRev(ctx, k, rev, sc, ttl, lw)
	})
}

// staleReads bounds how many times GetContext reads again a record the
// ledger does not admit and that was served before the write that set its
// key's mark committed (Ledger.stale).
const staleReads = 2

func (w *wrapped) GetContext(ctx context.Context, k store.ContextKey) (store.Context, error) {
	for read := 0; ; read++ {
		c, err := w.inner.GetContext(ctx, k)
		if err != nil {
			return store.Context{}, err
		}
		oc, seq, err := w.openContext(k, c)
		if err != nil {
			// The record is there and will not open. Its revision and
			// revocation are plaintext, and JoinContext needs both to replace
			// it without racing a revocation or lifting one
			// (store.UnreadableContextError). The wrapped error is openErr's,
			// so errors.Is(err, ErrUnknownKey) still tells a wrong key from a
			// tampered record, and ErrEarlierForm names the upgrade.
			return store.Context{}, &store.UnreadableContextError{Rev: c.Rev,
				RevokedAt: latest(c.RevokedAt, w.ledger.floor(k)), Err: w.openErr("context", c.Sealed, err)}
		}
		// The ledger (plan 7e, Ruling 3): a record sealed below the newest
		// write this process knows at the key is another login's, or an
		// earlier version of this one, written back, and is denied as one
		// that does not open. One served before that write committed raced
		// it, and is read again. A revocation whose seal sent nothing holds
		// through the ledger's floor (Ledger).
		if w.ledger.admits(k, seq) {
			w.ledger.Observe(k, seq, c.Rev, c.RevokedAt, oc.SessionExpires)
			oc.RevokedAt = latest(oc.RevokedAt, w.ledger.floor(k))
			return oc, nil
		}
		if read < staleReads && w.ledger.stale(k, c.Rev) {
			continue
		}
		return store.Context{}, &store.UnreadableContextError{Rev: c.Rev,
			RevokedAt: latest(c.RevokedAt, w.ledger.floor(k)), Err: w.openErr("context", c.Sealed, ErrNotLastWritten)}
	}
}

// latest is the later of a and b.
func latest(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

// TouchContext needs no sealed field, and that is exactly why it exists
// (store.Store): it writes an expiry and LastTouchedAt, both plaintext
// bookkeeping about the extension, so the inner store can extend a record it
// cannot read. The idle clock is not sealed (the package comment).
func (w *wrapped) TouchContext(ctx context.Context, k store.ContextKey, ttl time.Duration) error {
	return w.inner.TouchContext(ctx, k, ttl)
}

// rewrite is a narrow setter on a field the seal covers (plan 7d; Ruling
// 17): read the record, open it, apply the setter's rule, seal it again,
// and rewrite it on the revision read (store.RewriteContext), reading
// again on a lost race up to attempts times. apply may refuse
// (ErrConflict, ErrPastGrace), and then nothing is written. A record
// this layer cannot open, or the ledger does not admit, is GetContext's
// UnreadableContextError.
func (w *wrapped) rewrite(ctx context.Context, k store.ContextKey, ttl time.Duration, attempts int,
	apply func(c *store.Context) (policyMoved bool, err error)) error {
	for attempt := 0; attempt < attempts; attempt++ {
		c, err := w.GetContext(ctx, k)
		if err != nil {
			return err
		}
		rev := c.Rev
		moved, err := apply(&c)
		if err != nil {
			return err
		}
		seq := w.seqFor(k, rev)
		sc, err := w.sealContext(k, c, seq)
		if err != nil {
			return err
		}
		switch err := w.sent(k, seq, c.SessionExpires, func() (uint64, error) {
			return w.inner.RewriteContextRev(ctx, k, rev, sc, ttl, moved)
		}); {
		case err == nil:
			return nil
		case !errors.Is(err, store.ErrConflict):
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	return fmt.Errorf("crypt: context still changing after %d attempts: %w", attempts, store.ErrConflict)
}

// SetPrivilege is a rewrite: the level is sealed (plan 7d).
func (w *wrapped) SetPrivilege(ctx context.Context, k store.ContextKey, level uint8) error {
	return w.rewrite(ctx, k, 0, store.MaxJoinAttempts, func(c *store.Context) (bool, error) {
		return store.ApplyPrivilege(c, level), nil
	})
}

// AnnotateContext passes through, and that is the whole argument for
// hashing the discriminator: SessionDiscriminators and AccountingState are
// both plaintext -- a truncated hash of a device-local identifier and an
// advisory string -- so the inner store can record what accounting
// concluded on a record whose sealed fields it cannot read. They authorize
// nothing, so they are left out of the seal (spec §5.8).
func (w *wrapped) AnnotateContext(ctx context.Context, k store.ContextKey, discHash, state string) error {
	return w.inner.AnnotateContext(ctx, k, discHash, state)
}

// RefreshContext is a rewrite that extends the record, as the inner
// store's does; ExpectRev is compared with the revision each attempt
// reads. The window, the blob hash, the clocks and a rotated sid it writes
// are sealed (plan 7d). A rotated sid is written into the sealed credential
// (store.ApplyRefresh), so the re-index compares the index against it, and
// moves in the plaintext index too, through ReindexSid, which is what
// revocation by sid reads.
func (w *wrapped) RefreshContext(ctx context.Context, k store.ContextKey, r store.ContextRefresh, ttl time.Duration) error {
	return w.rewrite(ctx, k, ttl, store.MaxJoinAttempts, func(c *store.Context) (bool, error) {
		if r.ExpectRev != 0 && c.Rev != r.ExpectRev {
			return false, store.ErrConflict
		}
		return store.ApplyRefresh(c, r)
	})
}

// SetRevokedAt writes the plaintext mark first: it needs no key, lands
// whatever the record holds, and is in force at once, since a read takes
// the later of the two. Then it seals the mark into the record, so a
// store write cannot take it back (plan 7d). The seal's write is not a
// second policy write: the plaintext one already moved PolicyRev. A
// record this layer cannot open keeps the plaintext mark alone, and is
// denied as unreadable anyway; a record gone since is nothing to seal.
// Revocation is the path needed most on a bad day and must not depend on
// the encryption key or its rotation window being available.
//
// A busy session can win the seal's race many times, so it retries until
// the caller's deadline, and sealAttempts times when the caller set none.
// The revocation is in force from the first write either way, so an error
// after it says so, and that only the seal is pending (re-check MA2).
// Until a write at a later sequence lands, the ledger holds the mark as
// k's revocation floor, so a store writer who puts the record before it
// back, or zeroes the plaintext mark, lifts nothing while this process
// runs (final review 7d-2 I-1).
func (w *wrapped) SetRevokedAt(ctx context.Context, k store.ContextKey, at time.Time) error {
	if err := w.inner.SetRevokedAt(ctx, k, at); err != nil {
		return err
	}
	w.ledger.revoked(k, at, w.inner.Seen())
	attempts := sealAttempts
	if _, ok := ctx.Deadline(); ok {
		attempts = math.MaxInt
	}
	err := w.rewrite(ctx, k, 0, attempts, func(c *store.Context) (bool, error) {
		store.ApplyRevokedAt(c, at)
		return false, nil
	})
	var u *store.UnreadableContextError
	switch {
	case err == nil, errors.As(err, &u), errors.Is(err, store.ErrNotFound):
		return nil
	}
	return fmt.Errorf("crypt: revoked (the plaintext mark is in force); sealing it into the record is pending: %w", err)
}

// sealAttempts bounds SetRevokedAt's seal when its caller set no
// deadline: 64 lost races in a row is a store that never holds still.
const sealAttempts = 64

// SetContextPolicy is a rewrite compared on the policy revision each
// attempt reads. The principal the value was computed from is read up
// here, through GetContext, and the policy revision is what binds the
// write to that read. A revoking write on a record this layer cannot open
// still lands, through the inner store's plaintext compare and mark:
// revocation needs no key.
func (w *wrapped) SetContextPolicy(ctx context.Context, k store.ContextKey, policyRev uint64, p store.ContextPolicy) error {
	if err := store.CheckContextPolicy(p); err != nil {
		return err
	}
	err := w.rewrite(ctx, k, 0, store.MaxJoinAttempts, func(c *store.Context) (bool, error) {
		if c.PolicyRev != policyRev {
			return false, store.ErrConflict
		}
		store.ApplyContextPolicy(c, p)
		return true, nil
	})
	var u *store.UnreadableContextError
	if !p.RevokedAt.IsZero() && errors.As(err, &u) {
		return w.inner.SetContextPolicy(ctx, k, policyRev, store.ContextPolicy{RevokedAt: p.RevokedAt})
	}
	return err
}

// StampRefreshed is a rewrite compared on the policy revision that does
// not move it: RefreshedAt is sealed, and a stamp is no policy write.
func (w *wrapped) StampRefreshed(ctx context.Context, k store.ContextKey, policyRev uint64, at time.Time) error {
	return w.rewrite(ctx, k, 0, store.MaxJoinAttempts, func(c *store.Context) (bool, error) {
		if c.PolicyRev != policyRev {
			return false, store.ErrConflict
		}
		store.ApplyStamp(c, at)
		return false, nil
	})
}

// RewriteContext seals c for k and passes the write through, telling
// the ledger.
func (w *wrapped) RewriteContext(ctx context.Context, k store.ContextKey, rev uint64, c store.Context, ttl time.Duration,
	policyMoved bool) error {
	seq := w.seqFor(k, rev)
	sc, err := w.sealContext(k, c, seq)
	if err != nil {
		return err
	}
	return w.sent(k, seq, c.SessionExpires, func() (uint64, error) {
		return w.inner.RewriteContextRev(ctx, k, rev, sc, ttl, policyMoved)
	})
}

// DeleteContext is addressed by key alone, and passes through. The ledger
// keeps the key's mark: a record put back after the delete is still below
// it, or is the record deleted, at the mark, which is admitted. Every
// delete removes a record past its sealed ceiling or one that will not
// open, so that one is denied anyway (Ledger; Task 7 review M-5).
func (w *wrapped) DeleteContext(ctx context.Context, k store.ContextKey) error {
	return w.inner.DeleteContext(ctx, k)
}

// DeleteContextIf passes through: it is addressed by key and compares Rev,
// which is plaintext bookkeeping. The ledger keeps the key's mark, as for
// DeleteContext.
func (w *wrapped) DeleteContextIf(ctx context.Context, k store.ContextKey, rev uint64) error {
	return w.inner.DeleteContextIf(ctx, k, rev)
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

// IndexToken, TokensByPrincipal and TokensByCert are plaintext indexes, as
// the context indexes are (the package comment): revocation must not depend
// on the encryption key.
func (w *wrapped) IndexToken(ctx context.Context, principal, certKey string, k store.TokenKey, ttl time.Duration) error {
	return w.inner.IndexToken(ctx, principal, certKey, k, ttl)
}

func (w *wrapped) TokensByPrincipal(ctx context.Context, principal string) ([]store.TokenKey, error) {
	return w.inner.TokensByPrincipal(ctx, principal)
}

func (w *wrapped) TokensByCert(ctx context.Context, certKey string) ([]store.TokenKey, error) {
	return w.inner.TokensByCert(ctx, certKey)
}

// ReserveIdempotency passes a reservation through: it holds no response, so
// there is nothing to seal, and one that tries to carry a response is
// refused rather than written in clear. A completed record it finds is
// opened; a pending one has nothing sealed, and opening it would count a
// decryption failure that is not one.
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
		return store.Idempotency{}, false, w.openErr("idempotency", cur.Sealed, err)
	}
	cur.Response, cur.Sealed = resp, nil
	return cur, false, nil
}

// CompleteIdempotency seals the response, which holds the minted tokens
// (design §17), before the compare-and-set below. A pending record (Mint's
// renewal of its hold) holds no response and passes through unsealed, as a
// reservation does; one that tries to carry a response is refused rather
// than written in clear.
func (w *wrapped) CompleteIdempotency(ctx context.Context, principal, key, expect string, rec store.Idempotency) error {
	if rec.Pending {
		if len(rec.Response) != 0 {
			return errors.New("crypt: a pending record carries no response")
		}
		return w.inner.CompleteIdempotency(ctx, principal, key, expect, rec)
	}
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

// Revocation marks are plaintext: identity, no credential, and revocation
// must not depend on the encryption key.
func (w *wrapped) PutRevocation(ctx context.Context, r store.Revocation) error {
	return w.inner.PutRevocation(ctx, r)
}

func (w *wrapped) GetRevocation(ctx context.Context, kind, key string) (store.Revocation, error) {
	return w.inner.GetRevocation(ctx, kind, key)
}

func (w *wrapped) DeleteRevocation(ctx context.Context, kind, key string) error {
	return w.inner.DeleteRevocation(ctx, kind, key)
}

func (w *wrapped) ListRevocations(ctx context.Context) ([]store.Revocation, error) {
	return w.inner.ListRevocations(ctx)
}

// SupersedeTokens, SupersedeAll and SupersededAt pass through unsealed: an
// instant carries no credential.
func (w *wrapped) SupersedeTokens(ctx context.Context, k store.TokenKey, at time.Time) error {
	return w.inner.SupersedeTokens(ctx, k, at)
}

func (w *wrapped) SupersedeAll(ctx context.Context, at time.Time) error {
	return w.inner.SupersedeAll(ctx, at)
}

func (w *wrapped) SupersededAt(ctx context.Context, k store.TokenKey) (time.Time, error) {
	return w.inner.SupersededAt(ctx, k)
}

// PutOnce, TakeOnce, PutOIDCOwner, OIDCOwner, PutLogout and GetLogout pass
// through unsealed: each holds identity (an issuer, a sid, a sub, a
// principal, a time), never a credential, as the indexes do (plan 7h).
//
// Not sealed, on purpose (pre-flight M-9). A store writer could repoint an
// oo/ owner record, so a logout deletes another principal's unspent tokens
// (a denial, never a grant), or delete an lo/ logout record, so a logged-out
// session's token passes again. Both are what a store writer can already do
// to the marks (rv/, which pass through unsealed: crypt.go's PutRevocation)
// and to the tokens themselves, so sealing these would close no path the
// marks leave open. A logout, like a revocation, must not depend on the
// encryption key, and sealing the owner set would need a deterministic seal
// to merge entries by compare-and-set. The store's write access is the
// boundary here, as it is for the marks (spec §5.1.4).
func (w *wrapped) PutOnce(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error) {
	return w.inner.PutOnce(ctx, key, value, ttl)
}

func (w *wrapped) TakeOnce(ctx context.Context, key string) ([]byte, error) {
	return w.inner.TakeOnce(ctx, key)
}

func (w *wrapped) PutOIDCOwner(ctx context.Context, key, principal string, ttl time.Duration) error {
	return w.inner.PutOIDCOwner(ctx, key, principal, ttl)
}

func (w *wrapped) OIDCOwner(ctx context.Context, key string) (store.OIDCOwner, error) {
	return w.inner.OIDCOwner(ctx, key)
}

func (w *wrapped) PutLogout(ctx context.Context, l store.Logout, ttl time.Duration) error {
	return w.inner.PutLogout(ctx, l, ttl)
}

func (w *wrapped) GetLogout(ctx context.Context, key string) (store.Logout, error) {
	return w.inner.GetLogout(ctx, key)
}

// PutMFAProof and GetMFAProof pass through unsealed too: the key is a hash
// of a principal, a fingerprint and an agent session's hash, and the value
// a method and a clock; there is no identity and no credential to seal
// (plan 9c, Task 11).
func (w *wrapped) PutMFAProof(ctx context.Context, p store.MFAProof, ttl time.Duration) error {
	return w.inner.PutMFAProof(ctx, p, ttl)
}

func (w *wrapped) GetMFAProof(ctx context.Context, key string) (store.MFAProof, error) {
	return w.inner.GetMFAProof(ctx, key)
}

// The sign-in attempt counts pass through unsealed: the key is a principal
// or a source prefix, the value a count and a window's end (plan 9e).
func (w *wrapped) NoteSignInAttempt(ctx context.Context, key string, window time.Duration) (int, time.Time, error) {
	return w.inner.NoteSignInAttempt(ctx, key, window)
}

func (w *wrapped) UndoSignInAttempt(ctx context.Context, key string) error {
	return w.inner.UndoSignInAttempt(ctx, key)
}

func (w *wrapped) ClearSignInAttempts(ctx context.Context, key string) (int, error) {
	return w.inner.ClearSignInAttempts(ctx, key)
}

// membershipSecret is a membership's sealed part, bound to its principal.
// MapKeys and Refused are sealed as well as kept in the clear: the clear
// copies are the backend's index, the sealed ones the truth.
type membershipSecret struct {
	DN         string    `json:"dn"`
	EntryID    string    `json:"entry_id"`
	Username   string    `json:"username"`
	GroupDNs   []string  `json:"group_dns"`
	GroupNames []string  `json:"group_names"`
	MapKeys    []string  `json:"map_keys"`
	Refused    bool      `json:"refused"`
	VerifiedAt time.Time `json:"verified_at"`
}

var (
	errVerifiedMoved   = errors.New("crypt: a membership's plaintext verified_at differs from its sealed one")
	errMembershipMoved = errors.New("crypt: a membership's plaintext map keys or refusal differ from its sealed ones")
	// errKeyNotSealed is a key the index points at a record whose sealed
	// list does not hold it: a store write, answered as no membership.
	errKeyNotSealed = fmt.Errorf("crypt: a membership key its sealed record does not list: %w", store.ErrNotFound)
)

func membershipAAD(principal string) []byte { return []byte("membership\x00" + principal) }

func (w *wrapped) PutMembership(ctx context.Context, m store.Membership, ttl time.Duration) error {
	sealed, err := w.sealMembership(m)
	if err != nil {
		return err
	}
	return w.inner.PutMembership(ctx, sealed, ttl)
}

func (w *wrapped) PutPin(ctx context.Context, m store.Membership, expect store.PinExpect) error {
	sealed, err := w.sealMembership(m)
	if err != nil {
		return err
	}
	return w.inner.PutPin(ctx, sealed, expect)
}

// sealMembership is m as the backend keeps it: the clear part the index and
// the tombstone rule need, and the rest sealed.
func (w *wrapped) sealMembership(m store.Membership) (store.Membership, error) {
	b, err := json.Marshal(membershipSecret{DN: m.DN, EntryID: m.EntryID, Username: m.Username, GroupDNs: m.GroupDNs,
		GroupNames: m.GroupNames, MapKeys: m.MapKeys, Refused: m.Refused, VerifiedAt: m.VerifiedAt})
	if err != nil {
		return store.Membership{}, err
	}
	sealed, err := w.keys.SealBound(b, membershipAAD(m.Principal))
	if err != nil {
		return store.Membership{}, err
	}
	return store.Membership{Principal: m.Principal, MapKeys: m.MapKeys,
		Refused: m.Refused, VerifiedAt: m.VerifiedAt, Server: m.Server, Site: m.Site, Sealed: sealed}, nil
}

func (w *wrapped) RefuseMapKeys(ctx context.Context, mapKeys []string, at time.Time, ttl time.Duration) error {
	return w.inner.RefuseMapKeys(ctx, mapKeys, at, ttl)
}

func (w *wrapped) openMembership(m store.Membership, err error) (store.Membership, error) {
	if err != nil {
		return store.Membership{}, err
	}
	b, err := w.keys.OpenBound(m.Sealed, membershipAAD(m.Principal))
	if err != nil {
		return store.Membership{}, w.openErr("membership", m.Sealed, err)
	}
	var ms membershipSecret
	if err := json.Unmarshal(b, &ms); err != nil {
		return store.Membership{}, w.openErr("membership", m.Sealed, err)
	}
	if !ms.VerifiedAt.Equal(m.VerifiedAt) {
		return store.Membership{}, w.openErr("membership", m.Sealed, errVerifiedMoved)
	}
	if ms.Refused != m.Refused || !slices.Equal(ms.MapKeys, m.MapKeys) {
		return store.Membership{}, w.openErr("membership", m.Sealed, errMembershipMoved)
	}
	m.DN, m.EntryID, m.Username, m.GroupDNs, m.GroupNames, m.Sealed = ms.DN, ms.EntryID, ms.Username, ms.GroupDNs,
		ms.GroupNames, nil
	return m, nil
}

// GetMembership opens the record with the principal asked for, not the one
// the record names: a record a store writer copied under another key
// fails to open there (the same bound every other record has).
func (w *wrapped) GetMembership(ctx context.Context, principal string) (store.Membership, error) {
	m, err := w.inner.GetMembership(ctx, principal)
	m.Principal = principal
	return w.openMembership(m, err)
}

func (w *wrapped) MembershipByKey(ctx context.Context, mapKey string) (store.Membership, error) {
	m, err := w.openMembership(w.inner.MembershipByKey(ctx, mapKey))
	if err != nil {
		return store.Membership{}, err
	}
	// The sealed list is the truth (pre-flight I-6): the inner backend
	// checked the clear one, which openMembership has proved equal, and this
	// check stands should that ever change.
	if m.Refused || !slices.Contains(m.MapKeys, mapKey) {
		return store.Membership{}, w.openErr("membership", nil, errKeyNotSealed)
	}
	return m, nil
}

func (w *wrapped) MembershipPrincipals(ctx context.Context) ([]string, error) {
	return w.inner.MembershipPrincipals(ctx)
}

// DeleteMembership removes the record whatever it holds, and returns it
// opened. A record that does not open has been removed all the same: it
// served nothing, and forgetting it is what the operator asked. It is
// returned with its sealed part empty, its failure counted by openErr.
func (w *wrapped) DeleteMembership(ctx context.Context, principal string) (store.Membership, error) {
	m, err := w.inner.DeleteMembership(ctx, principal)
	if err != nil {
		return store.Membership{}, err
	}
	m.Principal = principal
	opened, err := w.openMembership(m, nil)
	if err != nil {
		return store.Membership{Principal: principal, VerifiedAt: m.VerifiedAt, Server: m.Server, Site: m.Site}, nil
	}
	return opened, nil
}

var _ store.Store = (*wrapped)(nil)
