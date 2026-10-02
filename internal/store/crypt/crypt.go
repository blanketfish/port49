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
// back an earlier version of the same context. That residual undoes a
// revocation that leaves no mark (a self or key revocation) or a policy
// narrowing, a clamp included, until the next refresh (spec §13, decision
// 35). The put-back that would be impersonation, another login's context
// written over this one's, the Ledger denies while this process runs.
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
// whole record. A context in any other form does not open, and is
// replaced at its next login (store.UnreadableContextError).
const contextSealVersion = 2

// contextSecret is everything of a context the authorizer trusts,
// sealed whole (plan 7d; Ruling 17): the identity and credential, as
// before, and the privilege, the ceiling, the policy, the clocks, the
// revocation and the login witness (Context.Logins). Only the store's bookkeeping stays outside it: the
// revisions, the idle clock (LastTouchedAt), and accounting's
// annotations, which authorize nothing. RevokedAt is also written in
// the clear (sealContext).
type contextSecret struct {
	V              int              `json:"v"`
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
}

// Option configures Wrap.
type Option func(*wrapped)

// WithLedger shares l with every other Wrap given it, so the daemon's and
// the broker's layers in one process agree on what each key last held
// (re-check IA1). Without it each Wrap keeps its own, never sealed.
func WithLedger(l *Ledger) Option { return func(w *wrapped) { w.ledger = l } }

// Wrap decorates inner so every credential-bearing record is sealed under k
// before it reaches the backend. openFailures may be nil; the daemon passes
// metrics.CryptOpenFailures. inner reports the revision each context write
// committed at, which is how the ledger orders them (store.RevStore).
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

// errExpiryMoved is a token whose plaintext expiry is not the one sealed
// with it. sealToken writes them equal, so a store write moved it, and an
// extended one would be redeemable past the sealed one: it is dropped as
// a token that will not open.
var errExpiryMoved = errors.New("crypt: a token's plaintext expiry differs from its sealed one")

func (w *wrapped) sealToken(k store.TokenKey, t store.Token) (store.Token, error) {
	b, err := json.Marshal(tokenSecret{Secret: t.Secret, Principal: t.Principal, Username: t.Username,
		Credential: t.Credential, Kind: t.Kind, ExpiresAt: t.ExpiresAt, BlobHash: t.BlobHash,
		MaxSessionAge: t.MaxSessionAge, Enable: t.Enable, MaxPrivilege: t.MaxPrivilege, AuthTime: t.AuthTime,
		MintedAt: t.MintedAt})
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
		MaxPrivilege: ts.MaxPrivilege, Credential: ts.Credential, AuthTime: ts.AuthTime, MintedAt: ts.MintedAt}, nil
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
			_ = w.openErr("token", err)
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
		return store.Receipt{}, w.openErr("receipt", err)
	}
	var rs receiptSecret
	if err := json.Unmarshal(b, &rs); err != nil {
		return store.Receipt{}, w.openErr("receipt", err)
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

// sealContext seals c's trusted fields for k. What the backend holds
// beside the sealed bytes is the bookkeeping and RevokedAt: the
// revocation stays in the clear too, so a revocation needs no key
// (SetRevokedAt), and a read takes the later of the two (openContext).
func (w *wrapped) sealContext(k store.ContextKey, c store.Context) (store.Context, error) {
	b, err := json.Marshal(contextSecret{V: contextSealVersion, CtxID: c.CtxID, Principal: c.Principal,
		Username: c.Username, Port: c.Port, RemAddr: c.RemAddr, Credential: c.Credential, PrivLvl: c.PrivLvl,
		BlobHash: c.BlobHash, MaxPrivilege: c.MaxPrivilege, Enable: c.Enable, AuthTime: c.AuthTime,
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

// openContext is sealContext reversed for the record read at k. Every
// trusted field is the sealed one; RevokedAt is the later of the sealed
// and the plaintext, so a keyless revocation is in force at once and a
// store write that zeroes the plaintext lifts nothing.
func (w *wrapped) openContext(k store.ContextKey, c store.Context) (store.Context, error) {
	b, err := w.keys.OpenBound(c.Sealed, contextAAD(k))
	if err != nil {
		return store.Context{}, err
	}
	var cs contextSecret
	if err := json.Unmarshal(b, &cs); err != nil {
		return store.Context{}, err
	}
	if cs.V != contextSealVersion {
		return store.Context{}, fmt.Errorf("crypt: a context sealed in form %d, not %d", cs.V, contextSealVersion)
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
		Rev: c.Rev, PolicyRev: c.PolicyRev}, nil
}

// sent sends one sealed write of the context id at k, compared on rev
// (zero for none), telling the ledger before and after, with the revision
// it committed at (re-check IA1; Task 6b).
func (w *wrapped) sent(k store.ContextKey, id string, rev uint64, send func() (uint64, error)) error {
	lw := w.ledger.begin(k, id, rev)
	committed, err := send()
	w.ledger.end(lw, committed, err)
	return err
}

func (w *wrapped) PutContext(ctx context.Context, k store.ContextKey, c store.Context, ttl time.Duration) error {
	sc, err := w.sealContext(k, c)
	if err != nil {
		return err
	}
	return w.sent(k, c.CtxID, 0, func() (uint64, error) { return w.inner.PutContextRev(ctx, k, sc, ttl) })
}

// SwapContext seals as PutContext does and hands the revision through
// untouched. Rev is plaintext, and that is what lets this layer take part in a
// compare-and-set at all: the inner store compares a revision it can read on a
// record it cannot, so the merge happens up here with the fields open and the
// precondition is enforced down there under its own lock (store.Store).
func (w *wrapped) SwapContext(ctx context.Context, k store.ContextKey, rev uint64, c store.Context, ttl time.Duration) error {
	sc, err := w.sealContext(k, c)
	if err != nil {
		return err
	}
	return w.sent(k, c.CtxID, rev, func() (uint64, error) { return w.inner.SwapContextRev(ctx, k, rev, sc, ttl) })
}

// SwapLogin seals as SwapContext does, and passes the index change and the
// marks through: both are plaintext, as the indexes and the marks are (the
// package comment), so the inner store compares and writes them under the
// same step as the sealed context.
func (w *wrapped) SwapLogin(ctx context.Context, k store.ContextKey, rev uint64, c store.Context, ttl time.Duration,
	lw store.LoginWrite) error {
	sc, err := w.sealContext(k, c)
	if err != nil {
		return err
	}
	return w.sent(k, c.CtxID, rev, func() (uint64, error) { return w.inner.SwapLoginRev(ctx, k, rev, sc, ttl, lw) })
}

func (w *wrapped) GetContext(ctx context.Context, k store.ContextKey) (store.Context, error) {
	at := w.ledger.mark()
	c, err := w.inner.GetContext(ctx, k)
	if errors.Is(err, store.ErrNotFound) {
		w.ledger.forget(k, at, true)
	}
	if err != nil {
		return store.Context{}, err
	}
	oc, err := w.openContext(k, c)
	if err != nil {
		// The record is there and will not open. Its revision and revocation
		// are plaintext, and JoinContext needs both to replace it without
		// racing a revocation or lifting one (store.UnreadableContextError).
		// The wrapped error is openErr's, so errors.Is(err, ErrUnknownKey)
		// still tells a wrong key from a tampered record.
		return store.Context{}, &store.UnreadableContextError{Rev: c.Rev, RevokedAt: c.RevokedAt,
			Err: w.openErr("context", err)}
	}
	// The ledger (re-check IA1): a record sealed for this key that is not
	// the one this process last wrote here, or first read here, is another
	// login's written back. It opens, since it is bound to this key, and so
	// it is denied as one that does not.
	if !w.ledger.admits(k, oc.CtxID) {
		return store.Context{}, &store.UnreadableContextError{Rev: c.Rev, RevokedAt: c.RevokedAt,
			Err: w.openErr("context", ErrNotLastWritten)}
	}
	return oc, nil
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
		sc, err := w.sealContext(k, c)
		if err != nil {
			return err
		}
		switch err := w.sent(k, c.CtxID, rev, func() (uint64, error) {
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
// reads. The window, the blob hash and the clocks it writes are sealed
// (plan 7d). The credential's sid is not rewritten: a rotated sid moves in
// the plaintext index instead, through ReindexSid, which is what
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
func (w *wrapped) SetRevokedAt(ctx context.Context, k store.ContextKey, at time.Time) error {
	if err := w.inner.SetRevokedAt(ctx, k, at); err != nil {
		return err
	}
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

// RewriteContext seals c for k and passes the write through, telling
// the ledger.
func (w *wrapped) RewriteContext(ctx context.Context, k store.ContextKey, rev uint64, c store.Context, ttl time.Duration,
	policyMoved bool) error {
	sc, err := w.sealContext(k, c)
	if err != nil {
		return err
	}
	return w.sent(k, c.CtxID, rev, func() (uint64, error) {
		return w.inner.RewriteContextRev(ctx, k, rev, sc, ttl, policyMoved)
	})
}

// DeleteContext is addressed by key alone. One that lands takes the key
// out of the ledger (Ledger.forget).
func (w *wrapped) DeleteContext(ctx context.Context, k store.ContextKey) error {
	at := w.ledger.mark()
	err := w.inner.DeleteContext(ctx, k)
	if err == nil {
		w.ledger.forget(k, at, false)
	}
	return err
}

// DeleteContextIf passes through: it is addressed by key and compares Rev,
// which is plaintext bookkeeping. One that lands takes the key out of the
// ledger, as DeleteContext does.
func (w *wrapped) DeleteContextIf(ctx context.Context, k store.ContextKey, rev uint64) error {
	at := w.ledger.mark()
	err := w.inner.DeleteContextIf(ctx, k, rev)
	if err == nil {
		w.ledger.forget(k, at, false)
	}
	return err
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
		return store.Idempotency{}, false, w.openErr("idempotency", err)
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

var _ store.Store = (*wrapped)(nil)
