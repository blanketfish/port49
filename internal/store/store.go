// Package store is the narrow interface every shared record passes through
// (design §12). The record set is the store plan; implementations are
// pluggable, and memory is the reference.
package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"
)

var ErrNotFound = errors.New("store: not found")

type TokenKey struct {
	NAS      string // device name from admission
	Username string // canonical form
}

// Token kinds.
const (
	KindLogin  = "login"
	KindEnable = "enable"
)

// Credential is what a token and its login context record about the credential
// that authorized them (spec §5.1.4). It is identity, not a secret — the daemon
// never sees the credential itself — and it is sealed, because a store dump
// should not enumerate who was logged into which device (design §8).
type Credential struct {
	Method      string // cert | oidc | k8s
	Fingerprint string
	Issuer      string
	Serial      string
	Subject     string
	Iss         string
	Sub         string
	Sid         string
	ACR         string
	AMR         []string
}

type Token struct {
	// ID is a handle, not a credential. It is never presented on the wire —
	// the daemon chooses it and only the daemon ever says it — and it is
	// deliberately plaintext so the sealing layer can address a record it
	// cannot read: RedeemAndReceipt removes by ID, because it cannot compare a
	// sealed Secret inside the inner store. That is also why memory matches it
	// with `==` rather than crypto/subtle: nothing an attacker can influence
	// reaches this comparison.
	ID        string
	Secret    []byte // sealed
	Kind      string // KindLogin | KindEnable
	ExpiresAt time.Time

	Principal     string // sealed
	Username      string // sealed
	BlobHash      string
	MaxSessionAge time.Duration // minimum across the principal's roles (spec §5.1.1)
	Enable        string        // none | auto | token (spec §7)
	MaxPrivilege  uint8
	Credential    Credential // sealed
	AuthTime      time.Time

	Sealed []byte // written by internal/store/crypt; zero in plaintext form
}

// ReceiptKey addresses the short-lived proof of a completed redemption. The
// credential hash is part of the key, not merely recorded in the record: that
// is what makes a byte-identical retransmission the only thing that replays,
// while a genuinely new login by the same user finds nothing and redeems
// normally (design §8; spec §13, decision 15).
//
// Kind is in the key for the same reason, and it is not cosmetic: a login
// receipt and an enable receipt are different records, so an enable START
// presenting the login token's secret misses and falls through to the
// candidate search and its `token_kind_mismatch`, instead of being answered
// PASS out of the login receipt and sliding it on every retry. Recording the
// kind on the Receipt instead would leave the two sharing one key, where an
// enable redemption overwrites a login receipt.
type ReceiptKey struct {
	NAS              string
	Username         string // canonical form
	Kind             string // KindLogin | KindEnable
	CredentialSHA256 [32]byte
}

// Receipt is the sliding retry tolerance of design §8. Three timestamps, and
// they answer three different questions:
//
//   - FirstRedeemedAt anchors the absolute cap. It never moves.
//   - IdleExpiresAt is the sliding bound, pushed out by ExtendReceipt on every
//     re-presentation this receipt answers.
//   - RetainUntil is the store's own TTL, and it is deliberately later than
//     both: a presentation past a bound has to find the receipt in order to be
//     answered `token_spent` rather than `token_not_found` (spec §5.7). Past
//     RetainUntil the record is reclaimed and the answer degrades to
//     `token_not_found`, which is honest — by then the token is gone too.
type Receipt struct {
	// CredentialSHA256 repeats the key's hash. The lookup already selects on
	// it; this copy is what the constant-time compare in package authen checks
	// after the lookup, so a store answering with a record it was not asked
	// for is caught rather than replayed. It is deliberately redundant and
	// must not be "simplified" away.
	CredentialSHA256 [32]byte // sealed
	Status           uint8    // sealed; the authentication REPLY status that was sent
	CtxID            string   // sealed

	FirstRedeemedAt time.Time
	IdleExpiresAt   time.Time
	RetainUntil     time.Time

	Sealed []byte
}

// ReceiptWrite is the receipt half of RedeemAndReceipt. Principal is an index
// key, not a field of the record: it is written into receipts_by_principal so
// revocation can delete a principal's receipts (spec §13, decision 15), and it
// is passed separately precisely because the record itself is sealed and the
// index is not (Task 5's argument).
type ReceiptWrite struct {
	Key       ReceiptKey
	Receipt   Receipt
	Principal string
	IndexTTL  time.Duration
}

// ContextKey addresses the login context. It is (nas, username), and it
// deliberately does not mention the port: measured, `port` is not the same
// value at the authentication that writes the context and the authorization
// that reads it on any platform in the lab (spec §13, decision 15; §15, L1).
// One consequence is accepted rather than fixed: two concurrent logins by one
// username on one device share this key.
type ContextKey struct {
	NAS      string
	Username string // canonical form
}

type Context struct {
	CtxID     string // sealed
	Principal string // sealed
	Username  string // sealed
	// Port and RemAddr are recorded as the device presented them at
	// authentication. They are attributes, never part of any key; RemAddr is
	// compared on the enable exchange (spec §5.6).
	Port     string // sealed
	RemAddr  string // sealed
	PrivLvl  uint8
	BlobHash string

	Credential     Credential // sealed
	AuthTime       time.Time
	SessionExpires time.Time // auth_time + max_session_age; zero means no ceiling
	RefreshedAt    time.Time // the staleness clock (spec §5.1.1)
	RevokedAt      time.Time // set by revocation; denies until the idle TTL reclaims
	// LastTouchedAt is when this record's expiry was last extended. It is
	// bookkeeping about the TTL, not about the session: the authorizer reads it
	// to decide whether an extension is due at all, so a steady operator costs
	// one store write per half of the idle TTL instead of one per command
	// (spec §5.6; Task 10). PutContext and TouchContext both stamp it; it is
	// plaintext, because it is a clock and not an identity.
	LastTouchedAt time.Time

	// SessionDiscriminators holds one entry per session of this user that
	// accounting has watched begin on this device, as HashDiscriminator
	// renders it (spec §5.8). It is §5.1.1's `task_id` slot under the name the
	// lab forced: `task_id` restarts at 1 per session on both Junos images, so
	// two concurrent logins both sent `task_id=1` while `session_pid` was
	// 31048 and 31050 (tests/lab/results/L17-juniper_vsrx.md:454,
	// L17-juniper_vjunos-router.md:458).
	//
	// A set rather than a value because the key is (nas, username): one
	// context covers every concurrent session of one operator (§13, decision
	// 15), so binding a single value made an operator's second window a
	// `foreign` alert. Capped at MaxSessionDiscriminators, oldest evicted.
	//
	// Plaintext, and hashed for exactly that reason: equality is all a binding
	// needs, nothing ever reads a value back out, and on cisco_nxos the
	// discriminator is `task_id`, measured as `172.100.100.1@pts/3`
	// (tests/lab/results/L1-cisco_nxos.md:60) — the client's source address.
	// RemAddr above is sealed so a store dump cannot enumerate who was logged
	// into which device; storing that address in the clear under another name
	// would have undone it. A truncated hash of a device-local identifier
	// carries neither identity nor credential, so it does not need the sealing
	// layer — and not needing it is what lets AnnotateContext be a narrow
	// under-lock setter, since the sealing layer cannot write one field of a
	// record it cannot read.
	SessionDiscriminators []string
	AccountingState       string // "" | AccountingStateOpen | AccountingStateClosing

	Enable       string // copied from the token: none | auto | token
	MaxPrivilege uint8
	CreatedAt    time.Time

	Sealed []byte
}

// The advisory accounting states (spec §5.8). Both are reported and neither
// authorizes, denies, or stops a refresh; the idle TTL reclaims the field with
// the context. A context that has never been annotated holds the empty string,
// which is why AnnotateContext treats "" as "leave it alone" and a START says
// AccountingStateOpen rather than clearing.
const (
	AccountingStateOpen    = "open"
	AccountingStateClosing = "closing"
)

// MaxSessionDiscriminators caps Context.SessionDiscriminators. Eight is well
// above the ten-concurrent-login cost §13 decision 15 accepts for the
// (nas, username) key, and the overflow is an eviction of the oldest rather
// than a refusal to add: both produce a spurious `foreign` on the evicted
// session's STOP, and refusing would lose the newest session, which is the one
// still running (spec §5.8).
const MaxSessionDiscriminators = 8

// HashDiscriminator renders a device's session discriminator for storage:
// sha256, truncated to 16 bytes, hex. Equality is all a binding needs, and the
// truncation is what keeps a client source address — the measured NX-OS
// `task_id` is `172.100.100.1@pts/3` — out of the store in the clear. See
// Context.SessionDiscriminators.
//
// It is not a security boundary against a chosen-plaintext guess: a
// discriminator's value space is small, so someone holding a store dump and a
// suspected address can confirm it. It is a defence against a dump ENUMERATING
// addresses, which is what sealing RemAddr buys and what this preserves.
func HashDiscriminator(v string) string {
	sum := sha256.Sum256([]byte(v))
	return hex.EncodeToString(sum[:16])
}

// ContextRef is what the indexes hold: the context key, nothing more.
type ContextRef struct {
	NAS      string
	Username string
}

type Idempotency struct {
	BodyHash  string
	Response  []byte // sealed — it contains the minted tokens (design §17)
	ExpiresAt time.Time
	Sealed    []byte
}

type Store interface {
	PutToken(ctx context.Context, k TokenKey, t Token) (count int, err error)
	Candidates(ctx context.Context, k TokenKey) ([]Token, error)
	// RedeemAndReceipt removes the token with this ID and writes the receipt in
	// one atomic operation, indexing the receipt by principal (design §12).
	RedeemAndReceipt(ctx context.Context, k TokenKey, tokenID string, w ReceiptWrite) error
	DeleteTokens(ctx context.Context, k TokenKey) error
	GetReceipt(ctx context.Context, rk ReceiptKey) (Receipt, error)
	// ExtendReceipt pushes the sliding bound out. It never moves RetainUntil or
	// FirstRedeemedAt, so the absolute cap cannot be slid.
	ExtendReceipt(ctx context.Context, rk ReceiptKey, idleExpiresAt time.Time) error
	DeleteReceiptsByPrincipal(ctx context.Context, principal string) (int, error)

	PutContext(ctx context.Context, k ContextKey, c Context, ttl time.Duration) error
	GetContext(ctx context.Context, k ContextKey) (Context, error)
	// TouchContext extends this context's expiry to now+ttl. It writes exactly
	// two things, both plaintext bookkeeping about the extension itself: the
	// expiry, and LastTouchedAt. It never takes a Context from the caller.
	//
	// That is the whole point of it. Extending a TTL by reading the record and
	// writing it back discards everything written between the two, and one of
	// those writers is revocation: an extension racing RevokeByPrincipal writes
	// a copy whose RevokedAt is zero, and it stays zero — the receipts are
	// already deleted, so nothing sets it again. The operator's revocation
	// reports contexts touched and the session keeps working, silently, on the
	// highest-frequency path in the daemon. Accounting's annotation and the
	// enable path's privilege raise lose the same way.
	//
	// ErrNotFound if the key is absent or already expired, which is how the
	// caller learns it lost the race; PutContext cannot tell it that.
	TouchContext(ctx context.Context, k ContextKey, ttl time.Duration) error
	// SetPrivilege records the level port49 last granted this context, in
	// place and under the store's own lock. It writes exactly one field,
	// PrivLvl, and is TouchContext's sibling for the same reason: the
	// authorization path must not write back a record it read at the top of
	// the request, because the writer it would race is revocation.
	//
	// It is not an extension. The expiry and LastTouchedAt are TouchContext's
	// to move, so a device that only ever authorizes sessions cannot keep a
	// context alive by being granted the same level over and over.
	//
	// The caller is a permitted session authorization whose reply carried a
	// `priv-lvl` attribute: on vEOS the login START arrives at level 1, that
	// reply grants 15, and every command after it arrives at 15, so a context
	// still holding the login level would deny all of them
	// (spec §5.3, §7; tests/lab/results/L1-arista_eos.md, L3-arista_eos.md).
	// The enable path updates the same field, also in place and with the same
	// ctx_id.
	//
	// ErrNotFound if the key is absent or already expired.
	SetPrivilege(ctx context.Context, k ContextKey, level uint8) error
	// AnnotateContext records what an exec accounting record concluded about
	// this session, in place and under the store's own lock (spec §5.8). It is
	// TouchContext's and SetPrivilege's sibling and exists for the same
	// reason, which store.Store's comment on TouchContext names by hand:
	// accounting must not write back a whole Context it read at the top of the
	// request, because the writer it would race is revocation, and the
	// re-put's RevokedAt is zero.
	//
	// discHash, when non-empty, is added to SessionDiscriminators if it is not
	// already there; past MaxSessionDiscriminators the oldest is evicted. It
	// is the output of HashDiscriminator, never a raw device value.
	// state, when non-empty, replaces AccountingState; the empty string leaves
	// it alone, so a START that clears it passes AccountingStateOpen rather
	// than "".
	//
	// It writes nothing else. In particular it does NOT extend the expiry or
	// stamp LastTouchedAt: accounting is not activity for the idle TTL (spec
	// §5.8), or a device sending only STOPs could hold a context open forever.
	//
	// ErrNotFound if the key is absent or already expired.
	AnnotateContext(ctx context.Context, k ContextKey, discHash, state string) error
	// DeleteContext has no production caller today: the caller it had was
	// author's `username_mismatch` branch, which under the old `(nas, port)`
	// key could delete a live operator's context on an uncredentialed request.
	// Plan 2 owns it — revocation and §5.6 teardown rows 2 through 4 all need
	// it — so it stays.
	DeleteContext(ctx context.Context, k ContextKey) error

	PutBlob(ctx context.Context, hash string, body []byte, ttl time.Duration) error
	GetBlob(ctx context.Context, hash string) ([]byte, error)
	// BumpBlob extends a blob to at least now+ttl and never shortens it.
	BumpBlob(ctx context.Context, hash string, ttl time.Duration) error

	IndexContext(ctx context.Context, principal, sid, certKey string, ref ContextRef, ttl time.Duration) error
	UnindexContext(ctx context.Context, principal, sid, certKey string, ref ContextRef) error
	ContextsByPrincipal(ctx context.Context, principal string) ([]ContextRef, error)
	ContextsBySid(ctx context.Context, sid string) ([]ContextRef, error)
	ContextsByCert(ctx context.Context, certKey string) ([]ContextRef, error)
	ReindexSid(ctx context.Context, oldSid, newSid string, ref ContextRef, ttl time.Duration) error
	ActivePrincipals(ctx context.Context) ([]string, error)

	PutIdempotency(ctx context.Context, principal, key string, rec Idempotency) error
	GetIdempotency(ctx context.Context, principal, key string) (Idempotency, error)
}

// CertKey is the index key a CRL or OCSP response names (spec §5.1.4).
func CertKey(issuer, serial string) string { return issuer + "|" + serial }

// HasCeiling reports whether this context carries a session ceiling.
func (c Context) HasCeiling() bool { return !c.SessionExpires.IsZero() && !c.AuthTime.IsZero() }
