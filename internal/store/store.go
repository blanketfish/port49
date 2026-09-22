// Package store is the narrow interface every shared record passes through
// (design §12). The record set is the store plan; implementations are
// pluggable, and memory is the reference.
package store

import (
	"context"
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
type ReceiptKey struct {
	NAS              string
	Username         string // canonical form
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

	// SessionDiscriminator is the value of whatever AV pair separates two
	// sessions of one user on one device, per platform (spec §5.8). It is
	// §5.1.1's `task_id` slot under the name the lab forced: `task_id` restarts
	// at 1 per session on both Junos images
	// (tests/lab/results/L1-juniper_vsrx.md, L1-juniper_vjunos-router.md).
	SessionDiscriminator string // sealed
	AccountingState      string // "" | "open" | "closing"; advisory, never authorizes

	Enable       string // copied from the token: none | auto | token
	MaxPrivilege uint8
	CreatedAt    time.Time

	Sealed []byte
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
	// DeleteContext has no production caller today: the caller it had was
	// author's `username_mismatch` branch, which under the old `(nas, port)`
	// key could delete a live operator's context on an uncredentialed request.
	// Plan 2 owns it — revocation and §5.6 teardown rows 2 through 4 all need
	// it — so it stays.
	DeleteContext(ctx context.Context, k ContextKey) error

	// Task 3 appends here: PutBlob, GetBlob, BumpBlob, IndexContext,
	// UnindexContext, ContextsByPrincipal, ContextsBySid, ContextsByCert,
	// ReindexSid, ActivePrincipals, PutIdempotency, GetIdempotency.
}

// CertKey is the index key a CRL or OCSP response names (spec §5.1.4).
func CertKey(issuer, serial string) string { return issuer + "|" + serial }

// HasCeiling reports whether this context carries a session ceiling.
func (c Context) HasCeiling() bool { return !c.SessionExpires.IsZero() && !c.AuthTime.IsZero() }
