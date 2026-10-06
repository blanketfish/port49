// Package store is the narrow interface every shared record passes through
// (design §12). The record set is the store plan; implementations are
// pluggable, and memory is the reference.
package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

var ErrNotFound = errors.New("store: not found")

// ErrConflict is a compare-and-set refused because the record is no longer
// the one the caller read: SwapContext's context, written by another writer
// since, expired, or appeared where none was; or CompleteIdempotency's
// record, no longer held by the caller (plan 7a); or a RefreshContext with
// an ExpectRev, or a DeleteContextIf, whose revision moved (plan 7b).
// Nothing was written. The caller reads again and decides again;
// JoinContext is the loop that does.
var ErrConflict = errors.New("store: context changed since it was read")

// ErrPastGrace is RefreshContext refusing a context whose ceiling is
// earlier than the refresh's GraceCutoff: past the grace window, a session
// is over and no refresh resumes it (spec §5.6, teardown row 3). Nothing
// was written.
var ErrPastGrace = errors.New("store: context is past its grace window")

// ErrUnavailable is a store that did not answer, or answered with an
// error that is not about the record: a network backend that timed out,
// lost its quorum, or is unreachable. The guard (internal/store/guard)
// counts it toward a pool's circuit, and every handler answers it
// store_unavailable, as any error that is not ErrNotFound (spec §5.7).
var ErrUnavailable = errors.New("store: unavailable")

// ErrRefused is a backend refusing this identity an operation by its own
// access control: an etcd role that does not grant it, or authentication
// that failed. It is configuration, not an outage: never ErrUnavailable,
// so it opens no circuit, and the guard (internal/store/guard) stops
// port49d's service when every call is refused for store.etcd.hold_ttl
// (plan 7d; pre-flight I10). Handlers answer it store_unavailable.
var ErrRefused = errors.New("store: refused this identity")

// UnreadableContextError is a context record the store returned and the
// sealing layer could not open: sealed under a key that has left the two-key
// window, or failing authentication. It is not ErrNotFound — the record is
// there — and it carries the two plaintext fields a login needs to replace the
// record safely (spec §5.6): the revision, so the replace is still a
// compare-and-set, and the revocation, so the replace cannot lift it. Every
// reader but JoinContext treats it as the store error it wraps.
type UnreadableContextError struct {
	Rev       uint64
	RevokedAt time.Time
	Err       error
}

// Error does not assume Err is set: it is read on the login path at the moment
// a key has rotated out, and a backend that left Err nil must not panic there.
func (e *UnreadableContextError) Error() string {
	if e.Err == nil {
		return "store: context record could not be opened"
	}
	return e.Err.Error()
}

func (e *UnreadableContextError) Unwrap() error { return e.Err }

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
	// MintedAt is when the broker cut this token, on the broker's clock — the
	// clock revocation stamps RevokedAt with. AuthTime cannot stand in for it:
	// that is when the human authenticated at the IdP, which can be hours
	// before a mint, so a token minted after a revocation can carry an
	// AuthTime from before it. JoinContext compares this to a live context's
	// RevokedAt (spec §5.6). Zero reads as "minted before any revocation",
	// which keeps the mark.
	MintedAt time.Time
	// VerifiedAt is when the directory membership this token was minted on
	// was verified (plan 7g, Ruling 11): the login writes it as the
	// context's RefreshedAt, so a grace mint never resets the staleness
	// clock. Zero is a mint with no directory: the redemption's now.
	VerifiedAt time.Time

	Sealed []byte // written by internal/store/crypt; zero in plaintext form
}

// String is the token with its secret withheld, so that a %v anywhere — a
// test's failure message, a debug line — never prints one (plan 7b final
// review M-1).
func (t Token) String() string {
	type plain Token
	p := plain(t)
	if len(p.Secret) > 0 {
		p.Secret = []byte("<withheld>")
	}
	return fmt.Sprintf("%+v", p)
}

// GoString is String, for %#v.
func (t Token) GoString() string { return t.String() }

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

	// Failed is set by FailReceipt and overrides Status: the login this
	// receipt was written for was refused after the receipt was written (a
	// join that wrote a revoked context), and every retransmission replays
	// that refusal. Plaintext on purpose, like the bounds: it is written
	// without opening the record, so any daemon can write it whatever key
	// sealed the rest. A store write can clear it, and that turns the
	// replay back into the PASS the receipt was written with; it is not what
	// refuses that login: the context never witnessed it (Context.Logins),
	// so a PASS replay is token_spent whatever Failed says (Task 4b review
	// I2). Failed is what makes the answer the refusal instead.
	Failed bool

	// Principal, Sid and CertKey name the credential the redeemed token
	// carried: its principal, its credential's sid, and CertKey of its
	// certificate. A retransmission replays this receipt's PASS only while
	// no mark stands for that principal or certificate, and, for a login,
	// only once the index reaches the context under the sid and the
	// certificate, which is how a login that committed is told from one
	// that did not or is still in flight (spec §5.6; plan 7d). Sealed.
	Principal string // sealed
	Sid       string // sealed
	CertKey   string // sealed

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

// LedgerMark is one key's entry in the ledger record (plan 7e, Ruling 4):
// the highest write sequence known there, a revocation's plaintext time
// held through FloorSeq (the floor, which a sequence above FloorSeq
// clears), and until when it is kept (zero: for good, a never context's).
type LedgerMark struct {
	Key       ContextKey
	Seq       uint64
	RevokedAt time.Time
	FloorSeq  uint64
	Until     time.Time
}

// ContextChange is one change to the context family, as a feed brings it
// (plan 7e, Ruling 3): the record as GetContext's backend returns it
// (sealed under crypt), or Deleted, at revision Rev.
type ContextChange struct {
	Key     ContextKey
	Context Context
	Deleted bool
	Rev     uint64
}

// ContextFeed is a backend's context family as a stream: a scan at one
// revision, then every change after it. A watch never admits a record;
// what follows it only raises what a read must clear.
type ContextFeed interface {
	// ScanContexts calls fn for every live context at one revision, which
	// it returns.
	ScanContexts(ctx context.Context, fn func(ContextKey, Context)) (uint64, error)
	// WatchContexts calls fn for every change after `after`, in revision
	// order, until ctx ends (ctx.Err()), the revision was compacted
	// (ErrCompacted), or the watch fails (ErrUnavailable, or ErrRefused
	// when the store will not let this identity watch). progress is told
	// a revision through which every change has been delivered: each
	// batch's highest event once fn has had them all, and each progress
	// notification's header revision. Each receive on asks requests one
	// such notification from the store; a nil asks requests none (plan 7e,
	// the feed fence).
	WatchContexts(ctx context.Context, after uint64, fn func(ContextChange), progress func(rev uint64),
		asks <-chan struct{}) error
}

// MarkFeed is a backend's revocation marks as a stream (plan 7e, Ruling 5):
// every mark at one revision, then every put and lift after it.
type MarkFeed interface {
	// Revocations is every mark in force at one revision, which it
	// returns.
	Revocations(ctx context.Context) (uint64, []Revocation, error)
	// WatchRevocations calls fn for every put (lifted false) and lift
	// (lifted true) after `after`, in revision order, with the change's
	// revision, until ctx ends (ctx.Err()), the revision was compacted
	// (ErrCompacted), or the watch fails. A lift carries only Kind and
	// Key. progress is told each progress notification's header revision,
	// through which every change has been delivered, so a re-watch after a
	// quiet hour resumes above a compaction rather than reloading (final
	// review 7e-1 I-1).
	WatchRevocations(ctx context.Context, after uint64, fn func(r Revocation, lifted bool, rev uint64),
		progress func(rev uint64)) error
}

// ErrCompacted is a feed asked for revisions the store no longer keeps: the
// follower scans again.
var ErrCompacted = errors.New("store: the feed's revision was compacted")

// LedgerSource reads the ledger record at one revision (plan 7e, Ruling 4).
type LedgerSource interface {
	LedgerMarks(ctx context.Context) (uint64, []LedgerMark, error)
}

// LedgerSink raises the ledger record's marks, never lowering one. It
// returns how many of ms, from the first, landed (or raised nothing) before
// an error, so a keeper owes again only the rest.
type LedgerSink interface {
	PutLedgerMarks(ctx context.Context, ms []LedgerMark) (int, error)
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

	// Logins witnesses the logins this context committed: LoginWitness of
	// each one's presented credential, written by the join in the same
	// step as the context, and only when the context it writes is not
	// revoked; the last MaxLogins are kept. A retransmission replays PASS
	// only for a login named here (spec §5.6; Task 4b review I1), so a
	// login whose join ERRORed, is still in flight, or wrote a revoked
	// context is token_spent. Sealed, and hash prefixes only: it is never
	// logged.
	Logins []string // sealed

	// Rev is the store's revision of this record. GetContext sets it and
	// SwapContext compares it; every other writer ignores what the caller
	// passes, and every write to the record — each narrow setter included —
	// moves it. That last part is the point: a read-merge-write that lost a
	// race to SetRevokedAt finds the revision moved and reads again, rather
	// than putting back a copy whose RevokedAt is zero. It only grows, across
	// every key: a write takes a revision above any context has held (etcd's
	// mod_revision), so of two writes the later holds the larger. The
	// sealing layer draws each write's sealed sequence above it, and above
	// every revision the store has told it (crypt.Ledger; RevStore.Seen),
	// so a restore that takes revisions back, or bumps them, moves no
	// sequence back. It is plaintext bookkeeping, like the expiry.
	Rev uint64
	// PolicyRev is the store's revision of what a policy refresh decides
	// (spec §5.1.3): GetContext sets it and SetContextPolicy compares it.
	// Only a write to what the refresh decides moves it — a whole-record
	// write (a join or replace), a revocation, a privilege level that
	// changed, and a policy write (blob hash, ceiling, enable). Accounting and
	// the idle TTL's touches do not, so a session reporting every command
	// never makes the refresh lose. It is plaintext bookkeeping, like Rev,
	// and is drawn from the same counter, so it never repeats either.
	PolicyRev uint64

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

// MaxLogins caps Context.Logins. A login evicted past it fails closed: its
// retransmission is token_spent rather than PASS, which costs the device
// one prompt. Eight is above the concurrent windows MaxSessionDiscriminators
// already accepts.
const MaxLogins = 8

// LoginWitness renders a login's presented credential for Context.Logins:
// the first 8 bytes of its credential_sha256, hex. It names a login within
// one context's last few, which is all a replay asks of it.
func LoginWitness(credentialSHA256 [32]byte) string {
	return hex.EncodeToString(credentialSHA256[:8])
}

// addLogins is held with add appended, the last MaxLogins kept, in a new
// slice.
func addLogins(held, add []string) []string {
	out := append(append([]string(nil), held...), add...)
	if len(out) > MaxLogins {
		out = out[len(out)-MaxLogins:]
	}
	return out
}

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

// ContextRefresh is what a broker refresh writes into a live context. It is a
// struct rather than a list of parameters because RefreshContext is a narrow
// setter: what it may write is a closed list, and naming that list in one type
// is what keeps it closed.
type ContextRefresh struct {
	// AuthTime is the new authentication time. SessionExpires is recomputed
	// from it inside the store's lock: from SessionAge when it is set, and
	// otherwise keeping the window the record's own (AuthTime,
	// SessionExpires) pair described — a ceiling moves forward by the same
	// span, and a context without one (HasCeiling false) does not gain one.
	// The caller cannot compute it, because the pair it would read is the
	// pair the write is about to replace.
	AuthTime time.Time
	// RefreshedAt is the staleness clock (spec §5.1.1). It is the broker's
	// clock, not the store's: the refresh happened when the broker said it
	// did.
	RefreshedAt time.Time
	// BlobHash, when non-empty, replaces the context's policy blob hash.
	// Empty leaves it alone — a refresh that did not recompute policy must
	// not erase the hash the authorizer reads.
	BlobHash string
	// Sid, when non-empty, is the OIDC session id a refresh rotated to: it
	// replaces the context's Credential.Sid, so the sealed record names
	// the sid the index lists, and the re-index can tell a sid a store
	// write swapped from one a refresh rotated (Task 7b review I-2). Empty
	// leaves it alone.
	Sid string
	// SessionAge, when set, is the ceiling the policy in force gives this
	// context: SessionExpires becomes AuthTime plus it, and zero clears it
	// (never). A refresh is a fresh authentication event, so it may lengthen
	// a ceiling (spec §5.6; decision 33). Nil keeps the window the record's
	// own pair described, as before. A caller passing SessionAge passes
	// GraceCutoff with it: without one, nothing stops the refresh carrying
	// a session already past its window forward.
	SessionAge *time.Duration
	// GraceCutoff, when non-zero, is the earliest ceiling a refresh may
	// extend: the refresh time less the grace window. A context whose
	// SessionExpires is non-zero and before it is ErrPastGrace and is not
	// written; that is the authorizer's reading of a ceiling, so a context it
	// denies session_expired is one no refresh resumes. A context with none
	// (never) has no window to be past and is refreshed. It is checked under
	// the store's lock, so a refresh racing the window's end cannot resume a
	// session the window closed. Zero checks nothing.
	GraceCutoff time.Time
	// ExpectRev, when non-zero, is the revision the caller read: the write
	// lands only on that record, else ErrConflict, so a context another
	// principal's login replaced in between is not extended.
	ExpectRev uint64
}

// ContextPolicy is what a policy refresh writes into a live context (spec
// §5.1.3): the policy's answer for this principal on this device, re-resolved
// against the policy now in force. It is a struct for the reason
// ContextRefresh is: what SetContextPolicy may write is a closed list, and
// naming that list in one type is what keeps it closed.
type ContextPolicy struct {
	// RevokedAt, when non-zero, is the whole write: the principal has no grant
	// on this device any more, and the context is marked revoked at this
	// instant, unless it is already revoked later. The fields below are then
	// ignored — a revoked context's policy is never read again (spec §5.3).
	RevokedAt time.Time
	// BlobHash replaces the context's policy blob hash. It is never empty on
	// a write that does not revoke.
	BlobHash string
	// MaxPrivilege replaces the context's privilege ceiling; zero is none,
	// as on the token (Context.PrivilegeCeiling). A held level above a new
	// ceiling is lowered to it.
	MaxPrivilege uint8
	// Enable replaces the enable mechanism: none | auto | token (spec §7).
	Enable string
	// MaxSessionAge is the policy's ceiling for this principal on this
	// device, zero for never (spec §5.6). SessionExpires becomes AuthTime
	// plus it only when that is earlier, or the context has none: a policy
	// edit shortens a session, and only a fresh authentication event
	// lengthens one (decision 33). Zero changes nothing. A context with no
	// AuthTime to anchor the ceiling to is given one in the distant past,
	// as a login gives a token with none: it denies, loudly, rather than
	// passing for a legitimate never.
	MaxSessionAge time.Duration
	// RefreshedAt, when non-zero, raises the context's RefreshedAt to it:
	// the scheduled refresh verified the directory (plan 7g, Ruling 12). A
	// policy reload leaves it zero: nothing about the directory was
	// re-verified (spec §5.1.3).
	RefreshedAt time.Time
}

// ContextRef is what the indexes hold: the context key, nothing more.
type ContextRef struct {
	NAS      string
	Username string
}

// IndexedRef is a context's ref and the keys its index record lists live,
// as the etcd backend's re-index scan reads them (plan 7d; re-check IA2
// and I2). The record is plaintext, so the re-index compares it with the
// context's own principal, sid and certificate, read sealed. A record that
// is gone, lists nothing live, or does not decode lists nothing.
type IndexedRef struct {
	ContextRef
	Principals, Sids, Certs []string
}

// MarkRead is a revocation mark as a login read it: At is the mark's, or
// zero when none stood (plan 7d).
type MarkRead struct {
	Kind, Key string
	At        time.Time
}

// LoginWrite is what a login's SwapLogin carries beside the context: the
// index change its join decided, and the marks it read (spec §13,
// decision 35). The zero value changes no index and checks no mark,
// which is SwapContext.
type LoginWrite struct {
	// ClearRef unindexes the ref from every key it was indexed under: a
	// replace by another principal, or of a record that would not open.
	ClearRef bool
	// DropSid and DropCertKey are a same-principal replace's displaced
	// credential, unindexed where this login does not share it.
	DropSid, DropCertKey string
	// Principal, Sid and CertKey index the ref for IndexTTL.
	Principal, Sid, CertKey string
	IndexTTL                time.Duration
	// Marks must still be as read for the write to land.
	Marks []MarkRead
}

type Idempotency struct {
	BodyHash  string
	Response  []byte // sealed — it contains the minted tokens (design §17)
	ExpiresAt time.Time
	Sealed    []byte
	// Holder is the request that reserved the record (ReserveIdempotency):
	// random, never logged, and kept when the record is completed, so a
	// completion is a compare-and-set on it (CompleteIdempotency).
	Holder string
	// Pending is a reservation whose mint has not finished. It carries no
	// Response; a request that finds it is told to retry, and nothing is
	// minted for it (design §17).
	Pending bool
}

type Store interface {
	PutToken(ctx context.Context, k TokenKey, t Token) (count int, err error)
	Candidates(ctx context.Context, k TokenKey) ([]Token, error)
	// RedeemAndReceipt removes the token with this ID and writes the receipt in
	// one atomic operation, indexing the receipt by principal (design §12).
	RedeemAndReceipt(ctx context.Context, k TokenKey, tokenID string, w ReceiptWrite) error
	DeleteTokens(ctx context.Context, k TokenKey) error
	// DeleteToken removes the one live token with this ID under k, and
	// nothing else: a principal ending its own sessions deletes its own
	// tokens, never another's under the same (device, username) (spec
	// §5.1.4; decision 34). ErrNotFound when no live token under k has that
	// ID. The ID is plaintext (Token.ID), so the sealing layer passes it
	// through.
	// It leaves the token index (IndexToken) as it is. That index is by key,
	// not by ID, and the same principal or certificate can hold a second live
	// token under k: pruning its entry would let a revocation miss that
	// token, where a stale entry costs a revocation of that principal one
	// DeleteTokens on k, which, as for a live entry, also ends any other
	// principal's tokens there.
	DeleteToken(ctx context.Context, k TokenKey, id string) error
	// PurgeTokens deletes every token record, live or expired, under every
	// key, and reports how many were live. It is a start on a store that
	// persists (plan 7d): no policy this port49d loaded minted them, so none
	// is redeemable after it, as none was after a restart of the memory
	// store. The token indexes stay; an entry that outlives its token costs
	// a revocation one DeleteTokens on an empty key (IndexToken).
	PurgeTokens(ctx context.Context) (int, error)
	GetReceipt(ctx context.Context, rk ReceiptKey) (Receipt, error)
	// ExtendReceipt pushes the sliding bound out. It never moves RetainUntil or
	// FirstRedeemedAt, so the absolute cap cannot be slid.
	ExtendReceipt(ctx context.Context, rk ReceiptKey, idleExpiresAt time.Time) error
	// FailReceipt sets Failed on a live receipt and touches nothing else. It
	// is how a login refused after its receipt was written makes every
	// retransmission replay the refusal (spec §5.6).
	FailReceipt(ctx context.Context, rk ReceiptKey) error
	DeleteReceiptsByPrincipal(ctx context.Context, principal string) (int, error)

	// PutContext writes c unconditionally. No production path calls it: the
	// login path joins through SwapContext (JoinContext), and every other
	// writer has a narrow setter. It stays for seeding and tests.
	PutContext(ctx context.Context, k ContextKey, c Context, ttl time.Duration) error
	GetContext(ctx context.Context, k ContextKey) (Context, error)
	// SwapContext is PutContext with a precondition: it writes c only if the
	// record at k is still the one the caller read. rev is the Rev GetContext
	// returned; zero means "only if there is no live record". Anything else —
	// a revision that moved, a record that expired, a record that appeared —
	// is ErrConflict, and nothing is written.
	//
	// It is how a whole-record write is made safe against the narrow setters.
	// The login path has to write most of a context (spec §5.6, the join
	// table), and the sealing layer cannot merge fields it cannot read under
	// the inner store's lock, so it reads, merges, and swaps; a revocation,
	// annotation, privilege raise or refresh that landed in between moves the
	// revision and the swap refuses. See JoinContext.
	//
	// On success it behaves as PutContext does: the expiry is now+ttl,
	// LastTouchedAt is stamped, and the context's index entries are extended.
	SwapContext(ctx context.Context, k ContextKey, rev uint64, c Context, ttl time.Duration) error
	// SwapLogin is SwapContext with a login's index bookkeeping and its
	// revocation check in the same atomic step (plan 7d; spec §13, decision
	// 35). It writes c only if the record at k is still the one the caller
	// read (rev, as SwapContext reads it) and each mark in w.Marks is still
	// as the caller read it: present at that At, or absent for a zero At.
	// Otherwise ErrConflict, and nothing — context or index — is written.
	// On success, after the context is written and its existing index
	// entries extended as SwapContext extends them, the ref is unindexed
	// wholly when w.ClearRef (UnindexRef), then from w.DropSid and
	// w.DropCertKey (UnindexContext, no principal), then indexed under
	// w.Principal, w.Sid and w.CertKey for w.IndexTTL (IndexContext), each
	// empty or blank key skipped.
	SwapLogin(ctx context.Context, k ContextKey, rev uint64, c Context, ttl time.Duration, w LoginWrite) error
	// RewriteContext writes c's fields over the live record at k only while
	// its Rev is rev: ErrNotFound when no record is live, ErrConflict when
	// Rev has moved, and nothing written either way (plan 7d; spec §13,
	// decision 35). Rev moves; PolicyRev moves to the new revision only when
	// policyMoved. A zero ttl leaves the expiry and LastTouchedAt as the
	// record has them; a non-zero ttl extends both, and the ref's index
	// entries, as TouchContext does. It is the sealing layer's narrow
	// setter: the layer reads the record, opens it, applies the setter's
	// rule (ApplyPrivilege, ApplyRefresh, ApplyRevokedAt,
	// ApplyContextPolicy), seals it again and rewrites it on the revision it
	// read, so no field the authorizer trusts is written in the clear by a
	// setter that cannot read it.
	RewriteContext(ctx context.Context, k ContextKey, rev uint64, c Context, ttl time.Duration, policyMoved bool) error
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
	// SetPrivilege raises the level this context records to level, in place
	// and under the store's own lock. It writes exactly one field, PrivLvl, and
	// is TouchContext's sibling for the same reason: the authorization path
	// must not write back a record it read at the top of the request, because
	// the writer it would race is revocation.
	//
	// Raise-only: the stored value is max(current, level), clamped to the
	// context's ceiling (Context.PrivilegeCeiling; zero MaxPrivilege is none).
	// PrivLvl means "the highest level port49 has granted this user on this
	// device", not "the level of the latest window" — the context is keyed
	// (nas, username) and covers every window of one operator, so a second
	// window's session authorization granting less must not take the first
	// window's enable away (spec §5.3). It is still a bound: the device cannot
	// exceed it without port49 having said yes somewhere. What a session
	// authorization REPLIES is policy's answer and never this field.
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
	// RefreshContext applies a broker refresh to this context in place and
	// under the store's own lock (spec §5.1.3, §5.6). It is the fourth of the
	// narrow setters and exists for the reason TouchContext's comment gives:
	// the broker must not write back a Context it read at the top of the
	// request, because the writers it would race are accounting's annotation,
	// the enable path's privilege raise, and a revocation of a principal whose
	// authorization was withdrawn one request after the broker refreshed it.
	//
	// It writes a closed list — AuthTime, SessionExpires, RefreshedAt and
	// BlobHash when non-empty — and, unlike AnnotateContext, it extends the
	// expiry to now+ttl and stamps LastTouchedAt: a refresh is activity for
	// the idle TTL in a way an accounting record is not.
	//
	// It does NOT touch RevokedAt, and that absence is the point. A refresh
	// is a directory re-resolution (spec §5.1.3) — the broker re-resolves a
	// principal whose group membership changed and updates blob_hash — not a
	// credential re-verification. The only thing that ends a revocation is
	// §5.6 row 6 reclaiming the record on the idle TTL. A refresh that lifted
	// the mark would un-revoke every revoked principal on the next scheduled
	// pass, which is exactly how §5.1.3 says a policy-driven revocation
	// reaches live sessions: within one refresh interval, the operator who
	// was revoked is authorized again, with nothing in the log connecting the
	// two. The one path that may lift a mark is a login whose token the broker
	// minted after the revocation — the credential verified again — and it
	// does so through JoinContext, never here (spec §13, decision 15).
	//
	// SessionExpires is recomputed here rather than by the caller because the
	// pair it is computed from is the pair about to be overwritten; see
	// ContextRefresh.AuthTime. A SessionAge sets it from the new AuthTime, and
	// may lengthen it: a refresh is a fresh authentication event (decision 33).
	//
	// Two checks come first, under the same lock, and either refuses with
	// nothing written. An ExpectRev that is not the record's Rev is
	// ErrConflict: the context was replaced or written since the caller read
	// it. A GraceCutoff later than the context's ceiling is ErrPastGrace: the
	// session ended with the grace window, and a refresh does not resume it
	// (spec §5.6, teardown row 3).
	//
	// It deliberately does NOT write the credential's sid. Sid lives inside
	// Credential, which is sealed, and a narrow setter cannot write one field
	// of a record the sealing layer cannot read (crypt's AnnotateContext
	// comment). A rotated sid moves in the index instead, with ReindexSid,
	// which is what revocation by sid reads.
	//
	// ErrNotFound if the key is absent or already expired.
	RefreshContext(ctx context.Context, k ContextKey, r ContextRefresh, ttl time.Duration) error
	// SetRevokedAt marks this context revoked, in place and under the store's
	// own lock. It writes exactly one field, RevokedAt, and it is the write
	// every other setter's comment names as the one that must not be raced
	// away — so it is held to the same rule itself.
	//
	// Marking, never deleting: spec §5.6 row 2 wants the next command denied
	// `credential_revoked` with a server_msg saying so, which a deleted
	// context cannot do — an absent context is indistinguishable from a
	// session port49 never saw. Row 6 reclaims the record on the idle TTL,
	// which is why this moves neither the expiry nor LastTouchedAt: a revoked
	// context ages out on the clock it was already on.
	//
	// It is monotonic: it keeps the later of the mark the record holds and
	// at. A mark moved earlier weakens the revocation — a token minted between
	// the two instants would count as minted after it and lift it at a join
	// (spec §5.6) — so a revocation written unconditionally, as the policy
	// refresh's is (spec §5.1.3), never undoes a later one another path made.
	//
	// ErrNotFound if the key is absent or already expired.
	SetRevokedAt(ctx context.Context, k ContextKey, at time.Time) error
	// SetContextPolicy writes a policy refresh's answer into this context, in
	// place and under the store's own lock, and only if what the refresh
	// decides is still what the caller read: policyRev is the PolicyRev
	// GetContext returned, and a policy revision that moved is ErrConflict
	// with nothing written (spec §5.1.3). It compares PolicyRev and not Rev
	// so that accounting and touches, which write nothing the refresh decides,
	// cannot keep a busy session's refresh losing; it moves both.
	//
	// It is the fifth narrow setter, and the only one that is also a
	// compare-and-set. The others write a value that is right whoever the
	// record belongs to; this one writes a value computed from who it belongs
	// to. The refresher reads the context's principal — sealed, so the inner
	// store cannot check it — resolves that principal on this device, and
	// writes the answer. A login that replaced the record with another
	// principal's in between, or joined it with a token minted under the
	// previous policy, would otherwise be handed the wrong principal's policy
	// or keep the superseded one. Conflict, read again, decide again.
	//
	// It writes a closed list: with RevokedAt set, RevokedAt alone; otherwise
	// BlobHash, MaxPrivilege and Enable, and PrivLvl lowered to the new
	// ceiling when it is above it — the join's rule (spec §5.3), so a lowered
	// max_privilege reaches the next command as privilege_exceeded. It never
	// raises PrivLvl: a widened level reaches the device only through the next
	// session authorization or enable, which is where a level is granted.
	// SessionExpires follows the same one-way rule: a MaxSessionAge whose
	// AuthTime plus it is earlier than the ceiling, or a context with none,
	// moves it to that; a later one, or zero, leaves it (decision 33). A
	// policy edit shortens a session and never lengthens or removes a
	// ceiling. A context with a zero AuthTime is given a ceiling in the
	// distant past, which denies (ContextPolicy.MaxSessionAge).
	//
	// It does not extend the expiry or stamp LastTouchedAt: a policy edit is
	// not activity, or every reload would keep every idle context alive. It
	// does not touch AuthTime, nor RefreshedAt unless p carries one, nor
	// lengthen SessionExpires:
	// nothing about the operator's authentication or the directory was
	// re-verified. And it never clears RevokedAt, for the reason
	// RefreshContext never does, nor moves it earlier: a revoking write onto
	// a context already revoked later keeps the later mark, so no token
	// minted between the two can lift it.
	//
	// ErrNotFound if the key is absent or already expired.
	SetContextPolicy(ctx context.Context, k ContextKey, policyRev uint64, p ContextPolicy) error

	// StampRefreshed raises k's RefreshedAt to at, only while its PolicyRev
	// is still policyRev, and moves neither PolicyRev nor the expiry: the
	// scheduled refresh's stamp on a context whose answer it found
	// unchanged (plan 7g, Ruling 12). A context changed since the read is
	// ErrConflict, read again; an earlier at than the one held leaves it.
	// ErrNotFound if the key is absent or expired.
	StampRefreshed(ctx context.Context, k ContextKey, policyRev uint64, at time.Time) error
	// DeleteContext has no production caller today: the caller it had was
	// author's `username_mismatch` branch, which under the old `(nas, port)`
	// key could delete a live operator's context on an uncredentialed request.
	// Plan 2 owns it — revocation and §5.6 teardown rows 2 through 4 all need
	// it — so it stays.
	DeleteContext(ctx context.Context, k ContextKey) error
	// DeleteContextIf deletes the context only while its Rev is rev, the
	// revision the caller read: ErrConflict otherwise, ErrNotFound when it is
	// absent. The grace window's sweep uses it, so it never deletes a context
	// a login wrote since it was read.
	DeleteContextIf(ctx context.Context, k ContextKey, rev uint64) error

	PutBlob(ctx context.Context, hash string, body []byte, ttl time.Duration) error
	GetBlob(ctx context.Context, hash string) ([]byte, error)
	// BumpBlob extends a blob to at least now+ttl and never shortens it.
	BumpBlob(ctx context.Context, hash string, ttl time.Duration) error

	IndexContext(ctx context.Context, principal, sid, certKey string, ref ContextRef, ttl time.Duration) error
	UnindexContext(ctx context.Context, principal, sid, certKey string, ref ContextRef) error
	// UnindexRef removes ref from every principal, sid and certificate entry
	// it was indexed under, including keys the caller cannot name any more: a
	// joined context is indexed under every login's sid and certificate, and
	// the record keeps only the last login's credential. It is what a replace
	// by another principal calls, so that no key of the displaced principal's
	// keeps reaching the context that replaced it (spec §5.6). An unreadable
	// replace calls it too: it cannot name what it displaced. Entries under
	// the same keys for other refs are untouched.
	//
	// It is not atomic with the context write before it or the IndexContext
	// after it, and two races follow, each needing logins under one username
	// on one device within a few milliseconds:
	//
	//   - The replacing principal's own second window joins the new context
	//     and indexes its sid and certificate between the replace's swap and
	//     this call. This call then wipes them. Revocation by that principal
	//     still reaches the context, because the replace's IndexContext puts
	//     the principal back; by that window's sid or certificate it does not.
	//   - Two different principals replace each other. The first's late call
	//     runs after the second's replace and index, wipes the second's
	//     entries, and the first's IndexContext then lands on the second's
	//     context. That context ends up indexed under the first principal's
	//     keys only: a revocation of the first marks it, and one of the second
	//     misses it. It also needs the username-uniqueness invariant broken
	//     (spec §5.6, P10).
	UnindexRef(ctx context.Context, ref ContextRef) error
	ContextsByPrincipal(ctx context.Context, principal string) ([]ContextRef, error)
	ContextsBySid(ctx context.Context, sid string) ([]ContextRef, error)
	ContextsByCert(ctx context.Context, certKey string) ([]ContextRef, error)
	ReindexSid(ctx context.Context, oldSid, newSid string, ref ContextRef, ttl time.Duration) error
	ActivePrincipals(ctx context.Context) ([]string, error)
	// IndexToken records that principal, and the certificate certKey
	// (CertKey), hold an unspent token under k, until ttl from now, keeping
	// the later expiry where one is already recorded. The minter writes it
	// before the token, so no token exists that a revocation cannot find
	// (plan 7a). An empty principal or certKey skips that index, as
	// IndexContext does, and so does a certKey with no issuer or no serial,
	// or that is not a CertKey at all.
	// An entry outliving its token costs a revocation one DeleteTokens on an
	// empty key.
	IndexToken(ctx context.Context, principal, certKey string, k TokenKey, ttl time.Duration) error
	// TokensByPrincipal and TokensByCert are the keys under which the
	// principal, or the certificate, holds or held an unspent token, sorted
	// by (NAS, Username).
	TokensByPrincipal(ctx context.Context, principal string) ([]TokenKey, error)
	TokensByCert(ctx context.Context, certKey string) ([]TokenKey, error)

	// ReserveIdempotency writes rec under (principal, key) when no live
	// record is there, in one atomic step, and reports true. When one is, it
	// writes nothing and returns that record and false. Two concurrent
	// requests under one key therefore cannot both pass (design §17). A
	// record without a Holder is refused: the empty holder is anyone's.
	ReserveIdempotency(ctx context.Context, principal, key string, rec Idempotency) (Idempotency, bool, error)
	// CompleteIdempotency replaces the live record under (principal, key)
	// with rec only while that record's Holder is expect; otherwise it writes
	// nothing and returns ErrConflict. An expired reservation, or one another
	// request has taken since, is never overwritten. An empty expect is
	// ErrConflict, and a rec without a Holder is refused.
	CompleteIdempotency(ctx context.Context, principal, key, expect string, rec Idempotency) error
	// ReleaseIdempotency deletes the record under (principal, key) only
	// while it is a pending reservation held by holder; anything else stays.
	ReleaseIdempotency(ctx context.Context, principal, key, holder string) error

	// PutRevocation puts r in force. An existing mark for (r.Kind, r.Key) is
	// kept whole: a repeat never moves its time or origin, and never lifts.
	// A mark that could match nothing is refused: a Kind that is neither
	// RevocationPrincipal nor RevocationCert, an empty Key, or a certificate
	// Key that is not a CertKey or has no issuer or no serial, which
	// IndexToken never indexes.
	PutRevocation(ctx context.Context, r Revocation) error
	// GetRevocation is the mark in force for (kind, key), or ErrNotFound.
	GetRevocation(ctx context.Context, kind, key string) (Revocation, error)
	// DeleteRevocation lifts the mark for (kind, key); none is not an error.
	DeleteRevocation(ctx context.Context, kind, key string) error
	// ListRevocations is every mark in force, sorted by (Kind, Key).
	ListRevocations(ctx context.Context) ([]Revocation, error)
	// SupersedeTokens records that k's unspent tokens were deleted at at, by
	// a refresh or a revocation, keeping the later of at and what stands,
	// for SupersededFor. An idempotent replay of a mint from before it, on
	// any broker process, is minted afresh rather than answered with a token
	// that no longer exists (plan 7e, Ruling 9).
	SupersedeTokens(ctx context.Context, k TokenKey, at time.Time) error
	// SupersedeAll is SupersedeTokens for every key at once: a start that
	// purged every unspent token.
	SupersedeAll(ctx context.Context, at time.Time) error
	// SupersededAt is the later of k's own instant and the all-keys one;
	// zero when neither stands or both are past SupersededFor. Never
	// ErrNotFound.
	SupersededAt(ctx context.Context, k TokenKey) (time.Time, error)

	// PutMembership writes m under m.Principal and indexes each of m.MapKeys,
	// keeping a record verified later than m whole; ttl from now. A key a live
	// record of another principal still lists is written ambiguous. A refused
	// m (Refused, no groups) supersedes an older record the same way. A write
	// verified before the principal's last forget is dropped, with no error:
	// the forget left a tombstone holding its time (DeleteMembership).
	PutMembership(ctx context.Context, m Membership, ttl time.Duration) error
	// RefuseMapKeys marks each key refused as of at, unless a later
	// verification holds it: MembershipByKey then answers ErrNotFound.
	RefuseMapKeys(ctx context.Context, mapKeys []string, at time.Time, ttl time.Duration) error
	// GetMembership is the record for principal, or ErrNotFound.
	GetMembership(ctx context.Context, principal string) (Membership, error)
	// MembershipByKey is the record a mapping key indexes, or ErrNotFound when
	// none does, the key is ambiguous or refused, or the record no longer
	// lists the key.
	MembershipByKey(ctx context.Context, mapKey string) (Membership, error)
	// MembershipPrincipals is every principal with a live membership record,
	// refused ones included, sorted: the set a policy refresh supersedes
	// group members' tokens over.
	MembershipPrincipals(ctx context.Context) ([]string, error)
	// DeleteMembership removes principal's record, refused or not, and with
	// it the entry the principal is pinned to, and returns what it held; or
	// ErrNotFound when no live record is held. Its mapping keys are left to
	// expire: MembershipByKey answers ErrNotFound for a key whose record is
	// gone, and a claim treats it as unclaimed. It leaves a tombstone for
	// principal holding the time of the forget, for what the record had left
	// to live, and at least TombstoneFloor: a PutMembership verified before it
	// is dropped, so a verification in flight when the operator forgot can
	// never write the old pin back. A tombstone is no record: no read
	// returns it. `port49 directory forget` alone calls it (Ruling 3's
	// escape; Task 13).
	DeleteMembership(ctx context.Context, principal string) (Membership, error)
}

// RevStore is a Store whose whole-context writes also return the revision
// each committed at: the record's Rev from then on, and zero with every
// error. The sealing layer keeps it beside the key's mark, so a read
// served before the write that set the mark committed is read again
// (crypt.Ledger; plan 7e, Ruling 3). Each is its plain method otherwise.
// The sealing layer calls only these, so a test double that overrides a
// plain method and not its Rev twin is bypassed.
type RevStore interface {
	Store
	PutContextRev(ctx context.Context, k ContextKey, c Context, ttl time.Duration) (uint64, error)
	SwapContextRev(ctx context.Context, k ContextKey, rev uint64, c Context, ttl time.Duration) (uint64, error)
	SwapLoginRev(ctx context.Context, k ContextKey, rev uint64, c Context, ttl time.Duration, w LoginWrite) (uint64, error)
	RewriteContextRev(ctx context.Context, k ContextKey, rev uint64, c Context, ttl time.Duration,
		policyMoved bool) (uint64, error)
	// Seen is the highest store revision this client has been told of, by
	// any read, write or watch; it makes no call and never goes back. A
	// context write's sealed sequence is drawn above it (crypt; plan 7e,
	// Ruling 3).
	Seen() uint64
	// Ping is one linearizable read: nil when the store answers. port49d's
	// probe calls it through the guard (plan 7e, Ruling 11).
	Ping(ctx context.Context) error
}

// SupersededFor is how long a superseded instant is kept: past the
// longest token_ttl (policy.MaxTokenTTL, 15m) and so past the life of any
// idempotency record whose replay it governs (plan 7e, Ruling 9; 4b m10).
const SupersededFor = 20 * time.Minute

// TombstoneFloor is the least a forget's tombstone is kept: a verification
// in flight at the forget must find it however little of the record's ttl
// was left.
const TombstoneFloor = 24 * time.Hour

// Membership is one principal's directory answer as the broker last
// verified it (plan 7g; decision 38): the entry its certificate mapped to,
// the username and groups read from it, and when and where. The broker's
// role alone reads or writes it.
type Membership struct {
	Principal string
	DN        string // sealed
	// EntryID is the entry's immutable id ("guid:" + objectGUID hex,
	// "uuid:" + entryUUID, else "dn:" + the canonical DN): the entry the
	// principal is pinned to (Ruling 3). A refusal keeps it.
	EntryID    string   // sealed
	Username   string   // sealed
	GroupDNs   []string // sealed: every group the entry is in, under the nested mode
	GroupNames []string // sealed: their names, those verified unique under groups_base_dn
	// MapKeys are MapKey(kind, value) for every certificate-mapping value the
	// entry answers to: the index a bind in grace finds the principal by.
	// Sealed, and in the clear for the backend's index; crypt refuses a
	// record whose two differ, so a store write cannot add a victim's key
	// to an admin's record.
	MapKeys []string
	// Refused is the directory's "no" (identity_unmapped,
	// identity_ambiguous, username_collision) as of VerifiedAt: no groups,
	// and grace never serves it (Ruling 10). Sealed and in the clear, as
	// MapKeys.
	Refused    bool
	VerifiedAt time.Time // sealed too: in the clear alone, a store write could extend grace
	Server     string
	Site       string
	Sealed     []byte // written by internal/store/crypt; nil in plaintext form
}

// MapKey is the index key of one certificate-mapping value: a hash, so the
// plaintext index names no certificate value. canonicalValue is the
// mapping's canonical form (the directory package's canonicalValue), the
// same on the certificate's side and the entry's.
func MapKey(kind, canonicalValue string) string {
	sum := sha256.Sum256([]byte(kind + "\x00" + canonicalValue))
	return hex.EncodeToString(sum[:])
}

// CertKey is the index key a CRL or OCSP response names (spec §5.1.4).
func CertKey(issuer, serial string) string { return issuer + "|" + serial }

// BlankCertKey reports whether certKey is CertKey of an empty issuer or an
// empty serial, or is not a CertKey at all (no "|"). It names no
// certificate: every OIDC login's credential has neither, so "|" would be
// one index entry holding every OIDC operator's context on the fleet, and
// a revocation by it would revoke them all. Every backend treats it as ""
// — never indexed, never marked (ruling P8).
func BlankCertKey(certKey string) bool {
	return !strings.Contains(certKey, "|") || strings.HasPrefix(certKey, "|") || strings.HasSuffix(certKey, "|")
}

// ErrIncompleteMark refuses a revocation mark that could match nothing: it
// would be reported as in force and revoke nothing.
var ErrIncompleteMark = errors.New("store: a revocation mark must name a principal, or a certificate by issuer and serial, and when it was made")

// CheckRevocation is PutRevocation's refusal, shared by every backend: a
// kind that is neither RevocationPrincipal nor RevocationCert, an empty
// key, a certificate key that is blank (BlankCertKey), or a zero At. A
// zero At is how a login reads "no mark stands" (MarkRead), so a mark
// written with one would be compared as absent: the memory store would
// refuse every login under it ErrConflict and etcd would land them
// unrevoked (pre-flight M10). The revocations file reaches every backend
// through PutRevocation, so a file mark with no time is refused at start.
func CheckRevocation(r Revocation) error {
	if r.At.IsZero() {
		return ErrIncompleteMark
	}
	switch {
	case r.Kind == RevocationPrincipal && r.Key != "":
		return nil
	case r.Kind == RevocationCert && !BlankCertKey(r.Key):
		return nil
	}
	return ErrIncompleteMark
}

// Revocation kinds (spec §5.1.4; plan 7a).
const (
	RevocationPrincipal = "principal"
	RevocationCert      = "cert"
)

// Revocation is a standing refusal of a principal, or of one certificate
// by CertKey(issuer, serial): every mint it names is refused until an
// operator deletes it (spec §5.1.4, §13 decision 32). It never expires. It
// is plaintext, as the indexes are: it names identity and holds no
// credential, and revocation must not depend on the encryption key.
type Revocation struct {
	Kind string
	Key  string
	// At is when the mark took force. A second put of the same key keeps the
	// first mark whole: the refusal has stood since then.
	At time.Time
	// Origin says who asked: "admin_socket uid 0".
	Origin string
}

// HasCeiling reports whether this context carries a session ceiling.
func (c Context) HasCeiling() bool { return !c.SessionExpires.IsZero() && !c.AuthTime.IsZero() }

// PrivilegeCeiling reports the highest level this context may hold, and whether
// it carries a privilege ceiling at all. A zero MaxPrivilege is a token minted
// without one, not a ceiling of zero — the same reading HasCeiling gives a zero
// SessionExpires, and it is stated here once because two paths ask: the enable
// path refuses an escalation above it (spec §7, `ceiling_exceeded`) and the
// authorizer clamps a granted level to it (spec §5.3).
//
// Reading zero as a ceiling of zero would split those two. A policy engine that
// mints without setting the field (plan 4) would get a fleet where session
// authorization grants 15 freely and every enable is refused naming a ceiling
// nobody configured — and the operator at 3am has no configured value to look
// at, because there is none.
func (c Context) PrivilegeCeiling() (uint8, bool) { return c.MaxPrivilege, c.MaxPrivilege > 0 }
