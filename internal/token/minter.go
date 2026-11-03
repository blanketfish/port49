package token

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/blanketfish/port49/internal/decision"
	"github.com/blanketfish/port49/internal/platform"
	"github.com/blanketfish/port49/internal/secretref"
	"github.com/blanketfish/port49/internal/store"
	"github.com/blanketfish/port49/internal/username"
)

// ErrIdempotencyConflict is the same idempotency key presented with a
// different body (design §17). The first request's result stands; nothing is
// minted.
var ErrIdempotencyConflict = errors.New("token: idempotency key reused with a different body")

// ErrIdempotencyInProgress is a request under an idempotency key that
// another request, under the same body, is still minting (design §17).
// Nothing is minted; the caller retries and is answered from the first
// request's record once it completes.
var ErrIdempotencyInProgress = errors.New("token: a request under this idempotency key is still being minted")

// ReservationTTL is how long a reservation stands with its mint unfinished.
// A broker that dies mid-mint leaves one behind; past this a retry mints
// afresh, and the first attempt's tokens, never returned, stand unspent
// until their TTL.
// Mint renews a device's reservation for this long just before minting it,
// so the lease covers one device's mint, not a whole batch: a mint's store
// calls are bounded at ten seconds (the broker's holdTimeout), so a minute is
// long for a live mint and short for a retry.
const ReservationTTL = time.Minute

// Reservation is a request's hold on its idempotency key, one record per
// device (idemScope), taken for the whole batch before any device is minted
// (Reserve).
type Reservation struct {
	Key, Holder string
	// Found is, by device, a completed record under the key and this body:
	// Mint replays it, unless a policy change or a revocation deleted its
	// tokens since.
	Found    map[string]store.Idempotency
	reserved []string
}

// ErrUsernameNotCanonical refuses a device-facing username that
// canonicalization would change. username.Canonical lowercases, strips a
// DOMAIN\ prefix and truncates at '@', and Go's simple case mapping folds
// U+0130 onto `i` — so `İrem`, `CORP\irem` and `irem@corp.example` all
// canonicalize onto `irem` and would share one (nas, username) context and one
// token key. A name that merely changes is just as bad in a quieter way: the
// mint writes the token under the name it was given while the daemon looks it
// up under Canonical(wire), so the operator holds a valid token that is
// `token_not_found` every time, with nothing saying why.
//
// The daemon cannot refuse a name a device sends; the mint can.
var ErrUsernameNotCanonical = errors.New("token: device-facing username must be printable ASCII and already canonical")

// ErrUsernameReserved refuses a device-facing username a device keeps for
// its own account: `remote`, the Junos template a session with no template
// lands under; every p49-* name, port49's template namespace, which every
// level's local_user_names entry is in; and every platform's system user
// (`root`). A session under such a name lands in that account's class
// whatever the reply says, so a subject the projection told less (the
// fail-closed reply) would run what that class runs (spec §13 decision 26).
// Policy load refuses a declared one; this catches one a directory derives.
var ErrUsernameReserved = errors.New("token: device-facing username is reserved for a device account (remote, p49-*, a system user)")

// ErrNoPrincipal refuses a mint for a subject with no principal. The token
// index skips an empty principal, so its tokens would be ones no revocation
// by principal can find (plan 7a).
var ErrNoPrincipal = errors.New("token: a mint needs a principal to index its tokens under")

// ErrNoAuthTime refuses a mint for a subject with a session ceiling and no
// AuthTime to anchor it. The ceiling would be measured from the epoch: the
// login would be refused session_expired with nothing saying why, or, read
// by a caller that took a zero time as "no ceiling", run unbounded. A
// `never` subject (MaxSessionAge zero) needs no AuthTime (spec §5.6).
var ErrNoAuthTime = errors.New("token: a mint with a session ceiling needs the subject's auth_time")

// ErrSessionExpired refuses a mint for a subject whose session ceiling has
// passed: its token would open a context born expired (spec §5.6). The
// broker refuses such a device per item before it mints; this is the
// minter's own floor under that check.
var ErrSessionExpired = errors.New("token: the subject's session ceiling has passed")

// ErrReplayLapsed refuses a ReplayOnly mint whose replay is no longer one:
// the caller decided, from Replays, to skip a requirement that a fresh mint
// must meet, and has to decide again.
var ErrReplayLapsed = errors.New("token: the replay the caller relied on has lapsed")

// ReservedUsername reports whether u is `remote`, a p49-* name, or a
// platform's system user (platform.ReservedUsername).
func ReservedUsername(u string) bool { return platform.ReservedUsername(u) }

// asciiUsername reports whether every byte of u is printable ASCII
// (0x21–0x7E), which excludes the empty name, spaces and control characters.
func asciiUsername(u string) bool {
	if u == "" {
		return false
	}
	for i := 0; i < len(u); i++ {
		if u[i] < 0x21 || u[i] > 0x7e {
			return false
		}
	}
	return true
}

// CanonicalUsername is the invariant, not just the character set: printable
// ASCII AND unchanged by canonicalization. The ASCII half alone would admit
// `@` and `\`, which are 0x21–0x7E and are exactly the two rewrites a
// directory-backed deployment hits every day. Exported so the broker's policy
// load refuses the same names the mint would, with one definition of them.
func CanonicalUsername(u string) bool { return asciiUsername(u) && username.Canonical(u) == u }

// ErrTooManyOutstanding is the candidate-set cap: this many unspent tokens
// already stand for one (device, username). It names the count so the operator
// reading it knows whether a client is looping or merely busy.
type ErrTooManyOutstanding struct {
	Device, Username string
	Count, Cap       int
}

func (e *ErrTooManyOutstanding) Error() string {
	return fmt.Sprintf("token: %d unspent tokens for %s on %s (cap %d); stop minting and use the ones you have",
		e.Count, e.Username, e.Device, e.Cap)
}

// Subject is what policy has already decided about the person being minted
// for: the identity the token carries and every ceiling it inherits. The
// minter reads it and judges none of it — the policy question is plan 4's.
type Subject struct {
	Principal, Username string
	TokenTTL            time.Duration // policy maximum for the subject
	Enable              string        // none | auto | token
	MaxPrivilege        uint8
	MaxSessionAge       time.Duration
	Credential          store.Credential
	AuthTime            time.Time
	VerifiedAt          time.Time // the membership's verification; zero: none
}

// Request is one mint: a Subject, the device the tokens are cut for, and the
// caller's asks — an enable token alongside the login one, a TTL no longer
// than the subject's, and an optional reservation of an idempotency key with
// the hash of the body it was sent with.
type Request struct {
	Subject          Subject
	Device, Platform string
	BlobHash         string
	WithEnable       bool
	TTL              time.Duration
	// Reservation is the request's hold on its idempotency key (Reserve),
	// nil for a request without one. The key is scoped per device, not per
	// key alone — see idemScope: design §17 sends one key for a whole batch,
	// and each device gets its own record. BodyHash is the request body's.
	Reservation *Reservation
	BodyHash    string
	// SupersededAt is when a policy refresh or a revocation last deleted
	// this (device, username)'s unspent tokens, zero for never. A replay of
	// tokens minted no later than that would hand back a token that no
	// longer exists, so it is not replayed: the mint is made afresh, as for
	// a record that will not decode, and the record says why.
	SupersededAt time.Time
	// ReplayOnly is set by a caller that skipped a requirement because
	// Replays said this request would be answered from a completed record.
	// Mint re-reads its clock, so a replay that lapsed in between (the
	// record's session ceiling passed) is refused with ErrReplayLapsed
	// instead of minted afresh: a token minted under a requirement must have
	// passed the check, and this one did not (decision 45 ruling 14).
	ReplayOnly bool
	// Policy is the subject and grants that allowed this mint. The minter
	// judges none of it and copies it onto the mint record (spec §5.7).
	Policy *decision.Policy
	// Directory is where the membership this mint used was read, for the
	// record's auth.directory; nil without a directory (spec §5.7).
	Directory *decision.Directory
	// OIDC is the verified token's identity for the record's auth.oidc; nil
	// on the certificate path (plan 7h).
	OIDC *decision.OIDC
	// K8s is a verified service account token's identity for the record's
	// auth.k8s; nil for any other caller (plan 10).
	K8s *decision.K8s
	// DirectoryPassword is a directory sign-in's authentication, for the
	// record's auth.directory_password; nil for any other caller (decision 47).
	DirectoryPassword *decision.DirectoryPassword
	// Sweep is the sweep this device was minted by, copied onto the permit
	// record; nil for a mint by name (spec §13 decision 42 ruling 4).
	Sweep *decision.Sweep
	// PerLoginMFA is the per-login requirement this mint was made under and
	// the proof that covered it (the broker judged it); copied onto the
	// permit record. Nil for a device with no requirement (decision 45
	// ruling 19). The proof's method and time are also in
	// Subject.Credential, which the token carries into its context.
	PerLoginMFA *decision.PerLoginMFA
	// Log is where Mint writes its permit record; nil is the minter's own
	// log. The broker passes a per-request decision.Buffer, flushed once
	// the request lets go of the policy (plan 7e, Ruling 10).
	Log decision.Emitter
}

// idemScope puts the device in the idempotency key. §17's key is one header
// for a whole batch of devices, and the record this minter writes is one
// device's Result: unscoped, device two in a batch replays device one's
// tokens and is handed a credential tagged for the wrong device, which that
// device refuses on every attempt. The separator matches the store's own
// convention (internal/store/memory/memory.go, idemKey).
func idemScope(key, device string) string { return key + "\x00" + device }

// Reserve takes key for every device in one pass, before any is minted
// (design §17; plan 7a): a record under another body is
// ErrIdempotencyConflict, one still pending under this body is
// ErrIdempotencyInProgress, and either gives back what this call reserved
// and refuses the whole batch. A store failure does the same and is
// returned wrapped. A completed record under this body is kept in Found for
// Mint to replay. An empty key reserves nothing and returns nil.
func (m *Minter) Reserve(ctx context.Context, principal, key string, devices []string, bodyHash string) (*Reservation, error) {
	if key == "" {
		return nil, nil
	}
	var b [16]byte
	if _, err := io.ReadFull(m.rand, b[:]); err != nil {
		return nil, err
	}
	res := &Reservation{Key: key, Holder: hex.EncodeToString(b[:]), Found: map[string]store.Idempotency{}}
	rec := store.Idempotency{BodyHash: bodyHash, Holder: res.Holder, Pending: true,
		ExpiresAt: m.now().Add(ReservationTTL)}
	for _, device := range devices {
		cur, ok, err := m.store.ReserveIdempotency(ctx, principal, idemScope(key, device), rec)
		switch {
		case err != nil:
			m.giveBack(ctx, principal, res)
			return nil, fmt.Errorf("token: reserving the idempotency key: %w", err)
		case ok:
			res.reserved = append(res.reserved, device)
		case cur.BodyHash != bodyHash:
			m.giveBack(ctx, principal, res)
			return nil, ErrIdempotencyConflict
		case cur.Pending:
			m.giveBack(ctx, principal, res)
			return nil, ErrIdempotencyInProgress
		default:
			res.Found[device] = cur
		}
	}
	return res, nil
}

// replayOf is the result a completed idempotency record replays, and why
// not ("") when it cannot be: the reason is what Mint carries onto the mint
// record that is made afresh instead.
func (m *Minter) replayOf(rec store.Idempotency, supersededAt time.Time) (prev Result, why string) {
	switch uerr := json.Unmarshal(rec.Response, &prev); {
	case uerr != nil:
		// A record that will not decode is a mint that cannot be replayed.
		// Mint — the caller gets working tokens — and say the replay was
		// abandoned, or this is silent.
		return Result{}, "idempotency record did not decode; minted again rather than replayed"
	case !supersededAt.IsZero() && !prev.MintedAt.After(supersededAt):
		// Its tokens were deleted since, by a policy change or a
		// revocation: replayed, the caller would hold a token no device
		// accepts. A record from before MintedAt was kept has a zero one,
		// and is not replayed either.
		return Result{}, "idempotency record names tokens a policy change or a revocation deleted; minted again rather than replayed"
	case !prev.SessionExpiresAt.IsZero() && !m.now().Before(prev.SessionExpiresAt):
		// Its tokens' ceiling has passed: replayed, the caller would hold a
		// token for a context born expired. Minted again under this
		// request's subject, whose ceiling the broker checked.
		return Result{}, "idempotency record names tokens past their session ceiling; minted again rather than replayed"
	}
	return prev, ""
}

// Replays reports whether Mint of r would answer from a completed
// idempotency record, minting nothing. The broker asks it before it reads a
// device's per-login requirement: a retry whose answer was lost is replayed
// even though the proof that covered it is spent (decision 45 ruling 14).
func (m *Minter) Replays(r Request) bool {
	res := r.Reservation
	if res == nil {
		return false
	}
	rec, ok := res.Found[r.Device]
	if !ok {
		return false
	}
	_, why := m.replayOf(rec, r.SupersededAt)
	return why == ""
}

// releaseTimeout bounds giveBack's store calls, as the broker's holdTimeout
// bounds a mint's.
const releaseTimeout = 10 * time.Second

// giveBack is Release for a batch Reserve refuses, on a context of its own:
// the caller's is often the one that just ran out at the store, and released
// on it, nothing would be given back, and every retry for a minute would be
// told a mint is in progress when none is.
func (m *Minter) giveBack(ctx context.Context, principal string, res *Reservation) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), releaseTimeout)
	defer cancel()
	m.Release(ctx, principal, res)
}

// Release gives back every reservation res took whose mint did not
// complete. A completed one is no longer pending and is left alone, so the
// broker calls this for the whole batch once the batch is answered.
func (m *Minter) Release(ctx context.Context, principal string, res *Reservation) {
	if res == nil {
		return
	}
	for _, device := range res.reserved {
		_ = m.store.ReleaseIdempotency(ctx, principal, idemScope(res.Key, device), res.Holder)
	}
}

// Result is the minted pair and what the caller must tell the operator:
// Enable is empty unless the subject's mechanism is `token`, and Username is
// the name the tokens were written under, which is the name the device must
// send.
type Result struct {
	Login, Enable string
	ExpiresAt     time.Time
	Username      string
	// MintedAt is when the tokens were minted, kept in the idempotency
	// record so a replay can be judged against Request.SupersededAt.
	MintedAt time.Time
	// SessionExpiresAt is when a login with these tokens stops being
	// authorized: the subject's AuthTime plus its MaxSessionAge, zero for
	// never. Kept in the idempotency record so a replay answers with the
	// ceiling of the tokens it returns, and is not made past it.
	SessionExpiresAt time.Time
	// Replayed is set on a result answered from the idempotency record,
	// for which no token was minted and no permit recorded. Never stored.
	Replayed bool `json:"-"`
}

// String is the result with its tokens withheld, so that a %v anywhere —
// a test's failure message, a debug line — never prints one (plan 7b final
// review M-1). The idempotency record is JSON and is untouched.
func (r Result) String() string {
	type plain Result
	p := plain(r)
	for _, t := range []*string{&p.Login, &p.Enable} {
		if *t != "" {
			*t = "<withheld>"
		}
	}
	return fmt.Sprintf("%+v", p)
}

// GoString is String, for %#v.
func (r Result) GoString() string { return r.String() }

// Minter issues device tokens. It is in-process and knows nothing of HTTP;
// plan 3's broker wraps it behind /v1/tokens.
type Minter struct {
	store  store.Store
	log    decision.Emitter
	rand   io.Reader
	tagKey secretref.Secret
	now    func() time.Time
	cap    int
}

// NewMinter builds a Minter over a store, a record emitter, a source of
// randomness, the device-tag key, a clock, and the candidate-set cap.
func NewMinter(s store.Store, e decision.Emitter, r io.Reader, tagKey []byte, now func() time.Time, cap int) *Minter {
	return &Minter{store: s, log: e, rand: r, tagKey: secretref.Of(tagKey), now: now, cap: cap}
}

// Mint issues a login token, and an enable token beside it when the caller
// asks and the subject's mechanism is `token`. It refuses a username
// canonicalization would change, replays an idempotent request without
// minting, clamps the TTL to the subject's maximum and the token's expiry to
// its session ceiling, refuses a subject whose ceiling has passed or has no
// AuthTime to anchor it, and emits one `mint` record naming each token by
// hash alone.
func (m *Minter) Mint(ctx context.Context, r Request) (Result, error) {
	if !CanonicalUsername(r.Subject.Username) {
		return Result{}, ErrUsernameNotCanonical
	}
	if ReservedUsername(r.Subject.Username) {
		return Result{}, ErrUsernameReserved
	}
	if r.Subject.Principal == "" {
		return Result{}, ErrNoPrincipal
	}
	if r.Subject.MaxSessionAge > 0 {
		if r.Subject.AuthTime.IsZero() {
			return Result{}, ErrNoAuthTime
		}
		if !m.now().Before(r.Subject.AuthTime.Add(r.Subject.MaxSessionAge)) {
			return Result{}, ErrSessionExpired
		}
	}
	// idemErr names what a lost idempotency record cost, carried onto the mint
	// record that is emitted anyway. It is Record.IndexError's idiom: the
	// failure does not fail the mint, so the only place it can be said is the
	// record for the mint that lost it.
	var idemErr string
	if r.ReplayOnly && r.Reservation == nil {
		return Result{}, ErrReplayLapsed // nothing to replay from
	}
	if res := r.Reservation; res != nil {
		if res.Holder == "" {
			return Result{}, errors.New("token: an idempotent mint without a reservation (Minter.Reserve)")
		}
		// expect is the holder the record stands under now: this request's
		// reservation, or, for a replay abandoned below, the holder of the
		// completed record read, which the new hold replaces and nothing
		// else may.
		expect := res.Holder
		if rec, ok := res.Found[r.Device]; ok {
			prev, why := m.replayOf(rec, r.SupersededAt)
			if why == "" {
				prev.Replayed = true
				return prev, nil
			}
			if r.ReplayOnly {
				return Result{}, ErrReplayLapsed
			}
			idemErr = why
			expect = rec.Holder
		} else if r.ReplayOnly {
			return Result{}, ErrReplayLapsed
		}
		// Hold the record, by compare-and-set, for a fresh ReservationTTL
		// before minting. Renewed, a reservation taken at the start of a
		// long batch cannot lapse while this device is minted, which would
		// let a retry reserve and mint it too (design §17). Taking over an
		// abandoned replay is the same write: of two retries that both
		// abandon it, one takes it and the other is told it is in progress,
		// so they cannot both mint (pre-flight M5). A reservation that has
		// lapsed or been taken already mints nothing here.
		if err := m.store.CompleteIdempotency(ctx, r.Subject.Principal, idemScope(res.Key, r.Device), expect,
			store.Idempotency{BodyHash: r.BodyHash, Holder: res.Holder, Pending: true,
				ExpiresAt: m.now().Add(ReservationTTL)}); err != nil {
			if errors.Is(err, store.ErrConflict) {
				return Result{}, ErrIdempotencyInProgress
			}
			return Result{}, fmt.Errorf("token: holding the idempotency record: %w", err)
		}
		if expect != res.Holder {
			// Taken over: give it back with the rest if this mint fails.
			res.reserved = append(res.reserved, r.Device)
		}
	}

	ttl := r.TTL
	if ttl <= 0 || ttl > r.Subject.TokenTTL {
		ttl = r.Subject.TokenTTL
	}
	key := store.TokenKey{NAS: r.Device, Username: r.Subject.Username}
	cands, err := m.store.Candidates(ctx, key)
	if err != nil {
		return Result{}, err
	}
	if len(cands) >= m.cap {
		// The cap refuses the mint, never the redemption: a runaway client is
		// told to stop while every token already issued stays usable (design §8).
		// The check is per mint, not per token, so a pair mint from cap-1 lands
		// cap+1. That is the bound, not a ratchet — the next mint is refused —
		// and §8 wants a backstop, not an exact ceiling.
		return Result{}, &ErrTooManyOutstanding{Device: r.Device, Username: r.Subject.Username, Count: len(cands), Cap: m.cap}
	}

	// Indexed before it is written: a token no index names is one no
	// revocation can find, so a failed index write refuses the mint (plan
	// 7a). The entry is stamped by the store's clock before the token's
	// expiry is computed, a remote store's later still, so it is given a
	// minute past the token's TTL: an index that expires a moment before its
	// token would hide that token from a revocation (pre-flight M6).
	certKey := ""
	if c := r.Subject.Credential; c.Issuer != "" && c.Serial != "" {
		certKey = store.CertKey(c.Issuer, c.Serial)
	}
	indexTTL := ttl + time.Minute // written with the token itself, in its transaction

	// A token never outlives its session ceiling. Given its full TTL, a token
	// minted just before the ceiling would open a session just after it on
	// the strength of the last proof, and on Junos, which asks once at login
	// and keeps a session whose authorization is refused, that session would
	// run until logout (plan 7b final review I-1). The clamp only shortens,
	// so the index entry written above with the full TTL still outlives it.
	mintedAt := m.now()
	expires := mintedAt.Add(ttl)
	var sessionExpires time.Time
	if r.Subject.MaxSessionAge > 0 {
		sessionExpires = r.Subject.AuthTime.Add(r.Subject.MaxSessionAge)
		if sessionExpires.Before(expires) {
			expires = sessionExpires
			ttl = expires.Sub(mintedAt)
		}
	}
	out := Result{ExpiresAt: expires, Username: r.Subject.Username, MintedAt: mintedAt,
		SessionExpiresAt: sessionExpires}
	var hashes []string

	mint := func(kind string) (string, error) {
		secret, err := New(m.rand, m.tagKey.Bytes(), r.Device)
		if err != nil {
			return "", err
		}
		id, err := New(m.rand, m.tagKey.Bytes(), r.Device) // any random string is a removal handle
		if err != nil {
			return "", err
		}
		if _, err := m.store.PutToken(ctx, key, store.Token{
			ID: id[TagLen:], Secret: []byte(secret), Kind: kind, ExpiresAt: expires,
			Principal: r.Subject.Principal, Username: r.Subject.Username, BlobHash: r.BlobHash,
			MaxSessionAge: r.Subject.MaxSessionAge, Enable: r.Subject.Enable, MaxPrivilege: r.Subject.MaxPrivilege,
			Credential: r.Subject.Credential, AuthTime: r.Subject.AuthTime, MintedAt: mintedAt,
			VerifiedAt:     r.Subject.VerifiedAt,
			IndexPrincipal: r.Subject.Principal, IndexCertKey: certKey, IndexTTL: indexTTL,
		}); err != nil {
			return "", err
		}
		sum := sha256.Sum256([]byte(secret))
		hashes = append(hashes, hex.EncodeToString(sum[:]))
		return secret, nil
	}

	if out.Login, err = mint(store.KindLogin); err != nil {
		return Result{}, err
	}
	if r.WithEnable && r.Subject.Enable == "token" {
		if out.Enable, err = mint(store.KindEnable); err != nil {
			return Result{}, err
		}
	}

	if res := r.Reservation; res != nil {
		body, _ := json.Marshal(out)
		// The tokens are minted and about to be returned, so this cannot
		// become a refusal. It is the moment the caller's next retry stops
		// being safe, and the only moment anything knows.
		if perr := m.store.CompleteIdempotency(ctx, r.Subject.Principal, idemScope(res.Key, r.Device), res.Holder,
			store.Idempotency{BodyHash: r.BodyHash, Response: body, ExpiresAt: expires, Holder: res.Holder}); perr != nil {
			idemErr = "idempotency record not written; a retry on this key will mint again"
		}
	}

	log := m.log
	if r.Log != nil {
		log = r.Log
	}
	log.Emit(decision.Record{TS: m.now(), Event: decision.EventMint, Verdict: decision.VerdictPermit,
		Reason: decision.GrantsMatched, Principal: r.Subject.Principal,
		Auth: &decision.Auth{Method: r.Subject.Credential.Method, Directory: r.Directory, OIDC: r.OIDC, K8s: r.K8s,
			DirectoryPassword: r.DirectoryPassword},
		Device:      &decision.Device{Name: r.Device, Platform: r.Platform},
		Mint:        &decision.Mint{TokenSHA256: hashes, TTLSeconds: int(ttl.Seconds()), BlobHash: r.BlobHash},
		Policy:      r.Policy,
		Sweep:       r.Sweep,
		PerLoginMFA: r.PerLoginMFA,
		IndexError:  idemErr})
	return out, nil
}
