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

	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/username"
)

// ErrIdempotencyConflict is the same idempotency key presented with a
// different body (design §17). The first request's result stands; nothing is
// minted.
var ErrIdempotencyConflict = errors.New("token: idempotency key reused with a different body")

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

// canonicalUsername is the invariant, not just the character set: printable
// ASCII AND unchanged by canonicalization. The ASCII half alone would admit
// `@` and `\`, which are 0x21–0x7E and are exactly the two rewrites a
// directory-backed deployment hits every day.
func canonicalUsername(u string) bool { return asciiUsername(u) && username.Canonical(u) == u }

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
}

// Request is one mint: a Subject, the device the tokens are cut for, and the
// caller's asks — an enable token alongside the login one, a TTL no longer
// than the subject's, and an optional idempotency key with the hash of the
// body it was sent with.
type Request struct {
	Subject          Subject
	Device, Platform string
	BlobHash         string
	WithEnable       bool
	TTL              time.Duration
	// IdempotencyKey is scoped per device, not per key alone — see idemScope.
	// A caller may send one key for a whole batch, which is what design §17's
	// POST /v1/tokens does, and each device still gets its own record.
	IdempotencyKey, BodyHash string
}

// idemScope puts the device in the idempotency key. §17's key is one header
// for a whole batch of devices, and the record this minter writes is one
// device's Result: unscoped, device two in a batch replays device one's
// tokens and is handed a credential tagged for the wrong device, which that
// device refuses on every attempt. The separator matches the store's own
// convention (internal/store/memory/memory.go, idemKey).
func idemScope(key, device string) string { return key + "\x00" + device }

// Result is the minted pair and what the caller must tell the operator:
// Enable is empty unless the subject's mechanism is `token`, and Username is
// the name the tokens were written under, which is the name the device must
// send.
type Result struct {
	Login, Enable string
	ExpiresAt     time.Time
	Username      string
}

// Minter issues device tokens. It is in-process and knows nothing of HTTP;
// plan 3's broker wraps it behind /v1/tokens.
type Minter struct {
	store  store.Store
	log    decision.Emitter
	rand   io.Reader
	tagKey []byte
	now    func() time.Time
	cap    int
}

// NewMinter builds a Minter over a store, a record emitter, a source of
// randomness, the device-tag key, a clock, and the candidate-set cap.
func NewMinter(s store.Store, e decision.Emitter, r io.Reader, tagKey []byte, now func() time.Time, cap int) *Minter {
	return &Minter{store: s, log: e, rand: r, tagKey: tagKey, now: now, cap: cap}
}

// Mint issues a login token, and an enable token beside it when the caller
// asks and the subject's mechanism is `token`. It refuses a username
// canonicalization would change, replays an idempotent request without
// minting, clamps the TTL to the subject's maximum, and emits one `mint`
// record naming each token by hash alone.
func (m *Minter) Mint(ctx context.Context, r Request) (Result, error) {
	if !canonicalUsername(r.Subject.Username) {
		return Result{}, ErrUsernameNotCanonical
	}
	// idemErr names what a lost idempotency record cost, carried onto the mint
	// record that is emitted anyway. It is Record.IndexError's idiom: the
	// failure does not fail the mint, so the only place it can be said is the
	// record for the mint that lost it.
	var idemErr string
	if r.IdempotencyKey != "" {
		rec, err := m.store.GetIdempotency(ctx, r.Subject.Principal, idemScope(r.IdempotencyKey, r.Device))
		switch {
		case err == nil:
			if rec.BodyHash != r.BodyHash {
				return Result{}, ErrIdempotencyConflict
			}
			var res Result
			if uerr := json.Unmarshal(rec.Response, &res); uerr == nil {
				return res, nil
			}
			// A record that will not decode is a mint that cannot be replayed.
			// Fall through and mint — the caller gets working tokens — but the
			// record must say the replay was abandoned, or this is silent.
			idemErr = "idempotency record did not decode; minted again rather than replayed"
		case !errors.Is(err, store.ErrNotFound):
			// Not a miss: the store failed. Minting here is the one thing §17
			// forbids, because the caller cannot tell a retry from a first try
			// and a retried batch burns a pair per device it never learns
			// about. The cap would eventually fire and blame the client.
			return Result{}, fmt.Errorf("token: reading the idempotency record: %w", err)
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

	expires := m.now().Add(ttl)
	res := Result{ExpiresAt: expires, Username: r.Subject.Username}
	var hashes []string

	mint := func(kind string) (string, error) {
		secret, err := New(m.rand, m.tagKey, r.Device)
		if err != nil {
			return "", err
		}
		id, err := New(m.rand, m.tagKey, r.Device) // any random string is a removal handle
		if err != nil {
			return "", err
		}
		if _, err := m.store.PutToken(ctx, key, store.Token{
			ID: id[TagLen:], Secret: []byte(secret), Kind: kind, ExpiresAt: expires,
			Principal: r.Subject.Principal, Username: r.Subject.Username, BlobHash: r.BlobHash,
			MaxSessionAge: r.Subject.MaxSessionAge, Enable: r.Subject.Enable, MaxPrivilege: r.Subject.MaxPrivilege,
			Credential: r.Subject.Credential, AuthTime: r.Subject.AuthTime,
		}); err != nil {
			return "", err
		}
		sum := sha256.Sum256([]byte(secret))
		hashes = append(hashes, hex.EncodeToString(sum[:]))
		return secret, nil
	}

	if res.Login, err = mint(store.KindLogin); err != nil {
		return Result{}, err
	}
	if r.WithEnable && r.Subject.Enable == "token" {
		if res.Enable, err = mint(store.KindEnable); err != nil {
			return Result{}, err
		}
	}

	if r.IdempotencyKey != "" {
		body, _ := json.Marshal(res)
		// The tokens are minted and about to be returned, so this cannot become
		// a refusal. It is the moment the caller's next retry stops being safe,
		// and the only moment anything knows.
		if perr := m.store.PutIdempotency(ctx, r.Subject.Principal, idemScope(r.IdempotencyKey, r.Device),
			store.Idempotency{BodyHash: r.BodyHash, Response: body, ExpiresAt: expires}); perr != nil {
			idemErr = "idempotency record not written; a retry on this key will mint again"
		}
	}

	m.log.Emit(decision.Record{TS: m.now(), Event: decision.EventMint, Verdict: decision.VerdictPermit,
		Reason: decision.GrantsMatched, Principal: r.Subject.Principal,
		Auth:       &decision.Auth{Method: r.Subject.Credential.Method},
		Device:     &decision.Device{Name: r.Device, Platform: r.Platform},
		Mint:       &decision.Mint{TokenSHA256: hashes, TTLSeconds: int(ttl.Seconds()), BlobHash: r.BlobHash},
		IndexError: idemErr})
	return res, nil
}
