package token

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/memory"
	"github.com/rhwendt/port49/internal/username"
)

// This file is `package token`, and it must stay importable: internal/username,
// not internal/daemon/authen. From Task 7 on, authen imports this package for
// the device tag, so an in-package test that reached Canonical through authen
// would be `import cycle not allowed in test` — the package would not build at
// all, and Step 2's predicted failure would never be reached (Task 1).

func minter(t *testing.T) (*Minter, *memory.Store, *bytes.Buffer) {
	t.Helper()
	st := memory.New(time.Now)
	log := &bytes.Buffer{}
	return NewMinter(st, decision.NewJSONLines(log), rand.Reader, TagKey([]byte("k")), time.Now, 3), st, log
}

func subject() Subject {
	return Subject{Principal: "user:alice@example.com", Username: "alice", TokenTTL: 900 * time.Second,
		Enable: "token", MaxPrivilege: 15, MaxSessionAge: 8 * time.Hour,
		Credential: store.Credential{Method: "oidc", Sub: "a7f3", Sid: "s1"}}
}

// sameResult compares two Results field-wise, with ExpiresAt by Equal rather
// than ==. An idempotent replay returns the stored Result decoded from JSON,
// and a time.Time loses its monotonic reading and its *time.Location through
// that round trip: == on the struct is false for a correct replay, which would
// make this test fail on the behaviour it exists to prove.
func sameResult(a, b Result) bool {
	return a.Login == b.Login && a.Enable == b.Enable && a.Username == b.Username &&
		a.ExpiresAt.Equal(b.ExpiresAt)
}

func TestMintPairAndClamp(t *testing.T) {
	m, st, log := minter(t)
	res, err := m.Mint(context.Background(), Request{Subject: subject(), Device: "leaf-01", BlobHash: "sha256:b", WithEnable: true, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Login) != Len || len(res.Enable) != Len || res.Login == res.Enable || res.Username != "alice" {
		t.Fatalf("%+v", res)
	}
	if until := time.Until(res.ExpiresAt); until > 901*time.Second || until < 890*time.Second {
		t.Fatalf("ttl not clamped to the subject maximum: %v", until)
	}
	if !strings.HasPrefix(res.Login, Tag(TagKey([]byte("k")), "leaf-01")) {
		t.Fatal("login token lacks the device tag")
	}
	c, _ := st.Candidates(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "alice"})
	if len(c) != 2 || c[0].Kind != store.KindLogin || c[1].Kind != store.KindEnable ||
		c[0].Principal != "user:alice@example.com" || c[0].MaxSessionAge != 8*time.Hour ||
		c[0].Credential.Sid != "s1" ||
		// Enable and MaxPrivilege ride the token into the login context
		// (store.Context.Enable: "copied from the token") and are what §7
		// escalation and every authorization read. Dropped, the operator
		// redeems a good token and then cannot enable, or is denied at every
		// command, with the token path looking healthy throughout. BlobHash is
		// the policy version the context is explained against.
		c[0].Enable != "token" || c[0].MaxPrivilege != 15 || c[0].BlobHash != "sha256:b" {
		t.Fatalf("%+v", c)
	}
	if strings.Contains(log.String(), res.Login) || strings.Contains(log.String(), res.Enable) ||
		!strings.Contains(log.String(), `"event":"mint"`) || !strings.Contains(log.String(), "token_sha256") ||
		// A mint record has no credential hash to carry (§5.7: it carries
		// token_sha256 instead). Blank, the field is present on every mint
		// record in the fleet and joins everything to everything.
		strings.Contains(log.String(), "credential_sha256") {
		t.Fatalf("log: %s", log.String())
	}
}

func TestMintWithoutTheTokenMechanismYieldsNoEnableToken(t *testing.T) {
	m, _, _ := minter(t)
	for _, mech := range []string{"none", "auto"} {
		s := subject()
		s.Enable = mech
		res, err := m.Mint(context.Background(), Request{Subject: s, Device: "leaf-01", WithEnable: true, TTL: time.Minute})
		if err != nil || res.Enable != "" {
			t.Fatalf("%s: %+v %v", mech, res, err)
		}
	}
}

func TestCapRefusesMintNotRedemption(t *testing.T) {
	m, st, _ := minter(t)
	for i := 0; i < 3; i++ {
		if _, err := m.Mint(context.Background(), Request{Subject: subject(), Device: "leaf-01", TTL: time.Minute}); err != nil {
			t.Fatal(err)
		}
	}
	_, err := m.Mint(context.Background(), Request{Subject: subject(), Device: "leaf-01", TTL: time.Minute})
	var tooMany *ErrTooManyOutstanding
	if !errors.As(err, &tooMany) || tooMany.Count != 3 || tooMany.Cap != 3 {
		t.Fatalf("%v", err)
	}
	if c, _ := st.Candidates(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "alice"}); len(c) != 3 {
		t.Fatal("issued tokens must stay usable")
	}
}

func TestIdempotentReplay(t *testing.T) {
	m, st, _ := minter(t)
	req := Request{Subject: subject(), Device: "leaf-01", TTL: time.Minute, IdempotencyKey: "01J", BodyHash: "h1"}
	a, err := m.Mint(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	b, err := m.Mint(context.Background(), req)
	if err != nil || !sameResult(a, b) {
		t.Fatalf("%+v %+v %v", a, b, err)
	}
	if c, _ := st.Candidates(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "alice"}); len(c) != 1 {
		t.Fatal("replay minted again")
	}
	req.BodyHash = "h2"
	if _, err := m.Mint(context.Background(), req); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("%v", err)
	}
}

// §17 sends one Idempotency-Key for a batch of devices, so the record must be
// scoped by device: unscoped, device two finds device one's record, the body
// hashes match, and it replays — handing the operator a valid 30-character
// token tagged for a device that is not the one they asked for.
func TestOneIdempotencyKeyAcrossDevicesDoesNotCross(t *testing.T) {
	m, st, _ := minter(t)
	req := Request{Subject: subject(), TTL: time.Minute, IdempotencyKey: "01J9F4B2QK7X", BodyHash: "body"}
	req.Device = "core-sw01"
	a, err := m.Mint(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	req.Device = "leaf-04"
	b, err := m.Mint(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if a.Login == b.Login || !strings.HasPrefix(b.Login, Tag(TagKey([]byte("k")), "leaf-04")) {
		t.Fatalf("leaf-04 was handed core-sw01's token: %q %q", a.Login, b.Login)
	}
	for _, d := range []string{"core-sw01", "leaf-04"} {
		if c, _ := st.Candidates(context.Background(), store.TokenKey{NAS: d, Username: "alice"}); len(c) != 1 {
			t.Fatalf("%s has %d tokens", d, len(c))
		}
	}
	// And the scoping must not cost the replay: the same key on the same
	// device still replays rather than minting again.
	req.Device = "core-sw01"
	again, err := m.Mint(context.Background(), req)
	if err != nil || !sameResult(a, again) {
		t.Fatalf("same key, same device must replay: %+v %+v %v", a, again, err)
	}
}

// failingStore is memory with one idempotency method made to fail, so the
// difference between a miss and a store that is down can be tested. Every
// other method is the embedded store's.
type failingStore struct {
	*memory.Store
	getErr, putErr error
}

func (f *failingStore) GetIdempotency(ctx context.Context, principal, key string) (store.Idempotency, error) {
	if f.getErr != nil {
		return store.Idempotency{}, f.getErr
	}
	return f.Store.GetIdempotency(ctx, principal, key)
}

func (f *failingStore) PutIdempotency(ctx context.Context, principal, key string, rec store.Idempotency) error {
	if f.putErr != nil {
		return f.putErr
	}
	return f.Store.PutIdempotency(ctx, principal, key, rec)
}

func failingMinter(t *testing.T, get, put error) (*Minter, *failingStore, *bytes.Buffer) {
	t.Helper()
	st := &failingStore{Store: memory.New(time.Now), getErr: get, putErr: put}
	log := &bytes.Buffer{}
	return NewMinter(st, decision.NewJSONLines(log), rand.Reader, TagKey([]byte("k")), time.Now, 3), st, log
}

// A store that fails is not a store that missed. §17 exists so a batch mint
// that times out mid-flight can be retried safely; if a timed-out
// GetIdempotency reads as "no record", every retry mints again and the
// operator is eventually told by the cap that their client is looping, while
// the real fault is the store.
func TestIdempotencyStoreFailureIsNotAMiss(t *testing.T) {
	m, st, log := failingMinter(t, errors.New("dial tcp 10.0.0.9:6379: i/o timeout"), nil)
	req := Request{Subject: subject(), Device: "leaf-01", TTL: time.Minute, IdempotencyKey: "01J", BodyHash: "h1"}
	_, err := m.Mint(context.Background(), req)
	if err == nil || errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a failing store must be returned, not swallowed: %v", err)
	}
	if c, _ := st.Candidates(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "alice"}); len(c) != 0 {
		t.Fatalf("a store failure minted %d tokens the caller cannot know about", len(c))
	}
	if log.Len() != 0 {
		t.Fatalf("nothing was minted, so no mint record: %s", log.String())
	}
	// The miss itself still mints: ErrNotFound is the normal path.
	st.getErr = nil
	if _, err := m.Mint(context.Background(), req); err != nil {
		t.Fatalf("a miss must mint: %v", err)
	}
}

// mintRecord decodes the single record the minter emitted.
func mintRecord(t *testing.T, log *bytes.Buffer) decision.Record {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(log.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("want one record, got %d: %s", len(lines), log.String())
	}
	var rec decision.Record
	if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
		t.Fatalf("decoding the mint record: %v", err)
	}
	return rec
}

// A lost idempotency record cannot fail the mint — the tokens exist and are
// about to be returned — so the record for that mint is the only place it can
// be said. Without it the operator who retried a timed-out call holds two
// pairs for one device, the first unspent and recoverable in the store for its
// whole TTL, and the log shows two mints with no hint the second was meant to
// be a replay.
func TestUnwrittenIdempotencyRecordIsNamedOnTheMintRecord(t *testing.T) {
	m, _, log := failingMinter(t, nil, errors.New("write: no space left on device"))
	res, err := m.Mint(context.Background(), Request{Subject: subject(), Device: "leaf-01",
		TTL: time.Minute, IdempotencyKey: "01J", BodyHash: "h1"})
	if err != nil || len(res.Login) != Len {
		t.Fatalf("the tokens are already minted; the write failure must not refuse them: %+v %v", res, err)
	}
	rec := mintRecord(t, log)
	if !strings.Contains(rec.IndexError, "mint again") {
		t.Fatalf("index_error does not name what the failure cost: %q", rec.IndexError)
	}
	if strings.Contains(log.String(), res.Login) {
		t.Fatalf("log: %s", log.String())
	}
}

// A record that will not decode is a replay that cannot happen. The caller
// gets working tokens, and the mint record says the replay was abandoned.
func TestUndecodableIdempotencyRecordIsNamedOnTheMintRecord(t *testing.T) {
	m, st, log := failingMinter(t, nil, nil)
	req := Request{Subject: subject(), Device: "leaf-01", TTL: time.Minute, IdempotencyKey: "01J", BodyHash: "h1"}
	if err := st.Store.PutIdempotency(context.Background(), req.Subject.Principal,
		idemScope(req.IdempotencyKey, req.Device),
		store.Idempotency{BodyHash: "h1", Response: []byte("{not json"), ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	res, err := m.Mint(context.Background(), req)
	if err != nil || len(res.Login) != Len {
		t.Fatalf("%+v %v", res, err)
	}
	if rec := mintRecord(t, log); !strings.Contains(rec.IndexError, "did not decode") {
		t.Fatalf("index_error does not say the replay was abandoned: %q", rec.IndexError)
	}
}

// A mint that loses nothing says nothing: index_error is omitempty, so it must
// be absent rather than present and blank on the ordinary path.
func TestAHealthyMintCarriesNoIndexError(t *testing.T) {
	m, _, log := minter(t)
	if _, err := m.Mint(context.Background(), Request{Subject: subject(), Device: "leaf-01",
		TTL: time.Minute, IdempotencyKey: "01J", BodyHash: "h1"}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(log.String(), "index_error") {
		t.Fatalf("log: %s", log.String())
	}
}

// Every name canonicalization would change is refused. A name that changes
// under Canonical is a token nothing can ever redeem — the mint stores what it
// was given and the daemon looks up Canonical(wire) — and two names that
// canonicalize alike are one context and one token key.
func TestMintRefusesUsernamesCanonicalizationWouldChange(t *testing.T) {
	// A canary on the Go version, not on port49: if simple case mapping ever
	// stops folding U+0130 onto `i`, the argument for this guard changes and
	// should be re-read rather than the guard relaxed.
	if username.Canonical("İrem") != "irem" {
		t.Fatalf("this Go version folds U+0130 differently (%q); re-read the argument before relaxing the guard",
			username.Canonical("İrem"))
	}
	m, st, _ := minter(t)
	// The two an ASCII-only guard passes, and which are the NORMAL forms in a
	// directory-backed deployment: 0x21–0x7E includes both `@` and `\`.
	for _, bad := range []string{"alice@corp.example", `CORP\alice`, "Alice"} {
		s := subject()
		s.Username = bad
		if _, err := m.Mint(context.Background(), Request{Subject: s, Device: "leaf-01", TTL: time.Minute}); !errors.Is(err, ErrUsernameNotCanonical) {
			t.Fatalf("%q: %v", bad, err)
		}
	}
	// And the non-printable and non-ASCII ones, the U+0130 fold included:
	for _, bad := range []string{"İrem", "alice ", "ali ce", "", "alice\n"} {
		s := subject()
		s.Username = bad
		if _, err := m.Mint(context.Background(), Request{Subject: s, Device: "leaf-01", TTL: time.Minute}); !errors.Is(err, ErrUsernameNotCanonical) {
			t.Fatalf("%q: %v", bad, err)
		}
	}
	for _, k := range []string{"irem", "alice"} {
		if c, _ := st.Candidates(context.Background(), store.TokenKey{NAS: "leaf-01", Username: k}); len(c) != 0 {
			t.Fatalf("a refused mint must write nothing, and wrote under %q", k)
		}
	}
}
