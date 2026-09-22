package token

import (
	"bytes"
	"context"
	"crypto/rand"
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
		c[0].Principal != "user:alice@example.com" || c[0].MaxSessionAge != 8*time.Hour || c[0].Credential.Sid != "s1" {
		t.Fatalf("%+v", c)
	}
	if strings.Contains(log.String(), res.Login) || strings.Contains(log.String(), res.Enable) ||
		!strings.Contains(log.String(), `"event":"mint"`) || !strings.Contains(log.String(), "token_sha256") {
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
