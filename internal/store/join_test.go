package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/memory"
)

var t0 = time.Unix(1_757_041_495, 0)

// live is window A's context as it stands when window B logs in: enabled to
// 15, one session bound by accounting, and an older broker decision.
func live() store.Context {
	return store.Context{CtxID: "ctxA", Principal: "user:alice@example.com", Username: "alice",
		Port: "ssh", RemAddr: "198.51.100.4", PrivLvl: 15, BlobHash: "sha256:old",
		Credential: store.Credential{Method: "oidc", Sid: "sid-A"},
		AuthTime:   t0.Add(-2 * time.Hour), SessionExpires: t0.Add(6 * time.Hour),
		RefreshedAt: t0.Add(-time.Hour), LastTouchedAt: t0.Add(-time.Minute),
		SessionDiscriminators: []string{store.HashDiscriminator("42")}, AccountingState: store.AccountingStateOpen,
		Enable: "token", MaxPrivilege: 15, CreatedAt: t0.Add(-2 * time.Hour), Rev: 9}
}

// login is window B's context as the login path builds it on its own.
func login() store.Context {
	return store.Context{CtxID: "ctxB", Principal: "user:alice@example.com", Username: "alice",
		Port: "vty6", RemAddr: "198.51.100.9", PrivLvl: 1, BlobHash: "sha256:new",
		Credential: store.Credential{Method: "oidc", Sid: "sid-B"},
		AuthTime:   t0.Add(-10 * time.Minute), SessionExpires: t0.Add(7*time.Hour + 50*time.Minute),
		RefreshedAt: t0, LastTouchedAt: t0, Enable: "auto", MaxPrivilege: 15, CreatedAt: t0}
}

// The join table of spec §5.6, one row per field.
func TestJoinFieldRules(t *testing.T) {
	got := store.Join(live(), login(), t0)
	for _, c := range []struct {
		field string
		ok    bool
	}{
		{"ctx_id kept", got.CtxID == "ctxA"},
		{"principal and username kept", got.Principal == "user:alice@example.com" && got.Username == "alice"},
		{"privilege kept: the login's 1 does not lower window A's 15", got.PrivLvl == 15},
		{"session discriminators kept", len(got.SessionDiscriminators) == 1 && got.SessionDiscriminators[0] == store.HashDiscriminator("42")},
		{"accounting state kept", got.AccountingState == store.AccountingStateOpen},
		{"created_at kept", got.CreatedAt.Equal(t0.Add(-2 * time.Hour))},
		{"blob hash from the newest login", got.BlobHash == "sha256:new"},
		{"enable from the newest login", got.Enable == "auto"},
		{"credential from the newest login", got.Credential.Sid == "sid-B"},
		{"port and rem_addr from the newest login", got.Port == "vty6" && got.RemAddr == "198.51.100.9"},
		{"auth_time is the later", got.AuthTime.Equal(t0.Add(-10 * time.Minute))},
		{"session_expires is the later", got.SessionExpires.Equal(t0.Add(7*time.Hour + 50*time.Minute))},
		{"refreshed_at and last_touched_at are now", got.RefreshedAt.Equal(t0) && got.LastTouchedAt.Equal(t0)},
		{"no revocation to carry", got.RevokedAt.IsZero()},
		{"the revision is the store's, not the merge's", got.Rev == 0},
	} {
		if !c.ok {
			t.Errorf("%s: %+v", c.field, got)
		}
	}
}

// The login's level raises, and the result is bounded by the newest ceiling —
// SetPrivilege's rule (spec §5.3). Zero MaxPrivilege is no ceiling.
func TestJoinPrivilegeIsRaiseOnlyAndClamped(t *testing.T) {
	for _, tt := range []struct {
		name            string
		held, in, limit uint8
		want            uint8
	}{
		{"a lower login keeps the held level", 15, 1, 15, 15},
		{"a higher login raises it", 1, 15, 15, 15},
		{"a lowered ceiling bounds what is kept", 15, 1, 7, 7},
		{"no ceiling bounds nothing", 15, 1, 0, 15},
	} {
		t.Run(tt.name, func(t *testing.T) {
			l, n := live(), login()
			l.PrivLvl, n.PrivLvl, n.MaxPrivilege = tt.held, tt.in, tt.limit
			if got := store.Join(l, n, t0).PrivLvl; got != tt.want {
				t.Fatalf("privilege %d, want %d", got, tt.want)
			}
		})
	}
}

// Zero session_expires is "no ceiling", which is later than any time.
func TestJoinNeverAddsACeiling(t *testing.T) {
	l, n := live(), login()
	n.SessionExpires = time.Time{}
	if got := store.Join(l, n, t0); !got.SessionExpires.IsZero() {
		t.Fatalf("a login with no ceiling must leave none: %v", got.SessionExpires)
	}
	l, n = live(), login()
	l.SessionExpires = time.Time{}
	if got := store.Join(l, n, t0); !got.SessionExpires.IsZero() {
		t.Fatalf("a context with no ceiling must not gain one: %v", got.SessionExpires)
	}
}

// A token minted before the revocation is what the revocation was meant to
// stop; one minted after it is the broker having verified the credential again
// (spec §13, decision 15). A zero MintedAt reads as before.
func TestJoinKeepsARevocationUnlessMintedAfterIt(t *testing.T) {
	revokedAt := t0.Add(-5 * time.Minute)
	for _, tt := range []struct {
		name     string
		mintedAt time.Time
		kept     bool
	}{
		{"minted before", revokedAt.Add(-time.Minute), true},
		{"minted at the same instant", revokedAt, true},
		{"no mint time recorded", time.Time{}, true},
		{"minted after", revokedAt.Add(time.Minute), false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			l := live()
			l.RevokedAt = revokedAt
			got := store.Join(l, login(), tt.mintedAt)
			if kept := !got.RevokedAt.IsZero(); kept != tt.kept {
				t.Fatalf("revoked_at %v, kept %v, want kept %v", got.RevokedAt, kept, tt.kept)
			}
		})
	}
}

func TestJoinable(t *testing.T) {
	other := login()
	other.Principal = "user:alice@corp.example"
	past := live()
	past.SessionExpires = t0.Add(-time.Second)
	never := live()
	never.SessionExpires = time.Time{}
	for _, tt := range []struct {
		name     string
		live, in store.Context
		joinable bool
	}{
		{"same principal, inside the ceiling", live(), login(), true},
		{"same principal, no ceiling", never, login(), true},
		{"another principal under the same username", live(), other, false},
		{"past session_expires", past, login(), false},
	} {
		if got := store.Joinable(tt.live, tt.in, t0); got != tt.joinable {
			t.Errorf("%s: joinable %v, want %v", tt.name, got, tt.joinable)
		}
	}
}

// A join witnesses the login only into a context it leaves unrevoked, and
// keeps the earlier logins' witnesses either way; the last MaxLogins are
// kept (Task 4b review I1, I2).
func TestJoinWitnessesOnlyAnUnrevokedLogin(t *testing.T) {
	a, b := live(), login()
	a.Logins = []string{"aa"}
	b.Logins = []string{"bb"}
	if got := store.Join(a, b, t0); len(got.Logins) != 2 || got.Logins[0] != "aa" || got.Logins[1] != "bb" {
		t.Fatalf("a join that commits the login: %v", got.Logins)
	}
	revoked := a
	revoked.RevokedAt = t0.Add(-time.Minute)
	if got := store.Join(revoked, b, t0.Add(-time.Hour)); len(got.Logins) != 1 || got.Logins[0] != "aa" {
		t.Fatalf("a join into a revocation the token predates: %v", got.Logins)
	}
	marked := b
	marked.RevokedAt = t0.Add(-time.Minute) // a mark JoinContext carried in
	if got := store.Join(a, marked, t0.Add(-time.Hour)); len(got.Logins) != 1 || got.Logins[0] != "aa" {
		t.Fatalf("a join under a mark: %v", got.Logins)
	}
	for i := 0; i < store.MaxLogins; i++ {
		a = store.Join(a, b, t0)
	}
	if len(a.Logins) != store.MaxLogins || a.Logins[0] != "bb" {
		t.Fatalf("the oldest witness is not the one evicted: %v", a.Logins)
	}
	var h [32]byte
	h[0], h[7], h[8] = 0xab, 0xcd, 0xef
	if w := store.LoginWitness(h); w != "ab000000000000cd" {
		t.Fatalf("the witness is the hash's first 8 bytes, hex: %q", w)
	}
}

// A login that writes a revoked context of its own, fresh or replacing,
// is not witnessed; an unrevoked one is.
func TestJoinContextWitnessesOnlyAnUnrevokedLogin(t *testing.T) {
	b := login()
	b.Logins = []string{"bb"}
	s := newMemory()
	if res, err := store.JoinContext(context.Background(), s, ck, b, t0, t0, time.Hour,
		store.LoginIndex{}); err != nil || len(res.Context.Logins) != 1 {
		t.Fatalf("a fresh login: %+v %v", res, err)
	}
	s = newMemory()
	if err := s.PutRevocation(context.Background(), store.Revocation{Kind: store.RevocationPrincipal,
		Key: b.Principal, At: t0.Add(-time.Minute), Origin: "test"}); err != nil {
		t.Fatal(err)
	}
	res, err := store.JoinContext(context.Background(), s, ck, b, t0.Add(-time.Hour), t0, time.Hour,
		store.LoginIndex{Principal: b.Principal})
	if err != nil || res.Context.RevokedAt.IsZero() || len(res.Context.Logins) != 0 {
		t.Fatalf("a fresh login under a mark: %+v %v", res, err)
	}
	if got, _ := s.GetContext(context.Background(), ck); len(got.Logins) != 0 {
		t.Fatalf("the store holds a witness for a refused login: %v", got.Logins)
	}
}

func newMemory() *memory.Store { return memory.New(func() time.Time { return t0 }) }

var ck = store.ContextKey{NAS: "leaf-01", Username: "alice"}

func TestJoinContextOnAnEmptyKeyWritesTheLogin(t *testing.T) {
	s := newMemory()
	res, err := store.JoinContext(context.Background(), s, ck, login(), t0, t0, time.Hour, store.LoginIndex{})
	if err != nil || res.Joined || res.Replaced != "" || res.Context.CtxID != "ctxB" {
		t.Fatalf("%+v %v", res, err)
	}
	if got, _ := s.GetContext(context.Background(), ck); got.CtxID != "ctxB" || got.PrivLvl != 1 {
		t.Fatalf("%+v", got)
	}
}

func TestJoinContextJoinsTheSamePrincipal(t *testing.T) {
	s := newMemory()
	s.PutContext(context.Background(), ck, live(), time.Hour)
	res, err := store.JoinContext(context.Background(), s, ck, login(), t0, t0, time.Hour, store.LoginIndex{})
	if err != nil || !res.Joined || res.Replaced != "" || res.Context.CtxID != "ctxA" || res.Prior.CtxID != "" {
		t.Fatalf("%+v %v", res, err)
	}
	if got, _ := s.GetContext(context.Background(), ck); got.CtxID != "ctxA" || got.PrivLvl != 15 || got.BlobHash != "sha256:new" {
		t.Fatalf("%+v", got)
	}
}

// A join whose newer ceiling lowers the held level says so: window A's next
// command is denied privilege_exceeded, and without the level before and
// after on window B's redeem record nothing connects the two (review M4).
func TestJoinContextReportsAClampedLevel(t *testing.T) {
	for _, tt := range []struct {
		name    string
		ceiling uint8
		want    uint8
	}{
		{"a lower ceiling clamps", 7, 15},
		{"the same ceiling does not", 15, 0},
		{"no ceiling does not", 0, 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := newMemory()
			s.PutContext(context.Background(), ck, live(), time.Hour)
			n := login()
			n.MaxPrivilege = tt.ceiling
			res, err := store.JoinContext(context.Background(), s, ck, n, t0, t0, time.Hour, store.LoginIndex{})
			if err != nil || !res.Joined || res.ClampedFrom != tt.want {
				t.Fatalf("ClampedFrom = %d, want %d: %+v %v", res.ClampedFrom, tt.want, res, err)
			}
		})
	}
}

// Another principal under the same username is not this operator's second
// window: it replaces, and names what it replaced.
func TestJoinContextReplacesAnotherPrincipal(t *testing.T) {
	s := newMemory()
	l := live()
	l.RevokedAt = t0.Add(-time.Minute)
	s.PutContext(context.Background(), ck, l, time.Hour)
	n := login()
	n.Principal = "user:alice@corp.example"
	res, err := store.JoinContext(context.Background(), s, ck, n, time.Time{}, t0, time.Hour, store.LoginIndex{})
	if err != nil || res.Joined || res.Replaced != "ctxA" || res.ReplacedUnreadable {
		t.Fatalf("%+v %v", res, err)
	}
	// The displaced record comes back whole, so the login can unindex its
	// credential: otherwise a revocation of user:alice@example.com's sid
	// would keep reaching user:alice@corp.example's context (ruling P3).
	if res.Prior.CtxID != "ctxA" || res.Prior.Principal != "user:alice@example.com" || res.Prior.Credential.Sid != "sid-A" {
		t.Fatalf("the replace must hand back what it displaced: %+v", res.Prior)
	}
	got, _ := s.GetContext(context.Background(), ck)
	if got.CtxID != "ctxB" || got.Principal != "user:alice@corp.example" || got.PrivLvl != 1 ||
		len(got.SessionDiscriminators) != 0 || !got.RevokedAt.IsZero() {
		t.Fatalf("another principal's login must start clean: %+v", got)
	}
}

// Past its ceiling the context is replaced, not joined — but a ceiling ending
// is not a credential verified again, so the same principal's revocation
// carries by the join's own rule.
func TestJoinContextReplacesPastTheCeilingAndCarriesTheRevocation(t *testing.T) {
	s := newMemory()
	l := live()
	l.SessionExpires = t0.Add(-time.Second)
	l.RevokedAt = t0.Add(-time.Minute)
	s.PutContext(context.Background(), ck, l, time.Hour)
	res, err := store.JoinContext(context.Background(), s, ck, login(), t0.Add(-2*time.Minute), t0, time.Hour, store.LoginIndex{})
	if err != nil || res.Joined || res.Replaced != "ctxA" || res.Prior.CtxID != "ctxA" {
		t.Fatalf("%+v %v", res, err)
	}
	got, _ := s.GetContext(context.Background(), ck)
	if got.CtxID != "ctxB" || got.PrivLvl != 1 || !got.RevokedAt.Equal(t0.Add(-time.Minute)) {
		t.Fatalf("%+v", got)
	}
}

// alwaysConflicts refuses every swap, which is what a context written to
// faster than a login can merge looks like from inside JoinContext.
type alwaysConflicts struct {
	*memory.Store
	swaps int
}

func (a *alwaysConflicts) SwapContext(context.Context, store.ContextKey, uint64, store.Context, time.Duration) error {
	a.swaps++
	return store.ErrConflict
}

func (a *alwaysConflicts) SwapLogin(context.Context, store.ContextKey, uint64, store.Context, time.Duration,
	store.LoginWrite) error {
	a.swaps++
	return store.ErrConflict
}

func TestJoinContextGivesUpAfterMaxJoinAttempts(t *testing.T) {
	s := &alwaysConflicts{Store: newMemory()}
	_, err := store.JoinContext(context.Background(), s, ck, login(), t0, t0, time.Hour, store.LoginIndex{})
	if !errors.Is(err, store.ErrConflict) || s.swaps != store.MaxJoinAttempts {
		t.Fatalf("want ErrConflict after %d swaps, got %v after %d", store.MaxJoinAttempts, err, s.swaps)
	}
}

// storeFails answers the read with an error that is neither ErrNotFound nor an
// UnreadableContextError: a store that is down. A record the store returned
// and the sealing layer could not open is the other case, and is replaced
// (TestJoinContextReplacesAnUnreadableContextCarryingItsRevocation).
type storeFails struct{ *memory.Store }

func (storeFails) GetContext(context.Context, store.ContextKey) (store.Context, error) {
	return store.Context{}, errors.New("store down")
}

func TestJoinContextDoesNotWriteBlindOverAReadError(t *testing.T) {
	s := storeFails{newMemory()}
	s.Store.PutContext(context.Background(), ck, live(), time.Hour)
	if _, err := store.JoinContext(context.Background(), s, ck, login(), t0, t0, time.Hour, store.LoginIndex{}); err == nil {
		t.Fatal("a context that cannot be read must not be replaced")
	}
	if got, _ := s.Store.GetContext(context.Background(), ck); got.CtxID != "ctxA" {
		t.Fatalf("%+v", got)
	}
}

// unreadable answers GetContext the way the sealing layer answers a record it
// cannot open: no sealed field, and the plaintext revision and revocation in an
// UnreadableContextError. beforeFirstAnswer runs once, after the first read and
// before JoinContext can swap — where a racing writer lands.
type unreadable struct {
	*memory.Store
	reads             *int
	beforeFirstAnswer func()
}

func (u unreadable) GetContext(ctx context.Context, k store.ContextKey) (store.Context, error) {
	c, err := u.Store.GetContext(ctx, k)
	if err != nil {
		return c, err
	}
	*u.reads++
	if *u.reads == 1 && u.beforeFirstAnswer != nil {
		u.beforeFirstAnswer()
	}
	return store.Context{}, &store.UnreadableContextError{Rev: c.Rev, RevokedAt: c.RevokedAt,
		Err: errors.New("crypt: opening context: sealed under an unknown key")}
}

// Ruling R1: a record the sealing layer cannot open is not joined — its fields
// are sealed — and not refused either, or a key rotation past the two-key
// window locks every operator with a live context out of login. It is replaced
// by the login, and its plaintext RevokedAt carries by the minted-after rule
// whoever its principal was, because the principal is sealed (ruling P2): the
// login here is another principal's, which a readable replace would start
// clean. Nothing about the displaced record can be named, so Replaced and
// Prior stay empty and ReplacedUnreadable says why.
func TestJoinContextReplacesAnUnreadableContextCarryingItsRevocation(t *testing.T) {
	revokedAt := t0.Add(-time.Minute)
	for _, tt := range []struct {
		name     string
		mintedAt time.Time
		kept     bool
	}{
		{"minted before the revocation", revokedAt.Add(-time.Minute), true},
		{"minted after the revocation", revokedAt.Add(time.Second), false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			reads := 0
			s := unreadable{Store: newMemory(), reads: &reads}
			l := live()
			l.RevokedAt = revokedAt
			s.Store.PutContext(context.Background(), ck, l, time.Hour)
			n := login()
			n.Principal = "user:alice@corp.example"
			res, err := store.JoinContext(context.Background(), s, ck, n, tt.mintedAt, t0, time.Hour, store.LoginIndex{})
			if err != nil || res.Joined || !res.ReplacedUnreadable || res.Replaced != "" || res.Prior.CtxID != "" {
				t.Fatalf("%+v %v", res, err)
			}
			got, _ := s.Store.GetContext(context.Background(), ck)
			if got.CtxID != "ctxB" || got.PrivLvl != 1 || len(got.SessionDiscriminators) != 0 {
				t.Fatalf("the login must replace the unreadable record: %+v", got)
			}
			if kept := got.RevokedAt.Equal(revokedAt); kept != tt.kept {
				t.Fatalf("revoked_at %v, kept %v, want kept %v", got.RevokedAt, kept, tt.kept)
			}
		})
	}
}

// The replace of an unreadable record is still a compare-and-set on the
// revision the read returned: a revocation landing between the read and the
// swap moves the revision, the swap is refused, and the second pass carries the
// revocation the first never saw.
func TestJoinContextReplacingAnUnreadableContextStillComparesTheRevision(t *testing.T) {
	reads := 0
	s := unreadable{Store: newMemory(), reads: &reads}
	s.Store.PutContext(context.Background(), ck, live(), time.Hour)
	s.beforeFirstAnswer = func() {
		if err := s.Store.SetRevokedAt(context.Background(), ck, t0); err != nil {
			t.Fatal(err)
		}
	}
	res, err := store.JoinContext(context.Background(), s, ck, login(), t0.Add(-time.Minute), t0, time.Hour, store.LoginIndex{})
	if err != nil || !res.ReplacedUnreadable || reads != 2 {
		t.Fatalf("%+v %v after %d reads", res, err, reads)
	}
	if got, _ := s.Store.GetContext(context.Background(), ck); got.CtxID != "ctxB" || !got.RevokedAt.Equal(t0) {
		t.Fatalf("the replace erased a revocation that landed mid-login: %+v", got)
	}
}

// readHook answers GetContext from the memory store and runs beforeFirstAnswer
// once, after the first read and before JoinContext can swap: the race the
// storetest helper only reaches by chance, forced on every run.
type readHook struct {
	*memory.Store
	reads             *int
	beforeFirstAnswer func()
}

func (h readHook) GetContext(ctx context.Context, k store.ContextKey) (store.Context, error) {
	c, err := h.Store.GetContext(ctx, k)
	*h.reads++
	if *h.reads == 1 && h.beforeFirstAnswer != nil {
		h.beforeFirstAnswer()
	}
	return c, err
}

// The join is a compare-and-set on the revision it read: a revocation landing
// between the read and the swap moves the revision, the swap is refused, and
// the second pass merges the revocation the first never saw. A join that wrote
// what it read would erase it.
func TestJoinContextKeepsARevocationThatLandsMidJoin(t *testing.T) {
	reads := 0
	s := readHook{Store: newMemory(), reads: &reads}
	s.Store.PutContext(context.Background(), ck, live(), time.Hour)
	s.beforeFirstAnswer = func() {
		if err := s.Store.SetRevokedAt(context.Background(), ck, t0); err != nil {
			t.Fatal(err)
		}
	}
	res, err := store.JoinContext(context.Background(), s, ck, login(), t0.Add(-time.Minute), t0, time.Hour, store.LoginIndex{})
	if err != nil || !res.Joined {
		t.Fatalf("%+v %v", res, err)
	}
	if got, _ := s.Store.GetContext(context.Background(), ck); got.CtxID != "ctxA" || !got.RevokedAt.Equal(t0) {
		t.Fatalf("the join erased a revocation that landed mid-login: %+v", got)
	}
	if reads != 2 {
		t.Fatalf("the refused swap must send the join back to the read: %d reads, want 2", reads)
	}
}

// An UnreadableContextError built without an Err — by a backend that has not
// been written yet — must still be loggable: it is read on the login path at
// the moment a key has rotated out.
func TestUnreadableContextErrorWithoutAnErr(t *testing.T) {
	e := &store.UnreadableContextError{Rev: 3}
	if e.Error() == "" || e.Unwrap() != nil || errors.Is(e, store.ErrNotFound) {
		t.Fatalf("%q %v", e.Error(), e.Unwrap())
	}
}
