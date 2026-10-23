package broker

import (
	"context"
	"crypto/rand"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/policy"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/crypt"
	"github.com/rhwendt/port49/internal/store/etcd"
	"github.com/rhwendt/port49/internal/store/etcd/etcdtest"
	"github.com/rhwendt/port49/internal/store/memory"
	"github.com/rhwendt/port49/internal/token"
)

// A refresh judges a changed key's unspent tokens one by one (spec §5.1.3):
// each is kept only if the policy in force would mint it now as it is. These
// tests read a token's secret only to compare it, never to print it.

// noReload is alice's grant without no_reload: an edit that changes her
// answer on every device, so her keys are judged token by token.
const noReload = "roles: [network_admin], max_privilege: admin"

var aliceOnNX1 = store.TokenKey{NAS: "nx1", Username: "alice"}

// settlePriors is what a reload's settle pass carries: the replaced policy
// over its span up to the swap, and the policy in force since.
func settlePriors(old *policy.Policy, from, swap time.Time, cur *policy.Policy) []Prior {
	return []Prior{{Policy: old, At: from, Until: swap}, {Policy: cur, At: swap}}
}

// mintLogin mints alice a token for device under the policy in force and
// returns the login token.
func (f *fixture) mintLogin(t *testing.T, device string) string {
	t.Helper()
	it := decodeMint(t, f.post(context.Background(), f.state(f.alice), `{"devices":["`+device+`"]}`, "")).Results[0]
	if it.Verdict != "permit" {
		t.Fatalf("mint on %s: verdict %q, reason %q", device, it.Verdict, it.Reason)
	}
	return it.Login
}

// mintUnder mints alice a token for device under p, as a replica still on p
// would, and puts the policy in force back.
func (f *fixture) mintUnder(t *testing.T, p *policy.Policy, device string) string {
	t.Helper()
	cur := f.b.Policy.Swap(p)
	defer f.b.Policy.Swap(cur)
	return f.mintLogin(t, device)
}

// holds reports whether st still holds the token whose secret is tok under k.
func holds(t *testing.T, st store.Store, k store.TokenKey, tok string) bool {
	t.Helper()
	toks, err := st.Candidates(context.Background(), k)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range toks {
		if string(c.Secret) == tok {
			return true
		}
	}
	return false
}

// rewriteToken puts the one token under k back changed by change, as a
// store writer, another build or a replica on another policy could have
// written it.
func rewriteToken(t *testing.T, st store.Store, k store.TokenKey, change func(*store.Token)) {
	t.Helper()
	ctx := context.Background()
	toks, err := st.Candidates(ctx, k)
	if err != nil || len(toks) != 1 {
		t.Fatalf("want one token under %v: %d, %v", k, len(toks), err)
	}
	tok := toks[0]
	if err := st.DeleteToken(ctx, k, tok.ID); err != nil {
		t.Fatal(err)
	}
	change(&tok)
	if _, err := st.PutToken(ctx, k, tok); err != nil {
		t.Fatal(err)
	}
}

// P-1: an operator tightens alice's grant and runs `port49 token` again.
// The settle pass after the edit keeps that token, and still deletes the one
// a late replica minted under the replaced policy into the same key; the
// report says both.
func TestASettlePassKeepsATokenThePolicyInForceMints(t *testing.T) {
	f := newFixture(t, 8)
	bg := context.Background()
	start := f.now
	before := f.mintLogin(t, "nx1")
	f.advance(time.Second)
	priors := f.reload(t, edit(t, aliceGrant, noReload))
	old, cur, swap := priors[0].Policy, f.b.Policy.Load(), f.now
	if _, err := f.b.Refresh(bg, priors); err != nil {
		t.Fatal(err)
	}
	f.advance(time.Second)
	fresh := f.mintLogin(t, "nx1")
	f.advance(time.Second)
	late := f.mintUnder(t, old, "nx1")
	f.advance(10 * time.Second)
	rep, err := f.b.Refresh(bg, settlePriors(old, start, swap, cur))
	if err != nil {
		t.Fatal(err)
	}
	if !holds(t, f.st, aliceOnNX1, fresh) {
		t.Fatal("the settle pass deleted the token minted under the policy in force")
	}
	if holds(t, f.st, aliceOnNX1, before) || holds(t, f.st, aliceOnNX1, late) {
		t.Fatal("a token minted under the replaced policy survived the settle pass")
	}
	if rep.TokenKeys != 1 || rep.TokensKept != 1 {
		t.Fatalf("the settle pass reports %d key(s) superseded, %d token(s) kept; want 1 and 1", rep.TokenKeys,
			rep.TokensKept)
	}
}

// C1: a grant of another principal's that expires after alice's mint is no
// reason to delete her token. Only her own answer judges it.
func TestAnotherPrincipalsExpiryDoesNotDeleteAToken(t *testing.T) {
	f := newFixture(t, 8)
	bg := context.Background()
	start := f.now
	carol := "  - {subject: idle, scope: all_devices, roles: [network_admin], expires: " +
		f.now.Add(10*time.Second).UTC().Format(time.RFC3339) + "}\n"
	priors := f.reload(t, edit(t, aliceGrant, noReload)+carol)
	old, cur, swap := priors[0].Policy, f.b.Policy.Load(), f.now
	f.advance(time.Second)
	fresh := f.mintLogin(t, "nx1")
	f.advance(20 * time.Second) // past carol's expiry
	if _, err := f.b.Refresh(bg, settlePriors(old, start, swap, cur)); err != nil {
		t.Fatal(err)
	}
	if !holds(t, f.st, aliceOnNX1, fresh) {
		t.Fatal("carol's grant expiring deleted alice's token")
	}
}

// Each field a token carries is compared with what the policy in force would
// mint now, and a token that differs in any is deleted; one that differs in
// none is kept.
func TestAChangedKeysTokenIsJudgedFieldByField(t *testing.T) {
	for _, c := range []struct {
		name   string
		change func(*store.Token)
		kept   bool
	}{
		{"as minted", func(*store.Token) {}, true},
		{"another blob", func(tk *store.Token) { tk.BlobHash = "sha256:another" }, false},
		{"a longer token_ttl", func(tk *store.Token) { tk.ExpiresAt = tk.MintedAt.Add(61 * time.Second) }, false},
		{"a longer max_session_age", func(tk *store.Token) { tk.MaxSessionAge += time.Hour }, false},
		{"no max_session_age", func(tk *store.Token) { tk.MaxSessionAge = 0 }, false},
		{"another ceiling", func(tk *store.Token) { tk.MaxPrivilege-- }, false},
		{"another enable", func(tk *store.Token) { tk.Enable = "auto" }, false},
		{"another principal's", func(tk *store.Token) { tk.Principal = "user:carol@example.com" }, false},
		{"another username's", func(tk *store.Token) { tk.Principal = "user:bob@example.com" }, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			// bob is granted what alice is after the edit, under his own
			// username: a token of his under alice's key differs in that alone.
			f := newFixtureWithPolicy(t, 8, withBob(testPolicy))
			start := f.now
			priors := f.reload(t, withBob(edit(t, aliceGrant, noReload)))
			old, cur, swap := priors[0].Policy, f.b.Policy.Load(), f.now
			f.advance(time.Second)
			f.mintLogin(t, "nx1")
			rewriteToken(t, f.st, aliceOnNX1, c.change)
			if _, err := f.b.Refresh(context.Background(), settlePriors(old, start, swap, cur)); err != nil {
				t.Fatal(err)
			}
			toks, _ := f.st.Candidates(context.Background(), aliceOnNX1)
			if kept := len(toks) == 1; kept != c.kept {
				t.Fatalf("kept %v, want %v", kept, c.kept)
			}
		})
	}
}

// withBob is body with bob, a subject of his own granted alice's role on
// every device, under the username bob.
func withBob(body string) string {
	return strings.Replace(body, "subjects:\n", "subjects:\n  - {name: bobs, identity: [\"user:bob@example.com\"], "+
		"username: bob, enable: token, token_ttl: 60s}\n", 1) +
		"  - {subject: bobs, scope: all_devices, " + noReload + "}\n"
}

// M3: a key flagged at an expiry instant judges a token by its blob, bundle
// included. alice held read_only until a lapse under the replaced policy, so
// her key is judged; her token minted after the lapse gives what the policy
// in force gives, but under the replaced bundle, and is deleted.
func TestATokenUnderTheReplacedBundleIsDeleted(t *testing.T) {
	f := newFixture(t, 8)
	start := f.now
	lapse := f.now.Add(time.Hour)
	extra := "  - {subject: netops, scope: all_devices, roles: [read_only], expires: " +
		lapse.UTC().Format(time.RFC3339) + "}\n"
	f.reload(t, edit(t, roleList, readOnly)+extra)
	f.advance(time.Hour + 30*time.Second)
	f.mintLogin(t, "nx1")
	pol, err := policy.Parse([]byte(edit(t, roleList, readOnly)), policy.Env{Devices: []admission.Device{
		f.devices["leaf1"], f.devices["nx1"], f.devices["bare"]}, Now: f.b.Now()})
	if err != nil {
		t.Fatal(err)
	}
	priors := []Prior{{Policy: f.b.Policy.Swap(pol), At: start, Until: f.b.Now()}}
	if _, err := f.b.Refresh(context.Background(), priors); err != nil {
		t.Fatal(err)
	}
	if toks, _ := f.st.Candidates(context.Background(), aliceOnNX1); len(toks) != 0 {
		t.Fatal("a token under the replaced bundle survived, its answer the same but for the bundle")
	}
}

// I2: a token this process cannot open, under a key whose answer changed, is
// deleted: it cannot be judged, and the whole-key delete took it too.
func TestAnUnreadableTokenUnderAChangedKeyIsDeleted(t *testing.T) {
	f := newFixture(t, 8)
	ctx := context.Background()
	var ours, theirs crypt.Key
	ours.ID, theirs.ID = "v1", "other"
	copy(ours.Bytes[:], "broker-test-token-key-32-bytes-a")
	copy(theirs.Bytes[:], "broker-test-token-key-32-bytes-b")
	if _, err := crypt.Wrap(f.st, crypt.Keys{Current: theirs}, nil).PutToken(ctx, aliceOnNX1, store.Token{ID: "sealed",
		Secret: []byte("secret-sealed"), Kind: store.KindLogin, ExpiresAt: f.now.Add(time.Minute),
		Principal: alice, Username: "alice", MintedAt: f.now}); err != nil {
		t.Fatal(err)
	}
	f.b.Store = crypt.Wrap(f.st, crypt.Keys{Current: ours}, nil)
	f.advance(time.Second)
	pass := f.b.Now()
	rep, err := f.b.Refresh(ctx, f.reload(t, edit(t, aliceGrant, noReload)))
	if err != nil {
		t.Fatal(err)
	}
	if ids, _ := f.st.TokenIDs(ctx, aliceOnNX1); len(ids) != 0 || rep.TokenKeys != 1 {
		t.Fatalf("%d token(s) left that this process cannot open; %d key(s) superseded", len(ids), rep.TokenKeys)
	}
	// Its MintedAt cannot be read, so the supersede is stamped at the pass's
	// now: unstamped, a replay of its mint would answer with a deleted token.
	local, err := f.b.supersededAt(ctx, aliceOnNX1)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := f.st.SupersededAt(ctx, aliceOnNX1)
	if err != nil {
		t.Fatal(err)
	}
	if local.Before(pass) || stored.Before(pass) {
		t.Fatalf("the supersede is stamped %v here and %v in the store; want the pass's now, %v", local, stored, pass)
	}
}

// supersedeFails refuses every supersede record, as a store down for the
// write would.
type supersedeFails struct{ store.Store }

func (supersedeFails) SupersedeTokens(context.Context, store.TokenKey, time.Time) error {
	return store.ErrUnavailable
}

// The local copy of a supersede is the fallback for a store write that
// failed, so it is kept SupersededFor from when it was recorded, as the
// store's is, not from the deleted token's MintedAt: a token minted longer
// ago than that (a long token_ttl) still has its replay minted afresh.
func TestALocalSupersedeIsKeptFromWhenItWasRecorded(t *testing.T) {
	f := newFixture(t, 8)
	ctx := context.Background()
	f.b.Store = supersedeFails{f.st}
	minted := f.b.Now().Add(-store.SupersededFor - time.Hour)
	f.b.supersede(ctx, aliceOnNX1, minted)
	f.advance(supersedePruneEvery + time.Second)
	f.b.supersede(ctx, aliceOnCore, f.b.Now()) // a later supersede prunes the copy
	at, err := f.b.supersededAt(ctx, aliceOnNX1)
	if err != nil {
		t.Fatal(err)
	}
	if !at.Equal(minted) {
		t.Fatalf("the local supersede reads %v; want %v, recorded %v ago", at, minted, supersedePruneEvery+time.Second)
	}
	// It goes SupersededFor after it was recorded.
	f.advance(store.SupersededFor)
	f.b.supersede(ctx, aliceOnCore, f.b.Now())
	if at, _ := f.b.supersededAt(ctx, aliceOnNX1); !at.IsZero() {
		t.Fatalf("the local supersede outlived SupersededFor: %v", at)
	}
}

// injectingStore runs inject once, after the first of the token pass's two
// reads of key k (TokenIDs, Candidates), whichever comes first: between them.
// A read inject makes itself does not fire it again.
type injectingStore struct {
	store.Store
	k      store.TokenKey
	fired  atomic.Bool
	inject func()
}

func (s *injectingStore) TokenIDs(ctx context.Context, k store.TokenKey) ([]string, error) {
	ids, err := s.Store.TokenIDs(ctx, k)
	if k == s.k && s.fired.CompareAndSwap(false, true) {
		s.inject()
	}
	return ids, err
}

func (s *injectingStore) Candidates(ctx context.Context, k store.TokenKey) ([]store.Token, error) {
	toks, err := s.Store.Candidates(ctx, k)
	if k == s.k && s.fired.CompareAndSwap(false, true) {
		s.inject()
	}
	return toks, err
}

// R-I4: the IDs are read before the tokens, so a mint landing between the
// two reads is judged with the rest, and kept, never deleted unjudged.
func TestAMintBetweenTheTwoReadsIsJudged(t *testing.T) {
	f := newFixture(t, 8)
	ctx := context.Background()
	start := f.now
	priors := f.reload(t, edit(t, aliceGrant, noReload))
	old, cur, swap := priors[0].Policy, f.b.Policy.Load(), f.now
	f.advance(time.Second)
	fresh := f.mintLogin(t, "nx1")
	toks, _ := f.st.Candidates(ctx, aliceOnNX1)
	if len(toks) != 1 || f.st.DeleteToken(ctx, aliceOnNX1, toks[0].ID) != nil {
		t.Fatal("the fresh token to hold back")
	}
	f.b.Store = &injectingStore{Store: f.st, k: aliceOnNX1, inject: func() {
		if _, err := f.st.PutToken(ctx, aliceOnNX1, toks[0]); err != nil {
			t.Error(err)
		}
	}}
	if _, err := f.b.Refresh(ctx, settlePriors(old, start, swap, cur)); err != nil {
		t.Fatal(err)
	}
	if !holds(t, f.st, aliceOnNX1, fresh) {
		t.Fatal("a mint between the ID read and the token read was deleted unjudged")
	}
}

// deleteFails fails every DeleteToken with the store down.
type deleteFails struct{ store.Store }

func (deleteFails) DeleteToken(context.Context, store.TokenKey, string) error {
	return store.ErrUnavailable
}

// I3: the supersede is recorded before the first delete, at the latest
// MintedAt among the tokens deleted. A pass the store stops part-way has
// recorded it: a replay of the deleted token's mint is minted afresh, and a
// replay of the kept token, minted after it, still replays.
func TestAPassStoppedAfterItsSupersedeRecordsIt(t *testing.T) {
	f := newFixture(t, 8)
	bg := context.Background()
	body := `{"devices":["nx1"]}`
	start := f.now
	gone := decodeMint(t, f.post(bg, f.state(f.alice), body, "idem-old")).Results[0]
	f.advance(time.Second)
	priors := f.reload(t, edit(t, aliceGrant, noReload))
	old, cur, swap := priors[0].Policy, f.b.Policy.Load(), f.now
	f.advance(time.Second)
	kept := decodeMint(t, f.post(bg, f.state(f.alice), body, "idem-new")).Results[0]
	f.advance(time.Second)
	f.b.Store = deleteFails{f.st}
	if _, err := f.b.Refresh(bg, settlePriors(old, start, swap, cur)); !errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("a pass whose deletes fail: %v", err)
	}
	f.b.Store = f.st
	f.advance(time.Second)
	if again := decodeMint(t, f.post(bg, f.state(f.alice), body, "idem-old")).Results[0]; again.Login == gone.Login {
		t.Fatal("a replay of the superseded token's mint was answered with it")
	}
	if again := decodeMint(t, f.post(bg, f.state(f.alice), body, "idem-new")).Results[0]; again.Login != kept.Login {
		t.Fatal("a replay of the kept token's mint was minted afresh")
	}
}

// spentOnDelete has every DeleteToken find its token spent: removed, then
// ErrNotFound, as a redemption between the read and the delete leaves it.
type spentOnDelete struct{ store.Store }

func (s spentOnDelete) DeleteToken(ctx context.Context, k store.TokenKey, id string) error {
	if err := s.Store.DeleteToken(ctx, k, id); err != nil {
		return err
	}
	return s.Store.DeleteToken(ctx, k, id)
}

// A token spent between the read and its delete does not stop the pass.
func TestATokenSpentMeanwhileDoesNotStopThePass(t *testing.T) {
	f := newFixture(t, 8)
	f.mintLogin(t, "nx1")
	f.mintLogin(t, "nx1")
	priors := f.reload(t, edit(t, aliceGrant, noReload))
	f.b.Store = spentOnDelete{f.st}
	rep, err := f.b.Refresh(context.Background(), priors)
	if err != nil || rep.TokenKeys != 1 {
		t.Fatalf("a pass whose tokens were spent meanwhile: %d key(s), %v", rep.TokenKeys, err)
	}
	if toks, _ := f.st.Candidates(context.Background(), aliceOnNX1); len(toks) != 0 {
		t.Fatalf("%d token(s) left", len(toks))
	}
}

// A policy swapped in while a pass judges a key stops the pass before it
// deletes there: a token the new policy minted is not judged by the one it
// replaced, and the swap's own pass judges the rest.
func TestASwapDuringThePassDeletesNothingTheNewPolicyMinted(t *testing.T) {
	f := newFixture(t, 8)
	ctx := context.Background()
	start := f.now
	priors := f.reload(t, edit(t, aliceGrant, noReload))
	old, cur, swap := priors[0].Policy, f.b.Policy.Load(), f.now
	f.advance(time.Second)
	// Another edit, here a comment: another bundle, so a token it mints is
	// not one the replaced policy would mint.
	next, err := policy.Parse([]byte(edit(t, aliceGrant, noReload)+"# reviewed\n"),
		policy.Env{Devices: []admission.Device{f.devices["leaf1"], f.devices["nx1"], f.devices["bare"]}, Now: f.b.Now()})
	if err != nil {
		t.Fatal(err)
	}
	var minted string
	f.b.Store = &injectingStore{Store: f.st, k: aliceOnNX1, inject: func() {
		f.b.Policy.Swap(next)
		minted = f.mintLogin(t, "nx1")
	}}
	_, err = f.b.Refresh(ctx, settlePriors(old, start, swap, cur))
	if !holds(t, f.st, aliceOnNX1, minted) {
		t.Fatal("the pass judged a token the new policy minted against the policy it replaced")
	}
	if !errors.Is(err, store.ErrConflict) {
		t.Fatalf("a pass across a swap: %v, want it left for the next pass", err)
	}
}

// countingStore counts the tokens written with each blob hash.
type countingStore struct {
	store.Store
	mu     sync.Mutex
	byHash map[string][]string
}

func (s *countingStore) PutToken(ctx context.Context, k store.TokenKey, tk store.Token) (int, error) {
	n, err := s.Store.PutToken(ctx, k, tk)
	if err == nil {
		s.mu.Lock()
		s.byHash[tk.BlobHash] = append(s.byHash[tk.BlobHash], tk.ID)
		s.mu.Unlock()
	}
	return n, err
}

// Mints under the policy in force and a late replica's under the replaced
// one race the settle passes into one key. Every token the policy in force
// minted survives every pass, and once the late replica stops, one more pass
// leaves none of its tokens. Run under -race.
func TestMintsRacingTheSettlePassKeepWhatThePolicyInForceMints(t *testing.T) {
	f := newFixture(t, 1000)
	ctx := context.Background()
	st := &countingStore{Store: f.st, byHash: map[string][]string{}}
	f.b.Store = st
	start := f.now
	priors := f.reload(t, edit(t, aliceGrant, noReload))
	old, cur, swap := priors[0].Policy, f.b.Policy.Load(), f.now
	f.b.Minter = token.NewMinter(st, f.b.Log, rand.Reader, token.TagKey([]byte("k")), f.b.Now, 1000)
	late := &Broker{Policy: policy.NewLive(old), Store: st, Log: f.b.Log, Now: f.b.Now,
		Minter:  token.NewMinter(st, decision.NewJSONLines(&lockedBuffer{}), rand.Reader, token.TagKey([]byte("late")), f.b.Now, 1000),
		Metrics: metrics.New(prometheus.NewRegistry()), MaxSessionAge: f.b.MaxSessionAge, BatchMax: 4,
		Sessions: f.b.Sessions, ContextIdleTTL: time.Hour}
	var wg sync.WaitGroup
	for _, b := range []*Broker{f.b, late} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 40 {
				r := postTo(f, b, `{"devices":["nx1"]}`, "")
				if r.Code != 200 {
					t.Errorf("a racing mint: %d", r.Code)
					return
				}
			}
		}()
	}
	for range 20 {
		if _, err := f.b.Refresh(ctx, settlePriors(old, start, swap, cur)); err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
	if _, err := f.b.Refresh(ctx, settlePriors(old, start, swap, cur)); err != nil {
		t.Fatal(err)
	}
	ids, err := f.st.TokenIDs(ctx, aliceOnNX1)
	if err != nil {
		t.Fatal(err)
	}
	left := map[string]bool{}
	for _, id := range ids {
		left[id] = true
	}
	ans, _ := mintedBy(cur, policy.MemberOf(alice), f.devices["nx1"], f.now, f.b.MaxSessionAge)
	st.mu.Lock()
	defer st.mu.Unlock()
	if len(st.byHash[ans.hash]) != 40 {
		t.Fatalf("%d tokens minted under the policy in force, want 40", len(st.byHash[ans.hash]))
	}
	for _, id := range st.byHash[ans.hash] {
		if !left[id] {
			t.Fatal("a settle pass deleted a token the policy in force minted")
		}
	}
	if len(ids) != 40 {
		t.Fatalf("%d tokens left, want only the 40 the policy in force minted", len(ids))
	}
}

// settleFrom runs the settle pass of a reload from the policy o describes to
// the one in force: o's answer differs from it, so alice's keys are judged
// token by token.
func (f *mfaFixture) settleFrom(t *testing.T, o mfaOpts) RefreshReport {
	t.Helper()
	old, err := policy.Parse([]byte(mfaPolicy(o)), policy.Env{Devices: f.inventory(), Now: f.b.Now()})
	if err != nil {
		t.Fatal(err)
	}
	swap := f.b.Now().Add(-time.Minute)
	rep, err := f.b.Refresh(context.Background(), settlePriors(old, swap.Add(-time.Minute), swap, f.b.Policy.Load()))
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

// mintFresh proves a touch for alice's challenge on device, waits after,
// and mints naming the challenge.
func (f *mfaFixture) mintFresh(t *testing.T, who *mfaActor, device string, after time.Duration) {
	t.Helper()
	ch := f.ask(t, who, device)
	if code := f.proveTouch(t, who, ch); code != 200 {
		t.Fatalf("the touch: %d", code)
	}
	f.advance(after)
	if it := f.mint(t, who, device, ch).Results[0]; it.Verdict != "permit" {
		t.Fatalf("the mint naming the challenge: verdict %q, reason %q", it.Verdict, it.Reason)
	}
}

var aliceOnCore = store.TokenKey{NAS: "core-sw01", Username: "alice"}

// R-C1: a fresh challenge covers its mint once, whatever reuse_for is, so a
// token minted on one 30s after the touch is kept under reuse_for 0s and
// under 10s alike. Only a reused proof is held to its age.
func TestAFreshProofKeepsItsTokenWhateverReuseFor(t *testing.T) {
	for name, o := range map[string]mfaOpt{
		"reuse_for 0s":  withReuseFor(0),
		"reuse_for 10s": func(o *mfaOpts) { o.reuseShort = true },
	} {
		t.Run(name, func(t *testing.T) {
			f := newMFAFixture(t, o)
			f.mintFresh(t, f.alice, "core-sw01", 30*time.Second)
			prior := f.opts
			prior.noRequirement = true
			if rep := f.settleFrom(t, prior); f.unspent(t, "core-sw01", "alice") != 1 || rep.TokensKept != 1 {
				t.Fatalf("a token on a fresh proof was deleted: %d kept", rep.TokensKept)
			}
		})
	}
}

// F-I1: the same, through the encodings a token is stored in: sealed by
// crypt over memory, etcd's plaintext record, and sealed over etcd, which is
// what port49d runs.
func TestAFreshProofSurvivesEveryEncoding(t *testing.T) {
	var k crypt.Key
	k.ID = "v1"
	copy(k.Bytes[:], "broker-test-token-key-32-bytes-a")
	onEtcd := func(t *testing.T, f *mfaFixture) *etcd.Store {
		srv := etcdtest.Start(t, etcdtest.Options{})
		es, err := etcd.Open(etcd.Config{Endpoints: []string{srv.Endpoint}, Prefix: "/port49-settle/", Now: f.b.Now})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { es.Close() })
		return es
	}
	for name, on := range map[string]func(*testing.T, *mfaFixture) store.Store{
		"sealed over memory": func(t *testing.T, f *mfaFixture) store.Store {
			return crypt.Wrap(memory.New(f.b.Now), crypt.Keys{Current: k}, nil)
		},
		"etcd": func(t *testing.T, f *mfaFixture) store.Store { return onEtcd(t, f) },
		"sealed over etcd": func(t *testing.T, f *mfaFixture) store.Store {
			return crypt.Wrap(onEtcd(t, f), crypt.Keys{Current: k}, nil)
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newMFAFixture(t, withReuseFor(0))
			f.mintFresh(t, f.alice, "core-sw01", 30*time.Second)
			toks, err := f.st.Candidates(context.Background(), aliceOnCore)
			if err != nil || len(toks) != 1 {
				t.Fatalf("the minted token: %d, %v", len(toks), err)
			}
			st := on(t, f)
			if _, err := st.PutToken(context.Background(), aliceOnCore, toks[0]); err != nil {
				t.Fatal(err)
			}
			f.b.Store = st
			prior := f.opts
			prior.noRequirement = true
			f.settleFrom(t, prior)
			if got, _ := st.Candidates(context.Background(), aliceOnCore); len(got) != 1 {
				t.Fatal("a token on a fresh proof was deleted after a round trip through the store")
			}
		})
	}
}

// The per-login proof a token carries is judged against the requirement in
// force: its method, a machine's touch alone, and a reused proof's age at the
// mint. A proof not recorded fresh is a reused one: a token an older build
// minted, with no fresh field, is held to reuse_for (F-I1's polarity).
func TestATokensOwnProofIsJudged(t *testing.T) {
	for _, c := range []struct {
		name   string
		opts   []mfaOpt
		who    func(*mfaFixture) (*mfaActor, store.TokenKey)
		change func(*store.Token)
		kept   bool
	}{
		{"a method the requirement does not accept", []mfaOpt{withTouchOnlyCore()}, nil,
			func(tk *store.Token) { tk.Credential.MFAMethod = "idp_mfa" }, false},
		{"no proof", nil, nil, func(tk *store.Token) { tk.Credential.MFAMethod = "" }, false},
		{"a reused proof older than reuse_for", nil, nil, func(tk *store.Token) {
			tk.Credential.MFAFresh, tk.Credential.MFAAt = false, tk.MintedAt.Add(-16*time.Minute)
		}, false},
		{"a reused proof within reuse_for", nil, nil, func(tk *store.Token) {
			tk.Credential.MFAFresh, tk.Credential.MFAAt = false, tk.MintedAt.Add(-14*time.Minute)
		}, true},
		{"a machine's proof that is not a touch", []mfaOpt{withAppliesToMachines()},
			func(f *mfaFixture) (*mfaActor, store.TokenKey) {
				return f.oxidized, store.TokenKey{NAS: "core-sw01", Username: "svc-oxidized"}
			}, func(tk *store.Token) { tk.Credential.MFAMethod = "idp_mfa" }, false},
		{"a machine's touch", []mfaOpt{withAppliesToMachines()},
			func(f *mfaFixture) (*mfaActor, store.TokenKey) {
				return f.oxidized, store.TokenKey{NAS: "core-sw01", Username: "svc-oxidized"}
			}, func(*store.Token) {}, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newMFAFixture(t, c.opts...)
			who, k := f.alice, aliceOnCore
			if c.who != nil {
				who, k = c.who(f)
			}
			f.mintFresh(t, who, "core-sw01", 0)
			rewriteToken(t, f.st, k, c.change)
			prior := f.opts
			prior.noRequirement = true
			f.settleFrom(t, prior)
			if kept := f.unspent(t, k.NAS, k.Username) == 1; kept != c.kept {
				t.Fatalf("kept %v, want %v", kept, c.kept)
			}
		})
	}
}
