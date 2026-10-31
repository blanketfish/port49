package broker

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/rhwendt/port49/internal/store"
)

// Two principals under one subject share its username, so their tokens
// and their context share (device, username) keys: the shape a self
// revocation must not reach across.
const sharedPolicy = `
scopes:
  - {name: all_devices, match: {}}
roles:
  - {name: network_admin, privilege: admin, permit: ["**"]}
subjects:
  - {name: netops, identity: ["user:alice@example.com", "user:alice2@example.com"], username: alice, token_ttl: 60s}
  - {name: oncall, identity: ["user:bob@example.com"], username: bob, token_ttl: 60s, api: [revoke_others]}
grants:
  - {subject: netops, scope: all_devices, roles: [network_admin], max_privilege: admin}
`

const alice2 = "user:alice2@example.com"

// mintFor mints one token on device for the certificate's principal and
// fails the test unless it is a permit.
func (f *fixture) mintFor(t *testing.T, email, device string) {
	t.Helper()
	c := f.client(t, email, f.now.Add(time.Hour))
	r := decodeMint(t, f.post(context.Background(), f.state(c), `{"devices":["`+device+`"]}`, ""))
	if len(r.Results) != 1 || r.Results[0].Verdict != "permit" {
		t.Fatalf("mint for %s on %s: %v", email, device, r.Results)
	}
}

func tokensOf(t *testing.T, f *fixture, k store.TokenKey) map[string]int {
	t.Helper()
	toks, err := f.st.Candidates(context.Background(), k)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]int{}
	for _, tk := range toks {
		out[tk.Principal]++
	}
	return out
}

// RevokeOwn deletes the caller's own tokens and marks the caller's own
// contexts, and nothing of another principal's under the same key; it
// leaves no mark, so the caller mints again at once (spec §5.1.4;
// decision 34).
func TestRevokeOwnTakesOnlyTheCallersOwn(t *testing.T) {
	f := newFixtureWithPolicy(t, 8, sharedPolicy)
	ctx := context.Background()
	f.mintFor(t, "alice@example.com", "leaf1")
	f.mintFor(t, "alice2@example.com", "leaf1")
	f.mintFor(t, "alice@example.com", "nx1")
	f.liveContext(t, "leaf1", "alice", alice2, "")       // alice2's context on the shared key
	f.liveContext(t, "nx1", "alice", alicePrincipal, "") // alice's own
	if err := f.st.IndexContext(ctx, alicePrincipal, "", "", store.ContextRef{NAS: "leaf1", Username: "alice"},
		time.Hour); err != nil { // a stale entry: alice once held leaf1's context
		t.Fatal(err)
	}
	rep := f.b.RevokeOwn(ctx, alicePrincipal, nil, "api "+alicePrincipal)
	if rep.Err != nil || rep.By != ByOwn || rep.TokenKeys != 2 || len(rep.Contexts) != 1 ||
		rep.Contexts[0] != (store.ContextRef{NAS: "nx1", Username: "alice"}) {
		t.Fatalf("%+v", rep)
	}
	if got := tokensOf(t, f, store.TokenKey{NAS: "leaf1", Username: "alice"}); got[alicePrincipal] != 0 || got[alice2] != 1 {
		t.Fatalf("leaf1's tokens after: %v", got)
	}
	if c, _ := f.st.GetContext(ctx, store.ContextKey{NAS: "leaf1", Username: "alice"}); !c.RevokedAt.IsZero() {
		t.Fatal("alice2's context was marked by alice's self-revocation")
	}
	if c, _ := f.st.GetContext(ctx, store.ContextKey{NAS: "nx1", Username: "alice"}); c.RevokedAt.IsZero() {
		t.Fatal("alice's own context was not marked")
	}
	if _, err := f.st.GetRevocation(ctx, store.RevocationPrincipal, alicePrincipal); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a self-revocation left a mark: %v", err)
	}
	f.mintFor(t, "alice@example.com", "leaf1") // nothing stands against her
}

// With a key it reaches that key alone.
func TestRevokeOwnOnOneKey(t *testing.T) {
	f := newFixtureWithPolicy(t, 8, sharedPolicy)
	ctx := context.Background()
	f.mintFor(t, "alice@example.com", "leaf1")
	f.mintFor(t, "alice@example.com", "nx1")
	f.liveContext(t, "leaf1", "alice", alicePrincipal, "")
	f.liveContext(t, "nx1", "alice", alicePrincipal, "")
	k := store.TokenKey{NAS: "leaf1", Username: "alice"}
	rep := f.b.RevokeOwn(ctx, alicePrincipal, &k, "api "+alicePrincipal)
	if rep.TokenKeys != 1 || len(rep.Contexts) != 1 || rep.Key != k {
		t.Fatalf("%+v", rep)
	}
	if got := tokensOf(t, f, store.TokenKey{NAS: "nx1", Username: "alice"}); got[alicePrincipal] != 1 {
		t.Fatalf("nx1's token was taken: %v", got)
	}
	if c, _ := f.st.GetContext(ctx, store.ContextKey{NAS: "nx1", Username: "alice"}); !c.RevokedAt.IsZero() {
		t.Fatal("nx1's context was marked")
	}
}

// replacingStore lets one GetContext of key read what was there, then puts
// another principal's context over it before the caller's write: a login
// that replaced the context between the read and the mark.
type replacingStore struct {
	store.Store
	key  store.ContextKey
	with store.Context
	once sync.Once
}

func (s *replacingStore) GetContext(ctx context.Context, k store.ContextKey) (store.Context, error) {
	c, err := s.Store.GetContext(ctx, k)
	if k == s.key {
		s.once.Do(func() { _ = s.Store.PutContext(ctx, k, s.with, time.Hour) })
	}
	return c, err
}

// A self-revocation never marks a context another principal's login
// replaced after it was read: the mark is a compare-and-set on the policy
// revision read, and the read again finds it is not the caller's (Review
// Focus 2; decision 34).
func TestRevokeOwnNeverMarksAContextAnotherLoginReplaced(t *testing.T) {
	f := newFixtureWithPolicy(t, 8, sharedPolicy)
	ctx := context.Background()
	f.liveContext(t, "leaf1", "alice", alicePrincipal, "")
	k := store.ContextKey{NAS: "leaf1", Username: "alice"}
	f.b.Store = &replacingStore{Store: f.st, key: k,
		with: store.Context{CtxID: "ctx_alice2", Principal: alice2, Username: "alice", PrivLvl: 1, AuthTime: f.now}}
	rep := f.b.RevokeOwn(ctx, alicePrincipal, nil, "api "+alicePrincipal)
	if len(rep.Contexts) != 0 {
		t.Fatalf("reported a context marked: %+v", rep)
	}
	c, err := f.st.GetContext(ctx, k)
	if err != nil || c.Principal != alice2 || !c.RevokedAt.IsZero() {
		t.Fatalf("alice2's replacing context: %+v %v", c, err)
	}
}

// RevokeKey, revoke_others' key form, takes everything under the key
// whoever's it is, with the owner's receipts, and leaves no mark.
func TestRevokeKeyTakesEverythingUnderTheKey(t *testing.T) {
	f := newFixtureWithPolicy(t, 8, sharedPolicy)
	ctx := context.Background()
	f.mintFor(t, "alice@example.com", "leaf1")
	f.mintFor(t, "alice2@example.com", "leaf1")
	f.liveContext(t, "leaf1", "alice", alice2, "")
	k := store.TokenKey{NAS: "leaf1", Username: "alice"}
	rep := f.b.RevokeKey(ctx, k, "api user:bob@example.com")
	if rep.Err != nil || rep.By != ByKey || rep.TokenKeys != 1 || len(rep.Contexts) != 1 || rep.Request.Principal != alice2 {
		t.Fatalf("%+v", rep)
	}
	if got := tokensOf(t, f, k); len(got) != 0 {
		t.Fatalf("tokens left: %v", got)
	}
	if c, _ := f.st.GetContext(ctx, store.ContextKey{NAS: "leaf1", Username: "alice"}); c.RevokedAt.IsZero() {
		t.Fatal("the context was not marked")
	}
	if rs, _ := f.st.ListRevocations(ctx); len(rs) != 0 {
		t.Fatalf("a key revocation left a mark: %v", rs)
	}
}

// receiptsStore notes whose receipts are deleted.
type receiptsStore struct {
	*replacingStore
	deleted []string
}

func (s *receiptsStore) DeleteReceiptsByPrincipal(ctx context.Context, principal string) (int, error) {
	s.deleted = append(s.deleted, principal)
	return s.Store.DeleteReceiptsByPrincipal(ctx, principal)
}

// A login that replaced the context between RevokeKey's two passes leaves
// both owners' receipts deleted, not the last one's alone.
func TestRevokeKeyDeletesEveryOwnersReceipts(t *testing.T) {
	f := newFixtureWithPolicy(t, 8, sharedPolicy)
	f.liveContext(t, "leaf1", "alice", alice2, "")
	k := store.ContextKey{NAS: "leaf1", Username: "alice"}
	st := &receiptsStore{replacingStore: &replacingStore{Store: f.st, key: k,
		with: store.Context{CtxID: "ctx_alice", Principal: alicePrincipal, Username: "alice", PrivLvl: 1, AuthTime: f.now}}}
	f.b.Store = st
	rep := f.b.RevokeKey(context.Background(), store.TokenKey{NAS: "leaf1", Username: "alice"}, "api user:bob@example.com")
	if rep.Err != nil || len(st.deleted) != 2 || st.deleted[0] != alice2 || st.deleted[1] != alicePrincipal {
		t.Fatalf("%+v; receipts deleted for %v", rep, st.deleted)
	}
}

// Each writes one revoke record (spec §5.7): by self or key, the origin,
// the key, no saved; and counts port49_revocations_total by self or key. A
// standing mark's record still says saved.
func TestSelfAndKeyRevocationsAreRecorded(t *testing.T) {
	f := newFixtureWithPolicy(t, 8, sharedPolicy)
	ctx := context.Background()
	f.liveContext(t, "leaf1", "alice", alicePrincipal, "")
	k := store.TokenKey{NAS: "leaf1", Username: "alice"}
	f.b.RevokeOwn(ctx, alicePrincipal, &k, "api "+alicePrincipal)
	f.b.RevokeKey(ctx, k, "api user:bob@example.com")
	if _, err := f.b.Revoke(ctx, RevokeRequest{Principal: alice2, Origin: "offline uid 0"}); err != nil {
		t.Fatal(err)
	}
	recs := eventsOf(f.records(t), "revoke")
	if len(recs) != 3 {
		t.Fatalf("%v", recs)
	}
	for i, by := range []string{"self", "key"} {
		rv := recs[i]["revocation"].(map[string]any)
		_, saved := rv["saved"]
		if recs[i]["verdict"] != "deny" || recs[i]["reason"] != "credential_revoked" || rv["by"] != by ||
			rv["device"] != "leaf1" || rv["username"] != "alice" || saved {
			t.Fatalf("%s: %v", by, recs[i])
		}
	}
	// This broker keeps no revocations_file, so a standing mark's record has no saved.
	if rv := recs[2]["revocation"].(map[string]any); rv["by"] != "principal" || rv["saved"] != nil {
		t.Fatalf("a standing mark's record: %v", recs[2])
	}
	if recs[0]["principal"] != alicePrincipal || recs[0]["revocation"].(map[string]any)["origin"] != "api "+alicePrincipal {
		t.Fatalf("self: %v", recs[0])
	}
	for _, by := range []string{"self", "key"} {
		if n := testutil.ToFloat64(f.b.Metrics.Revocations.WithLabelValues(by, "applied")); n != 1 {
			t.Fatalf("port49_revocations_total{by=%s} = %v", by, n)
		}
	}
}

// What port49 revoke prints for each.
func TestSelfAndKeyRevocationsSayWhatTheyDid(t *testing.T) {
	at := time.Date(2026, 10, 2, 3, 12, 9, 0, time.UTC)
	own := RevokeReport{By: ByOwn, Request: RevokeRequest{Principal: alicePrincipal}, Mark: store.Revocation{At: at},
		Contexts:  []store.ContextRef{{NAS: "leaf1", Username: "alice"}, {NAS: "srx1", Username: "alice"}},
		Unreached: []store.ContextRef{{NAS: "srx1", Username: "alice"}}, TokenKeys: 3}
	want := "ended user:alice@example.com's sessions everywhere at 2026-10-02T03:12:09Z: 2 live context(s) marked, " +
		"the unspent tokens under 3 (device, username) key(s) deleted; nothing stands against " +
		"user:alice@example.com, so a new `port49 token` and login work at once\n" +
		"your next login on a device re-admits every session open there under your username: if anyone else used " +
		"your token, close their session on the device (or ask an operator to revoke your principal) before you " +
		"log in there again\n" +
		"not reached, on a platform that never asks port49 about a command (close these on the device): srx1 (alice)"
	if got := own.Text(); got != want {
		t.Fatalf("self:\n%s\nwant\n%s", got, want)
	}
	key := RevokeReport{By: ByKey, Key: store.TokenKey{NAS: "leaf1", Username: "alice"},
		Request: RevokeRequest{Principal: alice2}, Mark: store.Revocation{At: at}, TokenKeys: 1,
		Contexts: []store.ContextRef{{NAS: "leaf1", Username: "alice"}}}
	if got := key.Text(); !strings.HasPrefix(got, "ended the session on leaf1 (alice), user:alice2@example.com's, at "+
		"2026-10-02T03:12:09Z: 1 live context(s) marked, the unspent tokens under 1 key(s) deleted; no revocation "+
		"stands, so its owner can mint and log in again (to stop that, revoke the principal)\n"+
		"the owner's next login on leaf1 re-admits any session still open on it under alice; close it on the device") {
		t.Fatalf("key: %s", got)
	}
	// A standing mark made over HTTP says where it is lifted (decision 34).
	mark := RevokeReport{By: ByPrincipal, Request: RevokeRequest{Principal: alice2},
		Mark: store.Revocation{Kind: store.RevocationPrincipal, At: at}, LiftNote: "the lift is made on X"}
	if got := mark.Text(); !strings.HasSuffix(got, "\nthe lift is made on X") {
		t.Fatalf("mark: %s", got)
	}
}

// A self-revocation limited to one key still deletes the caller's receipts
// on every device: the store holds no finer cut, and a receipt that
// survived would replay a PASS onto a context the caller's next login
// re-admits (spec §5.1.4; pre-flight M9).
func TestRevokeOwnOnOneKeyDeletesTheReceiptsEverywhere(t *testing.T) {
	f := newFixtureWithPolicy(t, 8, sharedPolicy)
	ctx := context.Background()
	f.mintFor(t, "alice@example.com", "nx1")
	nx := store.TokenKey{NAS: "nx1", Username: "alice"}
	toks, err := f.st.Candidates(ctx, nx)
	if err != nil || len(toks) != 1 {
		t.Fatalf("%d tokens: %v", len(toks), err)
	}
	rk := store.ReceiptKey{NAS: "nx1", Username: "alice", Kind: store.KindLogin, CredentialSHA256: [32]byte{1}}
	if err := f.st.RedeemAndReceipt(ctx, nx, toks[0].ID, store.ReceiptWrite{Key: rk, Principal: alicePrincipal,
		IndexTTL: time.Hour, Receipt: store.Receipt{FirstRedeemedAt: f.now,
			IdleExpiresAt: f.now.Add(15 * time.Minute), RetainUntil: f.now.Add(3 * time.Hour)}}); err != nil {
		t.Fatal(err)
	}
	leaf := store.TokenKey{NAS: "leaf1", Username: "alice"}
	if rep := f.b.RevokeOwn(ctx, alicePrincipal, &leaf, "api "+alicePrincipal); rep.Err != nil {
		t.Fatalf("%+v", rep)
	}
	if _, err := f.st.GetReceipt(ctx, rk); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the receipt on nx1 survived a self-revocation on leaf1: %v", err)
	}
}

// RevokeKey on a key with nothing under it says so, rather than that it
// ended a session: a mistyped device reads as a miss, not a success.
func TestRevokeKeyOnNothingSaysNothingWasFound(t *testing.T) {
	f := newFixtureWithPolicy(t, 8, sharedPolicy)
	rep := f.b.RevokeKey(context.Background(), store.TokenKey{NAS: "leaf9", Username: "alice"}, "api user:bob@example.com")
	if want := "nothing was found under leaf9 (alice): check the device and username as the log names them"; rep.Text() != want {
		t.Fatalf("got\n%s\nwant\n%s", rep.Text(), want)
	}
}

// faultStore fails the context reads and writes of one key as told.
type faultStore struct {
	store.Store
	key       store.ContextKey
	getErr    error
	policyErr error
	policies  int
}

func (s *faultStore) GetContext(ctx context.Context, k store.ContextKey) (store.Context, error) {
	if k == s.key && s.getErr != nil {
		return store.Context{}, s.getErr
	}
	return s.Store.GetContext(ctx, k)
}

func (s *faultStore) SetContextPolicy(ctx context.Context, k store.ContextKey, rev uint64, p store.ContextPolicy) error {
	if k == s.key && s.policyErr != nil {
		s.policies++
		return s.policyErr
	}
	return s.Store.SetContextPolicy(ctx, k, rev, p)
}

// A context that will not open is left unmarked, since whose it is cannot
// be read, and the run is partial.
func TestRevokeOwnLeavesAnUnreadableContext(t *testing.T) {
	f := newFixtureWithPolicy(t, 8, sharedPolicy)
	ctx := context.Background()
	f.liveContext(t, "leaf1", "alice", alicePrincipal, "")
	k := store.ContextKey{NAS: "leaf1", Username: "alice"}
	f.b.Store = &faultStore{Store: f.st, key: k, getErr: &store.UnreadableContextError{Err: errors.New("sealed under a retired key")}}
	only := store.TokenKey{NAS: "leaf1", Username: "alice"}
	rep := f.b.RevokeOwn(ctx, alicePrincipal, &only, "api "+alicePrincipal)
	if rep.Err == nil || len(rep.Contexts) != 0 {
		t.Fatalf("%+v", rep)
	}
	if c, _ := f.st.GetContext(ctx, k); !c.RevokedAt.IsZero() {
		t.Fatal("an unreadable context was marked")
	}
	if n := testutil.ToFloat64(f.b.Metrics.Revocations.WithLabelValues("self", "partial")); n != 1 {
		t.Fatalf("port49_revocations_total{by=self,outcome=partial} = %v", n)
	}
}

// A context whose compare-and-set loses every try is an error, and no mark.
func TestRevokeOwnContextGivesUpAfterItsTries(t *testing.T) {
	f := newFixtureWithPolicy(t, 8, sharedPolicy)
	ctx := context.Background()
	f.liveContext(t, "leaf1", "alice", alicePrincipal, "")
	k := store.ContextKey{NAS: "leaf1", Username: "alice"}
	st := &faultStore{Store: f.st, key: k, policyErr: store.ErrConflict}
	f.b.Store = st
	marked, err := f.b.revokeOwnContext(ctx, alicePrincipal, store.ContextRef{NAS: "leaf1", Username: "alice"}, f.now)
	if marked || err == nil || st.policies != ownRevokeTries {
		t.Fatalf("marked %v, err %v, after %d tries", marked, err, st.policies)
	}
	if c, _ := f.st.GetContext(ctx, k); !c.RevokedAt.IsZero() {
		t.Fatal("the context was marked")
	}
}

// keyReads counts the reads of one (device, username)'s tokens and context.
type keyReads struct {
	store.Store
	key   store.TokenKey
	reads *int
}

func (s keyReads) Candidates(ctx context.Context, k store.TokenKey) ([]store.Token, error) {
	if k == s.key {
		*s.reads++
	}
	return s.Store.Candidates(ctx, k)
}

func (s keyReads) GetContext(ctx context.Context, k store.ContextKey) (store.Context, error) {
	if k == (store.ContextKey{NAS: s.key.NAS, Username: s.key.Username}) {
		*s.reads++
	}
	return s.Store.GetContext(ctx, k)
}

// mine on a key the caller holds nothing under never reads that key's
// tokens or context, so what another principal holds there leaves them
// untouched and changes neither the answer nor the work done: no timing
// says whether anyone is logged in there (final review M1; design §17).
func TestMineOnAKeyReadsOnlyTheCallersOwn(t *testing.T) {
	k := store.TokenKey{NAS: "leaf1", Username: "alice"}
	// Both fixtures answer at one instant: each starts its clock at its own
	// second, and the answer's "at" would differ whenever the two straddled
	// a second boundary, which is not what this compares.
	at := time.Now().Truncate(time.Second)
	answer := func(occupied bool) (int, string, int) {
		f := newFixtureWithPolicy(t, 8, sharedPolicy)
		f.mu.Lock()
		f.now = at
		f.mu.Unlock()
		if occupied {
			f.mintFor(t, "alice2@example.com", "leaf1")
			f.liveContext(t, "leaf1", "alice", alice2, "")
		}
		reads := 0
		f.b.Store = keyReads{Store: f.st, key: k, reads: &reads}
		w := f.revokeAs(t, "alice@example.com", `{"mine":true,"device":"leaf1","username":"alice"}`)
		if occupied {
			if got := tokensOf(t, f, k); got[alice2] != 1 {
				t.Fatalf("alice2's tokens after alice's mine: %v", got)
			}
			if c, _ := f.st.GetContext(context.Background(), store.ContextKey{NAS: "leaf1", Username: "alice"}); !c.RevokedAt.IsZero() {
				t.Fatal("alice2's context was marked by alice's mine")
			}
		}
		return w.Code, w.Body.String(), reads
	}
	code0, body0, reads0 := answer(false)
	code1, body1, reads1 := answer(true)
	if code0 != 200 || code0 != code1 || body0 != body1 {
		t.Fatalf("the answer depends on another's: %d %s / %d %s", code0, body0, code1, body1)
	}
	if reads0 != 0 || reads1 != 0 {
		t.Fatalf("the key was read: %d with nobody there, %d with alice2 there", reads0, reads1)
	}
}

// A self or key revocation that did not finish says what it reached may
// not be sealed into its record yet, so a restart of port49d can let a
// store write bring it back, and tells the caller to run it again (final
// review 7d-2 I-1).
func TestAnIncompleteSelfOrKeyRevocationSaysToRunItAgain(t *testing.T) {
	for _, by := range []string{ByOwn, ByKey} {
		rep := RevokeReport{By: by, Key: store.TokenKey{NAS: "leaf1", Username: "alice"},
			Contexts: []store.ContextRef{{NAS: "leaf1", Username: "alice"}}, Err: errIncomplete}
		if text := rep.Text(); !strings.Contains(text, "may not be sealed into the store yet") ||
			!strings.Contains(text, "a restart of port49d") || !strings.Contains(text, "run the same command again") {
			t.Fatalf("%s:\n%s", by, text)
		}
	}
}
