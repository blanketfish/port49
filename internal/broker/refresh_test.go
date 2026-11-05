package broker

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/blanketfish/port49/internal/admission"
	"github.com/blanketfish/port49/internal/directory"
	"github.com/blanketfish/port49/internal/engine"
	"github.com/blanketfish/port49/internal/platform"
	"github.com/blanketfish/port49/internal/policy"
	"github.com/blanketfish/port49/internal/session"
	"github.com/blanketfish/port49/internal/store"
	"github.com/blanketfish/port49/internal/store/crypt"
)

const alice = "user:alice@example.com"

// reload parses body against the fixture's inventory and swaps it in, as
// port49d does, returning what the refresh compares against: the policy it
// replaced, read at the instant of the swap.
func (f *fixture) reload(t *testing.T, body string) []Prior {
	t.Helper()
	pol, err := policy.Parse([]byte(body), policy.Env{Devices: []admission.Device{f.devices["leaf1"],
		f.devices["nx1"], f.devices["bare"]}, Now: f.b.Now()})
	if err != nil {
		t.Fatal(err)
	}
	return []Prior{{Policy: f.b.Policy.Swap(pol), At: f.b.Now()}}
}

// edit is testPolicy with each old string replaced by its new one, in order.
func edit(t *testing.T, pairs ...string) string {
	t.Helper()
	body := testPolicy
	for i := 0; i < len(pairs); i += 2 {
		if !strings.Contains(body, pairs[i]) {
			t.Fatalf("testPolicy has no %q", pairs[i])
		}
		body = strings.Replace(body, pairs[i], pairs[i+1], 1)
	}
	return body
}

// Edits to testPolicy: alice's one grant, the role list's last line, and that
// line with a read_only role after it.
const (
	aliceGrant = "roles: [network_admin, no_reload], max_privilege: admin"
	roleList   = "  - {name: no_reload, deny: [\"reload **\"]}\n"
	readOnly   = roleList + "  - {name: read_only, privilege: readonly, permit: [show **]}\n"
)

// login mints principal a token for device through the broker and redeems it
// as the daemon does (package authen): the context takes the token's blob,
// ceiling and enable mechanism, at priv-lvl 15, and is indexed under the
// principal. It returns the context as written.
func (f *fixture) login(t testing.TB, principal, device, username string) store.Context {
	t.Helper()
	cert := f.alice
	if principal != alice {
		cert = f.client(t, strings.TrimPrefix(principal, "user:"), f.now.Add(24*time.Hour))
	}
	if it := decodeMint(t, f.post(context.Background(), f.state(cert), `{"devices":["`+device+`"]}`, "")).Results[0]; it.Verdict != "permit" {
		t.Fatalf("mint for %s on %s: verdict %q, reason %q", principal, device, it.Verdict, it.Reason)
	}
	ctx := context.Background()
	tk := store.TokenKey{NAS: device, Username: username}
	toks, err := f.st.Candidates(ctx, tk)
	if err != nil || len(toks) == 0 {
		t.Fatalf("no token to redeem: %v", err)
	}
	tok := toks[len(toks)-1]
	if err := f.st.DeleteTokens(ctx, tk); err != nil {
		t.Fatal(err)
	}
	k := store.ContextKey{NAS: device, Username: username}
	c := store.Context{CtxID: "ctx-" + device + "-" + username, Principal: principal, Username: username, PrivLvl: 15,
		BlobHash: tok.BlobHash, MaxPrivilege: tok.MaxPrivilege, Enable: tok.Enable, AuthTime: f.now,
		CreatedAt: f.now, RefreshedAt: f.now}
	if tok.MaxSessionAge > 0 { // the token's ceiling, as the daemon's redeem writes it
		c.SessionExpires = c.AuthTime.Add(tok.MaxSessionAge)
	}
	if err := f.st.PutContext(ctx, k, c, 12*time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := f.st.IndexContext(ctx, principal, "", "", store.ContextRef{NAS: device, Username: username}, 12*time.Hour); err != nil {
		t.Fatal(err)
	}
	got, _ := f.st.GetContext(ctx, k)
	return got
}

func (f *fixture) context(t testing.TB, device, username string) store.Context {
	t.Helper()
	c, err := f.st.GetContext(context.Background(), store.ContextKey{NAS: device, Username: username})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// decides compiles the blob a context names, from the store, and answers one
// command with it, as the daemon's authorizer does.
func (f *fixture) decides(t *testing.T, c store.Context, cmd ...string) bool {
	t.Helper()
	body, err := f.st.GetBlob(context.Background(), c.BlobHash)
	if err != nil {
		t.Fatalf("the context names a blob the store does not hold: %v", err)
	}
	b, err := engine.Decode(c.BlobHash, body)
	if err != nil {
		t.Fatal(err)
	}
	p, err := engine.Compile(b)
	if err != nil {
		t.Fatal(err)
	}
	raw := []string{"service=shell", "cmd=" + cmd[0]}
	for _, a := range cmd[1:] {
		raw = append(raw, "cmd-arg="+a)
	}
	return p.Command(append(raw, "cmd-arg=<cr>")).Permit
}

// The owner's goal (2026-09-24): a policy edit reaches a live session, and
// nobody is logged out. alice loses network_admin for read_only; her context
// keeps its ctx_id and its session, takes the new blob, and her next
// `configure` is denied while `show version` is still permitted.
func TestARefreshNarrowsALiveContextWithNoLogout(t *testing.T) {
	f := newFixture(t, 8)
	before := f.login(t, alice, "leaf1", "alice")
	if !f.decides(t, before, "configure") {
		t.Fatal("before the edit alice may configure")
	}
	priors := f.reload(t, edit(t, roleList, readOnly, aliceGrant, "roles: [read_only], max_privilege: admin"))
	f.log.Reset()
	rep, err := f.b.Refresh(context.Background(), priors)
	if err != nil {
		t.Fatal(err)
	}
	after := f.context(t, "leaf1", "alice")
	if after.CtxID != before.CtxID || !after.RevokedAt.IsZero() || after.BlobHash == before.BlobHash {
		t.Fatalf("the context must keep its ctx_id and take the new blob, unrevoked: %+v", after)
	}
	if f.decides(t, after, "configure") || !f.decides(t, after, "show", "version") {
		t.Fatal("after the edit alice's next configure is denied and show is permitted")
	}
	if rep.Updated != 1 || rep.Revoked != 0 {
		t.Fatalf("report: %+v", rep)
	}
	recs := eventsOf(f.records(t), "refresh")
	if len(recs) != 1 || recs[0]["verdict"] != "permit" || recs[0]["reason"] != "grants_matched" ||
		recs[0]["principal"] != alice {
		t.Fatalf("one refresh record, permit grants_matched: %v", recs)
	}
	if s, _ := recs[0]["session"].(map[string]any); s["ctx_id"] != before.CtxID {
		t.Fatalf("the record names the context's ctx_id: %v", recs[0])
	}
	if p, _ := recs[0]["policy"].(map[string]any); p["blob"] != after.BlobHash || p["bundle"] != f.b.Policy.Load().Bundle {
		t.Fatalf("the record names the blob and bundle written: %v", recs[0])
	}
	if n := testutil.ToFloat64(f.b.Metrics.ContextRefreshes.WithLabelValues("updated")); n != 1 {
		t.Fatalf("port49_context_refreshes_total{outcome=updated} = %v", n)
	}
	// The blob a context names is in the log, so a command decided against it
	// replays (spec §5.7).
	found := false
	for _, b := range f.blobRecords(t) {
		found = found || b.Hash == after.BlobHash
	}
	if !found {
		t.Fatal("the refreshed blob was never emitted")
	}
}

// A principal left with no grant on a device has that context revoked, not
// deleted: the next command is denied credential_revoked, distinguishable from
// a session port49 never saw (spec §5.6 row 2). The same edit supersedes her
// unspent token on nx1, which a redemption would otherwise turn into a fresh
// context carrying the grant the edit removed.
func TestARefreshRevokesAContextWhoseGrantIsGone(t *testing.T) {
	f := newFixture(t, 8)
	before := f.login(t, alice, "leaf1", "alice")
	decodeMint(t, f.post(context.Background(), f.state(f.alice), `{"devices":["nx1"]}`, ""))
	priors := f.reload(t, edit(t, "  - {subject: netops, scope: all_devices, "+aliceGrant+"}\n",
		"  - {subject: idle, scope: all_devices, roles: [network_admin]}\n"))
	f.log.Reset()
	rep, err := f.b.Refresh(context.Background(), priors)
	if err != nil {
		t.Fatal(err)
	}
	after := f.context(t, "leaf1", "alice")
	if !after.RevokedAt.Equal(f.now) || after.BlobHash != before.BlobHash || after.CtxID != before.CtxID {
		t.Fatalf("the context is marked revoked at the refresh, and nothing else changes: %+v", after)
	}
	if toks, _ := f.st.Candidates(context.Background(), store.TokenKey{NAS: "nx1", Username: "alice"}); len(toks) != 0 {
		t.Fatalf("alice's unspent nx1 token must be deleted: %d left", len(toks))
	}
	if rep.Revoked != 1 || rep.TokenKeys != 1 {
		t.Fatalf("report: %+v", rep)
	}
	recs := eventsOf(f.records(t), "refresh")
	if len(recs) != 1 || recs[0]["verdict"] != "deny" || recs[0]["reason"] != "no_grants_matched" {
		t.Fatalf("one refresh record, deny no_grants_matched: %v", recs)
	}
	if n := testutil.ToFloat64(f.b.Metrics.TokensSuperseded); n != 1 {
		t.Fatalf("port49_tokens_superseded_total = %v", n)
	}
}

// RefreshTokens is Refresh's token half alone (plan 7e, Ruling 6): the
// unspent token the withdrawn grant superseded is deleted, and the context
// on that grant is left as it was, for the runner's pass to judge.
func TestRefreshTokensJudgesTokensAndNoContext(t *testing.T) {
	f := newFixture(t, 8)
	before := f.login(t, alice, "leaf1", "alice")
	decodeMint(t, f.post(context.Background(), f.state(f.alice), `{"devices":["nx1"]}`, ""))
	priors := f.reload(t, edit(t, "  - {subject: netops, scope: all_devices, "+aliceGrant+"}\n",
		"  - {subject: idle, scope: all_devices, roles: [network_admin]}\n"))
	f.log.Reset()
	rep, err := f.b.RefreshTokens(context.Background(), priors)
	if err != nil {
		t.Fatal(err)
	}
	if toks, _ := f.st.Candidates(context.Background(), store.TokenKey{NAS: "nx1", Username: "alice"}); len(toks) != 0 {
		t.Fatalf("alice's unspent nx1 token must be deleted: %d left", len(toks))
	}
	after := f.context(t, "leaf1", "alice")
	if !after.RevokedAt.IsZero() || after.BlobHash != before.BlobHash || !after.RefreshedAt.Equal(before.RefreshedAt) {
		t.Fatalf("the context on the withdrawn grant is the runner's to judge: %+v", after)
	}
	if rep.TokenKeys != 1 || rep.Contexts() != 0 || rep.Updated+rep.Unchanged+rep.Revoked+rep.Quarantined+rep.Failed+
		rep.Unreached != 0 {
		t.Fatalf("report: %+v", rep)
	}
	if recs := eventsOf(f.records(t), "refresh"); len(recs) != 0 {
		t.Fatalf("no context judged, so no refresh record: %v", recs)
	}
}

// A lowered max_privilege reaches the next command: the held level comes down
// to the new ceiling (the join's rule, spec §5.3), and the record says from
// what to what, which is what explains the privilege_exceeded that follows.
func TestALoweredCeilingClampsTheHeldLevel(t *testing.T) {
	f := newFixture(t, 8)
	f.login(t, alice, "leaf1", "alice")
	priors := f.reload(t, edit(t, roleList, readOnly, aliceGrant, "roles: [read_only], max_privilege: readonly"))
	f.log.Reset()
	if _, err := f.b.Refresh(context.Background(), priors); err != nil {
		t.Fatal(err)
	}
	after := f.context(t, "leaf1", "alice")
	if after.PrivLvl != 1 || after.MaxPrivilege != 1 {
		t.Fatalf("the held level must come down to readonly's priv-lvl 1: %+v", after)
	}
	recs := eventsOf(f.records(t), "refresh")
	if len(recs) != 1 {
		t.Fatalf("one refresh record: %v", recs)
	}
	s, _ := recs[0]["session"].(map[string]any)
	clamp, _ := s["privilege_clamped"].(map[string]any)
	if clamp["from"] != 15.0 || clamp["to"] != 1.0 || s["privilege"] != 1.0 {
		t.Fatalf("the record says the level was clamped from 15 to 1: %v", recs[0])
	}
}

// A context on a device the new policy quarantines is left as it is: the
// daemon answers nothing from that device now, and the refresh that lifts the
// quarantine reaches it. The record says so. The edit lands alice at a level
// the policy declares and no built-in platform renders, which quarantines
// every device she reaches (spec §10), whatever the dialect table renders
// for the reserved levels.
func TestARefreshLeavesAQuarantinedDevicesContextAlone(t *testing.T) {
	f := newFixture(t, 8)
	before := f.login(t, alice, "leaf1", "alice")
	priors := f.reload(t, "privilege_levels: [{name: readonly}, {name: operator}, {name: unmapped}, {name: admin}]\n"+
		edit(t, "{name: network_admin, privilege: admin,", "{name: network_admin, privilege: unmapped,"))
	f.log.Reset()
	rep, err := f.b.Refresh(context.Background(), priors)
	if err != nil {
		t.Fatal(err)
	}
	if after := f.context(t, "leaf1", "alice"); after.BlobHash != before.BlobHash || !after.RevokedAt.IsZero() {
		t.Fatalf("a quarantined device's context is left as it was: %+v", after)
	}
	recs := eventsOf(f.records(t), "refresh")
	if rep.Quarantined != 1 || len(recs) != 1 || recs[0]["reason"] != "device_quarantined" {
		t.Fatalf("report %+v, records %v", rep, recs)
	}
}

// A withdrawn grant is revoked even on a device the new policy quarantines:
// the quarantine leaves a context on the answer it had, and a context whose
// principal has no grant has no answer to keep. This pins the order in
// resolution — no grant is answered before the quarantine is asked — which
// a reorder would silently turn into a withdrawn grant kept alive on every
// quarantined device (final review m9).
func TestAWithdrawnGrantOnAQuarantinedDeviceIsRevoked(t *testing.T) {
	f := newFixture(t, 8)
	f.login(t, alice, "leaf1", "alice")
	priors := f.reload(t, "privilege_levels: [{name: readonly}, {name: operator}, {name: unmapped}, {name: admin}]\n"+
		edit(t, "{name: network_admin, privilege: admin,", "{name: network_admin, privilege: unmapped,",
			"  - {subject: netops, scope: all_devices, "+aliceGrant+"}\n",
			"  - {subject: idle, scope: all_devices, roles: [network_admin]}\n"))
	if _, quarantined := f.b.Policy.Load().Quarantined("leaf1", f.now); !quarantined {
		t.Fatal("the edit must quarantine leaf1 for this test to mean anything")
	}
	rep, err := f.b.Refresh(context.Background(), priors)
	if err != nil || rep.Revoked != 1 || rep.Quarantined != 0 {
		t.Fatalf("report %+v, err %v", rep, err)
	}
	if c := f.context(t, "leaf1", "alice"); c.RevokedAt.IsZero() {
		t.Fatalf("the withdrawn grant's context must be revoked, not left: %+v", c)
	}
}

// An edit that changes no one's answer — here a comment — deletes no token: a
// reload is not a reason to make everyone mint again. Every live context still
// takes the new bundle's blob, so the records after the reload name the policy
// that was in force when they were decided. A second pass finds nothing to do.
func TestAnEditThatChangesNoAnswerKeepsEveryToken(t *testing.T) {
	f := newFixture(t, 8)
	before := f.login(t, alice, "leaf1", "alice")
	decodeMint(t, f.post(context.Background(), f.state(f.alice), `{"devices":["nx1"]}`, ""))
	priors := f.reload(t, testPolicy+"# reviewed 2026-09-24\n")
	rep, err := f.b.Refresh(context.Background(), priors)
	if err != nil {
		t.Fatal(err)
	}
	if toks, _ := f.st.Candidates(context.Background(), store.TokenKey{NAS: "nx1", Username: "alice"}); len(toks) != 1 {
		t.Fatalf("an unchanged answer keeps its token: %d left", len(toks))
	}
	after := f.context(t, "leaf1", "alice")
	if rep.TokenKeys != 0 || rep.Updated != 1 || after.BlobHash == before.BlobHash {
		t.Fatalf("report %+v; the context takes the new bundle's blob: %+v", rep, after)
	}
	rep, err = f.b.Refresh(context.Background(), []Prior{{Policy: f.b.Policy.Load(), At: f.now}})
	if err != nil || rep.Unchanged != 1 || rep.Updated != 0 {
		t.Fatalf("a second pass: %+v %v", rep, err)
	}
}

// What a refresh does not touch: a context the lab's instrument answers (no
// blob), one already revoked (a refresh never lifts a mark), and one that
// another principal's login has taken since the index was read.
func TestARefreshSkipsWhatIsNotItsToChange(t *testing.T) {
	f := newFixture(t, 8)
	ctx := context.Background()
	f.login(t, alice, "leaf1", "alice")
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	lab := store.ContextKey{NAS: "nx1", Username: "alice"}
	must(f.st.PutContext(ctx, lab, store.Context{CtxID: "lab", Principal: alice, Username: "alice", PrivLvl: 15}, time.Hour))
	must(f.st.IndexContext(ctx, alice, "", "", store.ContextRef{NAS: "nx1", Username: "alice"}, time.Hour))
	must(f.st.SetRevokedAt(ctx, store.ContextKey{NAS: "leaf1", Username: "alice"}, f.now.Add(-time.Minute)))
	taken := store.ContextKey{NAS: "leaf1", Username: "al"}
	must(f.st.PutContext(ctx, taken, store.Context{CtxID: "carol", Principal: "user:carol@example.com", Username: "al",
		BlobHash: "sha256:carol"}, time.Hour))
	must(f.st.IndexContext(ctx, alice, "", "", store.ContextRef{NAS: "leaf1", Username: "al"}, time.Hour))
	priors := f.reload(t, edit(t, aliceGrant, "roles: [no_reload], max_privilege: admin"))
	rep, err := f.b.Refresh(ctx, priors)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Updated+rep.Revoked+rep.Unchanged+rep.Quarantined+rep.Failed != 0 {
		t.Fatalf("nothing here is the refresh's to change: %+v", rep)
	}
	if c := f.context(t, "nx1", "alice"); c.BlobHash != "" || !c.RevokedAt.IsZero() {
		t.Fatalf("the lab's context was touched: %+v", c)
	}
	if c := f.context(t, "leaf1", "alice"); !c.RevokedAt.Equal(f.now.Add(-time.Minute)) {
		t.Fatalf("a revoked context was touched: %+v", c)
	}
	if c := f.context(t, "leaf1", "al"); c.BlobHash != "sha256:carol" || !c.RevokedAt.IsZero() {
		t.Fatalf("another principal's context was given alice's answer: %+v", c)
	}
}

// racingStore lands a write on the context between the refresh's read and its
// compare-and-set, once, and counts the attempts. join is a login joining
// with a token minted under the previous policy: a whole-record swap, which
// moves the policy revision. Otherwise the write is accounting's annotation,
// which does not.
type racingStore struct {
	store.Store
	join     bool
	raced    bool
	attempts int
}

func (r *racingStore) SetContextPolicy(ctx context.Context, k store.ContextKey, policyRev uint64, p store.ContextPolicy) error {
	r.attempts++
	if !r.raced {
		r.raced = true
		if r.join {
			c, err := r.Store.GetContext(ctx, k)
			if err != nil {
				return err
			}
			c.AccountingState = store.AccountingStateOpen
			if err := r.Store.SwapContext(ctx, k, c.Rev, c, 12*time.Hour); err != nil {
				return err
			}
		} else if err := r.Store.AnnotateContext(ctx, k, "", store.AccountingStateOpen); err != nil {
			return err
		}
	}
	return r.Store.SetContextPolicy(ctx, k, policyRev, p)
}

// A write that lands between the read and the refresh's own is not
// overwritten: the compare-and-set refuses, the refresh reads again and
// decides again, and the write it raced survives beside the new policy.
func TestARefreshThatLosesARaceReadsAgain(t *testing.T) {
	f := newFixture(t, 8)
	f.login(t, alice, "leaf1", "alice")
	racing := &racingStore{Store: f.st, join: true}
	f.b.Store = racing
	priors := f.reload(t, edit(t, roleList, readOnly, aliceGrant, "roles: [read_only], max_privilege: admin"))
	rep, err := f.b.Refresh(context.Background(), priors)
	if err != nil {
		t.Fatal(err)
	}
	after := f.context(t, "leaf1", "alice")
	if racing.attempts != 2 || rep.Updated != 1 || after.AccountingState != store.AccountingStateOpen ||
		f.decides(t, after, "configure") {
		t.Fatalf("attempts %d, report %+v, context %+v", racing.attempts, rep, after)
	}
}

// Accounting writes nothing the refresh decides, so it does not send the
// refresh back to read again: a session reporting every command never makes
// its refresh lose (store.Context.PolicyRev).
func TestAnAccountingWriteDoesNotMakeTheRefreshLose(t *testing.T) {
	f := newFixture(t, 8)
	f.login(t, alice, "leaf1", "alice")
	// The session has reported before, so its record's revision has moved
	// past its policy revision.
	if err := f.st.AnnotateContext(context.Background(), store.ContextKey{NAS: "leaf1", Username: "alice"},
		store.HashDiscriminator("31048"), ""); err != nil {
		t.Fatal(err)
	}
	racing := &racingStore{Store: f.st}
	f.b.Store = racing
	priors := f.reload(t, edit(t, roleList, readOnly, aliceGrant, "roles: [read_only], max_privilege: admin"))
	rep, err := f.b.Refresh(context.Background(), priors)
	if err != nil {
		t.Fatal(err)
	}
	after := f.context(t, "leaf1", "alice")
	if racing.attempts != 1 || rep.Updated != 1 || after.AccountingState != store.AccountingStateOpen {
		t.Fatalf("attempts %d, report %+v, context %+v", racing.attempts, rep, after)
	}
}

// failingStore fails the index read a refresh starts from.
type failingStore struct{ store.Store }

func (failingStore) ActivePrincipals(context.Context) ([]string, error) {
	return nil, errors.New("store: connection refused")
}

// A store that fails mid-refresh ends the pass with the error and what was
// done so far; the policy is already in force for every mint, and port49d
// runs the pass again (plan 4b). Nothing is half-written to any context.
func TestARefreshReturnsAStoreErrorForTheCallerToRetry(t *testing.T) {
	f := newFixture(t, 8)
	f.login(t, alice, "leaf1", "alice")
	f.b.Store = failingStore{f.st}
	priors := f.reload(t, edit(t, roleList, readOnly, aliceGrant, "roles: [read_only], max_privilege: admin"))
	if _, err := f.b.Refresh(context.Background(), priors); err == nil || !strings.Contains(err.Error(), "connection refused") {
		t.Fatalf("the store's error is returned: %v", err)
	}
	f.b.Store = f.st
	if rep, err := f.b.Refresh(context.Background(), priors); err != nil || rep.Updated != 1 {
		t.Fatalf("the pass run again finishes the job: %+v %v", rep, err)
	}
}

// lookupFailingStore is a store whose lookup of principal's contexts fails
// with err.
type lookupFailingStore struct {
	store.Store
	principal string
	err       error
}

func (l lookupFailingStore) ContextsByPrincipal(ctx context.Context, principal string) ([]store.ContextRef, error) {
	if principal == l.principal {
		return nil, l.err
	}
	return l.Store.ContextsByPrincipal(ctx, principal)
}

// One principal whose contexts cannot be looked up, for any reason but the
// store being unavailable or the pass ending, is said and counted failed,
// and the pass goes on to every principal after it: one store write must
// not hold the refresh for everyone (final review I-1). The store being
// unavailable still ends the pass, for port49d to run it again.
func TestAFailedLookupDoesNotStopTheRefresh(t *testing.T) {
	f := newFixtureWithPolicy(t, 8, sharedPolicy)
	ctx := context.Background()
	f.liveContextAt(t, "leaf1", "alice", alicePrincipal, "", f.now, f.now.Add(time.Hour))
	f.liveContextAt(t, "nx1", "alice2", alice2, "", f.now, f.now.Add(time.Hour))
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })
	// alice2 sorts before alice ('2' before '@'), so alice is after it.
	f.b.Store = lookupFailingStore{Store: f.st, principal: alice2, err: errors.New("test: does not parse")}
	rep, err := f.b.Refresh(ctx, nil)
	if !errors.Is(err, store.ErrConflict) || rep.Failed != 1 || rep.Updated+rep.Unchanged+rep.Revoked != 1 {
		t.Fatalf("a pass past one failed lookup: %+v %v", rep, err)
	}
	if !strings.Contains(buf.String(), alice2) {
		t.Fatalf("the failed lookup was not said: %q", buf.String())
	}
	f.b.Store = lookupFailingStore{Store: f.st, principal: alice2, err: store.ErrUnavailable}
	if _, err := f.b.Refresh(ctx, nil); !errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("a pass with the store unavailable = %v", err)
	}
}

// A pass that left a principal unjudged is not complete: it returns
// store.ErrConflict naming what it left, so port49d keeps
// port49_policy_refresh_pending at 1 and runs it again, and the tokens are
// still superseded (re-review r-m1).
func TestAPassThatLeftAPrincipalIsNotComplete(t *testing.T) {
	f := newFixture(t, 8)
	ctx := context.Background()
	f.liveContextAt(t, "leaf1", "alice", alicePrincipal, "", f.now, f.now.Add(time.Hour))
	tk := store.TokenKey{NAS: "nx1", Username: "alice"}
	decodeMint(t, f.post(ctx, f.state(f.alice), `{"devices":["nx1"]}`, ""))
	priors := f.reload(t, edit(t, "token_ttl: 60s}", "token_ttl: 30s}"))
	f.b.Store = lookupFailingStore{Store: f.st, principal: alicePrincipal, err: errors.New("test: does not parse")}
	rep, err := f.b.Refresh(ctx, priors)
	if !errors.Is(err, store.ErrConflict) || !strings.Contains(err.Error(), "a principal could not be looked up") {
		t.Fatalf("a pass that left a principal = %v, want ErrConflict naming it", err)
	}
	if toks, _ := f.st.Candidates(ctx, tk); len(toks) != 0 || rep.TokenKeys != 1 {
		t.Fatalf("the supersede did not run: %d left, report %+v", len(toks), rep)
	}
}

// A widening applies from the next command too: dropping no_reload lets
// alice's next `reload` through, in the session she already has.
func TestARefreshWidensALiveContext(t *testing.T) {
	f := newFixture(t, 8)
	before := f.login(t, alice, "leaf1", "alice")
	if f.decides(t, before, "reload") {
		t.Fatal("before the edit no_reload denies reload")
	}
	priors := f.reload(t, edit(t, aliceGrant, "roles: [network_admin], max_privilege: admin"))
	if _, err := f.b.Refresh(context.Background(), priors); err != nil {
		t.Fatal(err)
	}
	if after := f.context(t, "leaf1", "alice"); after.CtxID != before.CtxID || !f.decides(t, after, "reload") {
		t.Fatalf("after the edit the same context permits reload: %+v", after)
	}
}

// A grant's expiry changes a resolution with no edit to the file, and the
// refresh port49d runs at that instant (policy.NextChange) carries it into the
// live context: the policy's own schedule, applied like an edit (spec §5.1).
func TestAGrantsExpiryReachesALiveContext(t *testing.T) {
	f := newFixture(t, 8)
	lapse := f.now.Add(time.Hour)
	priors := f.reload(t, edit(t, aliceGrant, aliceGrant+", expires: "+lapse.UTC().Format(time.RFC3339)))
	f.login(t, alice, "leaf1", "alice")
	if _, err := f.b.Refresh(context.Background(), priors); err != nil {
		t.Fatal(err)
	}
	if c := f.context(t, "leaf1", "alice"); !c.RevokedAt.IsZero() {
		t.Fatalf("before the expiry the grant stands: %+v", c)
	}
	start := f.now
	f.advance(time.Hour)
	rep, err := f.b.Refresh(context.Background(), []Prior{{Policy: f.b.Policy.Load(), At: start}})
	if err != nil || rep.Revoked != 1 {
		t.Fatalf("at the expiry the context is revoked: %+v %v", rep, err)
	}
}

// A superseded policy's tokens are judged at every instant it could have
// minted them, not only where its span began (spec §5.1.3). Here alice also
// holds read_only until a lapse, and the pass that would have run at the lapse
// never completed, so her prior's span starts before it. Her token minted
// after the lapse carries no read_only; the new policy gives read_only for
// good, which is what the old one said at the start of its span — and not
// what it minted.
func TestASupersededPolicyIsJudgedAtEveryExpiryItSpanned(t *testing.T) {
	f := newFixture(t, 8)
	start := f.now
	lapse := f.now.Add(time.Hour)
	extra := "  - {subject: netops, scope: all_devices, roles: [read_only]"
	f.reload(t, edit(t, roleList, readOnly)+extra+", expires: "+lapse.UTC().Format(time.RFC3339)+"}\n")
	f.advance(2 * time.Hour)
	if it := decodeMint(t, f.post(context.Background(), f.state(f.alice), `{"devices":["leaf1"]}`, "")).Results[0]; it.Verdict != "permit" {
		t.Fatalf("mint after the lapse: verdict %q, reason %q", it.Verdict, it.Reason)
	}
	pol, err := policy.Parse([]byte(edit(t, roleList, readOnly)+extra+"}\n"), policy.Env{Devices: []admission.Device{
		f.devices["leaf1"], f.devices["nx1"], f.devices["bare"]}, Now: f.b.Now()})
	if err != nil {
		t.Fatal(err)
	}
	priors := []Prior{{Policy: f.b.Policy.Swap(pol), At: start, Until: f.b.Now()}}
	rep, err := f.b.Refresh(context.Background(), priors)
	if err != nil {
		t.Fatal(err)
	}
	if toks, _ := f.st.Candidates(context.Background(), store.TokenKey{NAS: "leaf1", Username: "alice"}); len(toks) != 0 || rep.TokenKeys != 1 {
		t.Fatalf("the token minted after the lapse must be superseded: %d left, report %+v", len(toks), rep)
	}
}

// stuckStore conflicts every compare-and-set on one context: a session busy
// enough that every read the refresh makes is stale by its write.
type stuckStore struct {
	store.Store
	stuck store.ContextKey
}

func (s stuckStore) SetContextPolicy(ctx context.Context, k store.ContextKey, rev uint64, p store.ContextPolicy) error {
	if k == s.stuck {
		return store.ErrConflict
	}
	return s.Store.SetContextPolicy(ctx, k, rev, p)
}

// One busy context does not hold every context after it on the superseded
// policy: it is counted failed and left for the retry, the pass goes on, and
// the error it returns is the conflict, so port49d runs it again.
func TestABusyContextDoesNotStopTheRefresh(t *testing.T) {
	f := newFixture(t, 8)
	f.login(t, alice, "leaf1", "alice")
	f.login(t, alice, "nx1", "alice")
	f.b.Store = stuckStore{Store: f.st, stuck: store.ContextKey{NAS: "leaf1", Username: "alice"}}
	priors := f.reload(t, edit(t, roleList, readOnly, aliceGrant, "roles: [read_only], max_privilege: admin"))
	rep, err := f.b.Refresh(context.Background(), priors)
	if !errors.Is(err, store.ErrConflict) || rep.Failed != 1 || rep.Updated != 1 {
		t.Fatalf("report %+v, err %v", rep, err)
	}
	if f.decides(t, f.context(t, "nx1", "alice"), "configure") {
		t.Fatal("the context after the busy one must still be refreshed")
	}
}

// A revocation is not left for the retry: where the answer is no grant, a
// context whose every compare-and-set would conflict is marked revoked anyway.
// A refresh revokes through the setter that writes the mark alone, never the
// compare-and-set, so no write racing it can hold a withdrawn grant in force
// (fail closed).
func TestABusyContextIsRevokedAnyway(t *testing.T) {
	f := newFixture(t, 8)
	f.login(t, alice, "leaf1", "alice")
	f.b.Store = stuckStore{Store: f.st, stuck: store.ContextKey{NAS: "leaf1", Username: "alice"}}
	priors := f.reload(t, edit(t, "  - {subject: netops, scope: all_devices, "+aliceGrant+"}\n",
		"  - {subject: idle, scope: all_devices, roles: [network_admin]}\n"))
	rep, err := f.b.Refresh(context.Background(), priors)
	if err != nil || rep.Revoked != 1 {
		t.Fatalf("report %+v, err %v", rep, err)
	}
	if c := f.context(t, "leaf1", "alice"); c.RevokedAt.IsZero() {
		t.Fatalf("the busy context must be revoked: %+v", c)
	}
}

// A context the policy in force cannot be resolved or compiled for is revoked,
// failing closed, and never silently: a `refresh` deny blob_unavailable names
// its ctx_id, it is counted failed, and the pass goes on to the next context.
// Revoked is its answer under the policy in force, so it is reached, and the
// pass returns no error for it (spec §5.1.3).
func TestACompileFaultRevokesThatContextAndSaysSo(t *testing.T) {
	f := newFixture(t, 8)
	before := f.login(t, alice, "leaf1", "alice")
	f.login(t, alice, "nx1", "alice")
	priors := f.reload(t, edit(t, roleList, readOnly, aliceGrant, "roles: [read_only], max_privilege: admin"))
	resolve := resolveFor
	resolveFor = func(p *policy.Policy, m policy.Member, d admission.Device, at time.Time) (policy.Resolution, error) {
		if d.Name == "leaf1" {
			return policy.Resolution{}, errors.New("policy: a composition the load never compiled")
		}
		return resolve(p, m, d, at)
	}
	t.Cleanup(func() { resolveFor = resolve })
	f.log.Reset()
	rep, err := f.b.Refresh(context.Background(), priors)
	if err != nil || rep.Failed != 1 || rep.Updated != 1 {
		t.Fatalf("report %+v, err %v", rep, err)
	}
	if c := f.context(t, "leaf1", "alice"); !c.RevokedAt.Equal(f.now) || c.BlobHash != before.BlobHash {
		t.Fatalf("the context the fault is on is revoked, and nothing else changes: %+v", c)
	}
	if f.decides(t, f.context(t, "nx1", "alice"), "configure") {
		t.Fatal("the context after the fault must still be refreshed")
	}
	var fault map[string]any
	for _, r := range eventsOf(f.records(t), "refresh") {
		if r["reason"] == "blob_unavailable" {
			fault = r
		}
	}
	if s, _ := fault["session"].(map[string]any); fault["verdict"] != "deny" || s["ctx_id"] != before.CtxID {
		t.Fatalf("one refresh deny blob_unavailable naming the ctx_id: %v", f.records(t))
	}
	if n := testutil.ToFloat64(f.b.Metrics.ContextRefreshes.WithLabelValues("failed")); n != 1 {
		t.Fatalf("port49_context_refreshes_total{outcome=failed} = %v", n)
	}
}

// unreadableStore answers one context as a record the sealing layer cannot
// open: sealed under a key that has left the two-key window. The error
// carries the record's plaintext revision and revocation, as crypt's does.
type unreadableStore struct {
	store.Store
	k store.ContextKey
}

func (u unreadableStore) GetContext(ctx context.Context, k store.ContextKey) (store.Context, error) {
	if k == u.k {
		c, err := u.Store.GetContext(ctx, k)
		if err != nil {
			return c, err
		}
		return store.Context{}, &store.UnreadableContextError{Rev: c.Rev, RevokedAt: c.RevokedAt,
			Err: errors.New("crypt: no key opens this record")}
	}
	return u.Store.GetContext(ctx, k)
}

// A context the refresher cannot open cannot be judged, so it cannot be left
// on a policy no longer in force: it is revoked the way a compile fault is,
// with a record, counted failed, and the pass goes on.
func TestARefreshRevokesAContextItCannotOpen(t *testing.T) {
	f := newFixture(t, 8)
	f.login(t, alice, "leaf1", "alice")
	k := store.ContextKey{NAS: "leaf1", Username: "alice"}
	f.b.Store = unreadableStore{Store: f.st, k: k}
	priors := f.reload(t, edit(t, aliceGrant, "roles: [network_admin], max_privilege: admin"))
	f.log.Reset()
	rep, err := f.b.Refresh(context.Background(), priors)
	if err != nil || rep.Failed != 1 {
		t.Fatalf("report %+v, err %v", rep, err)
	}
	if c := f.context(t, "leaf1", "alice"); !c.RevokedAt.Equal(f.now) {
		t.Fatalf("the unreadable context must be revoked: %+v", c)
	}
	recs := eventsOf(f.records(t), "refresh")
	if len(recs) != 1 || recs[0]["verdict"] != "deny" || recs[0]["reason"] != "blob_unavailable" {
		t.Fatalf("one refresh deny blob_unavailable: %v", recs)
	}
	// Revoked is its answer now, and its plaintext mark says so: the next
	// pass leaves it alone and records nothing.
	rep, err = f.b.Refresh(context.Background(), []Prior{{Policy: f.b.Policy.Load(), At: f.now}})
	if err != nil || rep.Failed != 0 || len(eventsOf(f.records(t), "refresh")) != 1 {
		t.Fatalf("a second pass: %+v %v", rep, err)
	}
}

// Whose an unopenable context is cannot be read, so its record names what is
// authoritative — the device and the username its key holds — and no
// principal: the index that led to it may be stale. Here carol's login has
// replaced the context alice's index entry still names, and the record of
// carol's revocation must not say it was alice's.
func TestAnUnopenableContextIsNotAttributedFromTheIndex(t *testing.T) {
	f := newFixture(t, 8)
	ctx := context.Background()
	f.login(t, alice, "leaf1", "alice")
	k := store.ContextKey{NAS: "leaf1", Username: "alice"}
	carol := "user:carol@example.com"
	if err := f.st.PutContext(ctx, k, store.Context{CtxID: "carol", Principal: carol, Username: "alice",
		BlobHash: "sha256:carol"}, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := f.st.IndexContext(ctx, carol, "", "", store.ContextRef{NAS: "leaf1", Username: "alice"}, time.Hour); err != nil {
		t.Fatal(err)
	}
	f.b.Store = unreadableStore{Store: f.st, k: k}
	priors := f.reload(t, edit(t, aliceGrant, "roles: [network_admin], max_privilege: admin"))
	f.log.Reset()
	if _, err := f.b.Refresh(ctx, priors); err != nil {
		t.Fatal(err)
	}
	recs := eventsOf(f.records(t), "refresh")
	if len(recs) != 1 {
		t.Fatalf("one record for the one revocation: %v", recs)
	}
	s, _ := recs[0]["session"].(map[string]any)
	d, _ := recs[0]["device"].(map[string]any)
	if _, named := recs[0]["principal"]; named || s["username"] != "alice" || d["name"] != "leaf1" {
		t.Fatalf("the record names the key's device and username, and no principal: %v", recs[0])
	}
}

// A quarantined device's context is recorded once per policy, not once per
// pass: the settle pass, the retries and the pass at every expiry would
// otherwise write the same line again and again. It is still counted at every
// pass, and a new policy that still quarantines it records it again.
func TestAQuarantinedContextIsRecordedOncePerPolicy(t *testing.T) {
	f := newFixture(t, 8)
	f.login(t, alice, "leaf1", "alice")
	quarantining := "privilege_levels: [{name: readonly}, {name: operator}, {name: unmapped}, {name: admin}]\n" +
		edit(t, "{name: network_admin, privilege: admin,", "{name: network_admin, privilege: unmapped,")
	priors := f.reload(t, quarantining)
	f.log.Reset()
	for i := 0; i < 3; i++ {
		rep, err := f.b.Refresh(context.Background(), priors)
		if err != nil || rep.Quarantined != 1 {
			t.Fatalf("pass %d: report %+v, err %v", i, rep, err)
		}
		priors = []Prior{{Policy: f.b.Policy.Load(), At: f.now}}
	}
	if recs := eventsOf(f.records(t), "refresh"); len(recs) != 1 {
		t.Fatalf("one record for three passes on one policy: %v", recs)
	}
	if n := testutil.ToFloat64(f.b.Metrics.ContextRefreshes.WithLabelValues("quarantined")); n != 3 {
		t.Fatalf("port49_context_refreshes_total{outcome=quarantined} = %v", n)
	}
	if _, err := f.b.Refresh(context.Background(), f.reload(t, quarantining+"# reviewed 2026-09-24\n")); err != nil {
		t.Fatal(err)
	}
	if recs := eventsOf(f.records(t), "refresh"); len(recs) != 2 {
		t.Fatalf("a new policy records the quarantine again: %v", recs)
	}
}

// slowStore advances the clock once, as the pass reaches the contexts: a pass
// on a real fleet takes seconds, and a grant can expire inside one.
type slowStore struct {
	store.Store
	f    *fixture
	d    time.Duration
	done bool
}

func (s *slowStore) ActivePrincipals(ctx context.Context) ([]string, error) {
	if !s.done {
		s.done = true
		s.f.advance(s.d)
	}
	return s.Store.ActivePrincipals(ctx)
}

// A grant that expires while a pass is running is not skipped: the contexts
// were judged before it, and the caller schedules the next expiry from the
// instant judged at, so neither would ever apply it. Refresh runs again at
// once, and the report's At is the instant the last pass judged at.
func TestAnExpiryInsideAPassIsApplied(t *testing.T) {
	f := newFixture(t, 8)
	lapse := f.now.Add(time.Second)
	priors := f.reload(t, edit(t, aliceGrant, aliceGrant+", expires: "+lapse.UTC().Format(time.RFC3339)))
	f.login(t, alice, "leaf1", "alice")
	start := f.now
	f.b.Store = &slowStore{Store: f.st, f: f, d: 2 * time.Second}
	rep, err := f.b.Refresh(context.Background(), priors)
	if err != nil || rep.Revoked != 1 {
		t.Fatalf("the grant that expired during the pass is applied: %+v %v", rep, err)
	}
	if c := f.context(t, "leaf1", "alice"); c.RevokedAt.IsZero() {
		t.Fatalf("the context must be revoked: %+v", c)
	}
	if !rep.At.After(start) || rep.At.Before(lapse) {
		t.Fatalf("At is the instant the last pass judged at, past the expiry: %v (lapse %v)", rep.At, lapse)
	}
	if _, more := f.b.Policy.Load().NextChange(rep.At); more {
		t.Fatal("no expiry is left before At for the caller to miss")
	}
}

// A shortened token_ttl is a changed answer: a token minted under the longer
// one would outlive what the policy now allows, so it is superseded. A
// lengthened one is not: the token lives less than the policy allows.
func TestAShortenedTokenTTLSupersedesTokens(t *testing.T) {
	f := newFixture(t, 8)
	tk := store.TokenKey{NAS: "nx1", Username: "alice"}
	decodeMint(t, f.post(context.Background(), f.state(f.alice), `{"devices":["nx1"]}`, ""))
	if _, err := f.b.Refresh(context.Background(), f.reload(t, edit(t, "token_ttl: 60s}", "token_ttl: 120s}"))); err != nil {
		t.Fatal(err)
	}
	if toks, _ := f.st.Candidates(context.Background(), tk); len(toks) != 1 {
		t.Fatalf("a lengthened token_ttl keeps the token: %d left", len(toks))
	}
	rep, err := f.b.Refresh(context.Background(), f.reload(t, edit(t, "token_ttl: 60s}", "token_ttl: 30s}")))
	if err != nil {
		t.Fatal(err)
	}
	if toks, _ := f.st.Candidates(context.Background(), tk); len(toks) != 0 || rep.TokenKeys != 1 {
		t.Fatalf("a shortened token_ttl supersedes the token: %d left, report %+v", len(toks), rep)
	}
}

// A role whose ceiling was shortened supersedes the tokens minted under the
// longer one; a lengthened one does not (decision 33's shorten-only rule,
// carried to tokens as token_ttl's is).
func TestAShortenedCeilingSupersedesTokens(t *testing.T) {
	long := minted{username: "a", ttl: time.Minute, age: 8 * time.Hour}
	short := long
	short.age = time.Hour
	never := long
	never.age = 0
	if long.keeps(short) || !short.keeps(long) || never.keeps(long) || !long.keeps(never) {
		t.Fatal("keeps must refuse a token whose ceiling is longer than the policy in force allows")
	}
}

// A subject whose username changed can no longer mint under the name the
// context is keyed by, so the context is revoked, and the record names no
// grant: none selects this key any more.
func TestAChangedUsernameRevokesTheContext(t *testing.T) {
	f := newFixture(t, 8)
	f.login(t, alice, "leaf1", "alice")
	priors := f.reload(t, edit(t, "username: alice,", "username: alice2,"))
	f.log.Reset()
	rep, err := f.b.Refresh(context.Background(), priors)
	if err != nil || rep.Revoked != 1 {
		t.Fatalf("report %+v, err %v", rep, err)
	}
	recs := eventsOf(f.records(t), "refresh")
	if len(recs) != 1 || recs[0]["reason"] != "no_grants_matched" {
		t.Fatalf("one refresh deny no_grants_matched: %v", recs)
	}
	if p, _ := recs[0]["policy"].(map[string]any); p["grants"] != nil {
		t.Fatalf("the record names no grant: %v", recs[0])
	}
}

// cancellingStore cancels the pass's context as it reads the first
// principal's contexts: SIGTERM arriving part-way through a long pass.
type cancellingStore struct {
	store.Store
	cancel context.CancelFunc
}

func (s cancellingStore) ContextsByPrincipal(ctx context.Context, principal string) ([]store.ContextRef, error) {
	s.cancel()
	return s.Store.ContextsByPrincipal(ctx, principal)
}

// A cancelled pass stops at once: port49d waits for the reloader before it
// flushes the accounting spool, and a pod killed at its grace period would
// lose it. The contexts come first — revoking a live session is the security
// priority — so the principal the pass was on is finished, the next is not
// begun, and the token scan after them never runs.
func TestACancelledPassStopsAtOnce(t *testing.T) {
	f := newFixture(t, 8)
	bg := context.Background()
	f.login(t, alice, "leaf1", "alice")
	decodeMint(t, f.post(bg, f.state(f.alice), `{"devices":["nx1"]}`, ""))
	carol := "user:carol@example.com"
	k := store.ContextKey{NAS: "leaf1", Username: "carol"}
	if err := f.st.PutContext(bg, k, store.Context{CtxID: "carol", Principal: carol, Username: "carol",
		BlobHash: "sha256:carol"}, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := f.st.IndexContext(bg, carol, "", "", store.ContextRef{NAS: "leaf1", Username: "carol"}, time.Hour); err != nil {
		t.Fatal(err)
	}
	priors := f.reload(t, edit(t, roleList, readOnly, aliceGrant, "roles: [read_only], max_privilege: admin"))
	ctx, cancel := context.WithCancel(bg)
	defer cancel()
	f.b.Store = cancellingStore{Store: f.st, cancel: cancel}
	rep, err := f.b.Refresh(ctx, priors)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("a cancelled pass returns the cancellation: %v", err)
	}
	if rep.Updated != 1 || f.decides(t, f.context(t, "leaf1", "alice"), "configure") {
		t.Fatalf("the principal the pass was on is finished: %+v", rep)
	}
	if c := f.context(t, "leaf1", "carol"); !c.RevokedAt.IsZero() {
		t.Fatalf("the principal after the cancellation is not begun: %+v", c)
	}
	if toks, _ := f.st.Candidates(bg, store.TokenKey{NAS: "nx1", Username: "alice"}); len(toks) != 1 {
		t.Fatalf("the token scan after the contexts never runs: %d left", len(toks))
	}
}

// The token scan stops at a cancellation too, before deleting anything.
func TestACancelledTokenScanStops(t *testing.T) {
	f := newFixture(t, 8)
	decodeMint(t, f.post(context.Background(), f.state(f.alice), `{"devices":["nx1"]}`, ""))
	priors := f.reload(t, edit(t, roleList, readOnly, aliceGrant, "roles: [read_only], max_privilege: admin"))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var rep RefreshReport
	if err := f.b.supersedeTokens(ctx, f.b.Policy.Load(), f.now, priors, &rep); !errors.Is(err, context.Canceled) {
		t.Fatalf("a cancelled scan returns the cancellation: %v", err)
	}
	if toks, _ := f.st.Candidates(context.Background(), store.TokenKey{NAS: "nx1", Username: "alice"}); len(toks) != 1 {
		t.Fatalf("a cancelled scan deletes nothing: %d left", len(toks))
	}
}

// A settle pass, or an expiry pass with no expiry since the last, compares
// the policy in force with itself over a span where no answer can change:
// the token scan skips it rather than compile the fleet for nothing, every
// 30s during retries.
func TestASettlePassComparesNoPolicyWithItself(t *testing.T) {
	f := newFixture(t, 8)
	mints := 0
	was := mintedFor
	mintedFor = func(p *policy.Policy, m policy.Member, d admission.Device, at time.Time,
		def time.Duration) (minted, bool) {
		mints++
		return was(p, m, d, at, def)
	}
	t.Cleanup(func() { mintedFor = was })
	if _, err := f.b.Refresh(context.Background(), []Prior{{Policy: f.b.Policy.Load(), At: f.now}}); err != nil {
		t.Fatal(err)
	}
	if mints != 0 {
		t.Fatalf("the policy in force was compared with itself: %d mints compiled", mints)
	}
	if _, err := f.b.Refresh(context.Background(), f.reload(t, testPolicy+"# reviewed\n")); err != nil {
		t.Fatal(err)
	}
	if mints == 0 {
		t.Fatal("a reload's prior is still compared")
	}
}

// Junos never sends a per-command authorization request (spec §13 decision
// 21), so a refresh cannot reach a live shell there: the context is written,
// for the next login and any receipt replay, but the session keeps what it
// had at login until logout. The refresh counts those contexts and the
// process log names each, so an operator withdrawing a compromised grant is
// not told it is gone from a shell that is still open.
func TestARefreshNamesTheContextsASessionOnlyPlatformKeeps(t *testing.T) {
	f := newFixture(t, 8)
	before := f.login(t, alice, "leaf1", "alice")
	f.login(t, alice, "nx1", "alice")
	sessionOnly, _ := platform.DialectFor("arista_eos")
	sessionOnly.Supports = []string{"session"}
	pol, err := policy.Parse([]byte(edit(t, "  - {subject: netops, scope: all_devices, "+aliceGrant+"}\n",
		"  - {subject: idle, scope: all_devices, roles: [network_admin]}\n")), policy.Env{
		Devices:  []admission.Device{f.devices["leaf1"], f.devices["nx1"], f.devices["bare"]},
		Dialects: map[string]platform.Dialect{"arista_eos": sessionOnly}, Now: f.b.Now()})
	if err != nil {
		t.Fatal(err)
	}
	priors := []Prior{{Policy: f.b.Policy.Swap(pol), At: f.b.Now()}}
	var out bytes.Buffer
	log.SetOutput(&out)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	rep, err := f.b.Refresh(context.Background(), priors)
	if err != nil {
		t.Fatal(err)
	}
	if c := f.context(t, "leaf1", "alice"); c.RevokedAt.IsZero() {
		t.Fatalf("the context is still revoked, for the next login and any receipt replay: %+v", c)
	}
	if rep.Revoked != 2 || rep.Unreached != 1 {
		t.Fatalf("two revoked, one of them on a session-only platform: %+v", rep)
	}
	if !strings.Contains(out.String(), before.CtxID) || !strings.Contains(out.String(), "until logout") ||
		strings.Contains(out.String(), "ctx-nx1-alice") {
		t.Fatalf("the process log names the unreached context, and only it: %q", out.String())
	}
}

// A context on a device the inventory in force no longer names is judged
// reached or not by the platform the policy before it knew (Task 11 M3): on a
// platform that authorizes commands it is not counted as a session left
// until logout, and on one that does not it is, named with its platform.
func TestARemovedDeviceIsJudgedByItsPlatformBefore(t *testing.T) {
	for _, supports := range [][]string{nil, {"session"}} {
		f := newFixture(t, 8)
		f.login(t, alice, "leaf1", "alice")
		dialects := map[string]platform.Dialect{}
		if supports != nil {
			d, _ := platform.DialectFor("arista_eos")
			d.Supports = supports
			dialects["arista_eos"] = d
		}
		parse := func(devices ...admission.Device) *policy.Policy {
			pol, err := policy.Parse([]byte(testPolicy), policy.Env{Devices: devices, Dialects: dialects, Now: f.b.Now()})
			if err != nil {
				t.Fatal(err)
			}
			return pol
		}
		f.b.Policy.Swap(parse(f.devices["leaf1"], f.devices["nx1"]))
		before := f.b.Policy.Swap(parse(f.devices["nx1"]))
		var out bytes.Buffer
		log.SetOutput(&out)
		t.Cleanup(func() { log.SetOutput(os.Stderr) })
		rep, err := f.b.Refresh(context.Background(), []Prior{{Policy: before, At: f.b.Now()}})
		if err != nil {
			t.Fatal(err)
		}
		if c := f.context(t, "leaf1", "alice"); c.RevokedAt.IsZero() {
			t.Fatalf("the context on the removed device is live: %+v", c)
		}
		switch {
		case supports == nil && rep.Unreached != 0:
			t.Fatalf("an EOS context counted unreached: %+v, %q", rep, out.String())
		case supports != nil && (rep.Unreached != 1 || !strings.Contains(out.String(), "arista_eos does not authorize")):
			t.Fatalf("a session-only context: %+v, %q", rep, out.String())
		}
	}
}

// An idempotent retry after a refresh superseded the tokens it would replay
// must not answer permit with a token that no longer exists (final review
// m2): the operator would be handed a dead token and then see token_not_found
// at the device, with nothing linking the two. The retry mints afresh under
// the policy in force, and the record says the replay was abandoned; a retry
// after that replays the fresh mint.
func TestARetryAfterASupersedeIsNotAnsweredWithTheDeletedToken(t *testing.T) {
	f := newFixture(t, 8)
	bg := context.Background()
	body := `{"devices":["nx1"]}`
	first := decodeMint(t, f.post(bg, f.state(f.alice), body, "retry-1")).Results[0]
	f.advance(time.Second)
	if _, err := f.b.Refresh(bg, f.reload(t, edit(t, roleList, readOnly, aliceGrant,
		"roles: [read_only], max_privilege: admin"))); err != nil {
		t.Fatal(err)
	}
	f.advance(time.Second)
	f.log.Reset()
	again := decodeMint(t, f.post(bg, f.state(f.alice), body, "retry-1")).Results[0]
	if again.Verdict != "permit" || again.Login == first.Login {
		t.Fatalf("the retry must not replay the superseded token: %+v", again)
	}
	toks, _ := f.st.Candidates(bg, store.TokenKey{NAS: "nx1", Username: "alice"})
	if len(toks) != 1 || string(toks[0].Secret) != again.Login {
		t.Fatalf("the token answered is the one standing: %d standing", len(toks))
	}
	mints := eventsOf(f.records(t), "mint")
	if len(mints) != 1 || !strings.Contains(mints[0]["index_error"].(string), "a policy change or a revocation deleted") {
		t.Fatalf("the mint record says the replay was abandoned: %v", mints)
	}
	if replay := decodeMint(t, f.post(bg, f.state(f.alice), body, "retry-1")).Results[0]; replay.Login != again.Login {
		t.Fatalf("a retry after the fresh mint replays it: verdict %q, same login as the fresh mint: %v", replay.Verdict,
			replay.Login == again.Login)
	}
}

// An inventory change that leaves a context's answer as it was writes nothing
// and records nothing: its blob differs from the new one only in the bundle
// it names (spec §5.1.3; plan 6a Decided 3). Every inventory change would
// otherwise rewrite and record every live context.
func TestAnInventoryOnlySwapLeavesAnUnchangedContextAlone(t *testing.T) {
	f := newFixture(t, 8)
	f.login(t, alice, "leaf1", "alice")
	before := f.context(t, "leaf1", "alice")
	old := f.b.Policy.Load()
	extra := admission.Device{Name: "leaf9", Platform: "arista_eos", Addresses: []netip.Addr{netip.MustParseAddr("172.100.100.19")}}
	pol, err := policy.Parse([]byte(testPolicy), policy.Env{Devices: append(old.Devices(), extra), Now: f.b.Now(),
		Bundle: "sha256:" + strings.Repeat("b", 64)})
	if err != nil {
		t.Fatal(err)
	}
	f.log.Reset()
	rep, err := f.b.Refresh(context.Background(), []Prior{{Policy: f.b.Policy.Swap(pol), At: f.b.Now()}})
	if err != nil || rep.Updated != 0 || rep.Unchanged != 1 {
		t.Fatalf("%+v, %v", rep, err)
	}
	if after := f.context(t, "leaf1", "alice"); after.BlobHash != before.BlobHash {
		t.Fatalf("the context was rewritten: %s → %s", before.BlobHash, after.BlobHash)
	}
	if strings.Contains(f.log.String(), `"event":"refresh"`) {
		t.Fatalf("an unchanged context was recorded: %s", f.log.String())
	}
}

// A policy edit keeps plan 4b's rule: every live context takes the new
// bundle's blob, and each is recorded.
func TestAPolicyEditStillRewritesEveryContext(t *testing.T) {
	f := newFixture(t, 8)
	f.login(t, alice, "leaf1", "alice")
	rep, err := f.b.Refresh(context.Background(), f.reload(t, testPolicy+"\n# an edit\n"))
	if err != nil || rep.Updated != 1 {
		t.Fatalf("%+v, %v", rep, err)
	}
}

// I2: a device admission refuses is not live. The mint denies it
// device_unknown, after the grants check, and a refresh revokes its context
// and supersedes its tokens, as for a device the inventory no longer names.
func TestARefusedDeviceIsNotMintedForAndItsContextIsRevoked(t *testing.T) {
	f := newFixture(t, 8)
	f.login(t, alice, "leaf1", "alice")
	f.post(context.Background(), f.state(f.alice), `{"devices":["leaf1"]}`, "") // an unspent token
	old := f.b.Policy.Load()
	// leaf1 keeps its record, and a key group now admits only nx1's range.
	pol, err := policy.Parse([]byte(testPolicy+"key_groups: [{match: {cidr: 172.100.100.31/32}, key_ref: k}]\n"+
		"keys: {k: {current: {version: 1, secret_ref: \"env:PORT49_KEY_TEST\"}}}\n"),
		policy.Env{Devices: old.Devices(), Now: f.b.Now()})
	if err != nil {
		t.Fatal(err)
	}
	priors := []Prior{{Policy: f.b.Policy.Swap(pol), At: f.b.Now()}}
	it := decodeMint(t, f.post(context.Background(), f.state(f.alice), `{"devices":["leaf1"]}`, "")).Results[0]
	if it.Verdict != "deny" || it.Reason != "device_unknown" {
		t.Fatalf("a refused device was minted for: verdict %q, reason %q", it.Verdict, it.Reason)
	}
	rep, err := f.b.Refresh(context.Background(), priors)
	if err != nil || rep.Revoked != 1 {
		t.Fatalf("%+v, %v", rep, err)
	}
	if c := f.context(t, "leaf1", "alice"); c.RevokedAt.IsZero() {
		t.Fatal("the context on the refused device is live")
	}
	var reasons []any
	for _, r := range f.records(t) {
		if r["event"] == "refresh" {
			reasons = append(reasons, r["reason"])
		}
	}
	if len(reasons) != 1 || reasons[0] != "device_unknown" {
		t.Fatalf("the refresh recorded %v, not one device_unknown", reasons)
	}
	if toks, _ := f.st.Candidates(context.Background(), store.TokenKey{NAS: "leaf1", Username: "alice"}); len(toks) != 0 {
		t.Fatalf("%d token(s) for the refused device survive", len(toks))
	}
}

// A device the inventory in force no longer names has its contexts revoked
// and its unspent tokens superseded (plan 4b's hand-off to plan 6).
func TestADeviceRemovedFromInventoryIsRevokedAndItsTokensGo(t *testing.T) {
	f := newFixture(t, 8)
	f.login(t, alice, "leaf1", "alice")
	f.post(context.Background(), f.state(f.alice), `{"devices":["leaf1"]}`, "")
	old := f.b.Policy.Load()
	var rest []admission.Device
	for _, d := range old.Devices() {
		if d.Name != "leaf1" {
			rest = append(rest, d)
		}
	}
	pol, err := policy.Parse([]byte(testPolicy), policy.Env{Devices: rest, Now: f.b.Now(), Bundle: "sha256:" + strings.Repeat("c", 64)})
	if err != nil {
		t.Fatal(err)
	}
	rep, err := f.b.Refresh(context.Background(), []Prior{{Policy: f.b.Policy.Swap(pol), At: f.b.Now()}})
	if err != nil || rep.Revoked != 1 {
		t.Fatalf("%+v, %v", rep, err)
	}
	if c := f.context(t, "leaf1", "alice"); c.RevokedAt.IsZero() {
		t.Fatal("the context on the removed device is live")
	}
	if toks, _ := f.st.Candidates(context.Background(), store.TokenKey{NAS: "leaf1", Username: "alice"}); len(toks) != 0 {
		t.Fatalf("%d token(s) for the removed device survive", len(toks))
	}
}

// swap loads body against devs, into a bundle named by fill, and swaps it in
// as an inventory reload does, returning what the refresh compares against.
// keyRefs are the keys the policy's keys: block defines; none declares no block.
func (f *fixture) swap(t *testing.T, body string, devs []admission.Device, keyRefs []string, fill string) []Prior {
	t.Helper()
	if keyRefs != nil {
		body += "keys:\n"
		for _, r := range keyRefs {
			body += "  " + r + ": {current: {version: 1, secret_ref: \"env:PORT49_KEY_TEST\"}}\n"
		}
	}
	pol, err := policy.Parse([]byte(body), policy.Env{Devices: devs, Now: f.b.Now(),
		Bundle: "sha256:" + strings.Repeat(fill, 64)})
	if err != nil {
		t.Fatal(err)
	}
	return []Prior{{Policy: f.b.Policy.Swap(pol), At: f.b.Now()}}
}

// withLeaf1 is the fixture's inventory with leaf1 replaced by change(leaf1).
func (f *fixture) withLeaf1(change func(*admission.Device)) []admission.Device {
	out := []admission.Device{f.devices["leaf1"], f.devices["nx1"], f.devices["bare"]}
	leaf1 := out[0]
	leaf1.Attributes = map[string]string{}
	for k, v := range f.devices["leaf1"].Attributes {
		leaf1.Attributes[k] = v
	}
	change(&leaf1)
	out[0] = leaf1
	return out
}

// refreshRecords is the reasons of the `refresh` records logged since the
// last reset.
func (f *fixture) refreshRecords(t *testing.T) []any {
	t.Helper()
	var reasons []any
	for _, r := range f.records(t) {
		if r["event"] == "refresh" {
			reasons = append(reasons, r["reason"])
		}
	}
	return reasons
}

// The skip's safety half (plan 6a Decided 3): an inventory-only swap that
// changes what decides a context's reply rewrites it and records it. Only an
// unchanged answer is left alone; the policy file being the same is not
// enough.
func TestAnInventoryOnlySwapThatChangesAContextRewritesIt(t *testing.T) {
	// siteLab adds a scope on the site attribute, which denies debug to
	// netops on the devices it selects.
	siteLab := edit(t,
		"  - {name: all_devices, match: {}}\n",
		"  - {name: all_devices, match: {}}\n  - {name: lab, match: {site: lab}, on_missing: include}\n",
		roleList, roleList+"  - {name: no_debug, deny: [\"debug **\"]}\n") +
		"  - {subject: netops, scope: lab, roles: [no_debug]}\n"
	for _, c := range []struct {
		name          string
		body          string
		before, after func(*admission.Device)
	}{
		{"the device moves platform", testPolicy,
			func(*admission.Device) {},
			func(d *admission.Device) { d.Platform = "cisco_nxos" }},
		{"a scope no longer selects it", siteLab,
			func(d *admission.Device) { d.Attributes["site"] = "lab" },
			func(d *admission.Device) { d.Attributes["site"] = "campus" }},
		{"a scope newly selects it", siteLab,
			func(d *admission.Device) { d.Attributes["site"] = "campus" },
			func(d *admission.Device) { d.Attributes["site"] = "lab" }},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t, 8)
			f.swap(t, c.body, f.withLeaf1(c.before), nil, "a")
			before := f.login(t, alice, "leaf1", "alice")
			f.log.Reset()
			rep, err := f.b.Refresh(context.Background(), f.swap(t, c.body, f.withLeaf1(c.after), nil, "b"))
			if err != nil || rep.Updated != 1 || rep.Unchanged != 0 {
				t.Fatalf("%+v, %v", rep, err)
			}
			if after := f.context(t, "leaf1", "alice"); after.BlobHash == before.BlobHash {
				t.Fatal("the context was left on the blob its old inventory record compiled")
			}
			if got := f.refreshRecords(t); len(got) != 1 || got[0] != "grants_matched" {
				t.Fatalf("the refresh recorded %v, not one grants_matched", got)
			}
		})
	}
}

// A device's key_ref is not in its reply: a move to another key port49d
// holds leaves its context as it was, and a move to one it holds no key for
// refuses the device, whose context is revoked device_unknown (spec §10).
func TestAnInventoryOnlyKeyRefChange(t *testing.T) {
	pin := func(k string) func(*admission.Device) { return func(d *admission.Device) { d.KeyRef = k } }
	for _, c := range []struct {
		name             string
		to               string
		updated, revoked int
		unchanged        int
		reasons          []any
	}{
		{"to another key held", "k2", 0, 0, 1, nil},
		{"to a key not held", "k3", 0, 1, 0, []any{"device_unknown"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t, 8)
			held := []string{"k1", "k2"}
			f.swap(t, testPolicy, f.withLeaf1(pin("k1")), held, "a")
			before := f.login(t, alice, "leaf1", "alice")
			f.log.Reset()
			rep, err := f.b.Refresh(context.Background(), f.swap(t, testPolicy, f.withLeaf1(pin(c.to)), held, "b"))
			if err != nil || rep.Updated != c.updated || rep.Revoked != c.revoked || rep.Unchanged != c.unchanged {
				t.Fatalf("%+v, %v", rep, err)
			}
			after := f.context(t, "leaf1", "alice")
			if c.revoked == 0 && (after.BlobHash != before.BlobHash || !after.RevokedAt.IsZero()) {
				t.Fatalf("the context was changed: %+v", after)
			}
			if c.revoked == 1 && after.RevokedAt.IsZero() {
				t.Fatal("the context on the refused device is live")
			}
			if got := f.refreshRecords(t); len(got) != len(c.reasons) || (len(got) == 1 && got[0] != c.reasons[0]) {
				t.Fatalf("the refresh recorded %v, not %v", got, c.reasons)
			}
		})
	}
}

// Design §17 at the broker: a caller with no grant on a refused device is
// answered no_grants_matched, as for a device that does not exist, so the
// refusal tells it nothing.
func TestARefusedDeviceIsNoGrantsMatchedToACallerWithNoGrant(t *testing.T) {
	f := newFixture(t, 8)
	f.swap(t, testPolicy, f.withLeaf1(func(d *admission.Device) { d.KeyRef = "k9" }), []string{"k1"}, "a")
	carol := f.client(t, "carol@example.com", f.now.Add(24*time.Hour))
	for _, dev := range []string{"leaf1", "nosuch"} {
		it := decodeMint(t, f.post(context.Background(), f.state(carol), `{"devices":["`+dev+`"]}`, "")).Results[0]
		if it.Verdict != "deny" || it.Reason != "no_grants_matched" {
			t.Fatalf("%s: %+v", dev, it)
		}
	}
}

// A role shortened in the policy shortens every live context's ceiling at
// the next refresh, and says so on the record; one lengthened does not
// (decision 33).
func TestAPolicyRefreshShortensALiveCeiling(t *testing.T) {
	f := newFixture(t, 8) // alice's login on leaf1 carries the 12h default
	before := f.login(t, alice, "leaf1", "alice")
	f.log.Reset()
	// The edit rewrites the context (its bundle is new), but not its ceiling.
	priors := f.reload(t, edit(t, `permit: ["**"]}`, `permit: ["**"], max_session_age: 24h}`,
		`deny: ["reload **"]}`, `deny: ["reload **"], max_session_age: 24h}`))
	if _, err := f.b.Refresh(context.Background(), priors); err != nil {
		t.Fatal(err)
	}
	recs := eventsOf(f.records(t), "refresh")
	if c := f.context(t, "leaf1", "alice"); !c.SessionExpires.Equal(before.SessionExpires) || len(recs) != 1 ||
		recs[0]["session"].(map[string]any)["session_expires"] != nil {
		t.Fatalf("a lengthened ceiling waits for a fresh authentication: %v, %v", c.SessionExpires, recs)
	}
	f.log.Reset()
	priors = f.reload(t, edit(t, `permit: ["**"]}`, `permit: ["**"], max_session_age: 1h}`))
	rep, err := f.b.Refresh(context.Background(), priors)
	if err != nil || rep.Updated != 1 {
		t.Fatalf("%+v %v", rep, err)
	}
	c := f.context(t, "leaf1", "alice")
	if !c.SessionExpires.Equal(c.AuthTime.Add(time.Hour)) {
		t.Fatalf("session_expires %v, auth_time %v", c.SessionExpires, c.AuthTime)
	}
	recs = eventsOf(f.records(t), "refresh")
	if len(recs) != 1 || recs[0]["session"].(map[string]any)["session_expires"] == nil {
		t.Fatalf("the record does not say the ceiling moved: %v", recs)
	}
}

// liveContextOn writes alice's leaf1 context under device too, indexed under
// her: a context the mint would refuse, as on a device with no platform.
func (f *fixture) liveContextOn(t *testing.T, device, username string) {
	t.Helper()
	ctx := context.Background()
	c := f.context(t, "leaf1", username)
	c.CtxID = "ctx-" + device + "-" + username
	if err := f.st.PutContext(ctx, store.ContextKey{NAS: device, Username: username}, c, 12*time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := f.st.IndexContext(ctx, c.Principal, "", "", store.ContextRef{NAS: device, Username: username},
		12*time.Hour); err != nil {
		t.Fatal(err)
	}
}

// A refresh record for a context on a platform that never asks about a
// command says unreached (decision 21; carried from plan 7a).
func TestARefreshRecordNamesAnUnreachedContext(t *testing.T) {
	f := newFixture(t, 8)
	f.login(t, alice, "leaf1", "alice")
	f.liveContextOn(t, "bare", "alice") // no platform: assumed out of reach, as the revocation assumes
	if _, err := f.b.Refresh(context.Background(), f.reload(t, edit(t, `permit: ["**"]`, `permit: ["show **"]`))); err != nil {
		t.Fatal(err)
	}
	recs := eventsOf(f.records(t), "refresh")
	if len(recs) != 2 {
		t.Fatalf("one record per context: %v", recs)
	}
	// leaf1 is arista_eos, which authorizes commands: its record is reached.
	for _, rec := range recs {
		s := rec["session"].(map[string]any)
		if (rec["device"].(map[string]any)["name"] == "bare") != (s["unreached"] == true) {
			t.Fatalf("unreached on the wrong record: %v", rec)
		}
	}
}

// A context the policy in force leaves as it is has no record to mark
// unreached, on a platform that never asks about a command or any other
// (pre-flight I13).
func TestAnUnchangedContextDoesNotPanic(t *testing.T) {
	f := newFixture(t, 8)
	f.login(t, alice, "leaf1", "alice")
	f.log.Reset()
	rep, err := f.b.Refresh(context.Background(), f.reload(t, testPolicy))
	if err != nil || rep.Unchanged != 1 || rep.Updated != 0 {
		t.Fatalf("%+v %v", rep, err)
	}
	if recs := eventsOf(f.records(t), "refresh"); len(recs) != 0 {
		t.Fatalf("an unchanged context is recorded: %v", recs)
	}
}

// A context with no AuthTime to anchor a ceiling to is written at the next
// refresh even when nothing else changed, so the store fails it closed with a
// ceiling in the distant past (review M-1).
func TestAContextWithNoAuthTimeIsFailedClosed(t *testing.T) {
	f := newFixture(t, 8)
	c := f.login(t, alice, "leaf1", "alice")
	c.AuthTime, c.SessionExpires = time.Time{}, time.Time{}
	if err := f.st.PutContext(context.Background(), store.ContextKey{NAS: "leaf1", Username: "alice"}, c,
		12*time.Hour); err != nil {
		t.Fatal(err)
	}
	rep, err := f.b.Refresh(context.Background(), f.reload(t, testPolicy))
	if err != nil || rep.Updated != 1 {
		t.Fatalf("%+v %v", rep, err)
	}
	if got := f.context(t, "leaf1", "alice"); got.SessionExpires.IsZero() || got.SessionExpires.After(f.now) {
		t.Fatalf("session_expires %v: not failed closed", got.SessionExpires)
	}
}

// blobTTLStore records the TTL of every blob written.
type blobTTLStore struct {
	store.Store
	mu   sync.Mutex
	ttls map[string]time.Duration
}

func (s *blobTTLStore) PutBlob(ctx context.Context, hash string, body []byte, ttl time.Duration) error {
	s.mu.Lock()
	s.ttls[hash] = ttl
	s.mu.Unlock()
	return s.Store.PutBlob(ctx, hash, body, ttl)
}

// A refresh keeps the blob it writes as long as the context naming it can
// live, as a mint does: with context_idle_ttl above max_session_age_default,
// an idle context must not outlive its blob and be denied blob_unavailable
// (final review M-4).
func TestARefreshKeepsItsBlobAsLongAsTheContext(t *testing.T) {
	f := newFixture(t, 8)
	f.login(t, alice, "leaf1", "alice")
	f.b.ContextIdleTTL = 48 * time.Hour
	rec := &blobTTLStore{Store: f.st, ttls: map[string]time.Duration{}}
	f.b.Store = rec
	priors := f.reload(t, edit(t, roleList, readOnly, aliceGrant, "roles: [read_only], max_privilege: admin"))
	if rep, err := f.b.Refresh(context.Background(), priors); err != nil || rep.Updated != 1 {
		t.Fatalf("report %+v err %v", rep, err)
	}
	after := f.context(t, "leaf1", "alice")
	if ttl := rec.ttls[after.BlobHash]; ttl < f.b.ContextIdleTTL {
		t.Fatalf("the refreshed blob is kept %v, under context_idle_ttl %v", ttl, f.b.ContextIdleTTL)
	}
}

// RefreshAtStart carries the policy in force into a context a persistent
// store kept across a restart, whatever bundle it was written under: a
// narrowing reaches it before TACACS+ binds (plan 7d, Ruling 12).
func TestRefreshAtStartCarriesThePolicyIntoKeptContexts(t *testing.T) {
	f := newFixtureWithPolicy(t, 8, sharedPolicy)
	ctx := context.Background()
	f.liveContext(t, "leaf1", "alice", alicePrincipal, "")
	k := store.ContextKey{NAS: "leaf1", Username: "alice"}
	before, err := f.st.GetContext(ctx, k)
	if err != nil {
		t.Fatal(err)
	}
	// The kept context names a blob the policy in force would not write.
	if err := f.st.SetContextPolicy(ctx, k, before.PolicyRev, store.ContextPolicy{BlobHash: "sha256:from-before",
		MaxPrivilege: before.MaxPrivilege, Enable: before.Enable}); err != nil {
		t.Fatal(err)
	}
	rep, err := f.b.RefreshAtStart(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got, err := f.st.GetContext(ctx, k)
	if err != nil || got.BlobHash == "sha256:from-before" {
		t.Fatalf("the kept context was not carried onto the policy in force: %+v %v (report %+v)", got, err, rep)
	}
}

// What a start's carry leaves unjudged is told apart by its error, since
// port49d does a different thing with each (plan 7d; decision 35, a start
// on etcd, step 6; Rulings T12-a, T12-c, T12-d):
//   - a context under a key this port49d does not hold is
//     ErrLeftUnderUnheldKey, and the start opens;
//   - a context still changing after every attempt is a plain
//     ErrConflict, and the start opens and runs a pass again at once;
//   - a principal whose contexts could not be looked up is
//     ErrPrincipalUnvisited, and holds the start, whatever else the pass
//     left before it.
func TestRefreshAtStartTellsWhatItLeft(t *testing.T) {
	const zed = "user:zed@example.com" // sorts after alicePrincipal, so it is visited after her
	kept := func(t *testing.T, f *fixture) {
		t.Helper()
		ctx := context.Background()
		f.liveContext(t, "leaf1", "alice", alicePrincipal, "")
		k := store.ContextKey{NAS: "leaf1", Username: "alice"}
		before, err := f.st.GetContext(ctx, k)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.st.SetContextPolicy(ctx, k, before.PolicyRev, store.ContextPolicy{BlobHash: "sha256:from-before",
			MaxPrivilege: before.MaxPrivilege, Enable: before.Enable}); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range []struct {
		name                    string
		arrange                 func(t *testing.T, f *fixture)
		unheld, busy, unvisited bool
	}{
		{"a context under an unheld key", func(t *testing.T, f *fixture) {
			sealedContext(t, f, testKeys("k1"))
			f.b.Store = crypt.Wrap(f.st, testKeys("k2"), nil)
		}, true, false, false},
		{"a context still changing", func(t *testing.T, f *fixture) {
			kept(t, f)
			f.b.Store = conflictingPolicyStore{f.st}
		}, false, true, false},
		{"a principal unvisited after a context still changing", func(t *testing.T, f *fixture) {
			kept(t, f)
			f.liveContextAt(t, "nx1", "zed", zed, "", f.now, f.now.Add(time.Hour))
			f.b.Store = conflictingPolicyStore{lookupFailingStore{Store: f.st, principal: zed,
				err: errors.New("test: does not parse")}}
		}, false, false, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFixtureWithPolicy(t, 8, sharedPolicy)
			c.arrange(t, f)
			_, err := f.b.RefreshAtStart(context.Background())
			if !errors.Is(err, store.ErrConflict) {
				t.Fatalf("RefreshAtStart = %v, want an ErrConflict", err)
			}
			unheld, unvisited := errors.Is(err, ErrLeftUnderUnheldKey), errors.Is(err, ErrPrincipalUnvisited)
			if unheld != c.unheld || unvisited != c.unvisited || (!unheld && !unvisited) != c.busy {
				t.Fatalf("RefreshAtStart = %v: unheld key %v, unvisited %v; want %v, %v (busy %v)", err, unheld,
					unvisited, c.unheld, c.unvisited, c.busy)
			}
		})
	}
}

// A context still changing outranks one under an unheld key, whichever
// the pass met first: the start opens either way, but only the busy one
// owes a pass at once (Ruling T12-d), and the unheld one must not hide it.
// alice2 sorts before alice, so each order is one case.
func TestRefreshAtStartPutsBusyOverUnheld(t *testing.T) {
	k1, k2 := testKeys("k1"), testKeys("k2")
	seal := func(t *testing.T, f *fixture, keys crypt.Keys, principal, device string) {
		t.Helper()
		ctx := context.Background()
		k := store.ContextKey{NAS: device, Username: "alice"}
		if err := crypt.Wrap(f.st, keys, nil).PutContext(ctx, k, store.Context{CtxID: "ctx_" + device,
			Principal: principal, Username: "alice", PrivLvl: 1, AuthTime: f.now, RefreshedAt: f.now,
			BlobHash: "sha256:from-before"}, time.Hour); err != nil {
			t.Fatal(err)
		}
		if err := f.st.IndexContext(ctx, principal, "", "", store.ContextRef{NAS: device, Username: "alice"},
			time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range []struct{ name, busy, unheld string }{
		{"busy met first", alice2, alicePrincipal},
		{"unheld met first", alicePrincipal, alice2},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFixtureWithPolicy(t, 8, sharedPolicy)
			seal(t, f, k2, c.busy, "nx1")
			seal(t, f, k1, c.unheld, "leaf1")
			f.b.Store = conflictingPolicyStore{crypt.Wrap(f.st, k2, nil)}
			_, err := f.b.RefreshAtStart(context.Background())
			if !errors.Is(err, store.ErrConflict) || errors.Is(err, ErrLeftUnderUnheldKey) ||
				errors.Is(err, ErrPrincipalUnvisited) {
				t.Fatalf("RefreshAtStart = %v, want a busy context's ErrConflict", err)
			}
		})
	}
}

// A start applies every standing mark to the contexts a persistent store
// kept, before any listener binds: a mark added to the revocations file
// with port49d stopped, or a revocation whose passes an outage cut short,
// reaches the session it was meant for (plan 7d; pre-flight C1).
func TestApplyMarksAtStartRevokesAKeptContext(t *testing.T) {
	f := newFixtureWithPolicy(t, 8, sharedPolicy)
	ctx := context.Background()
	f.liveContext(t, "leaf1", "alice", alicePrincipal, store.CertKey("CN=Corp CA", "0a"))
	f.liveContext(t, "leaf2", "alice", alicePrincipal, store.CertKey("CN=Corp CA", "0b"))
	n, err := f.b.ApplyMarksAtStart(ctx, []store.Revocation{
		{Kind: store.RevocationCert, Key: store.CertKey("CN=Corp CA", "0b"), At: f.now},
	})
	if err != nil || n != 1 {
		t.Fatalf("ApplyMarksAtStart = %d, %v; want the one context the certificate reaches", n, err)
	}
	one, _ := f.st.GetContext(ctx, store.ContextKey{NAS: "leaf1", Username: "alice"})
	two, _ := f.st.GetContext(ctx, store.ContextKey{NAS: "leaf2", Username: "alice"})
	if !one.RevokedAt.IsZero() || two.RevokedAt.IsZero() {
		t.Fatalf("leaf1 revoked %v (want no), leaf2 revoked %v (want yes)", one.RevokedAt, two.RevokedAt)
	}
	if n, err := f.b.ApplyMarksAtStart(ctx, []store.Revocation{
		{Kind: store.RevocationPrincipal, Key: alicePrincipal, At: f.now},
	}); err != nil || n != 2 {
		t.Fatalf("by principal: %d %v", n, err)
	}
}

// A kept context that will not open (sealed under a key this window
// lacks) under a certificate mark is still marked, since a revocation
// needs no key, and never fails the start: it is denied as unreadable
// anyway (re-check R-I3).
func TestApplyMarksAtStartSkipsAnUnreadableContext(t *testing.T) {
	f := newFixtureWithPolicy(t, 8, sharedPolicy)
	ctx := context.Background()
	f.liveContext(t, "leaf1", "alice", alicePrincipal, store.CertKey("CN=Corp CA", "0a"))
	k := store.ContextKey{NAS: "leaf1", Username: "alice"}
	f.b.Sessions = session.New(unreadableAt{Store: f.st, k: k}, f.b.Now, time.Hour, time.Hour)
	n, err := f.b.ApplyMarksAtStart(ctx, []store.Revocation{
		{Kind: store.RevocationCert, Key: store.CertKey("CN=Corp CA", "0a"), At: f.now},
	})
	if err != nil || n != 1 {
		t.Fatalf("ApplyMarksAtStart = %d, %v; want the unreadable context marked and no error", n, err)
	}
	if got, _ := f.st.GetContext(ctx, k); got.RevokedAt.IsZero() {
		t.Fatal("the unreadable context was not marked")
	}
}

// withoutOpsGrant is groupPolicy with the grant secret-group's members held
// through withdrawn.
var withoutOpsGrant = strings.Replace(groupPolicy,
	"  - {subject: ops, scope: all_devices, roles: [ro], max_privilege: readonly}\n", "", 1)

// reloadDir parses body for a directory and swaps it in, returning the
// prior, as reload does without one.
func (f *fixture) reloadDir(t *testing.T, body string) []Prior {
	t.Helper()
	pol, err := policy.Parse([]byte(body), policy.Env{Devices: f.inventory(), Directory: policy.DirectoryOn,
		Now: f.b.Now()})
	if err != nil {
		t.Fatal(err)
	}
	return []Prior{{Policy: f.b.Policy.Swap(pol), At: f.b.Now()}}
}

// holdMembership stores a's membership as verified at verified, refused or
// not, under a grace of an hour.
func (f *fixture) holdMembership(t *testing.T, r *directory.Resolver, a directory.Answer, verified time.Time,
	refused bool) {
	t.Helper()
	r.Cfg.Grace = time.Hour
	m := a.Membership
	m.VerifiedAt, m.Refused = verified, refused
	if err := f.st.PutMembership(context.Background(), m, 24*time.Hour); err != nil {
		t.Fatal(err)
	}
}

// memberContext writes a live context for member a on device, as the policy
// in force compiles it for her, refreshed at refreshed.
func (f *fixture) memberContext(t *testing.T, a directory.Answer, device string, refreshed time.Time) store.Context {
	t.Helper()
	ctx := context.Background()
	pol := f.b.Policy.Load()
	dev, _ := pol.Device(device)
	res, err := pol.ResolveMember(member(a), dev, f.b.Now())
	if err != nil {
		t.Fatal(err)
	}
	body, hash, err := engine.Encode(res.Blob)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.b.putBlobLogged(ctx, hash, body, 24*time.Hour); err != nil {
		t.Fatal(err)
	}
	k := store.ContextKey{NAS: device, Username: a.Username}
	if err := f.st.PutContext(ctx, k, store.Context{CtxID: "ctx_" + device, Principal: a.Principal,
		Username: a.Username, PrivLvl: 1, BlobHash: hash, MaxPrivilege: res.MaxPrivilege, Enable: res.Enable, AuthTime: f.now,
		SessionExpires: f.now.Add(12 * time.Hour), RefreshedAt: refreshed, LastTouchedAt: f.now}, 24*time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := f.st.IndexContext(ctx, a.Principal, "", "", store.ContextRef{NAS: device, Username: a.Username},
		24*time.Hour); err != nil {
		t.Fatal(err)
	}
	return f.context(t, device, a.Username)
}

// A policy reload judges a group member by the stored membership: a grant
// withdrawn from their group revokes their context with no server asked
// (Ruling 12), and refreshed_at is not touched.
func TestAReloadJudgesTheStoredMembership(t *testing.T) {
	a := answerFor(corpAlice, "alice")
	f, r := groupFixture(t, map[string]directory.Answer{corpAlice: a}, nil)
	f.holdMembership(t, r, a, f.now.Add(-10*time.Minute), false)
	before := f.memberContext(t, a, "leaf1", f.now.Add(-time.Hour))
	if rep, err := f.b.Refresh(context.Background(), []Prior{{Policy: f.b.Policy.Load(), At: f.now}}); err != nil ||
		rep.Revoked != 0 || rep.Unchanged != 1 {
		t.Fatalf("a reload that changes nothing keeps the member's context: %+v %v", rep, err)
	}
	if got := f.context(t, "leaf1", "alice"); !got.RefreshedAt.Equal(before.RefreshedAt) || !got.RevokedAt.IsZero() {
		t.Fatalf("a policy pass moved refreshed_at or revoked: %+v", got)
	}
	priors := f.reloadDir(t, withoutOpsGrant)
	f.log.Reset()
	rep, err := f.b.Refresh(context.Background(), priors)
	if err != nil || rep.Revoked != 1 {
		t.Fatalf("%+v %v", rep, err)
	}
	got := f.context(t, "leaf1", "alice")
	if got.RevokedAt.IsZero() || !got.RefreshedAt.Equal(before.RefreshedAt) {
		t.Fatalf("the withdrawn grant revokes the member's context, refreshed_at untouched: %+v", got)
	}
	if n := r.Calls.Load(); n != 0 {
		t.Fatalf("the pass asked the directory %d times", n)
	}
	recs := eventsOf(f.records(t), "refresh")
	if len(recs) != 1 || recs[0]["reason"] != "no_grants_matched" || recs[0]["principal"] != corpAlice ||
		strings.Contains(f.log.String(), "secret-group") {
		t.Fatalf("%v", recs)
	}
}

// A principal with no stored membership, a refused one, or one verified
// longer ago than directory.grace, is judged with no groups: a context held
// only through a group is revoked, and a refused membership's stored groups
// are never read (pre-flight C-1, I-14).
func TestAnAbsentRefusedOrOldMembershipIsNoGroups(t *testing.T) {
	for _, tc := range []struct {
		name     string
		store    bool
		verified time.Duration
		refused  bool
	}{
		{"absent", false, 0, false},
		{"refused", true, -time.Minute, true},
		{"past grace", true, -2 * time.Hour, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := answerFor(corpAlice, "alice")
			f, r := groupFixture(t, map[string]directory.Answer{corpAlice: a}, nil)
			f.memberContext(t, a, "leaf1", f.now.Add(-time.Hour))
			if tc.store {
				f.holdMembership(t, r, a, f.now.Add(tc.verified), tc.refused)
			}
			f.log.Reset()
			rep, err := f.b.Refresh(context.Background(), []Prior{{Policy: f.b.Policy.Load(), At: f.now}})
			if err != nil || rep.Revoked != 1 {
				t.Fatalf("%+v %v", rep, err)
			}
			if got := f.context(t, "leaf1", "alice"); got.RevokedAt.IsZero() {
				t.Fatalf("a member with no groups keeps a context held through one: %+v", got)
			}
			if rep.Unverified != 0 {
				t.Fatalf("an unverified membership is judged, not unverified: %+v", rep)
			}
		})
	}
}

// A context whose subjects' composition a joint check now refuses is
// revoked composition_refused.
func TestARefusedCompositionRevokesOnRefresh(t *testing.T) {
	f := newFixture(t, 8)
	f.login(t, alice, "leaf1", "alice")
	resolve := resolveFor
	resolveFor = func(p *policy.Policy, m policy.Member, d admission.Device, at time.Time) (policy.Resolution, error) {
		return policy.Resolution{}, policy.ErrCompositionRefused
	}
	t.Cleanup(func() { resolveFor = resolve })
	f.log.Reset()
	rep, err := f.b.Refresh(context.Background(), []Prior{{Policy: f.b.Policy.Load(), At: f.now}})
	if err != nil || rep.Revoked != 1 || rep.Failed != 0 {
		t.Fatalf("%+v %v", rep, err)
	}
	if got := f.context(t, "leaf1", "alice"); got.RevokedAt.IsZero() {
		t.Fatalf("not revoked: %+v", got)
	}
	recs := eventsOf(f.records(t), "refresh")
	if len(recs) != 1 || recs[0]["verdict"] != "deny" || recs[0]["reason"] != "composition_refused" {
		t.Fatalf("%v", recs)
	}
}

// A machine principal (app:) is judged as MemberOf under a directory, and
// keeps its context (pre-flight I-10).
func TestAMachinePrincipalIsJudgedWithoutTheDirectory(t *testing.T) {
	f, r := groupFixture(t, nil, nil)
	ci := directory.Answer{Membership: store.Membership{Principal: "app:ci-runner", Username: "ci"}}
	pol := f.b.Policy.Load()
	dev, _ := pol.Device("leaf1")
	res, err := pol.ResolveMember(policy.MemberOf("app:ci-runner"), dev, f.now)
	if err != nil {
		t.Fatal(err)
	}
	body, hash, err := engine.Encode(res.Blob)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := f.b.putBlobLogged(ctx, hash, body, 24*time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := f.st.PutContext(ctx, store.ContextKey{NAS: "leaf1", Username: "ci"}, store.Context{CtxID: "ctx_ci",
		Principal: ci.Principal, Username: "ci", PrivLvl: 1, BlobHash: hash, MaxPrivilege: res.MaxPrivilege, Enable: res.Enable,
		AuthTime: f.now, SessionExpires: f.now.Add(12 * time.Hour), RefreshedAt: f.now}, 24*time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := f.st.IndexContext(ctx, ci.Principal, "", "", store.ContextRef{NAS: "leaf1", Username: "ci"},
		24*time.Hour); err != nil {
		t.Fatal(err)
	}
	rep, err := f.b.Refresh(ctx, []Prior{{Policy: pol, At: f.now}})
	if err != nil || rep.Unchanged != 1 || rep.Revoked != 0 {
		t.Fatalf("%+v %v", rep, err)
	}
	if got := f.context(t, "leaf1", "ci"); !got.RevokedAt.IsZero() {
		t.Fatalf("a machine principal's context was revoked: %+v", got)
	}
	if n := r.Calls.Load(); n != 0 {
		t.Fatalf("a machine principal reached the directory %d times", n)
	}
}

// A reload that withdraws a group's grant supersedes its members' unspent
// tokens, though no identity subject names them (pre-flight I-13).
func TestAReloadSupersedesAGroupMembersTokens(t *testing.T) {
	a := answerFor(corpAlice, "alice")
	f, r := groupFixture(t, map[string]directory.Answer{corpAlice: a}, nil)
	f.holdMembership(t, r, a, f.now, false)
	if r := decodeMint(t, f.mintOnPinned(a, `["leaf1"]`)); r.Results[0].Verdict != "permit" {
		t.Fatalf("%+v", r)
	}
	k := store.TokenKey{NAS: "leaf1", Username: "alice"}
	if toks, _ := f.st.Candidates(context.Background(), k); len(toks) != 1 {
		t.Fatalf("%d tokens minted", len(toks))
	}
	priors := f.reloadDir(t, withoutOpsGrant)
	rep, err := f.b.Refresh(context.Background(), priors)
	if err != nil || rep.TokenKeys != 1 {
		t.Fatalf("%+v %v", rep, err)
	}
	if toks, _ := f.st.Candidates(context.Background(), k); len(toks) != 0 {
		t.Fatalf("the group member's token survived the withdrawn grant: %d", len(toks))
	}
}

// A pass's judge that gets no answer from the directory leaves the
// principal's contexts as they are and unstamped, counted unverified; one
// the directory answered no revokes them under its reason; any other error
// ends the pass (Ruling 12).
func TestAPassTellsTheDirectoryNotAnsweringFromNo(t *testing.T) {
	judge := func(err error) passJudge {
		return passJudge{member: func(context.Context, string) (policy.Member, time.Time, error) {
			return policy.Member{}, time.Time{}, err
		}}
	}
	run := func(f *fixture, err error) (RefreshReport, error) {
		rep := RefreshReport{At: f.now}
		return rep, f.b.refreshContexts(context.Background(), f.b.Policy.Load(), nil, f.now, &rep, false, judge(err))
	}
	f := newFixture(t, 8)
	before := f.login(t, alice, "leaf1", "alice")
	rep, err := run(f, fmt.Errorf("%w: no server", directory.ErrUnavailable))
	if err != nil || rep.Unverified != 1 || rep.UnverifiedPrincipals != 1 || !rep.OldestUnverified.Equal(before.RefreshedAt) ||
		rep.Revoked != 0 {
		t.Fatalf("%+v %v", rep, err)
	}
	if got := f.context(t, "leaf1", "alice"); !got.RevokedAt.IsZero() || got.PolicyRev != before.PolicyRev {
		t.Fatalf("an unverified context moved: %+v", got)
	}
	if _, err := run(f, errors.New("the store broke")); err == nil {
		t.Fatal("any other error ends the pass")
	}
	if got := f.context(t, "leaf1", "alice"); !got.RevokedAt.IsZero() {
		t.Fatalf("another error revoked: %+v", got)
	}
	f.log.Reset()
	rep, err = run(f, directory.ErrAmbiguous)
	if err != nil || rep.Revoked != 1 || !slices.Equal(rep.Narrowed, []string{alice}) {
		t.Fatalf("%+v %v", rep, err)
	}
	recs := eventsOf(f.records(t), "refresh")
	if got := f.context(t, "leaf1", "alice"); got.RevokedAt.IsZero() ||
		len(recs) != 1 || recs[0]["reason"] != "identity_ambiguous" {
		t.Fatalf("%+v %v", got, recs)
	}
}

// identityPolicy is groupPolicy with alice also listed by identity.
var identityPolicy = strings.Replace(groupPolicy,
	"  - {name: ci, identity: [\"app:ci-runner\"], username: ci, token_ttl: 60s}\n",
	"  - {name: ci, identity: [\"app:ci-runner\"], username: ci, token_ttl: 60s}\n"+
		"  - {name: alice_id, identity: [\""+corpAlice+"\"], token_ttl: 60s}\n", 1) +
	"  - {subject: alice_id, scope: all_devices, roles: [ro], max_privilege: readonly}\n"

// A directory principal listed by identity keeps her context through a
// reload during an outage longer than grace: the membership is judged with
// no groups, never with no username, and a grant added to her group in that
// reload is not written into it (spec §5.1.3; pre-flight I-14). The context
// is left unstamped, for context_stale to take over.
func TestAPastGraceMembershipStillKeysAnIdentityContext(t *testing.T) {
	a := answerFor(corpAlice, "alice")
	f, r := groupFixture(t, map[string]directory.Answer{corpAlice: a}, nil)
	f.reloadDir(t, identityPolicy)
	a.GroupDNs, a.GroupNames = nil, nil // held through identity alone
	before := f.memberContext(t, a, "leaf1", f.now.Add(-time.Hour))
	f.holdMembership(t, r, a, f.now.Add(-2*time.Hour), false)
	widened := strings.Replace(identityPolicy,
		"  - {subject: ops, scope: all_devices, roles: [ro], max_privilege: readonly}\n",
		"  - {subject: ops, scope: all_devices, roles: [network_admin], max_privilege: admin}\n", 1)
	if rep, err := f.b.Refresh(context.Background(), []Prior{{Policy: f.b.Policy.Load(), At: f.now}}); err != nil ||
		rep.Revoked != 0 || rep.Updated != 0 || rep.Unchanged != 1 {
		t.Fatalf("a reload of nothing during the outage: %+v %v", rep, err)
	}
	rep, err := f.b.Refresh(context.Background(), f.reloadDir(t, widened))
	got := f.context(t, "leaf1", "alice")
	if err != nil || rep.Revoked != 0 || !got.RevokedAt.IsZero() || got.MaxPrivilege != before.MaxPrivilege ||
		!got.RefreshedAt.Equal(before.RefreshedAt) {
		t.Fatalf("%+v %v: %+v", rep, err, got)
	}
	// Her group's new grant is not in her context: the past-grace member has no groups.
	if !f.decides(t, got, "show", "version") || f.decides(t, got, "configure", "terminal") {
		t.Fatal("the context was widened by a grant to a group the membership is too old to claim")
	}
}

// A store failing mid-pass is a failed pass, not the directory's silence:
// a deadline from the store must not count the principal unverified and let
// the pass end complete.
func TestAStoreDeadlineInAPassIsNotUnverified(t *testing.T) {
	a := answerFor(corpAlice, "alice")
	f, _ := groupFixture(t, map[string]directory.Answer{corpAlice: a}, nil)
	f.memberContext(t, a, "leaf1", f.now.Add(-time.Hour))
	f.b.Store = membershipDeadline{f.b.Store}
	f.b.Directory.Store = f.b.Store
	rep, err := f.b.Refresh(context.Background(), []Prior{{Policy: f.b.Policy.Load(), At: f.now}})
	if err == nil || rep.Unverified != 0 {
		t.Fatalf("%+v %v", rep, err)
	}
}

// membershipDeadline fails every membership read with a store deadline.
type membershipDeadline struct{ store.Store }

func (membershipDeadline) GetMembership(context.Context, string) (store.Membership, error) {
	return store.Membership{}, context.DeadlineExceeded
}
