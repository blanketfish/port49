package broker

import (
	"bytes"
	"context"
	"errors"
	"log"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/engine"
	"github.com/rhwendt/port49/internal/platform"
	"github.com/rhwendt/port49/internal/policy"
	"github.com/rhwendt/port49/internal/store"
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
func (f *fixture) login(t *testing.T, principal, device, username string) store.Context {
	t.Helper()
	cert := f.alice
	if principal != alice {
		cert = f.client(t, strings.TrimPrefix(principal, "user:"), f.now.Add(24*time.Hour))
	}
	if it := decodeMint(t, f.post(context.Background(), f.state(cert), `{"devices":["`+device+`"]}`, "")).Results[0]; it.Verdict != "permit" {
		t.Fatalf("mint for %s on %s: %+v", principal, device, it)
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
	if err := f.st.PutContext(ctx, k, c, 12*time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := f.st.IndexContext(ctx, principal, "", "", store.ContextRef{NAS: device, Username: username}, 12*time.Hour); err != nil {
		t.Fatal(err)
	}
	got, _ := f.st.GetContext(ctx, k)
	return got
}

func (f *fixture) context(t *testing.T, device, username string) store.Context {
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
		t.Fatalf("mint after the lapse: %+v", it)
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
	resolveFor = func(p *policy.Policy, principal string, d admission.Device, at time.Time) (policy.Resolution, error) {
		if d.Name == "leaf1" {
			return policy.Resolution{}, errors.New("policy: a composition the load never compiled")
		}
		return resolve(p, principal, d, at)
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
	mintedFor = func(p *policy.Policy, principal string, d admission.Device, at time.Time) (minted, bool) {
		mints++
		return was(p, principal, d, at)
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
	if len(mints) != 1 || !strings.Contains(mints[0]["index_error"].(string), "superseded") {
		t.Fatalf("the mint record says the replay was abandoned: %v", mints)
	}
	if replay := decodeMint(t, f.post(bg, f.state(f.alice), body, "retry-1")).Results[0]; replay.Login != again.Login {
		t.Fatalf("a retry after the fresh mint replays it: %+v", replay)
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
	pol, err := policy.Parse([]byte(testPolicy+"key_groups: [{match: {cidr: 172.100.100.31/32}, key_ref: k}]\n"),
		policy.Env{Devices: old.Devices(), Now: f.b.Now(), KeyRefs: []string{"k"}})
	if err != nil {
		t.Fatal(err)
	}
	priors := []Prior{{Policy: f.b.Policy.Swap(pol), At: f.b.Now()}}
	it := decodeMint(t, f.post(context.Background(), f.state(f.alice), `{"devices":["leaf1"]}`, "")).Results[0]
	if it.Verdict != "deny" || it.Reason != "device_unknown" {
		t.Fatalf("a refused device was minted for: %+v", it)
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
