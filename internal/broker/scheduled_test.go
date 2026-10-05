package broker

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/directory"
	"github.com/rhwendt/port49/internal/engine"
	"github.com/rhwendt/port49/internal/policy"
	"github.com/rhwendt/port49/internal/store"
)

// widenedOps is groupPolicy with the grant secret-group's members hold widened
// from read-only to admin.
var widenedOps = strings.Replace(groupPolicy,
	"  - {subject: ops, scope: all_devices, roles: [ro], max_privilege: readonly}\n",
	"  - {subject: ops, scope: all_devices, roles: [network_admin], max_privilege: admin}\n", 1)

// answering gives f's broker a static resolver that answers from answers as
// the map stands at each call, a grace of an hour, so a test changes what the
// directory says between passes.
func (f *fixture) answering(answers map[string]directory.Answer) *directory.Resolver {
	r := directory.ForTestsFuncResolver(f.st, func(principal string) (directory.Answer, error) {
		a, ok := answers[principal]
		if !ok {
			return directory.Answer{}, fmt.Errorf("%w: no entry for %s", directory.ErrUnmapped, principal)
		}
		return a, nil
	})
	r.Cfg.Grace = time.Hour
	f.b.Directory = r
	return r
}

// verifiedNow is a's answer as a server gives it at the fixture's clock.
func (f *fixture) verifiedNow(a directory.Answer) directory.Answer {
	a.VerifiedAt = f.b.Now()
	return a
}

// The scheduled pass verifies each active principal, stamps every context
// it judged with the verification time, changed or not, and writes a
// record only for a change (spec §5.1.3).
func TestTheScheduledPassStamps(t *testing.T) {
	ctx := context.Background()
	a := answerFor(corpAlice, "alice")
	f, _ := groupFixture(t, nil, nil)
	answers := map[string]directory.Answer{corpAlice: a}
	f.answering(answers)
	old := f.now.Add(-time.Hour)
	f.memberContext(t, a, "leaf1", old)
	f.memberContext(t, a, "nx1", old)
	f.advance(10 * time.Minute)
	a = f.verifiedNow(a)
	answers[corpAlice] = a
	f.log.Reset()

	rep, err := f.b.RefreshDirectory(ctx)
	if err != nil || rep.Unchanged != 2 || rep.Updated != 0 || rep.Revoked != 0 || rep.Unverified != 0 {
		t.Fatalf("%+v %v", rep, err)
	}
	for _, dev := range []string{"leaf1", "nx1"} {
		if got := f.context(t, dev, "alice"); !got.RefreshedAt.Equal(a.VerifiedAt) || !got.RevokedAt.IsZero() {
			t.Fatalf("%s: refreshed_at %v, want the verification %v: %+v", dev, got.RefreshedAt, a.VerifiedAt, got)
		}
	}
	if recs := eventsOf(f.records(t), "refresh"); len(recs) != 0 {
		t.Fatalf("a pass that changed nothing wrote records: %v", recs)
	}
	if v := testutil.ToFloat64(f.b.Metrics.DirectoryRefreshLastComplete); v != float64(rep.At.Unix()) {
		t.Fatalf("last complete %v, want %d", v, rep.At.Unix())
	}

	// A grant widened since: the contexts are rewritten, stamped, and each
	// recorded once.
	f.reloadDir(t, widenedOps)
	f.advance(10 * time.Minute)
	answers[corpAlice] = f.verifiedNow(a)
	f.log.Reset()
	rep, err = f.b.RefreshDirectory(ctx)
	if err != nil || rep.Updated != 2 || rep.Revoked != 0 {
		t.Fatalf("%+v %v", rep, err)
	}
	got := f.context(t, "leaf1", "alice")
	if !got.RefreshedAt.Equal(f.b.Now()) || !f.decides(t, got, "configure", "terminal") {
		t.Fatalf("the widened context is stamped and permits: %+v", got)
	}
	if recs := eventsOf(f.records(t), "refresh"); len(recs) != 2 || recs[0]["reason"] != "grants_matched" ||
		strings.Contains(f.log.String(), "secret-group") {
		t.Fatalf("%v", recs)
	}
}

// A directory that does not answer leaves every context unstamped and
// unrevoked, counted unverified (Ruling 12; spec §14 "Directory").
func TestAnOutageStampsNothingAndRevokesNothing(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"no server", fmt.Errorf("%w: no server answered", directory.ErrUnavailable)},
		{"a deadline", fmt.Errorf("the search: %w", context.DeadlineExceeded)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := answerFor(corpAlice, "alice")
			f, _ := groupFixture(t, nil, nil)
			f.b.Directory = directory.ForTestsStaticResolver(f.st, nil, tc.err)
			old := f.now.Add(-time.Hour)
			f.memberContext(t, a, "leaf1", old)
			f.memberContext(t, a, "nx1", old.Add(-time.Minute))
			f.advance(time.Minute)
			rep, err := f.b.RefreshDirectory(context.Background())
			if err != nil || rep.Unverified != 2 || rep.UnverifiedPrincipals != 1 ||
				!rep.OldestUnverified.Equal(old.Add(-time.Minute)) || rep.Updated+rep.Unchanged+rep.Revoked != 0 {
				t.Fatalf("%+v %v", rep, err)
			}
			if got := f.context(t, "leaf1", "alice"); !got.RefreshedAt.Equal(old) || !got.RevokedAt.IsZero() {
				t.Fatalf("a context moved with the directory silent: %+v", got)
			}
			if v := testutil.ToFloat64(f.b.Metrics.DirectoryRefreshLastComplete); v != 0 {
				t.Fatalf("an incomplete pass is complete: %v", v)
			}
			if len(rep.Narrowed) != 0 {
				t.Fatalf("a silent directory supersedes tokens: %v", rep.Narrowed)
			}
		})
	}
}

// An entry gone revokes identity_unmapped; two entries identity_ambiguous;
// a username taken username_collision; and each principal's unspent
// tokens are superseded (pre-flight I-13). None is stamped.
func TestAGoneOrAmbiguousEntryRevokes(t *testing.T) {
	ctx := context.Background()
	people := map[string]directory.Answer{}
	for _, name := range []string{"alice", "bob", "carol"} {
		people["user:"+name+"@corp.example.com"] = answerFor("user:"+name+"@corp.example.com", name)
	}
	f, _ := groupFixture(t, nil, nil)
	f.answering(people)
	old := f.now.Add(-time.Hour)
	for _, a := range people {
		f.memberContext(t, a, "leaf1", old)
		if r := decodeMint(t, f.mintOnPinned(a, `["leaf1"]`)); r.Results[0].Verdict != "permit" {
			t.Fatalf("%+v", r)
		}
	}
	refusal := map[string]error{"user:alice@corp.example.com": directory.ErrUnmapped,
		"user:bob@corp.example.com": directory.ErrAmbiguous, "user:carol@corp.example.com": directory.ErrUsernameTaken}
	f.b.Directory = directory.ForTestsFuncResolver(f.st, func(p string) (directory.Answer, error) {
		return directory.Answer{}, refusal[p]
	})
	f.advance(10 * time.Second) // inside the tokens' 60s
	f.log.Reset()
	rep, err := f.b.RefreshDirectory(ctx)
	if err != nil || rep.Revoked != 3 || rep.TokenKeys != 3 || rep.Unverified != 0 {
		t.Fatalf("%+v %v", rep, err)
	}
	want := map[string]string{"alice": "identity_unmapped", "bob": "identity_ambiguous", "carol": "username_collision"}
	got := map[string]string{}
	for _, rec := range eventsOf(f.records(t), "refresh") {
		got[strings.TrimSuffix(strings.TrimPrefix(rec["principal"].(string), "user:"), "@corp.example.com")] =
			rec["reason"].(string)
	}
	for name, reason := range want {
		if got[name] != reason {
			t.Errorf("%s: reason %q, want %q", name, got[name], reason)
		}
		c := f.context(t, "leaf1", name)
		if c.RevokedAt.IsZero() || !c.RefreshedAt.Equal(old) {
			t.Errorf("%s: revoked and unstamped, got %+v", name, c)
		}
		if toks, _ := f.st.Candidates(ctx, store.TokenKey{NAS: "leaf1", Username: name}); len(toks) != 0 {
			t.Errorf("%s: %d unspent tokens survive the refusal", name, len(toks))
		}
	}
}

// Without a directory the pass judges on the policy and stamps its own
// instant: the ceiling bounds a broker outage (Ruling 12).
func TestWithoutADirectoryThePassStampsItsInstant(t *testing.T) {
	f := newFixture(t, 8)
	before := f.login(t, alice, "leaf1", "alice")
	f.advance(30 * time.Minute)
	rep, err := f.b.RefreshDirectory(context.Background())
	if err != nil || rep.Unchanged != 1 || rep.Revoked != 0 {
		t.Fatalf("%+v %v", rep, err)
	}
	got := f.context(t, "leaf1", "alice")
	if !got.RefreshedAt.Equal(rep.At) || !got.RefreshedAt.After(before.RefreshedAt) || !got.RevokedAt.IsZero() {
		t.Fatalf("refreshed_at %v, want the pass's instant %v: %+v", got.RefreshedAt, rep.At, got)
	}
}

// machineContext writes ci's live context on leaf1 as the policy in force
// compiles it, refreshed at refreshed.
func (f *fixture) machineContext(t *testing.T, refreshed time.Time) {
	t.Helper()
	ctx := context.Background()
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
	if err := f.b.putBlobLogged(ctx, hash, body, 24*time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := f.st.PutContext(ctx, store.ContextKey{NAS: "leaf1", Username: "ci"}, store.Context{CtxID: "ctx_ci",
		Principal: "app:ci-runner", Username: "ci", PrivLvl: 1, BlobHash: hash, MaxPrivilege: res.MaxPrivilege,
		Enable: res.Enable, AuthTime: f.now, SessionExpires: f.now.Add(12 * time.Hour), RefreshedAt: refreshed}, 24*time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := f.st.IndexContext(ctx, "app:ci-runner", "", "", store.ContextRef{NAS: "leaf1", Username: "ci"},
		24*time.Hour); err != nil {
		t.Fatal(err)
	}
}

// A machine principal's context under a directory is judged as MemberOf,
// stamped with the pass's instant, and never revoked identity_unmapped
// (pre-flight I-10).
func TestAMachinePrincipalIsStampedAndKept(t *testing.T) {
	f, _ := groupFixture(t, nil, nil)
	r := f.answering(map[string]directory.Answer{})
	f.machineContext(t, f.now.Add(-time.Hour))
	f.advance(time.Minute)
	rep, err := f.b.RefreshDirectory(context.Background())
	if err != nil || rep.Unchanged != 1 || rep.Revoked != 0 || rep.Unverified != 0 {
		t.Fatalf("%+v %v", rep, err)
	}
	if got := f.context(t, "leaf1", "ci"); !got.RevokedAt.IsZero() || !got.RefreshedAt.Equal(rep.At) {
		t.Fatalf("a machine principal's context: %+v", got)
	}
	if n := r.Calls.Load(); n != 0 {
		t.Fatalf("a machine principal reached the directory %d times", n)
	}
}

// A removal from a group reaches the live context at the next pass:
// revoked no_grants_matched, the next command denied credential_revoked.
func TestARemovalReachesTheSessionAtTheNextPass(t *testing.T) {
	a := answerFor(corpAlice, "alice")
	f, _ := groupFixture(t, nil, nil)
	answers := map[string]directory.Answer{corpAlice: a}
	f.answering(answers)
	f.memberContext(t, a, "leaf1", f.now)
	f.advance(time.Minute)
	if rep, err := f.b.RefreshDirectory(context.Background()); err != nil || rep.Revoked != 0 || rep.Unchanged != 1 {
		t.Fatalf("the member still in the group: %+v %v", rep, err)
	}
	// The directory now says she left the group.
	left := f.verifiedNow(a)
	left.GroupDNs, left.GroupNames = nil, nil
	answers[corpAlice] = left
	f.advance(time.Minute)
	f.log.Reset()
	rep, err := f.b.RefreshDirectory(context.Background())
	if err != nil || rep.Revoked != 1 {
		t.Fatalf("%+v %v", rep, err)
	}
	if got := f.context(t, "leaf1", "alice"); got.RevokedAt.IsZero() {
		t.Fatalf("the removal did not revoke: %+v", got)
	}
	recs := eventsOf(f.records(t), "refresh")
	if len(recs) != 1 || recs[0]["reason"] != "no_grants_matched" || recs[0]["verdict"] != "deny" ||
		strings.Contains(f.log.String(), "secret-group") {
		t.Fatalf("%v", recs)
	}
}

// A reload that lands while the pass is verifying a principal is the
// policy that principal is judged and written under: the pass never
// writes a superseded policy over a reload's (pre-flight I-11). The
// static resolver's answer for the principal swaps the policy (b.Policy.Swap)
// before returning.
func TestAReloadDuringThePassIsThePolicyItWrites(t *testing.T) {
	a := answerFor(corpAlice, "alice")
	f, _ := groupFixture(t, nil, nil)
	f.memberContext(t, a, "leaf1", f.now.Add(-time.Hour))
	f.advance(time.Minute)
	a = f.verifiedNow(a)
	reloaded, perr := policy.Parse([]byte(withoutOpsGrant), policy.Env{Devices: f.inventory(),
		Directory: policy.DirectoryOn, Now: f.b.Now()})
	if perr != nil {
		t.Fatal(perr)
	}
	swapped := false
	f.b.Directory = directory.ForTestsFuncResolver(f.st, func(string) (directory.Answer, error) {
		if !swapped {
			swapped = true
			f.b.Policy.Swap(reloaded) // blocks while a Hold is held: the pass must hold none here
		}
		return a, nil
	})
	done := make(chan struct{})
	var rep RefreshReport
	var err error
	go func() {
		defer close(done)
		rep, err = f.b.RefreshDirectory(context.Background())
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the pass held the policy while it asked the directory: a reload waited on a query")
	}
	if err != nil || rep.Revoked != 1 || rep.Unchanged != 0 {
		t.Fatalf("%+v %v", rep, err)
	}
	if got := f.context(t, "leaf1", "alice"); got.RevokedAt.IsZero() {
		t.Fatalf("judged under the superseded policy, not the reload's: %+v", got)
	}
}

// A widening rewrites the context and clears the unspent tokens, a re-mint,
// and revokes nothing the member still holds (Task 14 review M-2).
func TestAWideningNeverRevokesAndOnlyReMints(t *testing.T) {
	ctx := context.Background()
	a := answerFor(corpAlice, "alice")
	f, _ := groupFixture(t, nil, nil)
	f.answering(map[string]directory.Answer{corpAlice: a})
	f.memberContext(t, a, "leaf1", f.now)
	if r := decodeMint(t, f.mintOnPinned(a, `["leaf1"]`)); r.Results[0].Verdict != "permit" {
		t.Fatalf("%+v", r)
	}
	f.reloadDir(t, widenedOps)
	f.advance(10 * time.Second) // inside the token's 60s
	rep, err := f.b.RefreshDirectory(ctx)
	if err != nil || rep.Updated != 1 || rep.Revoked != 0 || rep.TokenKeys != 1 {
		t.Fatalf("%+v %v", rep, err)
	}
	got := f.context(t, "leaf1", "alice")
	if !got.RevokedAt.IsZero() || !f.decides(t, got, "show", "version") || !f.decides(t, got, "configure", "terminal") {
		t.Fatalf("a widening left the live context short of what it holds: %+v", got)
	}
	k := store.TokenKey{NAS: "leaf1", Username: "alice"}
	if toks, _ := f.st.Candidates(ctx, k); len(toks) != 0 {
		t.Fatalf("the token minted under the narrower grant survived: %d", len(toks))
	}
	if r := decodeMint(t, f.mintOnPinned(a, `["leaf1"]`)); r.Results[0].Verdict != "permit" {
		t.Fatalf("a re-mint after a widening: %+v", r)
	}
}

// aliceDeclared is groupPolicy with a subject declaring the username alice,
// the one the directory derives for the group member.
var aliceDeclared = strings.Replace(groupPolicy,
	"  - {name: ci, identity: [\"app:ci-runner\"], username: ci, token_ttl: 60s}\n",
	"  - {name: ci, identity: [\"app:ci-runner\"], username: ci, token_ttl: 60s}\n"+
		"  - {name: svc_alice, identity: [\"app:alice-svc\"], username: alice, token_ttl: 60s}\n", 1) +
	"  - {subject: svc_alice, scope: all_devices, roles: [ro]}\n"

// A directory member whose username a subject declares is refused
// username_collision, never kept: by a policy pass over a stored
// membership within grace or past it, and by the scheduled pass (pre-flight
// M-11; Task 14 review).
func TestADeclaredUsernameRefusesTheDirectoryMemberOnEveryPass(t *testing.T) {
	for _, tc := range []struct {
		name string
		run  func(t *testing.T, f *fixture, a directory.Answer, r *directory.Resolver) (RefreshReport, error)
	}{
		{"a policy pass within grace", func(t *testing.T, f *fixture, a directory.Answer, r *directory.Resolver) (RefreshReport, error) {
			f.holdMembership(t, r, a, f.now.Add(-10*time.Minute), false)
			return f.b.Refresh(context.Background(), []Prior{{Policy: f.b.Policy.Load(), At: f.now}})
		}},
		{"a policy pass past grace", func(t *testing.T, f *fixture, a directory.Answer, r *directory.Resolver) (RefreshReport, error) {
			f.holdMembership(t, r, a, f.now.Add(-2*time.Hour), false)
			return f.b.Refresh(context.Background(), []Prior{{Policy: f.b.Policy.Load(), At: f.now}})
		}},
		{"the scheduled pass", func(t *testing.T, f *fixture, a directory.Answer, r *directory.Resolver) (RefreshReport, error) {
			return f.b.RefreshDirectory(context.Background())
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := answerFor(corpAlice, "alice")
			f, _ := groupFixture(t, nil, nil)
			r := f.answering(map[string]directory.Answer{corpAlice: f.verifiedNow(a)})
			before := f.memberContext(t, a, "leaf1", f.now.Add(-time.Hour))
			f.reloadDir(t, aliceDeclared)
			r.Declared = func() map[string]string { return f.b.Policy.Load().DeclaredUsernames() }
			f.advance(time.Minute)
			f.log.Reset()
			rep, err := tc.run(t, f, a, r)
			if err != nil || rep.Revoked != 1 || rep.Updated+rep.Unchanged != 0 {
				t.Fatalf("%+v %v", rep, err)
			}
			got := f.context(t, "leaf1", "alice")
			if got.RevokedAt.IsZero() || !got.RefreshedAt.Equal(before.RefreshedAt) {
				t.Fatalf("the directory member kept a context under a username a subject declares: %+v", got)
			}
			recs := eventsOf(f.records(t), "refresh")
			if len(recs) != 1 || recs[0]["reason"] != "username_collision" || strings.Contains(f.log.String(), "secret-group") {
				t.Fatalf("%v", recs)
			}
		})
	}
}

// One principal's directory error that is neither a refusal nor an outage (an
// LDAP 50 on a protected account, say) leaves that principal unverified,
// unstamped and unrevoked, and the pass goes on: the principals after it are
// stamped, and the pass still returns the error and is not complete.
func TestOnePrincipalsDirectoryErrorDoesNotEndThePass(t *testing.T) {
	aaron := answerFor("user:aaron@corp.example.com", "aaron")
	bob := answerFor("user:bob@corp.example.com", "bob")
	f, _ := groupFixture(t, nil, nil)
	old := f.now.Add(-time.Hour)
	f.memberContext(t, aaron, "leaf1", old)
	f.memberContext(t, bob, "leaf1", old)
	f.advance(time.Minute)
	bob = f.verifiedNow(bob)
	f.b.Directory = directory.ForTestsFuncResolver(f.st, func(p string) (directory.Answer, error) {
		if p == aaron.Principal {
			return directory.Answer{}, errors.New("LDAP Result Code 50 \"Insufficient Access Rights\"")
		}
		return bob, nil
	})
	rep, err := f.b.RefreshDirectory(context.Background())
	if err == nil || rep.UnverifiedPrincipals != 1 || rep.Unverified != 1 || rep.Unchanged != 1 {
		t.Fatalf("%+v %v", rep, err)
	}
	if got := f.context(t, "leaf1", "aaron"); !got.RefreshedAt.Equal(old) || !got.RevokedAt.IsZero() {
		t.Fatalf("the erroring principal's context moved: %+v", got)
	}
	if got := f.context(t, "leaf1", "bob"); !got.RefreshedAt.Equal(bob.VerifiedAt) {
		t.Fatalf("the principal after the error was not stamped: %+v", got)
	}
	if v := testutil.ToFloat64(f.b.Metrics.DirectoryRefreshLastComplete); v != 0 {
		t.Fatalf("an incomplete pass is complete: %v", v)
	}
}

// An inventory-only swap leaves a context alone at the scheduled pass as at
// the policy pass: stamped, not rewritten, not recorded, its tokens kept
// (plan 6a Decided 3; spec §5.1.3).
func TestAnInventoryOnlySwapIsNotARewriteAtTheScheduledPass(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, 8)
	f.login(t, alice, "leaf1", "alice")
	f.post(ctx, f.state(f.alice), `{"devices":["nx1"]}`, "") // an unspent token
	before := f.context(t, "leaf1", "alice")
	old := f.b.Policy.Load()
	extra := admission.Device{Name: "leaf9", Platform: "arista_eos", Addresses: []netip.Addr{netip.MustParseAddr("172.100.100.19")}}
	pol, err := policy.Parse([]byte(testPolicy), policy.Env{Devices: append(old.Devices(), extra), Now: f.b.Now(),
		Bundle: "sha256:" + strings.Repeat("b", 64)})
	if err != nil {
		t.Fatal(err)
	}
	f.b.Policy.Swap(pol)
	f.advance(10 * time.Second)
	f.log.Reset()
	rep, err := f.b.RefreshDirectory(ctx)
	if err != nil || rep.Unchanged != 1 || rep.Updated != 0 || rep.TokenKeys != 0 {
		t.Fatalf("%+v %v", rep, err)
	}
	after := f.context(t, "leaf1", "alice")
	if after.BlobHash != before.BlobHash || !after.RefreshedAt.Equal(rep.At) {
		t.Fatalf("rewritten or unstamped: %+v", after)
	}
	if strings.Contains(f.log.String(), `"event":"refresh"`) {
		t.Fatalf("an unchanged context was recorded: %s", f.log.String())
	}
	if toks, _ := f.st.Candidates(ctx, store.TokenKey{NAS: "nx1", Username: "alice"}); len(toks) != 1 {
		t.Fatalf("the unspent token was cleared: %d", len(toks))
	}
}

// A collided member's unspent tokens are cleared at once, by the policy pass
// and by every replica's token pass, and an unrelated member's token at its
// own key stands: a token minted before a subject declared the username must
// not redeem under it.
func TestACollidedMembersTokensAreClearedAtOnce(t *testing.T) {
	for _, tc := range []struct {
		name string
		run  func(f *fixture, priors []Prior) error
	}{
		{"the policy pass", func(f *fixture, priors []Prior) error {
			_, err := f.b.Refresh(context.Background(), priors)
			return err
		}},
		{"the token pass", func(f *fixture, priors []Prior) error {
			_, err := f.b.RefreshTokens(context.Background(), priors)
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			a, bob := answerFor(corpAlice, "alice"), answerFor("user:bob@corp.example.com", "bob")
			f, _ := groupFixture(t, nil, nil)
			r := f.answering(map[string]directory.Answer{corpAlice: a, bob.Principal: bob})
			f.holdMembership(t, r, a, f.now, false)
			f.holdMembership(t, r, bob, f.now, false)
			for _, m := range []directory.Answer{a, bob} {
				if res := decodeMint(t, f.mintOnPinned(m, `["leaf1"]`)); res.Results[0].Verdict != "permit" {
					t.Fatalf("%+v", res)
				}
			}
			priors := f.reloadDir(t, aliceDeclared)
			r.Declared = func() map[string]string { return f.b.Policy.Load().DeclaredUsernames() }
			f.advance(10 * time.Second)
			if err := tc.run(f, priors); err != nil {
				t.Fatal(err)
			}
			if toks, _ := f.st.Candidates(ctx, store.TokenKey{NAS: "leaf1", Username: "alice"}); len(toks) != 0 {
				t.Fatalf("the collided member's token survived: %d", len(toks))
			}
			if toks, _ := f.st.Candidates(ctx, store.TokenKey{NAS: "leaf1", Username: "bob"}); len(toks) != 1 {
				t.Fatalf("an unrelated member's token was cleared: %d", len(toks))
			}
		})
	}
}
