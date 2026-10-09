package broker

import (
	"context"
	"errors"
	"log"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/directory"
	"github.com/rhwendt/port49/internal/engine"
	"github.com/rhwendt/port49/internal/policy"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/testpki"
)

// mappedPolicy: a human group subject and a machine_group subject.
const mappedPolicy = `
scopes:
  - {name: all_devices, match: {}}
roles:
  - {name: network_admin, privilege: admin, permit: ["**"]}
  - {name: backup, privilege: admin, permit: ["show running-config", "show version"]}
subjects:
  - {name: ops, group: secret-group, token_ttl: 60s}
  - {name: backup_hosts, machine_group: backup-hosts, token_ttl: 60s}
grants:
  - {subject: ops, scope: all_devices, roles: [network_admin], max_privilege: admin}
  - {subject: backup_hosts, scope: all_devices, roles: [backup], max_privilege: admin}
`

const workloadDN = "CN=svc-oxidized-01,OU=Workloads,DC=corp"

// workloadAnswer is the directory's answer for workloadID.
func workloadAnswer(username string, groups ...string) directory.Answer {
	return directory.Answer{Membership: store.Membership{Principal: workloadID, DN: workloadDN, EntryID: "guid:0102",
		Username: username, GroupNames: groups}, Source: directory.Fresh}
}

// mapped gives f's broker a workload mapping (decision 41) pinned to wca, over
// a static resolver answering answers by principal, or err when it is set.
func (f *fixture) mapped(wca *testpki.CA, answers map[string]directory.Answer, err error) *directory.Resolver {
	r := directory.ForTestsStaticResolver(f.st, answers, err)
	r.Cfg.Grace = time.Hour
	r.Cfg.Workload = &directory.WorkloadMapping{Attribute: "uid", Issuers: []string{wca.Cert.Subject.String()},
		UserFilter: "(objectClass=user)", TrustDomains: []string{"corp.example.com"}}
	f.b.Directory = r
	return r
}

// processLog takes the process log until the test ends.
func processLog(t *testing.T) *lockedBuffer {
	t.Helper()
	logs := &lockedBuffer{}
	prev := log.Writer()
	log.SetOutput(logs)
	t.Cleanup(func() { log.SetOutput(prev) })
	return logs
}

// Opt-in (decision 41 ruling 1; the brief's pin): with broker.directory and no
// workload mapping, a workload is plan 8's. It mints with every server down,
// the resolver is never asked, and a machine_group subject matches it not.
func TestWithoutTheMappingAWorkloadNeverReachesTheDirectory(t *testing.T) {
	f, wca, w := newWorkloadFixture(t)
	f.loadPolicy(t, strings.Replace(workloadPolicy, "grants:\n",
		"  - {name: backup_hosts, machine_group: backup-hosts, token_ttl: 60s}\ngrants:\n", 1)+
		"  - {subject: backup_hosts, scope: all_devices, roles: [network_admin], max_privilege: admin}\n")
	r := directory.ForTestsStaticResolver(f.st, nil, directory.ErrUnavailable)
	f.b.Directory = r // a directory for people, none for workloads
	resp := decodeMint(t, f.post(context.Background(), chainState(w, wca), mintLeaf1, "k1"))
	if resp.Subject != "svc_oxidized" || resp.Results[0].Verdict != decision.VerdictPermit ||
		resp.Results[0].Username != "svc-oxidized" {
		t.Fatalf("%+v", resp)
	}
	if n := r.Calls.Load(); n != 0 {
		t.Fatalf("the directory was asked %d times for an unmapped workload", n)
	}
}

// A mapped workload mints through its machine_group, under its entry's
// username; no token reaches the decision log or the process log.
func TestAMappedWorkloadMintsThroughItsMachineGroup(t *testing.T) {
	f, wca, w := newWorkloadFixture(t)
	f.loadPolicy(t, mappedPolicy)
	r := f.mapped(wca, map[string]directory.Answer{workloadID: workloadAnswer("svc-oxidized-01", "backup-hosts")}, nil)
	logs := processLog(t)
	resp := decodeMint(t, f.post(context.Background(), chainState(w, wca), mintLeaf1, "k1"))
	if resp.Principal != workloadID || resp.Subject != "backup_hosts" || len(resp.Results) != 1 ||
		resp.Results[0].Verdict != decision.VerdictPermit || resp.Results[0].Username != "svc-oxidized-01" {
		t.Fatalf("%+v", resp)
	}
	if r.Calls.Load() == 0 {
		t.Fatal("a mapped workload's mint never asked the directory")
	}
	login := resp.Results[0].Login
	if login == "" || strings.Contains(f.log.String(), login) || strings.Contains(logs.String(), login) {
		t.Fatal("a token is in a log")
	}
}

// Both directions (decision 41 ruling 5; Review Focus 3): a workload in a
// human group: subject's group gets none of it; a person in a machine_group's
// group gets none of it.
func TestAWorkloadNeverMatchesAHumanGroup(t *testing.T) {
	f, wca, w := newWorkloadFixture(t)
	f.loadPolicy(t, mappedPolicy)
	f.mapped(wca, map[string]directory.Answer{workloadID: workloadAnswer("svc-oxidized-01", "secret-group")}, nil)
	resp := decodeMint(t, f.post(context.Background(), chainState(w, wca), mintLeaf1, "k1"))
	if resp.Results[0].Verdict != decision.VerdictDeny || resp.Results[0].Reason != string(decision.NoGrantsMatched) {
		t.Fatalf("%+v", resp)
	}
}

func TestAPersonNeverMatchesAMachineGroup(t *testing.T) {
	f, wca, _ := newWorkloadFixture(t)
	f.loadPolicy(t, mappedPolicy)
	alice := answerFor(alicePrincipal, "alice")
	alice.GroupNames, alice.GroupDNs = []string{"backup-hosts"}, nil
	f.mapped(wca, map[string]directory.Answer{alicePrincipal: alice}, nil)
	resp := decodeMint(t, f.post(context.Background(), f.state(f.alice), mintLeaf1, "k1"))
	if resp.Results[0].Verdict != decision.VerdictDeny || resp.Results[0].Reason != string(decision.NoGrantsMatched) {
		t.Fatalf("%+v", resp)
	}
}

// Declared wins (decision 41 ruling 4; Review Focus 2): a workload whose own
// subject declares the username its entry also holds mints under it, never
// refused against itself, and composes its identity and machine_group grants.
func TestAWorkloadsOwnDeclaredUsernameIsNoCollision(t *testing.T) {
	f, wca, w := newWorkloadFixture(t)
	f.loadPolicy(t, strings.Replace(mappedPolicy, "grants:\n",
		"  - {name: svc_oxidized, identity: [\""+workloadID+"\"], username: svc-oxidized, token_ttl: 60s}\ngrants:\n", 1)+
		"  - {subject: svc_oxidized, scope: all_devices, roles: [backup], max_privilege: admin}\n")
	f.mapped(wca, map[string]directory.Answer{workloadID: workloadAnswer("svc-oxidized", "backup-hosts")}, nil)
	resp := decodeMint(t, f.post(context.Background(), chainState(w, wca), mintLeaf1, "k1"))
	if resp.Results[0].Verdict != decision.VerdictPermit || resp.Results[0].Username != "svc-oxidized" ||
		len(resp.Subjects) != 2 {
		t.Fatalf("%+v", resp)
	}
	// Its entry's name differs: the declared one is still the workload's.
	f.mapped(wca, map[string]directory.Answer{workloadID: workloadAnswer("svc-oxidized-01", "backup-hosts")}, nil)
	resp = decodeMint(t, f.post(context.Background(), chainState(w, wca), mintLeaf1, "k2"))
	if resp.Results[0].Username != "svc-oxidized" {
		t.Fatalf("%+v", resp)
	}
}

// An entry's username a subject declares is the workload's collision; the
// declared one stands (decision 38 ruling 3, decision 41 ruling 4).
func TestAnEntryUsernameASubjectDeclaresIsTheWorkloadsCollision(t *testing.T) {
	f, wca, w := newWorkloadFixture(t)
	f.loadPolicy(t, strings.Replace(mappedPolicy, "grants:\n",
		"  - {name: netops, identity: [\"user:alice@example.com\"], username: alice, token_ttl: 60s}\ngrants:\n", 1)+
		"  - {subject: netops, scope: all_devices, roles: [network_admin]}\n")
	f.mapped(wca, map[string]directory.Answer{workloadID: workloadAnswer("alice", "backup-hosts")}, nil)
	res := f.post(context.Background(), chainState(w, wca), mintLeaf1, "k1")
	if res.Code != http.StatusUnauthorized || !strings.Contains(res.Body.String(), `"username_collision"`) {
		t.Fatalf("%s", answer(res))
	}
}

// The 3am case (decision 41 ruling 7): a mapped workload in an outage past
// grace is refused 503 directory_unavailable with Retry-After, recorded.
func TestADirectoryOutagePastGraceStopsAMappedWorkload(t *testing.T) {
	f, wca, w := newWorkloadFixture(t)
	f.loadPolicy(t, mappedPolicy)
	f.mapped(wca, nil, directory.ErrUnavailable)
	res := f.post(context.Background(), chainState(w, wca), mintLeaf1, "k1")
	if res.Code != http.StatusServiceUnavailable || res.Header().Get("Retry-After") != "30" ||
		!strings.Contains(res.Body.String(), `"directory_unavailable"`) {
		t.Fatalf("%s", answer(res))
	}
	recs := eventsOf(f.records(t), decision.EventMint)
	if len(recs) != 1 || recs[0]["reason"] != string(decision.DirectoryUnavailable) || recs[0]["principal"] != workloadID {
		t.Fatalf("records %v", recs)
	}
}

// The issuer pin is read at every reading of the certificate, before any
// search: an issuer not pinned is identity_unmapped (decision 41 ruling 2).
func TestAnUnpinnedIssuerIsIdentityUnmapped(t *testing.T) {
	f, wca, w := newWorkloadFixture(t)
	f.loadPolicy(t, mappedPolicy)
	r := f.mapped(wca, map[string]directory.Answer{workloadID: workloadAnswer("svc-oxidized-01", "backup-hosts")}, nil)
	r.Cfg.Workload.Issuers = []string{"CN=Some Other CA"}
	res := f.post(context.Background(), chainState(w, wca), mintLeaf1, "k1")
	if res.Code != http.StatusUnauthorized || !strings.Contains(res.Body.String(), `"identity_unmapped"`) ||
		!strings.Contains(res.Body.String(), "directory.issuers") {
		t.Fatalf("%s", answer(res))
	}
	if n := r.Calls.Load(); n != 0 {
		t.Fatalf("the directory was asked %d times before the pin", n)
	}
	// The refusal names the workload refused (pre-flight M-4).
	recs := eventsOf(f.records(t), decision.EventMint)
	if len(recs) != 1 || recs[0]["reason"] != string(decision.IdentityUnmapped) || recs[0]["principal"] != workloadID {
		t.Fatalf("records %v", recs)
	}
}

// The session refresh judges the username at its hold as the mint does
// (decision 41 ruling 4; pre-flight I-1): a workload's own subject declaring
// its entry's name is no collision, and its refresh extends; another
// workload whose entry holds that name is still refused.
func TestASessionRefreshSettlesAWorkloadsUsernameAsTheMintDoes(t *testing.T) {
	f, wca, w := newWorkloadFixture(t)
	f.loadPolicy(t, strings.Replace(mappedPolicy, "grants:\n",
		"  - {name: svc_oxidized, identity: [\""+workloadID+"\"], username: svc-oxidized, token_ttl: 60s}\ngrants:\n", 1)+
		"  - {subject: svc_oxidized, scope: all_devices, roles: [backup], max_privilege: admin}\n")
	a := workloadAnswer("svc-oxidized", "backup-hosts")
	f.mapped(wca, map[string]directory.Answer{workloadID: a}, nil)
	if resp := decodeMint(t, f.post(context.Background(), chainState(w, wca), mintLeaf1, "k1")); resp.Results[0].Verdict != decision.VerdictPermit {
		t.Fatalf("the mint: %+v", resp)
	}
	// The device session the mint's token opened, as a redemption writes it;
	// then the refresh, as /v1/refresh calls it after memberFor (as
	// TestAReloadBetweenTheMemberAndTheHoldRefusesARefresh drives it).
	f.workloadContext(t, a, f.now)
	m, err := workloadMember(f.b.Policy.Load(), a)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := f.b.RefreshSession(context.Background(), m, &a, store.Credential{Method: "cert"}, f.b.Now(), nil)
	if err != nil || len(rep.Sessions) != 1 || rep.Sessions[0].Outcome != "extended" {
		t.Fatalf("its own declared username refused its refresh: %+v %v", rep, err)
	}
	other := a
	other.Principal = "spiffe://corp.example.com/host/other"
	om := policy.Member{Principal: other.Principal, Domain: policy.DomainMachines, Directory: true,
		Username: "svc-oxidized", GroupNames: other.GroupNames}
	if _, err := f.b.RefreshSession(context.Background(), om, &other, store.Credential{Method: "cert"}, f.b.Now(),
		nil); !errors.Is(err, directory.ErrUsernameTaken) {
		t.Fatalf("another workload's entry name: %v", err)
	}
}

// A reload between opting in and a workload's first verification (pre-flight
// M-2): with no membership stored, the policy pass judges it by its identity
// subject's declared username, so its live context is not revoked.
func TestAReloadBeforeAWorkloadsFirstVerificationKeepsItsDeclaredName(t *testing.T) {
	f, wca, _ := newWorkloadFixture(t)
	body := strings.Replace(mappedPolicy, "grants:\n",
		"  - {name: svc_oxidized, identity: [\""+workloadID+"\"], username: svc-oxidized, token_ttl: 60s}\ngrants:\n", 1) +
		"  - {subject: svc_oxidized, scope: all_devices, roles: [backup], max_privilege: admin}\n"
	f.loadPolicy(t, body)
	f.mapped(wca, nil, nil) // nothing stored for the workload
	f.workloadContext(t, workloadAnswer("svc-oxidized", "backup-hosts"), f.now)
	rep, err := f.b.Refresh(context.Background(), f.reloadDir(t, body))
	if err != nil || rep.Revoked != 0 {
		t.Fatalf("%+v %v", rep, err)
	}
	if got := f.context(t, "leaf1", "svc-oxidized"); !got.RevokedAt.IsZero() {
		t.Fatalf("revoked: %+v", got)
	}
}

// workloadContext writes the workload's live context on leaf1 as the policy
// in force compiles it for a, refreshed at refreshed.
func (f *fixture) workloadContext(t *testing.T, a directory.Answer, refreshed time.Time) {
	t.Helper()
	ctx := context.Background()
	pol := f.b.Policy.Load()
	dev, _ := pol.Device("leaf1")
	m, err := workloadMember(pol, a)
	if err != nil {
		t.Fatal(err)
	}
	res, err := pol.ResolveMember(m, dev, f.b.Now())
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
	if err := f.st.PutContext(ctx, store.ContextKey{NAS: "leaf1", Username: m.Username}, store.Context{CtxID: "ctx_wl",
		Principal: workloadID, Username: m.Username, PrivLvl: 1, BlobHash: hash, MaxPrivilege: res.MaxPrivilege,
		Enable: res.Enable, AuthTime: f.now, SessionExpires: f.now.Add(12 * time.Hour), RefreshedAt: refreshed,
		LastTouchedAt: f.now}, 24*time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := f.st.IndexContext(ctx, workloadID, "", "", store.ContextRef{NAS: "leaf1", Username: m.Username},
		24*time.Hour); err != nil {
		t.Fatal(err)
	}
}

// The scheduled refresh verifies a mapped workload from a server and stamps
// its context with the verification (decision 41 ruling 6).
func TestTheScheduledPassVerifiesAMappedWorkload(t *testing.T) {
	f, wca, _ := newWorkloadFixture(t)
	f.loadPolicy(t, mappedPolicy)
	a := workloadAnswer("svc-oxidized-01", "backup-hosts")
	answers := map[string]directory.Answer{workloadID: a}
	r := f.mapped(wca, answers, nil)
	f.workloadContext(t, a, f.now.Add(-time.Hour))
	f.advance(time.Minute)
	answers[workloadID] = f.verifiedNow(a)
	rep, err := f.b.RefreshDirectory(context.Background())
	if err != nil || rep.Unchanged != 1 || rep.Unverified != 0 || rep.Revoked != 0 {
		t.Fatalf("%+v %v", rep, err)
	}
	if got := f.context(t, "leaf1", "svc-oxidized-01"); !got.RefreshedAt.Equal(answers[workloadID].VerifiedAt) {
		t.Fatalf("refreshed_at %v, want the verification", got.RefreshedAt)
	}
	if r.Calls.Load() == 0 {
		t.Fatal("the pass never asked the directory for a mapped workload")
	}
}

// In an outage, the pass leaves a mapped workload's context unstamped and
// unrevoked, counted unverified: port49d denies it context_stale at the
// ceiling (decision 41 ruling 7; the daemon side is TestStaleContextDenies).
func TestAnOutageLeavesAMappedWorkloadUnstamped(t *testing.T) {
	f, wca, _ := newWorkloadFixture(t)
	f.loadPolicy(t, mappedPolicy)
	a := workloadAnswer("svc-oxidized-01", "backup-hosts")
	f.mapped(wca, nil, directory.ErrUnavailable)
	old := f.now.Add(-time.Hour)
	f.workloadContext(t, a, old)
	f.advance(time.Minute)
	rep, err := f.b.RefreshDirectory(context.Background())
	if err != nil || rep.Unverified != 1 || rep.UnverifiedPrincipals != 1 || rep.Revoked != 0 {
		t.Fatalf("%+v %v", rep, err)
	}
	if got := f.context(t, "leaf1", "svc-oxidized-01"); !got.RefreshedAt.Equal(old) || !got.RevokedAt.IsZero() {
		t.Fatalf("%+v", got)
	}
}

// forget takes a workload's SPIFFE ID verbatim (decision 41 ruling 3).
func TestForgetTakesASPIFFEID(t *testing.T) {
	f, wca, _ := newWorkloadFixture(t)
	f.mapped(wca, nil, nil)
	m := workloadAnswer("svc-oxidized-01").Membership
	m.VerifiedAt = f.now
	if err := f.st.PutMembership(context.Background(), m, 24*time.Hour); err != nil {
		t.Fatal(err)
	}
	out, err := f.b.Forget(context.Background(), workloadID, "test")
	if err != nil || !strings.Contains(out, "forgot "+workloadID) {
		t.Fatalf("%q %v", out, err)
	}
	if _, err := f.st.GetMembership(context.Background(), workloadID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("still held: %v", err)
	}
	if _, err := f.b.Forget(context.Background(), "SPIFFE://corp.example.com/host/oxidized-01", "test"); err == nil ||
		!strings.Contains(err.Error(), "is not a principal as the log spells one") {
		t.Fatalf("an upper-case scheme was taken: %v", err)
	}
	// With no workload mapping, no workload's membership is used: forget
	// says so rather than answer as if it forgot something (pre-flight M-6).
	f.b.Directory.Cfg.Workload = nil
	if _, err := f.b.Forget(context.Background(), workloadID, "test"); err == nil ||
		!strings.Contains(err.Error(), "no workload mapping is configured") {
		t.Fatalf("no mapping: %v", err)
	}
}
