package broker

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/directory"
	"github.com/rhwendt/port49/internal/testpki"
)

// workloadPolicy is testPolicy with svc_oxidized: the workload's SPIFFE ID
// and an app: client, one subject (spec §2's multi-identity subject).
const workloadPolicy = `
scopes:
  - {name: all_devices, match: {}}
roles:
  - {name: network_admin, privilege: admin, permit: ["**"]}
  - {name: backup, privilege: admin, permit: ["show running-config", "show version"]}
subjects:
  - {name: netops, identity: ["user:alice@example.com"], username: alice, enable: token, token_ttl: 60s}
  - {name: svc_oxidized, identity: ["spiffe://corp.example.com/host/oxidized-01", "app:Oxidized-01"],
     username: svc-oxidized, token_ttl: 60s}
grants:
  - {subject: netops, scope: all_devices, roles: [network_admin], max_privilege: admin}
  - {subject: svc_oxidized, scope: all_devices, roles: [backup], max_privilege: admin}
`

func newWorkloadFixture(t *testing.T) (*fixture, *testpki.CA, tls.Certificate) {
	t.Helper()
	f := newFixtureWithPolicy(t, 8, workloadPolicy)
	wca := f.withWorkload(t)
	return f, wca, f.workloadCert(t, wca, workloadID)
}

func TestAWorkloadMints(t *testing.T) {
	f, wca, w := newWorkloadFixture(t)
	resp := decodeMint(t, f.post(context.Background(), chainState(w, wca), mintLeaf1, "k1"))
	if resp.Principal != workloadID || resp.Subject != "svc_oxidized" || len(resp.Results) != 1 ||
		resp.Results[0].Verdict != decision.VerdictPermit || resp.Results[0].Username != "svc-oxidized" {
		t.Fatalf("%+v", resp)
	}
	var mint map[string]any
	for _, r := range eventsOf(f.records(t), decision.EventMint) {
		mint = r
	}
	if mint["principal"] != workloadID {
		t.Fatalf("the mint record %v", mint)
	}
	if auth, _ := mint["auth"].(map[string]any); auth["method"] != "cert" {
		t.Fatalf("auth %v", mint["auth"])
	}
}

// A workload never reaches the directory (decision 40 ruling 5): it mints
// with every server down and no grace held, and the resolver is never asked.
// A person on the same broker is answered directory_unavailable as before.
func TestAWorkloadMintsWhileTheDirectoryIsDown(t *testing.T) {
	f, wca, w := newWorkloadFixture(t)
	f.b.Directory = directory.ForTestsStaticResolver(f.st, nil, directory.ErrUnavailable)
	if res := f.post(context.Background(), chainState(w, wca), mintLeaf1, "k1"); res.Code != http.StatusOK {
		t.Fatalf("the workload: %s", answer(res))
	}
	if n := f.b.Directory.Calls.Load(); n != 0 {
		t.Fatalf("the directory was asked %d times for a workload", n)
	}
	if res := f.post(context.Background(), f.state(f.alice), mintLeaf1, "k2"); res.Code != http.StatusServiceUnavailable ||
		!strings.Contains(res.Body.String(), "directory_unavailable") {
		t.Fatalf("alice: %s", answer(res))
	}
}

// identity_unmapped over HTTP, recorded with the reason (decision 40 ruling 3).
func TestAnUnmappedWorkloadIsRefusedIdentityUnmapped(t *testing.T) {
	f, wca, _ := newWorkloadFixture(t)
	bad := f.workloadCert(t, wca, "spiffe://lab.example.net/host/x")
	res := f.post(context.Background(), chainState(bad, wca), mintLeaf1, "k1")
	if res.Code != http.StatusUnauthorized || !strings.Contains(res.Body.String(), `"identity_unmapped"`) {
		t.Fatalf("%s", answer(res))
	}
	recs := eventsOf(f.records(t), decision.EventMint)
	if len(recs) != 1 || recs[0]["reason"] != string(decision.IdentityUnmapped) {
		t.Fatalf("records %v", recs)
	}
}

// spec §2: one subject, a workload certificate and an OIDC client, one
// username; neither is a person.
func TestTwoIdentitiesOfOneSubjectMintOneUsername(t *testing.T) {
	f, wca, w := newWorkloadFixture(t)
	iss := f.withOIDC(t)
	byCert := decodeMint(t, f.post(context.Background(), chainState(w, wca), mintLeaf1, "k1"))
	now := f.b.Now()
	raw := iss.Token(t, "k1", map[string]any{"iss": iss.URL, "aud": "api://port49-svc", "sub": "svc",
		"azp": "Oxidized-01", "iat": now.Unix(), "exp": now.Add(time.Hour).Unix()})
	byApp := decodeMint(t, f.bearer(context.Background(), "POST", "/v1/tokens", mintLeaf1, raw))
	if byCert.Subject != "svc_oxidized" || byApp.Subject != "svc_oxidized" || byApp.Principal != "app:Oxidized-01" ||
		byCert.Results[0].Username != byApp.Results[0].Username {
		t.Fatalf("by certificate %+v; by OIDC %+v", byCert, byApp)
	}
}

// The declared username stands (decision 40 ruling 6): a directory person
// whose username a workload subject declares is refused username_collision,
// and the workload mints.
func TestADirectoryUsernameAWorkloadDeclaresIsTheDirectorysCollision(t *testing.T) {
	f, wca, w := newWorkloadFixture(t)
	f.loadPolicy(t, strings.Replace(workloadPolicy,
		`  - {name: netops, identity: ["user:alice@example.com"], username: alice, enable: token, token_ttl: 60s}`,
		`  - {name: netops, group: secret-group, enable: token, token_ttl: 60s}`, 1))
	withDirectory(f, map[string]directory.Answer{alicePrincipal: answerFor(alicePrincipal, "svc-oxidized")}, nil)
	res := f.post(context.Background(), f.state(f.alice), mintLeaf1, "k1")
	if res.Code != http.StatusUnauthorized || !strings.Contains(res.Body.String(), "username_collision") {
		t.Fatalf("alice: %s", answer(res))
	}
	if res := f.post(context.Background(), chainState(w, wca), mintLeaf1, "k2"); res.Code != http.StatusOK {
		t.Fatalf("the workload: %s", answer(res))
	}
}

// /v1/identity answers a workload: its SPIFFE ID, its subject, no groups.
func TestIdentityAnswersAWorkload(t *testing.T) {
	f, wca, w := newWorkloadFixture(t)
	res := f.call(context.Background(), chainState(w, wca), "GET", "/v1/identity", "")
	var id api.Identity
	if res.Code != http.StatusOK || json.Unmarshal(res.Body.Bytes(), &id) != nil || id.Principal != workloadID ||
		id.Subject != "svc_oxidized" || id.Method != "cert" || len(id.GroupDNs) != 0 {
		t.Fatalf("%s", answer(res))
	}
}

// A late renewal is said once per certificate per 24h and counted
// (decision 40 ruling 9); a certificate with time left is neither.
func TestALateRenewalIsSaidOncePerDay(t *testing.T) {
	f, wca, w := newWorkloadFixture(t)
	// logf is the standard logger's, as certcheck_test.go reads it.
	logged := &lockedBuffer{}
	prev := log.Writer()
	log.SetOutput(logged)
	t.Cleanup(func() { log.SetOutput(prev) })
	f.post(context.Background(), chainState(w, wca), mintLeaf1, "k1")
	if testutil.ToFloat64(f.b.Metrics.WorkloadRenewalLate) != 0 {
		t.Fatal("a certificate with 23h of 24h left was counted late")
	}
	f.advance(19 * time.Hour) // 4h of 24h left: under a quarter
	for i := range 3 {
		f.post(context.Background(), chainState(w, wca), mintLeaf1, "k"+string(rune('2'+i)))
	}
	if got := testutil.ToFloat64(f.b.Metrics.WorkloadRenewalLate); got != 1 {
		t.Fatalf("counted %v times, want once", got)
	}
	if n := strings.Count(logged.String(), "its renewal is late"); n != 1 ||
		!strings.Contains(logged.String(), "workload certificate "+workloadID) {
		t.Fatalf("the process log: %q", logged.String())
	}
}

// spec §14: a scope's attached_roles.machines compose into a workload's
// grant, and attached_roles.humans do not (pre-flight M-14). The workload
// explains its own commands, which needs no api: right.
func TestAttachedRolesComposeByTheWorkloadsDomain(t *testing.T) {
	f, wca, w := newWorkloadFixture(t)
	f.loadPolicy(t, strings.NewReplacer(
		`  - {name: all_devices, match: {}}`,
		`  - {name: all_devices, match: {}, attached_roles: {humans: [no_version], machines: [no_config]}}`,
		`  - {name: backup, privilege: admin, permit: ["show running-config", "show version"]}`,
		`  - {name: backup, privilege: admin, permit: ["show running-config", "show version"]}
  - {name: no_version, deny: ["show version"]}
  - {name: no_config, deny: ["show running-config"]}`,
	).Replace(workloadPolicy))
	for cmd, want := range map[string]string{"show running-config": "deny", "show version": "permit"} {
		res := f.call(context.Background(), chainState(w, wca), "POST", "/v1/explain",
			`{"device":"leaf1","command":"`+cmd+`"}`)
		if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), `"verdict":"`+want+`"`) {
			t.Errorf("%s: want %s: %s", cmd, want, answer(res))
		}
	}
}

// methods names how a person authenticates (decision 40 ruling 12): a broker
// whose one x509 verifier is the workloads' offers people oidc alone.
func TestConfigMethodsNameAPersonsMethods(t *testing.T) {
	f, _, _ := newWorkloadFixture(t)
	f.withOIDC(t)
	f.b.NoX509 = true
	res := f.call(context.Background(), &tls.ConnectionState{}, "GET", "/v1/config", "")
	var c api.Config
	if json.Unmarshal(res.Body.Bytes(), &c) != nil || strings.Join(c.Methods, ",") != "oidc" {
		t.Fatalf("%s", answer(res))
	}
}

// The handshake's pool holds both anchors, and a workload-only broker serves.
func TestTheServersPoolHoldsBothAnchors(t *testing.T) {
	f, wca, _ := newWorkloadFixture(t)
	srv, err := f.b.Server("127.0.0.1:0", tls.Certificate{}, f.ca.Pool())
	if err != nil {
		t.Fatal(err)
	}
	want := x509.NewCertPool()
	want.AddCert(f.ca.Cert)
	want.AddCert(wca.Cert)
	if !srv.TLSConfig.ClientCAs.Equal(want) || srv.TLSConfig.ClientAuth != tls.VerifyClientCertIfGiven {
		t.Fatal("ClientCAs is not both anchors")
	}
	f.b.NoX509 = true
	f.withOIDC(t)
	srv, err = f.b.Server("127.0.0.1:0", tls.Certificate{}, nil)
	if err != nil || srv.TLSConfig.ClientAuth != tls.VerifyClientCertIfGiven {
		t.Fatalf("a broker whose one x509 verifier is the workloads': %v", err)
	}
	only := x509.NewCertPool()
	only.AddCert(wca.Cert)
	if !srv.TLSConfig.ClientCAs.Equal(only) {
		t.Fatal("ClientCAs is not the workload anchor alone")
	}
}

// Only a certificate that is served is counted late: one refused
// credential_revoked is told nothing more, and the operator's alert on the
// counter stays true.
func TestARefusedLateWorkloadIsNotCountedLate(t *testing.T) {
	f, wca, w := newWorkloadFixture(t)
	logged := &lockedBuffer{}
	prev := log.Writer()
	log.SetOutput(logged)
	t.Cleanup(func() { log.SetOutput(prev) })
	cc, err := f.b.CertCallerOf(chainState(w, wca), f.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.b.Revoke(context.Background(), RevokeRequest{Issuer: w.Leaf.Issuer.String(),
		Serial: cc.Cred.Serial, Origin: "t"}); err != nil {
		t.Fatal(err)
	}
	f.advance(19 * time.Hour)
	res := f.post(context.Background(), chainState(w, wca), mintLeaf1, "k1")
	if res.Code != http.StatusUnauthorized || !strings.Contains(res.Body.String(), "credential_revoked") {
		t.Fatalf("%s", answer(res))
	}
	if got := testutil.ToFloat64(f.b.Metrics.WorkloadRenewalLate); got != 0 {
		t.Fatalf("a refused certificate was counted late %v times", got)
	}
	if strings.Contains(logged.String(), "its renewal is late") {
		t.Fatalf("the process log: %q", logged.String())
	}
}
