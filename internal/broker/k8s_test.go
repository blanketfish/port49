package broker

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"strings"
	"testing"

	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/oidc/oidctest"
)

const clusterPolicy = `
scopes:
  - {name: all_devices, match: {}}
roles:
  - {name: network_admin, privilege: admin, permit: ["**"]}
subjects:
  - {name: netops, identity: ["user:alice@example.com"], username: alice, enable: token, token_ttl: 60s}
  - {name: backup, identity: ["system:serviceaccount:netops:oxidized"], username: svc-backup, token_ttl: 60s}
grants:
  - {subject: netops, scope: all_devices, roles: [network_admin], max_privilege: admin}
  - {subject: backup, scope: all_devices, roles: [network_admin], max_privilege: admin}
`

func TestAServiceAccountMints(t *testing.T) {
	f := newFixtureWithPolicy(t, 8, clusterPolicy)
	iss := f.withCluster(t)
	raw := iss.ServiceAccountToken(t, "k1", k8sTestIssuer, "port49", "netops", "oxidized", f.b.Now(), nil)
	w := f.bearer(context.Background(), "POST", "/v1/tokens", mintLeaf1, raw)
	resp := decodeMint(t, w)
	if w.Code != 200 || resp.Principal != "system:serviceaccount:netops:oxidized" || resp.Results[0].Username != "svc-backup" {
		t.Fatalf("%s", shown(w))
	}
	recs := eventsOf(f.records(t), decision.EventMint)
	auth := recs[len(recs)-1]["auth"].(map[string]any)
	k := auth["k8s"].(map[string]any)
	if auth["method"] != "k8s" || auth["oidc"] != nil || k["cluster"] != "l69_a" || k["issuer"] != k8sTestIssuer ||
		k["sub"] != "system:serviceaccount:netops:oxidized" || k["pod"] != "oxidized-7d9f" || k["pod_uid"] == "" ||
		k["serviceaccount_uid"] == "" || k["node"] != "l69-a-worker" || k["jti"] == "" {
		t.Fatalf("the record's auth: %v", auth)
	}
	if strings.Contains(f.log.String(), raw) {
		t.Fatal("the token was logged")
	}
}

// Two clusters listing netops both mint as its service account (decision 49
// ruling 4, ruled 2026-10-16), and each record says which cluster minted.
func TestTwoClustersMintAsOneServiceAccount(t *testing.T) {
	f := newFixtureWithPolicy(t, 8, clusterPolicy)
	east := f.withClusterNamed(t, "us_east", "https://us-east.port49.lab")
	west := f.withClusterNamed(t, "eu_west", "https://eu-west.port49.lab")
	for _, c := range []struct {
		iss             *oidctest.Issuer
		cluster, issuer string
	}{{east, "us_east", "https://us-east.port49.lab"}, {west, "eu_west", "https://eu-west.port49.lab"}} {
		raw := c.iss.ServiceAccountToken(t, "k1", c.issuer, "port49", "netops", "oxidized", f.b.Now(), nil)
		w := f.bearer(context.Background(), "POST", "/v1/tokens", mintLeaf1, raw)
		if resp := decodeMint(t, w); w.Code != 200 || resp.Principal != "system:serviceaccount:netops:oxidized" {
			t.Fatalf("%s: %s", c.cluster, shown(w))
		}
		recs := eventsOf(f.records(t), decision.EventMint)
		k := recs[len(recs)-1]["auth"].(map[string]any)["k8s"].(map[string]any)
		if k["cluster"] != c.cluster || k["issuer"] != c.issuer {
			t.Fatalf("%s: the record's auth.k8s %v", c.cluster, k)
		}
	}
}

// A refused cluster token is recorded method k8s, with nothing of the token.
func TestARefusedClusterTokenIsRecordedAsK8s(t *testing.T) {
	f := newFixtureWithPolicy(t, 8, clusterPolicy)
	iss := f.withCluster(t)
	raw := iss.ServiceAccountToken(t, "k1", k8sTestIssuer, "vault", "netops", "oxidized", f.b.Now(), nil)
	w := f.bearer(context.Background(), "POST", "/v1/tokens", mintLeaf1, raw)
	if w.Code != 401 || !strings.Contains(w.Body.String(), string(decision.TrustDomainUnresolved)) ||
		!strings.Contains(w.Body.String(), "its aud is not exactly [port49]") {
		t.Fatalf("%s", shown(w))
	}
	recs := eventsOf(f.records(t), decision.EventMint)
	last := recs[len(recs)-1]
	if last["principal"] != nil || last["auth"].(map[string]any)["method"] != "k8s" || last["auth"].(map[string]any)["k8s"] != nil {
		t.Fatalf("the refusal's record: %v", last)
	}
}

// A k8s identity_unmapped refusal reaches the workload with its reason: it
// names only the caller's own verified namespace and the configured issuer
// (pre-flight I1; the 3am section and L69 (f) rely on it).
func TestAnUnlistedNamespaceIsUnmapped(t *testing.T) {
	f := newFixtureWithPolicy(t, 8, clusterPolicy)
	iss := f.withCluster(t)
	raw := iss.ServiceAccountToken(t, "k1", k8sTestIssuer, "port49", "backup", "oxidized", f.b.Now(), nil)
	w := f.bearer(context.Background(), "POST", "/v1/tokens", mintLeaf1, raw)
	if w.Code != 401 || !strings.Contains(w.Body.String(), string(decision.IdentityUnmapped)) ||
		!strings.Contains(w.Body.String(), "its namespace backup is not one cluster l69_a ("+k8sTestIssuer+") lists in namespaces") {
		t.Fatalf("%s", shown(w))
	}
}

// A mark on the principal refuses the cluster path, and the answer says the
// mark outlives a re-created account (decision 49 ruling 11).
func TestRevokingAServiceAccountRefusesItsToken(t *testing.T) {
	f := newFixtureWithPolicy(t, 8, clusterPolicy)
	iss := f.withCluster(t)
	rep, err := f.b.Revoke(context.Background(), RevokeRequest{Principal: "system:serviceaccount:netops:oxidized",
		Origin: "admin_socket uid 0"})
	if err != nil {
		t.Fatal(err)
	}
	if text := rep.Text(); !strings.Contains(text, "a token its cluster issued stays valid at port49 until its exp") ||
		!strings.Contains(text, "re-created under that name") {
		t.Fatalf("%s", text)
	}
	raw := iss.ServiceAccountToken(t, "k1", k8sTestIssuer, "port49", "netops", "oxidized", f.b.Now(), nil)
	if w := f.bearer(context.Background(), "POST", "/v1/tokens", mintLeaf1, raw); w.Code != 401 ||
		!strings.Contains(w.Body.String(), string(decision.CredentialRevoked)) {
		t.Fatalf("%s", shown(w))
	}
}

// Review Focus 5: a 339-byte principal revokes whole, and the mark refuses its token.
func TestALongServiceAccountRevokes(t *testing.T) {
	sa := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	ns := strings.Repeat("n", 63)
	p := "system:serviceaccount:" + ns + ":" + sa
	if got, err := normalPrincipal(p); err != nil || got != p || len(p) != 339 {
		t.Fatalf("%q %v", got, err)
	}
	f := newFixtureWithPolicy(t, 8, clusterPolicy)
	iss := f.withCluster(t)
	f.b.Identity.Verifiers[0].Namespaces = []string{ns}
	if _, err := f.b.Revoke(context.Background(), RevokeRequest{Principal: p, Origin: "admin_socket uid 0"}); err != nil {
		t.Fatal(err)
	}
	raw := iss.ServiceAccountToken(t, "k1", k8sTestIssuer, "port49", ns, sa, f.b.Now(), nil)
	if w := f.bearer(context.Background(), "POST", "/v1/tokens", mintLeaf1, raw); w.Code != 401 ||
		!strings.Contains(w.Body.String(), string(decision.CredentialRevoked)) {
		t.Fatalf("%s", shown(w))
	}
}

func TestAServiceAccountPrincipalIsVerbatimOrRefused(t *testing.T) {
	if got, err := normalPrincipal("system:serviceaccount:netops:oxidized"); err != nil || got != "system:serviceaccount:netops:oxidized" {
		t.Fatalf("%q %v", got, err)
	}
	for _, in := range []string{"System:ServiceAccount:netops:oxidized", "system:serviceaccount:NetOps:oxidized",
		"system:serviceaccount:netops", "system:serviceaccount:netops:a_b"} {
		if _, err := normalPrincipal(in); !errors.Is(err, ErrBadRevocation) {
			t.Errorf("%s: %v", in, err)
		}
	}
}

// A workload's token is no proof of a second factor (decision 49 ruling 15):
// under per_login_mfa with applies_to_machines a k8s workload is asked for a
// touch it cannot give, and a token's acr is ignored and its amr refused,
// so no claim can stand for a proof.
func TestAClusterTokenIsAskedForMFAAndCannotClaimIt(t *testing.T) {
	f := newMFAFixture(t, withAppliesToMachines())
	iss := f.withCluster(t)
	body := `{"devices":["core-sw01"],"ttl_seconds":60}`
	plain := iss.ServiceAccountToken(t, "k1", k8sTestIssuer, "port49", "netops", "oxidized", f.b.Now(), nil)
	resp := decodeMint(t, f.bearer(context.Background(), "POST", "/v1/tokens", body, plain))
	if it := resp.Results[0]; it.Verdict != "deny" || it.Reason != "per_login_mfa_required" || it.PerLoginMFA == nil {
		t.Fatalf("a k8s workload under per_login_mfa = %+v", it)
	}
	// An acr is ignored, not believed: the workload is asked all the same.
	acr := iss.ServiceAccountToken(t, "k1", k8sTestIssuer, "port49", "netops", "oxidized", f.b.Now(), map[string]any{"acr": "phr"})
	resp = decodeMint(t, f.bearer(context.Background(), "POST", "/v1/tokens", body, acr))
	if it := resp.Results[0]; it.Reason != "per_login_mfa_required" || it.PerLoginMFA == nil {
		t.Fatalf("a k8s workload claiming acr phr = %+v", it)
	}
	// An amr is refused by the verifier: no mint, no claim of a factor.
	amr := iss.ServiceAccountToken(t, "k1", k8sTestIssuer, "port49", "netops", "oxidized", f.b.Now(),
		map[string]any{"acr": "phr", "amr": []string{"pwd", "otp", "hwk"}})
	if w := f.bearer(context.Background(), "POST", "/v1/tokens", body, amr); w.Code != 401 {
		t.Fatalf("a cluster token claiming an amr: %s", shown(w))
	}
}

// A k8s assertion is recorded through auth.k8s, never as a person's auth.oidc.
func TestAK8sAssertionIsNeverRecordedAsOIDC(t *testing.T) {
	f := newFixtureWithPolicy(t, 8, clusterPolicy)
	iss := f.withCluster(t)
	raw := iss.ServiceAccountToken(t, "k1", k8sTestIssuer, "port49", "netops", "oxidized", f.b.Now(), nil)
	a, err := f.b.Identity.Verify(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	got := caller{principal: a.Principal, cred: a.Credential(), oidc: &a}.auth()
	if got.K8s == nil || got.OIDC != nil || got.Method != "k8s" || got.K8s.Cluster != "l69_a" {
		t.Fatalf("auth = %+v", got)
	}
}

// GET /v1/identity answers a workload as k8s, never as a person's oidc caller.
func TestAK8sCallersIdentityAnswerHasNoOIDC(t *testing.T) {
	f := newFixtureWithPolicy(t, 8, clusterPolicy)
	iss := f.withCluster(t)
	raw := iss.ServiceAccountToken(t, "k1", k8sTestIssuer, "port49", "netops", "oxidized", f.b.Now(), nil)
	w := f.bearer(context.Background(), "GET", "/v1/identity", "", raw)
	var got map[string]any
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &got) != nil {
		t.Fatalf("%s", shown(w))
	}
	if got["method"] != "k8s" || got["principal"] != "system:serviceaccount:netops:oxidized" || got["oidc"] != nil {
		t.Fatalf("the identity answer: %v", got)
	}
}

// The operator line for a refused cluster token says so, and is its own line:
// an oidc refusal inside the same window does not silence it.
func TestAClusterRefusalsOperatorLineSaysK8s(t *testing.T) {
	logs := &lockedBuffer{}
	prev := log.Writer()
	log.SetOutput(logs)
	t.Cleanup(func() { log.SetOutput(prev) })
	f := newFixtureWithPolicy(t, 8, clusterPolicy)
	iss := f.withCluster(t)
	f.b.Say = nil
	f.bearer(context.Background(), "POST", "/v1/tokens", mintLeaf1, "not-a-token") // an oidc-worded refusal first
	raw := iss.ServiceAccountToken(t, "k1", k8sTestIssuer, "port49", "backup", "oxidized", f.b.Now(), nil)
	f.bearer(context.Background(), "POST", "/v1/tokens", mintLeaf1, raw)
	out := logs.String()
	if !strings.Contains(out, "a k8s token was refused (identity_unmapped): its namespace backup is not one cluster l69_a") {
		t.Fatalf("the operator's lines: %s", out)
	}
}
