package broker

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/policy"
	"github.com/rhwendt/port49/internal/store"
)

// explainPolicy is testPolicy with an on-call who may explain others,
// added to its subjects list after carol's.
var explainPolicy = strings.Replace(testPolicy, "username: carol, token_ttl: 60s}\n",
	"username: carol, token_ttl: 60s}\n"+
		`  - {name: oncall, identity: ["user:bob@example.com"], username: bob, token_ttl: 60s, api: [explain_others]}`+"\n", 1)

func (f *fixture) explainAs(t *testing.T, email, body string) *httptest.ResponseRecorder {
	t.Helper()
	return f.explainOn(f.state(f.client(t, email, f.now.Add(time.Hour))), body)
}

// explainOn asks on one connection, so records can be compared whole,
// asked_by_fingerprint included.
func (f *fixture) explainOn(cs *tls.ConnectionState, body string) *httptest.ResponseRecorder {
	return f.call(context.Background(), cs, "POST", "/v1/explain", body)
}

func decodeExplain(t *testing.T, w *httptest.ResponseRecorder) api.ExplainResponse {
	t.Helper()
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	var r api.ExplainResponse
	if err := json.Unmarshal(w.Body.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	return r
}

// A caller explains itself: the broker's answer from the policy in force,
// the daemon's evaluator, and one explain record that names who asked, by
// principal and certificate, and the bundle that answered, carries no
// auth, and never the command (spec §5.7; decision 34).
func TestExplainAnswersTheCallerAndNeverLogsTheCommand(t *testing.T) {
	f := newFixtureWithPolicy(t, 8, explainPolicy)
	r := decodeExplain(t, f.explainAs(t, "alice@example.com", `{"device":"leaf1","command":"reload now"}`))
	if r.Principal != alicePrincipal || r.Subject != "netops" || r.Platform != "arista_eos" || r.Verdict != "deny" ||
		r.Reason != "no_permit_dominates_deny" || !strings.HasPrefix(r.Text, "deny no_permit_dominates_deny") {
		t.Fatalf("%+v", r)
	}
	if s := decodeExplain(t, f.explainAs(t, "alice@example.com", `{"device":"leaf1"}`)); s.Verdict != "permit" ||
		s.Reason != "context_matched" || strings.Contains(s.Text, "session attributes") {
		t.Fatalf("the session, which returns no attributes: %+v", s)
	}
	recs := eventsOf(f.records(t), "explain")
	if len(recs) != 2 || recs[0]["reason"] != "no_permit_dominates_deny" || recs[0]["principal"] != alicePrincipal {
		t.Fatalf("%v", recs)
	}
	ex := recs[0]["explain"].(map[string]any)
	if ex["asked_by"] != alicePrincipal || ex["command"] != true ||
		!strings.HasPrefix(ex["asked_by_fingerprint"].(string), "sha256:") || recs[0]["auth"] != nil {
		t.Fatalf("%v", recs[0])
	}
	if pol, _ := recs[0]["policy"].(map[string]any); pol["bundle"] != f.b.Policy.Load().Bundle {
		t.Fatalf("the record does not name the bundle that answered: %v", recs[0])
	}
	if strings.Contains(f.log.String(), "reload now") {
		t.Fatal("the log holds the command explain was asked")
	}
}

// An unknown device is answered exactly as a device the caller has no grant
// on: the same verdict, reason and text but for the name, and no platform
// (design §17; Review Focus 3).
func TestAnUnknownDeviceIsAnsweredAsOneWithNoGrant(t *testing.T) {
	f := newFixtureWithPolicy(t, 8, explainPolicy)
	known := decodeExplain(t, f.explainAs(t, "carol@example.com", `{"device":"leaf1"}`))
	carol := f.state(f.client(t, "carol@example.com", f.now.Add(time.Hour)))
	unknown := decodeExplain(t, f.explainOn(carol, `{"device":"nosuch"}`))
	if known.Platform != "" || unknown.Platform != "" || known.Reason != "no_grants_matched" ||
		strings.ReplaceAll(known.Text, "leaf1", "X") != strings.ReplaceAll(unknown.Text, "nosuch", "X") {
		t.Fatalf("known %+v\nunknown %+v", known, unknown)
	}
	for _, r := range eventsOf(f.records(t), "explain") {
		if d := r["device"].(map[string]any); d["platform"] != "" && d["platform"] != nil {
			t.Fatalf("a no-grant record named a platform: %v", r)
		}
	}
}

// A scoped caller asking about a device outside its grants that is
// quarantined, or refused admission, is answered and recorded exactly as
// about a device that does not exist (Review Focus 7; pre-flight M7).
// Explain judges no grant before a quarantine or a refusal, as the mint
// does; a reordering would tell a caller which devices exist and what state
// they are in. nx1 is cisco_nxos, which defines no @loopback, so alice's
// grant quarantines it (TestAQuarantinedDeviceIsRefusedAtMint); bare lies
// outside the key group's range, so it is refused admission; carol's grant
// selects arista_eos alone.
func TestAScopedCallerLearnsNothingOfADeviceOutsideItsGrants(t *testing.T) {
	f := newFixture(t, 8)
	body := `
scopes: [{name: all_devices, match: {}}, {name: eos, match: {platform: arista_eos}, on_missing: exclude}]
roles: [{name: r, permit: ["**"], deny: [interface @loopback]}]
subjects:
  - {name: c, identity: "user:carol@example.com", username: carol, token_ttl: 60s}
  - {name: s, identity: "user:alice@example.com", username: alice, token_ttl: 60s}
grants: [{subject: s, scope: all_devices, roles: [r]}, {subject: c, scope: eos, roles: [r]}]
key_groups: [{match: {cidr: 172.100.100.0/27}, key_ref: k}]
`
	pol, err := policy.Parse([]byte(body), policy.Env{Devices: f.b.Policy.Load().Devices(), Now: f.b.Now(),
		KeyRefs: []string{"k"}})
	if err != nil {
		t.Fatal(err)
	}
	f.b.Policy.Swap(pol)
	if _, q := pol.Quarantined("nx1", f.b.Now()); !q {
		t.Fatal("the fixture does not quarantine nx1")
	}
	if r, _ := pol.Admitted("bare"); r.Refused == "" {
		t.Fatal("the fixture does not refuse bare admission")
	}
	carol := f.state(f.client(t, "carol@example.com", f.now.Add(time.Hour)))
	unknown := decodeExplain(t, f.explainOn(carol, `{"device":"nosuch"}`))
	if unknown.Reason != "no_grants_matched" || unknown.Platform != "" {
		t.Fatalf("unknown: %+v", unknown)
	}
	for _, name := range []string{"nx1", "bare"} {
		got := decodeExplain(t, f.explainOn(carol, `{"device":"`+name+`"}`))
		got.Device, got.Text = "nosuch", strings.ReplaceAll(got.Text, name, "nosuch")
		if got != unknown {
			t.Fatalf("%s:\n%+v\nunknown:\n%+v", name, got, unknown)
		}
	}
	recs := eventsOf(f.records(t), "explain")
	if len(recs) != 3 {
		t.Fatalf("%d explain records", len(recs))
	}
	var same []string
	for _, r := range recs {
		delete(r, "ts")
		r["device"].(map[string]any)["name"] = "nosuch"
		raw, _ := json.Marshal(r) // map keys sorted
		same = append(same, string(raw))
	}
	if same[1] != same[0] || same[2] != same[0] {
		t.Fatalf("records differ but for the name:\n%s", strings.Join(same, "\n"))
	}
}

// Explaining another principal needs explain_others: without it, 403 and
// one deny api_right_missing record naming the target and who asked, with
// no auth (decision 34); with it, the target's answer, and a target under a
// mark is credential_revoked.
func TestExplainingAnotherNeedsTheRight(t *testing.T) {
	f := newFixtureWithPolicy(t, 8, explainPolicy)
	if w := f.explainAs(t, "carol@example.com", `{"device":"leaf1","principal":"USER:alice@example.com"}`); w.Code != 403 ||
		!strings.Contains(w.Body.String(), "explain_others") {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	recs := eventsOf(f.records(t), "explain")
	if len(recs) != 1 || recs[0]["reason"] != "api_right_missing" || recs[0]["principal"] != alicePrincipal ||
		recs[0]["explain"].(map[string]any)["asked_by"] != "user:carol@example.com" || recs[0]["auth"] != nil {
		t.Fatalf("%v", recs)
	}
	if r := decodeExplain(t, f.explainAs(t, "bob@example.com", `{"device":"leaf1","principal":"user:alice@example.com"}`)); r.Verdict != "permit" || r.Subject != "netops" {
		t.Fatalf("bob explaining alice: %+v", r)
	}
	if err := f.st.PutRevocation(context.Background(), store.Revocation{Kind: store.RevocationPrincipal,
		Key: alicePrincipal, At: f.now, Origin: "test"}); err != nil {
		t.Fatal(err)
	}
	if r := decodeExplain(t, f.explainAs(t, "bob@example.com", `{"device":"leaf1","principal":"user:alice@example.com"}`)); r.Verdict != "deny" || r.Reason != "credential_revoked" || r.Subject != "" {
		t.Fatalf("explaining a revoked principal: %+v", r)
	}
}

// A policy fault on a granted device is answered 500 broker_error and still
// recorded, as the mint's item error, with no verdict (decision 34); a
// principal under a mark is answered credential_revoked from the mark
// alone, whatever the policy would have done.
func TestAnExplainFaultIsRecordedAndARevokedTargetSkipsThePolicy(t *testing.T) {
	f := newFixtureWithPolicy(t, 8, explainPolicy)
	defer func(of func(*policy.Policy, policy.Member, string, string, time.Time) (policy.Explanation, error)) {
		explanationOf = of
	}(explanationOf)
	explanationOf = func(*policy.Policy, policy.Member, string, string, time.Time) (policy.Explanation, error) {
		return policy.Explanation{Platform: "arista_eos"}, errors.New("a compile defect")
	}
	if w := f.explainAs(t, "alice@example.com", `{"device":"leaf1","command":"show version"}`); w.Code != 500 ||
		!strings.Contains(w.Body.String(), "broker_error") {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	recs := eventsOf(f.records(t), "explain")
	if len(recs) != 1 || recs[0]["verdict"] != nil || recs[0]["reason"] != nil || recs[0]["principal"] != alicePrincipal {
		t.Fatalf("%v", recs)
	}
	if ex := recs[0]["explain"].(map[string]any); ex["mint_error"] != "broker_error" || ex["command"] != true {
		t.Fatalf("%v", recs[0])
	}
	if err := f.st.PutRevocation(context.Background(), store.Revocation{Kind: store.RevocationPrincipal,
		Key: alicePrincipal, At: f.now, Origin: "test"}); err != nil {
		t.Fatal(err)
	}
	if r := decodeExplain(t, f.explainAs(t, "bob@example.com", `{"device":"leaf1","principal":"user:alice@example.com"}`)); r.Reason != "credential_revoked" {
		t.Fatalf("a revoked target answered from the policy: %+v", r)
	}
}

// A command is printable and bounded; a secret typed into one never comes
// back unredacted, nor reaches the log.
func TestExplainBoundsAndRedactsTheCommand(t *testing.T) {
	f := newFixtureWithPolicy(t, 8, explainPolicy)
	for _, body := range []string{`{"device":"leaf1","command":"show\u0007version"}`,
		`{"device":"leaf1","command":"` + strings.Repeat("a", 1025) + `"}`, `{"device":""}`, `{"device":"leaf1","x":1}`,
		`{"device":"leaf1"}{"device":"leaf1","command":"reload now"}`,
		// Past the body's bound, refused rather than read in part.
		`{"device":"leaf1"}` + strings.Repeat(" ", 17<<10) + "x"} {
		if w := f.explainAs(t, "alice@example.com", body); w.Code != 400 {
			t.Errorf("%.60s: %d %s", body, w.Code, w.Body)
		}
	}
	w := f.explainAs(t, "alice@example.com", `{"device":"leaf1","command":"username bob secret Hunter2"}`)
	if w.Code != 200 || strings.Contains(w.Body.String(), "Hunter2") || strings.Contains(f.log.String(), "Hunter2") {
		t.Fatalf("%d %s\nlog: %s", w.Code, w.Body, f.log)
	}
}
