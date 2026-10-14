package broker

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/policy"
	"github.com/rhwendt/port49/internal/store"
)

// /v1/identity answers the caller with its subject, its grants, its rights
// and its session's clock, and writes one identity record (design §17;
// spec §5.7). A query naming someone else changes nothing: the caller is
// the connection's certificate and nothing else (decision 34).
func TestIdentityAnswersTheCallerAlone(t *testing.T) {
	f := newFixture(t, 8)
	at := f.now.Add(-time.Hour)
	w := f.call(withHeldConn(context.Background(), at, nil), f.state(f.alice), "GET",
		"/v1/identity?principal=user:carol@example.com", "")
	if w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	var id api.Identity
	if err := json.Unmarshal(w.Body.Bytes(), &id); err != nil {
		t.Fatal(err)
	}
	if id.Principal != alicePrincipal || id.Subject != "netops" || id.Method != "cert" ||
		!strings.HasPrefix(id.Fingerprint, "sha256:") || len(id.API) != 0 || len(id.Groups) != 0 {
		t.Fatalf("%+v", id)
	}
	if len(id.Grants) != 1 || id.Grants[0].Scope != "all_devices" || id.Grants[0].MaxPrivilege != "admin" ||
		strings.Join(id.Grants[0].Roles, " ") != "network_admin no_reload" {
		t.Fatalf("grants: %+v", id.Grants)
	}
	if id.AuthTime != at.UTC().Format(time.RFC3339) || id.ConnectionEndsAt != at.Add(12*time.Hour).UTC().Format(time.RFC3339) {
		t.Fatalf("clock: %s %s", id.AuthTime, id.ConnectionEndsAt)
	}
	recs := eventsOf(f.records(t), "identity")
	if len(recs) != 1 || recs[0]["verdict"] != "permit" || recs[0]["reason"] != "grants_matched" ||
		recs[0]["principal"] != alicePrincipal {
		t.Fatalf("records: %v", recs)
	}
	if strings.Contains(w.Body.String(), "leaf1") {
		t.Fatal("identity listed a device: the API never lists the fleet")
	}
}

// A principal with a subject and no grant, and one no subject names, are
// told so, recorded deny no_grants_matched.
func TestIdentityOfAPrincipalWithNoGrant(t *testing.T) {
	f := newFixture(t, 8)
	for _, email := range []string{"carol@example.com", "dave@example.com"} {
		w := f.call(context.Background(), f.state(f.client(t, email, f.now.Add(time.Hour))), "GET", "/v1/identity", "")
		var id api.Identity
		if err := json.Unmarshal(w.Body.Bytes(), &id); err != nil || w.Code != 200 || len(id.Grants) != 0 {
			t.Fatalf("%s: %d %s", email, w.Code, w.Body)
		}
	}
	recs := eventsOf(f.records(t), "identity")
	if len(recs) != 2 || recs[0]["reason"] != "no_grants_matched" || recs[1]["reason"] != "no_grants_matched" {
		t.Fatalf("%v", recs)
	}
}

// A call is refused before it is read for what a mint is refused for, and
// recorded under its own event (spec §5.7; decision 34).
func TestIdentityIsRefusedAsAMintIs(t *testing.T) {
	f := newFixture(t, 8)
	ctx := context.Background()
	expired := f.client(t, "alice@example.com", f.now.Add(-time.Minute))
	if w := f.call(ctx, f.state(expired), "GET", "/v1/identity", ""); w.Code != 401 ||
		!strings.Contains(w.Body.String(), "trust_domain_unresolved") {
		t.Fatalf("expired: %d %s", w.Code, w.Body)
	}
	old := withHeldConn(ctx, f.now.Add(-13*time.Hour), nil)
	if w := f.call(old, f.state(f.alice), "GET", "/v1/identity", ""); w.Code != 401 ||
		!strings.Contains(w.Body.String(), "session_expired") {
		t.Fatalf("past max_session_age: %d %s", w.Code, w.Body)
	}
	if err := f.st.PutRevocation(ctx, store.Revocation{Kind: store.RevocationPrincipal, Key: alicePrincipal,
		At: f.now, Origin: "test"}); err != nil {
		t.Fatal(err)
	}
	if w := f.call(ctx, f.state(f.alice), "GET", "/v1/identity", ""); w.Code != 401 ||
		!strings.Contains(w.Body.String(), "credential_revoked") {
		t.Fatalf("marked: %d %s", w.Code, w.Body)
	}
	reasons := map[string]bool{}
	for _, r := range eventsOf(f.records(t), "identity") {
		if r["verdict"] != "deny" {
			t.Fatalf("%v", r)
		}
		reasons[r["reason"].(string)] = true
	}
	for _, want := range []string{"trust_domain_unresolved", "session_expired", "credential_revoked"} {
		if !reasons[want] {
			t.Fatalf("no identity deny %s: %v", want, reasons)
		}
	}
	if n := len(eventsOf(f.records(t), "mint")); n != 0 {
		t.Fatalf("%d mint records for identity calls", n)
	}
}

// No right widens a mint or a refresh (decision 34; 7b's carried item): a
// principal holding every right still cannot name another in a mint, and its
// refresh does not extend another principal's context, even one a stale
// index entry lists under it. Neither path reads a right, so this passes on
// 7b's code: it is a regression pin on 7b's self-only rule, against a
// future rights-aware change to either (pre-flight M17), not a test of
// this plan's rights code.
func TestNoRightWidensAMintOrARefresh(t *testing.T) {
	f := newFixtureWithPolicy(t, 8, strings.Replace(testPolicy, "enable: token, token_ttl: 60s}",
		"enable: token, token_ttl: 60s, api: [revoke_others, explain_others, sync, keys_show, replay]}", 1))
	ctx := context.Background()
	if w := f.post(ctx, f.state(f.alice), `{"devices":["leaf1"],"principal":"user:carol@example.com"}`, ""); w.Code != 400 {
		t.Fatalf("a mint naming another principal: %d %s", w.Code, w.Body)
	}
	carol := "user:carol@example.com"
	f.liveContextAt(t, "nx1", "carol", carol, "", f.now, f.now.Add(time.Hour))
	ref := store.ContextRef{NAS: "nx1", Username: "carol"}
	if err := f.st.IndexContext(ctx, alicePrincipal, "", "", ref, time.Hour); err != nil {
		t.Fatal(err)
	}
	f.advance(30 * time.Minute)
	if _, err := f.b.RefreshSession(ctx, policy.MemberOf(alicePrincipal), nil, store.Credential{Method: "cert"}, f.b.Now(), nil, nil, "", nil); err != nil {
		t.Fatal(err)
	}
	c, err := f.st.GetContext(ctx, store.ContextKey{NAS: "nx1", Username: "carol"})
	if err != nil || !c.AuthTime.Equal(f.now.Add(-30*time.Minute)) || !c.RevokedAt.IsZero() {
		t.Fatalf("carol's context was touched by alice's refresh: %+v %v", c, err)
	}
}

// A request the listener refuses as its connection binds is recorded under
// the event of the path it asked for, as authenticate records a refusal
// after the bind (decision 34; pre-flight M8); any other path stays mint.
func TestARefusalAtBindIsRecordedUnderItsEndpointsEvent(t *testing.T) {
	f := newFixture(t, 8)
	cred := store.Credential{Method: "cert", Fingerprint: "sha256:ab12"}
	for _, path := range []string{"/v1/identity", "/v1/explain", "/v1/tokens/revoke", "/v1/tokens", "/v1/refresh", "/nowhere"} {
		f.b.RefusedAtBind(path, alicePrincipal, cred, decision.CredentialRevoked)
	}
	var got []string
	for _, r := range f.records(t) {
		got = append(got, r["event"].(string))
		if r["reason"] != "credential_revoked" || r["principal"] != alicePrincipal {
			t.Fatalf("%v", r)
		}
	}
	if want := "identity explain revoke mint mint mint"; strings.Join(got, " ") != want {
		t.Fatalf("events %v, want %s", got, want)
	}
}

// A grant past its expiry selects nothing, so identity does not list it;
// the subject's live grant still answers (design §17).
func TestIdentityListsOnlyUnexpiredGrants(t *testing.T) {
	f := newFixture(t, 8)
	lapse := f.now.Add(time.Hour)
	extra := "  - {subject: netops, scope: all_devices, roles: [read_only]"
	f.reload(t, edit(t, roleList, readOnly)+extra+", expires: "+lapse.UTC().Format(time.RFC3339)+"}\n")
	grants := func() []api.IdentityGrant {
		t.Helper()
		w := f.call(context.Background(), f.state(f.alice), "GET", "/v1/identity", "")
		var id api.Identity
		if err := json.Unmarshal(w.Body.Bytes(), &id); err != nil || w.Code != http.StatusOK {
			t.Fatalf("%d %s", w.Code, w.Body)
		}
		return id.Grants
	}
	if g := grants(); len(g) != 2 || g[1].Expires != lapse.UTC().Format(time.RFC3339) {
		t.Fatalf("before the lapse both grants stand: %+v", g)
	}
	f.advance(2 * time.Hour)
	if g := grants(); len(g) != 1 || strings.Join(g[0].Roles, " ") != "network_admin no_reload" || g[0].Expires != "" {
		t.Fatalf("after the lapse only the live grant: %+v", g)
	}
}
