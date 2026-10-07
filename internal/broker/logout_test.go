package broker

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/oidc"
	"github.com/rhwendt/port49/internal/oidc/oidctest"
	"github.com/rhwendt/port49/internal/store"
)

// lshown is a logout response as a test message: its code and the error
// fields alone, never a body that could carry a token.
func lshown(w *httptest.ResponseRecorder) string {
	var e struct {
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &e)
	return fmt.Sprintf("code %d, error %q, detail %q", w.Code, e.Error, e.Description)
}

// logoutFor is a logout token for alice from iss at f's now: by sid alone
// when sid is not "" (the RevokeSid and other-provider shape; Keycloak
// always sends both, see logoutNaming), else by sub-alice.
func logoutFor(t *testing.T, f *fixture, iss *oidctest.Issuer, sid, jti string) string {
	t.Helper()
	if sid != "" {
		return logoutNaming(t, f, iss, sid, "", jti)
	}
	return logoutNaming(t, f, iss, "", "sub-alice", jti)
}

// logoutNaming is a logout token from iss at f's now carrying sid and sub,
// each only when not "".
func logoutNaming(t *testing.T, f *fixture, iss *oidctest.Issuer, sid, sub, jti string) string {
	t.Helper()
	now := f.b.Now()
	c := map[string]any{"iss": iss.URL, "aud": testClientID, "iat": now.Unix(), "exp": now.Add(2 * time.Minute).Unix(),
		"jti": jti, "events": map[string]any{oidc.BackchannelLogoutEvent: map[string]any{}}}
	if sid != "" {
		c["sid"] = sid
	}
	if sub != "" {
		c["sub"] = sub
	}
	return iss.TokenWith(t, "k1", map[string]any{"kid": "k1", "typ": "logout+jwt"}, c)
}

// postLogout posts raw as a logout token, form-encoded, with no client
// certificate, as a provider does.
func (f *fixture) postLogout(raw string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "/v1/logout", strings.NewReader(url.Values{"logout_token": {raw}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.TLS = &tls.ConnectionState{}
	w := httptest.NewRecorder()
	f.b.Handler().ServeHTTP(w, r)
	return w
}

// oidcLoggedIn is alice minted for leaf1 and nx1 by OIDC, logged in on
// leaf1 (a context indexed under her session's sid, as the daemon indexes
// a login), with nx1's token unspent.
func oidcLoggedIn(t *testing.T) (*fixture, *oidctest.Issuer, string) {
	t.Helper()
	f := newFixture(t, 8)
	iss := f.withOIDC(t)
	tok := f.idToken(t, iss, nil)
	if w := f.bearer(context.Background(), "POST", "/v1/tokens", `{"devices":["leaf1","nx1"],"ttl_seconds":60}`, tok); w.Code != 200 {
		t.Fatalf("mint: %s", shown(w))
	}
	now := f.b.Now()
	f.liveContextAt(t, "leaf1", "alice", alicePrincipal, "", now, now.Add(12*time.Hour))
	if err := f.st.IndexContext(context.Background(), alicePrincipal, store.SidKey(iss.URL, "s-sub-alice"), "",
		store.ContextRef{NAS: "leaf1", Username: "alice"}, time.Hour); err != nil {
		t.Fatal(err)
	}
	_ = f.st.DeleteTokens(context.Background(), store.TokenKey{NAS: "leaf1", Username: "alice"}) // spent at login
	return f, iss, tok
}

func contextRevokedAt(t *testing.T, f *fixture, device string) time.Time {
	t.Helper()
	c, err := f.st.GetContext(context.Background(), store.ContextKey{NAS: device, Username: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	return c.RevokedAt
}

// A logout by sid ends that session's context, deletes the person's unspent
// tokens, refuses the session's token from then on, and is one revoke
// record; it needed no certificate and no right (spec §2).
func TestALogoutBySidEndsThatSession(t *testing.T) {
	f, iss, tok := oidcLoggedIn(t)
	w := f.postLogout(logoutFor(t, f, iss, "s-sub-alice", "j1"))
	if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("%s %v", lshown(w), w.Header())
	}
	if contextRevokedAt(t, f, "leaf1").IsZero() {
		t.Fatal("the session's context was not marked")
	}
	if toks, _ := f.st.Candidates(context.Background(), store.TokenKey{NAS: "nx1", Username: "alice"}); len(toks) != 0 {
		t.Fatal("the person's unspent token on nx1 survived")
	}
	revs := eventsOf(f.records(t), decision.EventRevoke)
	rv := revs[len(revs)-1]["revocation"].(map[string]any)
	if rv["by"] != "sid" || rv["sid"] != "s-sub-alice" || rv["oidc_issuer"] != iss.URL ||
		rv["origin"] != "backchannel_logout "+iss.URL || revs[len(revs)-1]["principal"] != alicePrincipal {
		t.Fatalf("revoke record %v", revs[len(revs)-1])
	}
	if w := f.bearer(context.Background(), "POST", "/v1/tokens", mintLeaf1, tok); w.Code != 401 {
		t.Fatalf("the ended session's token minted: %s", shown(w))
	}
	fresh := f.idToken(t, iss, map[string]any{"sid": "s-new"})
	if w := f.bearer(context.Background(), "POST", "/v1/tokens", mintLeaf1, fresh); w.Code != 200 {
		t.Fatalf("a new login after the logout: %s", shown(w))
	}
}

// Review Focus 7: tokens minted before the logout are found through the
// owner record and deleted.
func TestALogoutFindsTokensMintedBeforeIt(t *testing.T) {
	f, iss, _ := oidcLoggedIn(t)
	if w := f.postLogout(logoutFor(t, f, iss, "s-sub-alice", "j1")); w.Code != 200 {
		t.Fatalf("%s", lshown(w))
	}
	keys, _ := f.st.TokensByPrincipal(context.Background(), alicePrincipal)
	for _, k := range keys {
		if toks, _ := f.st.Candidates(context.Background(), k); len(toks) != 0 {
			t.Fatalf("a token under %v survived the logout", k)
		}
	}
}

// A logout by sub alone ends every context of the person, a
// certificate-path one included (decision 15; Ruling 13).
func TestALogoutBySubEndsEveryContextOfThePerson(t *testing.T) {
	f, iss, _ := oidcLoggedIn(t)
	now := f.b.Now()
	f.liveContextAt(t, "nx1", "alice", alicePrincipal, certKey(f.alice), now, now.Add(12*time.Hour))
	if w := f.postLogout(logoutFor(t, f, iss, "", "j-sub")); w.Code != 200 {
		t.Fatalf("%s", lshown(w))
	}
	for _, d := range []string{"leaf1", "nx1"} {
		if contextRevokedAt(t, f, d).IsZero() {
			t.Fatalf("%s's context was not marked", d)
		}
	}
}

// Review Focus 5: the provider sending the same logout twice changes
// nothing the second time, even for a session opened between the two.
func TestALogoutReplayedIsANoOp(t *testing.T) {
	f, iss, _ := oidcLoggedIn(t)
	raw := logoutFor(t, f, iss, "", "j-replay")
	if w := f.postLogout(raw); w.Code != 200 {
		t.Fatalf("%s", lshown(w))
	}
	f.advance(2 * time.Minute)
	now := f.b.Now()
	f.liveContextAt(t, "nx1", "alice", alicePrincipal, "", now, now.Add(12*time.Hour)) // a login after the logout
	if w := f.postLogout(raw); w.Code != 200 {
		t.Fatalf("the replay: %s", lshown(w))
	}
	if !contextRevokedAt(t, f, "nx1").IsZero() {
		t.Fatal("a replayed logout ended a session opened after it")
	}
	if got := testutil.ToFloat64(f.b.Metrics.OIDCLogouts.WithLabelValues("replayed")); got != 1 {
		t.Fatalf("replayed counted %v", got)
	}
}

// Review Focus 5: a logout for a session port49 never saw still refuses
// that session's tokens from then on.
func TestALogoutForAnUnseenSessionStillRefusesItsTokens(t *testing.T) {
	f := newFixture(t, 8)
	iss := f.withOIDC(t)
	if w := f.postLogout(logoutFor(t, f, iss, "s-unseen", "j2")); w.Code != 200 {
		t.Fatalf("%s", lshown(w))
	}
	if got := testutil.ToFloat64(f.b.Metrics.OIDCLogouts.WithLabelValues("nothing")); got != 1 {
		t.Fatalf("nothing counted %v", got)
	}
	tok := f.idToken(t, iss, map[string]any{"sid": "s-unseen"})
	if w := f.bearer(context.Background(), "POST", "/v1/tokens", mintLeaf1, tok); w.Code != 401 {
		t.Fatalf("a token of the logged-out session: %s", shown(w))
	}
}

// Review Focus 5: with the store down the logout is 503, its jti given
// back, and the provider's retry applies it.
func TestALogoutTheStoreFailedIsRetriable(t *testing.T) {
	f, iss, _ := oidcLoggedIn(t)
	real := f.b.Store
	f.b.Store = hookStore{Store: real, before: map[string]func() error{
		"PutLogout": func() error { return store.ErrUnavailable }}}
	raw := logoutFor(t, f, iss, "s-sub-alice", "j3")
	w := f.postLogout(raw)
	if w.Code != 503 || w.Header().Get("Retry-After") != "30" {
		t.Fatalf("%s %v", lshown(w), w.Header())
	}
	if !contextRevokedAt(t, f, "leaf1").IsZero() {
		t.Fatal("a logout whose record failed marked a context")
	}
	f.b.Store = real
	if w := f.postLogout(raw); w.Code != 200 || contextRevokedAt(t, f, "leaf1").IsZero() {
		t.Fatalf("the retry: %s", lshown(w))
	}
}

// A PutOnce that committed but timed out must not turn the provider's retry
// into a replayed 200: the jti is given back on any PutOnce error.
func TestALogoutWhosePutOnceFailedGivesTheJTIBack(t *testing.T) {
	f, iss, _ := oidcLoggedIn(t)
	real := f.b.Store
	raw := logoutFor(t, f, iss, "s-sub-alice", "j-putonce")
	f.b.Store = hookStore{Store: real, before: map[string]func() error{
		"PutOnce": func() error {
			// The write committed, then the answer was lost.
			_, _ = real.PutOnce(context.Background(), jtiKey(iss.URL, "j-putonce"), nil, time.Hour)
			return store.ErrUnavailable
		}}}
	if w := f.postLogout(raw); w.Code != 503 {
		t.Fatalf("%s", lshown(w))
	}
	f.b.Store = real
	if w := f.postLogout(raw); w.Code != 200 || contextRevokedAt(t, f, "leaf1").IsZero() {
		t.Fatalf("the retry after a lost PutOnce answer: %s", lshown(w))
	}
}

func TestALogoutThatDoesNotValidateIs400AndReachesNothing(t *testing.T) {
	f, iss, _ := oidcLoggedIn(t)
	forger := oidctest.NewIssuer(t)
	forged := forger.TokenWith(t, "k1", map[string]any{"kid": "k1", "typ": "logout+jwt"}, map[string]any{
		"iss": iss.URL, "aud": testClientID, "iat": f.b.Now().Unix(), "jti": "j4", "sid": "s-sub-alice",
		"events": map[string]any{oidc.BackchannelLogoutEvent: map[string]any{}}})
	before := len(eventsOf(f.records(t), decision.EventRevoke))
	w := f.postLogout(forged)
	if w.Code != 400 || !strings.Contains(w.Body.String(), `"error":"invalid_request"`) {
		t.Fatalf("%s", lshown(w))
	}
	if !contextRevokedAt(t, f, "leaf1").IsZero() || len(eventsOf(f.records(t), decision.EventRevoke)) != before {
		t.Fatal("a forged logout reached something")
	}
}

// Ruling 24, pre-flight I-1: a person renamed under one sub (alice@ to
// alice2@) is two principals on the owner record, and a sub logout ends
// both, and names both in its record.
func TestALogoutReachesEveryPrincipalOfTheSub(t *testing.T) {
	f, iss, _ := oidcLoggedIn(t)
	ctx := context.Background()
	now := f.b.Now()
	const alice2 = "user:alice2@example.com"
	if err := f.st.PutOIDCOwner(ctx, store.OIDCKey(store.OIDCSub, iss.URL, "sub-alice"), alice2, time.Hour); err != nil {
		t.Fatal(err)
	}
	f.liveContextAt(t, "nx1", "alice2", alice2, "", now, now.Add(12*time.Hour))
	if w := f.postLogout(logoutFor(t, f, iss, "", "j-rename")); w.Code != 200 {
		t.Fatalf("%s", lshown(w))
	}
	for _, k := range []store.ContextKey{{NAS: "leaf1", Username: "alice"}, {NAS: "nx1", Username: "alice2"}} {
		if c, err := f.st.GetContext(ctx, k); err != nil || c.RevokedAt.IsZero() {
			t.Fatalf("%v was not marked: %v", k, err)
		}
	}
	revs := eventsOf(f.records(t), decision.EventRevoke)
	rv := revs[len(revs)-1]["revocation"].(map[string]any)
	if fmt.Sprint(rv["principals"]) != "["+alice2+" "+alicePrincipal+"]" {
		t.Fatalf("revocation.principals %v", rv["principals"])
	}
}

// Ruling 22, pre-flight C-2: a second provider cannot mint as Alice, and its
// sub logout reaches none of her contexts or tokens, even through an owner
// record that names her (one left from before a configuration change).
func TestAnotherIssuersSubLogoutReachesNoneOfAlices(t *testing.T) {
	f, _, _ := oidcLoggedIn(t)
	contractor := oidctest.NewIssuer(t)
	f.addIssuer(t, contractor, "contractor.example.net", false)
	ctx := context.Background()
	impostor := contractor.IDToken(t, "k1", testClientID, "sub-alice", f.b.Now(),
		map[string]any{"preferred_username": "alice@example.com"})
	if w := f.bearer(ctx, "POST", "/v1/tokens", mintLeaf1, impostor); w.Code != 401 ||
		!strings.Contains(w.Body.String(), string(decision.IdentityUnmapped)) {
		t.Fatalf("another issuer naming alice: %s", shown(w))
	}
	key := store.OIDCKey(store.OIDCSub, contractor.URL, "sub-alice")
	if _, err := f.st.OIDCOwner(ctx, key); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the refused mint wrote an owner record: %v", err)
	}
	if err := f.st.PutOIDCOwner(ctx, key, alicePrincipal, time.Hour); err != nil {
		t.Fatal(err)
	}
	var said strings.Builder
	f.b.Say = func(format string, args ...any) { said.WriteString(fmt.Sprintf(format, args...) + "\n") }
	if w := f.postLogout(logoutFor(t, f, contractor, "", "j-contractor")); w.Code != 200 {
		t.Fatalf("%s", lshown(w))
	}
	if !contextRevokedAt(t, f, "leaf1").IsZero() {
		t.Fatal("another issuer's sub logout ended alice's context")
	}
	if toks, _ := f.st.Candidates(ctx, store.TokenKey{NAS: "nx1", Username: "alice"}); len(toks) != 1 {
		t.Fatal("another issuer's sub logout deleted alice's unspent token")
	}
	if !strings.Contains(said.String(), "outside this verifier's principal_domains") {
		t.Fatalf("the skipped principal was not said:\n%s", said.String())
	}
}

// Pre-flight M-13: a logout whose writes fail and whose jti cannot be given
// back says so, naming the session and how to end it by hand, since the
// provider's retry will be answered 200 "replayed".
func TestALogoutWhoseJTICannotBeGivenBackSaysSo(t *testing.T) {
	f, iss, _ := oidcLoggedIn(t)
	var said strings.Builder
	f.b.Say = func(format string, args ...any) { said.WriteString(fmt.Sprintf(format, args...) + "\n") }
	f.b.Store = hookStore{Store: f.st, before: map[string]func() error{
		"PutLogout": func() error { return store.ErrUnavailable },
		"TakeOnce":  func() error { return store.ErrUnavailable }}}
	if w := f.postLogout(logoutFor(t, f, iss, "s-sub-alice", "j-lost")); w.Code != 503 {
		t.Fatalf("%s", lshown(w))
	}
	if !strings.Contains(said.String(), "could not be given back") ||
		!strings.Contains(said.String(), `POST /v1/tokens/revoke {"sid": "s-sub-alice"`) {
		t.Fatalf("the lost logout was not said with its manual end:\n%s", said.String())
	}
}

func TestALogoutRequestIsAForm(t *testing.T) {
	f := newFixture(t, 8)
	iss := f.withOIDC(t)
	raw := logoutFor(t, f, iss, "s", "j5")
	for name, req := range map[string]func() *httptest.ResponseRecorder{
		"json": func() *httptest.ResponseRecorder {
			r := httptest.NewRequest("POST", "/v1/logout", strings.NewReader(`{"logout_token":"`+raw+`"}`))
			r.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			f.b.Handler().ServeHTTP(w, r)
			return w
		},
		"two tokens": func() *httptest.ResponseRecorder {
			r := httptest.NewRequest("POST", "/v1/logout", strings.NewReader(url.Values{"logout_token": {raw, raw}}.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			w := httptest.NewRecorder()
			f.b.Handler().ServeHTTP(w, r)
			return w
		},
		"text/plain": func() *httptest.ResponseRecorder {
			r := httptest.NewRequest("POST", "/v1/logout", strings.NewReader(url.Values{"logout_token": {raw}}.Encode()))
			r.Header.Set("Content-Type", "text/plain")
			w := httptest.NewRecorder()
			f.b.Handler().ServeHTTP(w, r)
			return w
		},
		"no content type": func() *httptest.ResponseRecorder {
			r := httptest.NewRequest("POST", "/v1/logout", strings.NewReader(url.Values{"logout_token": {raw}}.Encode()))
			w := httptest.NewRecorder()
			f.b.Handler().ServeHTTP(w, r)
			return w
		},
		"oversized": func() *httptest.ResponseRecorder {
			return f.postLogout(strings.Repeat("a", 17<<10))
		},
	} {
		w := req()
		if w.Code != 400 {
			t.Errorf("%s: %s", name, lshown(w))
		}
		// Refused for its shape, not for failing to verify.
		if !strings.Contains(w.Body.String(), "a logout ") ||
			(strings.HasPrefix(name, "text") || strings.HasPrefix(name, "no ")) && !strings.Contains(w.Body.String(), "is a form") {
			t.Errorf("%s was not refused as a malformed request: %s", name, lshown(w))
		}
	}
}

// The logout record outlives the logged-out session's ID token while the
// token could still be presented: it refuses it 2 minutes on, not only at
// once (I1).
func TestALogoutRecordOutlivesTheTokenItRefuses(t *testing.T) {
	f, iss, tok := oidcLoggedIn(t)
	if w := f.postLogout(logoutFor(t, f, iss, "s-sub-alice", "j-ttl")); w.Code != 200 {
		t.Fatalf("%s", lshown(w))
	}
	f.advance(2 * time.Minute)
	w := f.bearer(context.Background(), "POST", "/v1/tokens", mintLeaf1, tok)
	if w.Code != 401 || !strings.Contains(w.Body.String(), string(decision.CredentialRevoked)) {
		t.Fatalf("the logged-out session's token, 2m on: %s", shown(w))
	}
}

// receiptsHook notes whose receipts are deleted, and, on the first
// ContextsByPrincipal, writes alice a context after answering with the list
// it read: a login landing between a logout's two context passes.
type receiptsHook struct {
	store.Store
	deleted []string
	late    func()
	reads   int
}

func (s *receiptsHook) DeleteReceiptsByPrincipal(ctx context.Context, principal string) (int, error) {
	s.deleted = append(s.deleted, principal)
	return s.Store.DeleteReceiptsByPrincipal(ctx, principal)
}

func (s *receiptsHook) ContextsByPrincipal(ctx context.Context, principal string) ([]store.ContextRef, error) {
	refs, err := s.Store.ContextsByPrincipal(ctx, principal)
	if s.reads++; s.reads == 1 && s.late != nil {
		s.late()
	}
	return refs, err
}

// A sub logout deletes each owner principal's receipts (spec §5.1.4: it
// closes the concurrent duplicate's replay), as the sid path does through
// the session manager (M2).
func TestALogoutBySubDeletesEveryOwnPrincipalsReceipts(t *testing.T) {
	f, iss, _ := oidcLoggedIn(t)
	ctx := context.Background()
	const alice2 = "user:alice2@example.com"
	if err := f.st.PutOIDCOwner(ctx, store.OIDCKey(store.OIDCSub, iss.URL, "sub-alice"), alice2, time.Hour); err != nil {
		t.Fatal(err)
	}
	st := &receiptsHook{Store: f.st}
	f.b.Store = st
	if w := f.postLogout(logoutFor(t, f, iss, "", "j-receipts")); w.Code != 200 {
		t.Fatalf("%s", lshown(w))
	}
	if fmt.Sprint(st.deleted) != "["+alice2+" "+alicePrincipal+"]" {
		t.Fatalf("receipts deleted for %v", st.deleted)
	}
}

// A session that lands after the first context pass read is caught by the
// second (spec §5.1.4: a redemption in flight) (M3).
func TestALogoutMarksAContextThatLandsDuringItsFirstPass(t *testing.T) {
	f, iss, _ := oidcLoggedIn(t)
	now := f.b.Now()
	f.b.Store = &receiptsHook{Store: f.st, late: func() {
		f.liveContextAt(t, "nx1", "alice", alicePrincipal, "", now, now.Add(12*time.Hour))
	}}
	if w := f.postLogout(logoutFor(t, f, iss, "", "j-late")); w.Code != 200 {
		t.Fatalf("%s", lshown(w))
	}
	if contextRevokedAt(t, f, "nx1").IsZero() {
		t.Fatal("a context written during the first pass was not marked")
	}
}

// A broker with no human verifier fails closed (M4).
func TestLogoutAndRevokeSidWithNoIdentityFailClosed(t *testing.T) {
	f := newFixture(t, 8)
	f.b.Identity = nil
	if _, err := f.b.RevokeSid(context.Background(), "https://sso.example.com", "s", "x"); err == nil {
		t.Fatal("RevokeSid with no identity did not fail")
	}
	if _, err := f.b.Logout(context.Background(), oidc.LogoutToken{Issuer: "i", Sid: "s"}, "x"); err == nil {
		t.Fatal("Logout with no identity did not fail")
	}
}

// A logout that wrote nothing says an unconditional recovery: no revoke
// record to look for, a lift time, and the sid API call first (N1, N2).
func TestAStoreFailedLogoutSaysAnUnconditionalRecovery(t *testing.T) {
	f, iss, _ := oidcLoggedIn(t)
	var said strings.Builder
	f.b.Say = func(format string, args ...any) { said.WriteString(fmt.Sprintf(format, args...) + "\n") }
	f.b.AdminSocket = "/run/port49/admin.sock"
	f.b.Store = hookStore{Store: f.st, before: map[string]func() error{
		"PutLogout": func() error { return store.ErrUnavailable },
		"TakeOnce":  func() error { return store.ErrUnavailable }}}
	lift := f.b.Now().Add(f.b.Identity.Timing.MaxTokenAge + 2*f.b.Identity.Timing.ClockSkew).UTC().Format(time.RFC3339)
	if w := f.postLogout(logoutFor(t, f, iss, "s-sub-alice", "j-hand")); w.Code != 503 {
		t.Fatalf("%s", lshown(w))
	}
	out := said.String()
	first, _, _ := strings.Cut(out, "\n")
	if strings.Contains(out, "if the decision log has a revoke record") || !strings.Contains(out, "--lift` there only after "+lift) ||
		!strings.Contains(out, "port49 revoke --list") || strings.Contains(out, "port49 revoke <principal>") ||
		!strings.Contains(first, `POST /v1/tokens/revoke {"sid": "s-sub-alice"`) || !strings.Contains(first, "(needs revoke_others)") {
		t.Fatalf("the recovery said:\n%s", out)
	}
}

// A logout that wrote its record and failed after says logoutRecovery's
// form, its revoke record being in the log (N1).
func TestAPartialLogoutSaysTheRecoveryOfItsRecord(t *testing.T) {
	f, iss, _ := oidcLoggedIn(t)
	var said strings.Builder
	f.b.Say = func(format string, args ...any) { said.WriteString(fmt.Sprintf(format, args...) + "\n") }
	f.b.AdminSocket = "/run/port49/admin.sock"
	f.b.Store = hookStore{Store: f.st, before: map[string]func() error{
		"TakeOnce": func() error { return store.ErrUnavailable }}}
	st := &partialStore{Store: f.b.Store}
	f.b.Store = st
	if w := f.postLogout(logoutFor(t, f, iss, "s-sub-alice", "j-part")); w.Code != 503 {
		t.Fatalf("%s", lshown(w))
	}
	out := said.String()
	if !strings.Contains(out, "if the decision log has a revoke record with origin backchannel_logout for "+alicePrincipal) ||
		!strings.Contains(out, "--lift") || strings.Contains(out, "only after") {
		t.Fatalf("the recovery said:\n%s", out)
	}
}

// partialStore fails a later step of a logout, the tokens read, after its
// record is written.
type partialStore struct{ store.Store }

func (s *partialStore) TokensByPrincipal(ctx context.Context, principal string) ([]store.TokenKey, error) {
	return nil, store.ErrUnavailable
}

// ttlStore fails PutLogout, noting the ttl it was given.
type ttlStore struct {
	store.Store
	ttl time.Duration
}

func (s *ttlStore) PutLogout(ctx context.Context, l store.Logout, ttl time.Duration) error {
	s.ttl = ttl
	return store.ErrUnavailable
}

// The lift time a failed logout advises is the life of the record it would
// have written, not a second copy of the sum (P1).
func TestTheAdvisedLiftTimeIsTheLogoutRecordsLife(t *testing.T) {
	f, iss, _ := oidcLoggedIn(t)
	var said strings.Builder
	f.b.Say = func(format string, args ...any) { said.WriteString(fmt.Sprintf(format, args...) + "\n") }
	f.b.AdminSocket = "/run/port49/admin.sock"
	st := &ttlStore{Store: f.st}
	f.b.Store = st
	now := f.b.Now()
	if w := f.postLogout(logoutFor(t, f, iss, "s-sub-alice", "j-life")); w.Code != 503 {
		t.Fatalf("%s", lshown(w))
	}
	if st.ttl != f.b.logoutRecordTTL() {
		t.Fatalf("PutLogout was given %s, the record's life is %s", st.ttl, f.b.logoutRecordTTL())
	}
	if want := now.Add(st.ttl).UTC().Format(time.RFC3339); !strings.Contains(said.String(), "only after "+want) {
		t.Fatalf("the lift time is not now plus the record's life (%s):\n%s", want, said.String())
	}
}

// twoSessions is oidcLoggedIn with a second session of alice's: a context
// on nx1 indexed under another sid. (nx1's unspent token is oidcLoggedIn's.)
func twoSessions(t *testing.T) (*fixture, *oidctest.Issuer) {
	t.Helper()
	f, iss, _ := oidcLoggedIn(t)
	ctx := context.Background()
	now := f.b.Now()
	f.liveContextAt(t, "nx1", "alice", alicePrincipal, "", now, now.Add(12*time.Hour))
	if err := f.st.IndexContext(ctx, alicePrincipal, store.SidKey(iss.URL, "s-other"), "",
		store.ContextRef{NAS: "nx1", Username: "alice"}, time.Hour); err != nil {
		t.Fatal(err)
	}
	return f, iss
}

// Ruling 13: a token carrying both sid and sub is a logout by the sid and
// then one by the sub, so Keycloak's "sign out user" over several sessions
// ends them all, not the one session its token names.
func TestALogoutCarryingSidAndSubEndsEverySessionOfTheSub(t *testing.T) {
	f, iss := twoSessions(t)
	ctx := context.Background()
	st := &receiptsHook{Store: f.st}
	f.b.Store = st
	if w := f.postLogout(logoutNaming(t, f, iss, "s-sub-alice", "sub-alice", "j-both")); w.Code != 200 {
		t.Fatalf("%s", lshown(w))
	}
	for _, d := range []string{"leaf1", "nx1"} {
		if contextRevokedAt(t, f, d).IsZero() {
			t.Fatalf("%s's context survived a logout naming the sub", d)
		}
	}
	if toks, _ := f.st.Candidates(ctx, store.TokenKey{NAS: "nx1", Username: "alice"}); len(toks) != 0 {
		t.Fatal("the person's unspent token survived")
	}
	if fmt.Sprint(st.deleted) != "["+alicePrincipal+"]" {
		t.Fatalf("receipts deleted for %v", st.deleted)
	}
	revs := eventsOf(f.records(t), decision.EventRevoke)
	if len(revs) != 2 {
		t.Fatalf("%d revoke records, want 2", len(revs))
	}
	first, second := revs[0]["revocation"].(map[string]any), revs[1]["revocation"].(map[string]any)
	if first["by"] != "sid" || first["sid"] != "s-sub-alice" || second["by"] != "sub" || second["sub"] != "sub-alice" {
		t.Fatalf("revoke records %v, %v", first, second)
	}
}

// The API stays narrow: RevokeSid, a sid alone, ends the one session.
func TestRevokeSidEndsOnlyTheNamedSession(t *testing.T) {
	f, iss := twoSessions(t)
	if _, err := f.b.RevokeSid(context.Background(), iss.URL, "s-sub-alice", "api"); err != nil {
		t.Fatal(err)
	}
	if contextRevokedAt(t, f, "leaf1").IsZero() {
		t.Fatal("the named session's context was not marked")
	}
	if !contextRevokedAt(t, f, "nx1").IsZero() {
		t.Fatal("RevokeSid ended another session")
	}
}

// The merged report of a both-token names both, and unions the halves: a
// rename the sub's owner record names and the sid's does not (Ruling 24) is
// reached by the sub half alone, its context, token and Unreached included.
func TestABothLogoutsReportIsTheUnionOfItsHalves(t *testing.T) {
	f, iss := twoSessions(t)
	ctx := context.Background()
	now := f.b.Now()
	const alice2 = "user:alice2@example.com"
	if err := f.st.PutOIDCOwner(ctx, store.OIDCKey(store.OIDCSub, iss.URL, "sub-alice"), alice2, time.Hour); err != nil {
		t.Fatal(err)
	}
	f.liveContextAt(t, "bare", "alice2", alice2, "", now, now.Add(12*time.Hour))
	if _, err := f.st.PutToken(ctx, store.TokenKey{NAS: "leaf1", Username: "alice2"}, store.Token{ID: "t-alice2",
		Secret: []byte("x"), Kind: store.KindLogin, ExpiresAt: now.Add(time.Minute), Principal: alice2,
		Username: "alice2"}); err != nil {
		t.Fatal(err)
	}
	if err := f.st.IndexToken(ctx, alice2, "", store.TokenKey{NAS: "leaf1", Username: "alice2"}, time.Hour); err != nil {
		t.Fatal(err)
	}
	rep, err := f.b.Logout(ctx, oidc.LogoutToken{Issuer: iss.URL, Sid: "s-sub-alice",
		Subject: "sub-alice", IssuedAt: now, Domains: f.b.Identity.HumanDomains(iss.URL)}, "x")
	if err != nil || rep.Err != nil {
		t.Fatalf("%v, %v", err, rep.Err)
	}
	if rep.By != ByLogoutSid || rep.Sid != "s-sub-alice" || rep.Sub != "sub-alice" ||
		fmt.Sprint(rep.Principals) != "["+alicePrincipal+" "+alice2+"]" || rep.Request.Principal != alicePrincipal {
		t.Fatalf("report %+v", rep)
	}
	has := func(refs []store.ContextRef, ref store.ContextRef) bool { return slices.Contains(refs, ref) }
	if len(rep.Contexts) != 3 || !has(rep.Contexts, store.ContextRef{NAS: "bare", Username: "alice2"}) {
		t.Fatalf("contexts %v", rep.Contexts)
	}
	// The sid half deleted alice's token (1 key); the sub half, alice2's.
	if rep.TokenKeys != 2 {
		t.Fatalf("TokenKeys %d, want 2", rep.TokenKeys)
	}
	// bare serves no platform, so its context is unreached, and only the
	// sub half's.
	if !has(rep.Unreached, store.ContextRef{NAS: "bare", Username: "alice2"}) {
		t.Fatalf("Unreached %v", rep.Unreached)
	}
}

// The sub half's record failing after the sid half ran is 503 with the jti
// given back, and the by-hand line is the unconditional sub form: the sid
// half's revoke record is in the log, but no record refuses the person's
// other sessions' ID tokens, so the lift waits and the sid-only API call
// (one session) is not offered. Following the line ends the other session.
func TestABothLogoutWhoseSubRecordFailsGivesTheUnconditionalForm(t *testing.T) {
	f, iss := twoSessions(t)
	var said strings.Builder
	f.b.Say = func(format string, args ...any) { said.WriteString(fmt.Sprintf(format, args...) + "\n") }
	f.b.AdminSocket = "/run/port49/admin.sock"
	calls := 0
	f.b.Store = hookStore{Store: f.st, before: map[string]func() error{
		"PutLogout": func() error {
			if calls++; calls == 2 {
				return store.ErrUnavailable
			}
			return nil
		}}}
	lift := f.b.Now().Add(f.b.Identity.Timing.MaxTokenAge + 2*f.b.Identity.Timing.ClockSkew).UTC().Format(time.RFC3339)
	if w := f.postLogout(logoutNaming(t, f, iss, "s-sub-alice", "sub-alice", "j-half")); w.Code != 503 {
		t.Fatalf("%s", lshown(w))
	}
	out := said.String()
	last := out[strings.LastIndex(strings.TrimSpace(out), "\n")+1:]
	if strings.Contains(out, `{"sid":`) || strings.Contains(out, "if the decision log has a revoke record") ||
		!strings.Contains(last, "for each principal the decision log's mint records name for this sub") ||
		!strings.Contains(last, "--lift` there only after "+lift) {
		t.Fatalf("the recovery said:\n%s", out)
	}
	// The jti was given back: the provider's retry is applied, not replayed.
	f.b.Store = f.st
	if w := f.postLogout(logoutNaming(t, f, iss, "s-sub-alice", "sub-alice", "j-half")); w.Code != 200 ||
		contextRevokedAt(t, f, "nx1").IsZero() {
		t.Fatalf("the retry: %s", lshown(w))
	}
}

// Following that line (a principal revoke, run at once) refuses a held ID
// token of the other session, which no logout record does until the retry.
func TestAHeldIDTokenOfTheOtherSessionIsRefusedOnceTheByHandLineIsFollowed(t *testing.T) {
	f, iss := twoSessions(t)
	calls := 0
	f.b.Store = hookStore{Store: f.st, before: map[string]func() error{
		"PutLogout": func() error {
			if calls++; calls == 2 {
				return store.ErrUnavailable
			}
			return nil
		}}}
	other := f.idToken(t, iss, map[string]any{"sid": "s-other"})
	if w := f.postLogout(logoutNaming(t, f, iss, "s-sub-alice", "sub-alice", "j-held")); w.Code != 503 {
		t.Fatalf("%s", lshown(w))
	}
	if w := f.bearer(context.Background(), "POST", "/v1/tokens", mintLeaf1, other); w.Code != 200 {
		t.Fatalf("premise: nothing refuses the other session yet: %s", shown(w))
	}
	if _, err := f.b.Revoke(context.Background(), RevokeRequest{Principal: alicePrincipal, Origin: "by hand"}); err != nil {
		t.Fatal(err)
	}
	if w := f.bearer(context.Background(), "POST", "/v1/tokens", mintLeaf1, other); w.Code == 200 {
		t.Fatalf("the other session's held token minted after the by-hand revoke: %s", shown(w))
	}
}

// partialSubStore fails ContextsByPrincipal, which only the sub half reads
// (the sid half goes through the session manager).
type partialSubStore struct{ store.Store }

func (s partialSubStore) ContextsByPrincipal(context.Context, string) ([]store.ContextRef, error) {
	return nil, store.ErrUnavailable
}

// The sub half failing part way, its record written, is 503 "partial", the
// jti given back and the conditional by-hand line (its revoke record stands);
// the retry ends the other session.
func TestABothLogoutWhoseSubHalfFailsPartWayIsPartial(t *testing.T) {
	f, iss := twoSessions(t)
	var said strings.Builder
	f.b.Say = func(format string, args ...any) { said.WriteString(fmt.Sprintf(format, args...) + "\n") }
	f.b.AdminSocket = "/run/port49/admin.sock"
	f.b.Store = partialSubStore{f.st}
	raw := logoutNaming(t, f, iss, "s-sub-alice", "sub-alice", "j-part-sub")
	if w := f.postLogout(raw); w.Code != 503 {
		t.Fatalf("%s", lshown(w))
	}
	if out := said.String(); !strings.Contains(out, "if the decision log has a revoke record with origin "+
		"backchannel_logout for "+alicePrincipal) || strings.Contains(out, `{"sid":`) {
		t.Fatalf("the recovery said:\n%s", out)
	}
	f.b.Store = f.st
	if w := f.postLogout(raw); w.Code != 200 || contextRevokedAt(t, f, "nx1").IsZero() {
		t.Fatalf("the retry: %s", lshown(w))
	}
}

// A both-token whose first record fails: 503, the retry ends both sessions.
func TestABothLogoutTheStoreFailedIsRetriable(t *testing.T) {
	f, iss := twoSessions(t)
	f.b.Store = hookStore{Store: f.st, before: map[string]func() error{
		"PutLogout": func() error { return store.ErrUnavailable }}}
	raw := logoutNaming(t, f, iss, "s-sub-alice", "sub-alice", "j-both-retry")
	if w := f.postLogout(raw); w.Code != 503 || w.Header().Get("Retry-After") != "30" {
		t.Fatalf("%s %v", lshown(w), w.Header())
	}
	if !contextRevokedAt(t, f, "leaf1").IsZero() || !contextRevokedAt(t, f, "nx1").IsZero() {
		t.Fatal("a logout whose record failed marked a context")
	}
	f.b.Store = f.st
	if w := f.postLogout(raw); w.Code != 200 || contextRevokedAt(t, f, "leaf1").IsZero() ||
		contextRevokedAt(t, f, "nx1").IsZero() {
		t.Fatalf("the retry: %s", lshown(w))
	}
}

// A both-token whose jti the store would not take: the sub form, no sid-only
// API call, and neither the token nor its jti in the line.
func TestABothLogoutWhosePutOnceFailedSaysSo(t *testing.T) {
	f, iss := twoSessions(t)
	var said strings.Builder
	f.b.Say = func(format string, args ...any) { said.WriteString(fmt.Sprintf(format, args...) + "\n") }
	f.b.AdminSocket = "/run/port49/admin.sock"
	f.b.Store = hookStore{Store: f.st, before: map[string]func() error{
		"PutOnce": func() error { return store.ErrUnavailable }}}
	raw := logoutNaming(t, f, iss, "s-sub-alice", "sub-alice", "j-secret-both")
	if w := f.postLogout(raw); w.Code != 503 {
		t.Fatalf("%s", lshown(w))
	}
	out := said.String()
	lift := f.b.Now().Add(f.b.Identity.Timing.MaxTokenAge + 2*f.b.Identity.Timing.ClockSkew).UTC().Format(time.RFC3339)
	if !strings.Contains(out, "--lift` there only after "+lift) || strings.Contains(out, `{"sid":`) ||
		!strings.Contains(out, "for this sub") {
		t.Fatalf("the PutOnce failure said:\n%s", out)
	}
	if strings.Contains(out, raw) || strings.Contains(out, "j-secret-both") {
		t.Fatalf("the line carries the token or its jti:\n%s", out)
	}
}

func TestLogoutByHandAlternatives(t *testing.T) {
	f, iss, _ := oidcLoggedIn(t)
	cases := []struct {
		name      string
		lt        oidc.LogoutToken
		sidAPI    bool
		leadsWith string
	}{
		{"sid", oidc.LogoutToken{Issuer: iss.URL, Sid: "s1"}, true, ""},
		{"sub", oidc.LogoutToken{Issuer: iss.URL, Subject: "u1"}, false, "for each principal the decision log's mint records name for this sub"},
		{"both", oidc.LogoutToken{Issuer: iss.URL, Sid: "s1", Subject: "u1"}, false, "for each principal the decision log's mint records name for this sub"},
	}
	for _, c := range cases {
		out := f.b.logoutByHand(c.lt, RevokeReport{}, false)
		if strings.Contains(out, `POST /v1/tokens/revoke {"sid"`) != c.sidAPI || !strings.Contains(out, c.leadsWith) {
			t.Errorf("%s: %s", c.name, out)
		}
	}
}
