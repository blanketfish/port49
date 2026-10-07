package broker

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"net/url"
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

// logoutFor is a Keycloak-shaped logout token for alice from iss at f's
// now: sub sub-alice, and sid when not "".
func logoutFor(t *testing.T, f *fixture, iss *oidctest.Issuer, sid, jti string) string {
	t.Helper()
	now := f.b.Now()
	c := map[string]any{"iss": iss.URL, "aud": testClientID, "iat": now.Unix(), "exp": now.Add(2 * time.Minute).Unix(),
		"jti": jti, "sub": "sub-alice", "events": map[string]any{oidc.BackchannelLogoutEvent: map[string]any{}}}
	if sid != "" {
		c["sid"] = sid
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

// The say lines of a failed logout end with logoutRecovery's form, never a
// bare port49 revoke: a logout is not a ban (M5).
func TestAFailedLogoutSaysTheRecoveryNotABan(t *testing.T) {
	f, iss, _ := oidcLoggedIn(t)
	var said strings.Builder
	f.b.Say = func(format string, args ...any) { said.WriteString(fmt.Sprintf(format, args...) + "\n") }
	f.b.AdminSocket = "/run/port49/admin.sock"
	f.b.Store = hookStore{Store: f.st, before: map[string]func() error{
		"PutLogout": func() error { return store.ErrUnavailable },
		"TakeOnce":  func() error { return store.ErrUnavailable }}}
	if w := f.postLogout(logoutFor(t, f, iss, "s-sub-alice", "j-hand")); w.Code != 503 {
		t.Fatalf("%s", lshown(w))
	}
	out := said.String()
	if !strings.Contains(out, "--lift") || !strings.Contains(out, "port49 revoke --list") ||
		strings.Contains(out, "revoke the principal with port49 revoke") || strings.Contains(out, "port49 revoke <principal>") {
		t.Fatalf("the recovery said:\n%s", out)
	}
}
