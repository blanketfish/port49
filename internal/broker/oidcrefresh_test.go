package broker

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/oidc/oidctest"
	"github.com/rhwendt/port49/internal/store"
)

// oidcSession is a fixture with OIDC and alice's live context on leaf1,
// authenticated an hour ago, indexed under her first session's sid.
func oidcSession(t *testing.T) (*fixture, func(extra map[string]any) string, string) {
	t.Helper()
	f := newFixture(t, 8)
	iss := f.withOIDC(t)
	at := f.b.Now().Add(-time.Hour)
	f.liveContextAt(t, "leaf1", "alice", alicePrincipal, "", at, at.Add(12*time.Hour))
	if err := f.st.IndexContext(context.Background(), alicePrincipal, store.SidKey(iss.URL, "s-first"), "",
		store.ContextRef{NAS: "leaf1", Username: "alice"}, time.Hour); err != nil {
		t.Fatal(err)
	}
	tok := func(extra map[string]any) string { return f.idToken(t, iss, extra) }
	return f, tok, iss.URL
}

func challenge(t *testing.T, f *fixture, token string) string {
	t.Helper()
	w := f.bearer(context.Background(), "POST", "/v1/refresh/challenge", "", token)
	var c api.RefreshChallenge
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &c) != nil || c.Nonce == "" {
		t.Fatalf("challenge: %s", shown(w))
	}
	return c.Nonce
}

func TestAnOIDCRefreshExtendsFromTheNewAuthTime(t *testing.T) {
	f, tok, iss := oidcSession(t)
	nonce := challenge(t, f, tok(map[string]any{"auth_time": f.b.Now().Add(-time.Hour).Unix(), "sid": "s-first"}))
	f.advance(time.Minute)
	fresh := f.b.Now()
	w := f.bearer(context.Background(), "POST", "/v1/refresh", "{}", tok(map[string]any{"nonce": nonce,
		"sid": "s-second", "auth_time": fresh.Unix()}))
	var resp api.RefreshResponse
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &resp) != nil {
		t.Fatalf("%s", shown(w))
	}
	if resp.AuthTime != fresh.UTC().Format(time.RFC3339) || len(resp.Sessions) != 1 || resp.Sessions[0].Outcome != "extended" {
		t.Fatalf("response %+v", resp)
	}
	c, _ := f.st.GetContext(context.Background(), store.ContextKey{NAS: "leaf1", Username: "alice"})
	if !c.AuthTime.Equal(fresh) || !c.SessionExpires.Equal(fresh.Add(12*time.Hour)) {
		t.Fatalf("context auth_time %v expires %v", c.AuthTime, c.SessionExpires)
	}
	// Ruling 15: a logout of either session still reaches it.
	for _, sid := range []string{"s-first", "s-second"} {
		if refs, _ := f.st.ContextsBySid(context.Background(), store.SidKey(iss, sid)); len(refs) != 1 {
			t.Fatalf("by sid %s: %v", sid, refs)
		}
	}
}

func TestARefreshNeedsItsChallenge(t *testing.T) {
	f, tok, _ := oidcSession(t)
	if w := f.bearer(context.Background(), "POST", "/v1/refresh", "{}", tok(map[string]any{"nonce": "made-up"})); w.Code != 401 ||
		!strings.Contains(w.Body.String(), "refresh_challenge_missing") {
		t.Fatalf("a nonce the broker never issued: %s", shown(w))
	}
	if w := f.bearer(context.Background(), "POST", "/v1/refresh", "{}", tok(nil)); w.Code != 401 ||
		!strings.Contains(w.Body.String(), "refresh_challenge_missing") {
		t.Fatalf("no nonce: %s", shown(w))
	}
	nonce := challenge(t, f, tok(nil))
	f.advance(time.Second)
	again := tok(map[string]any{"nonce": nonce, "auth_time": f.b.Now().Unix()})
	if w := f.bearer(context.Background(), "POST", "/v1/refresh", "{}", again); w.Code != 200 {
		t.Fatalf("the refresh: %s", shown(w))
	}
	if w := f.bearer(context.Background(), "POST", "/v1/refresh", "{}", again); w.Code != 401 ||
		!strings.Contains(w.Body.String(), "refresh_challenge_missing") {
		t.Fatalf("the same token again: %s", shown(w))
	}
}

// The provider must have authenticated the person after the challenge
// (prompt=login honoured): an older auth_time extends nothing.
func TestARefreshTheProviderDidNotReauthenticateIsNotFresh(t *testing.T) {
	f, tok, _ := oidcSession(t)
	before := f.b.Now()
	nonce := challenge(t, f, tok(nil))
	f.advance(time.Minute)
	w := f.bearer(context.Background(), "POST", "/v1/refresh", "{}", tok(map[string]any{"nonce": nonce,
		"auth_time": before.Add(-2 * time.Minute).Unix()}))
	if w.Code != 401 || !strings.Contains(w.Body.String(), "refresh_not_fresh") ||
		!strings.Contains(w.Body.String(), "prompt=login was not honoured") {
		t.Fatalf("%s", shown(w))
	}
	c, _ := f.st.GetContext(context.Background(), store.ContextKey{NAS: "leaf1", Username: "alice"})
	if !c.AuthTime.Equal(before.Add(-time.Hour)) {
		t.Fatalf("a refused refresh moved auth_time to %v", c.AuthTime)
	}
}

// Review Focus 6: within clock_skew of the challenge is fresh.
func TestARefreshWithinSkewOfTheChallengeIsFresh(t *testing.T) {
	f, tok, _ := oidcSession(t)
	at := f.b.Now()
	nonce := challenge(t, f, tok(nil))
	w := f.bearer(context.Background(), "POST", "/v1/refresh", "{}", tok(map[string]any{"nonce": nonce,
		"auth_time": at.Add(-30 * time.Second).Unix()}))
	if w.Code != 200 {
		t.Fatalf("an auth_time 30s before the challenge: %s", shown(w))
	}
}

func TestAChallengeIsItsPrincipalsAlone(t *testing.T) {
	f, tok, _ := oidcSession(t)
	nonce := challenge(t, f, tok(nil))
	carol := tok(map[string]any{"nonce": nonce, "preferred_username": "carol@example.com", "auth_time": f.b.Now().Unix()})
	if w := f.bearer(context.Background(), "POST", "/v1/refresh", "{}", carol); w.Code != 401 ||
		!strings.Contains(w.Body.String(), "refresh_challenge_missing") {
		t.Fatalf("carol answering alice's challenge: %s", shown(w))
	}
}

// Ruling 9: a person whose session reached the ceiling can still ask for a
// challenge with the token they hold.
func TestAChallengeOutlivesTheSessionCeiling(t *testing.T) {
	f, tok, _ := oidcSession(t)
	old := tok(map[string]any{"auth_time": f.b.Now().Add(-13 * time.Hour).Unix()})
	if w := f.bearer(context.Background(), "POST", "/v1/tokens", mintLeaf1, old); w.Code != 401 {
		t.Fatalf("a mint 13h after authentication: %s", shown(w))
	}
	nonce := challenge(t, f, old)
	f.advance(time.Minute)
	w := f.bearer(context.Background(), "POST", "/v1/refresh", "{}", tok(map[string]any{"nonce": nonce,
		"auth_time": f.b.Now().Unix()}))
	if w.Code != 200 {
		t.Fatalf("the refresh after it: %s", shown(w))
	}
}

func TestChallengesArePacedPerPrincipal(t *testing.T) {
	f, tok, _ := oidcSession(t)
	challenge(t, f, tok(nil))
	w := f.bearer(context.Background(), "POST", "/v1/refresh/challenge", "", tok(nil))
	if w.Code != 429 || w.Header().Get("Retry-After") == "" {
		t.Fatalf("a second challenge within 10s: %s", shown(w))
	}
	f.advance(11 * time.Second)
	challenge(t, f, tok(nil))
}

func TestAMachineHasNoSessionToRefresh(t *testing.T) {
	f := newFixtureWithPolicy(t, 8, machinePolicy)
	iss := f.withOIDC(t)
	now := f.b.Now()
	raw := iss.Token(t, "k1", map[string]any{"iss": iss.URL, "aud": "api://port49-svc", "sub": "svc",
		"azp": "Oxidized-01", "iat": now.Unix(), "exp": now.Add(time.Hour).Unix()})
	if w := f.bearer(context.Background(), "POST", "/v1/refresh/challenge", "", raw); w.Code != 400 {
		t.Fatalf("%s", shown(w))
	}
}

func TestARefreshBodyIsEmpty(t *testing.T) {
	f, tok, _ := oidcSession(t)
	nonce := challenge(t, f, tok(nil))
	w := f.bearer(context.Background(), "POST", "/v1/refresh", `{"nonce":"x","signature":"y"}`,
		tok(map[string]any{"nonce": nonce, "auth_time": f.b.Now().Unix()}))
	if w.Code != 400 {
		t.Fatalf("a certificate-path body on the OIDC path: %s", shown(w))
	}
}

func (h hookStore) RefreshContext(ctx context.Context, k store.ContextKey, r store.ContextRefresh, ttl time.Duration) error {
	if f := h.before["RefreshContext"]; f != nil {
		if err := f(); err != nil {
			return err
		}
	}
	return h.Store.RefreshContext(ctx, k, r, ttl)
}

// Pre-flight I-2: a logout that lands while a refresh extends the session
// never leaves an extended context alive to its new ceiling. The new sid is
// indexed before the extension, so a logout's RevokeBySid that runs after
// the index reaches the context; a logout whose passes ran before the index
// leaves only its record, and the refresh's after-check marks what it
// extended before it answers 401.
func TestALogoutDuringARefreshMarksTheExtendedContext(t *testing.T) {
	for name, during := range map[string]func(f *fixture, iss string) error{
		"the logout's passes run after the index": func(f *fixture, iss string) error {
			ctx := context.Background()
			if err := f.st.PutLogout(ctx, store.Logout{Key: store.SidKey(iss, "s-second"), At: f.b.Now()},
				time.Hour); err != nil {
				return err
			}
			_, err := f.b.Sessions.RevokeBySid(ctx, store.SidKey(iss, "s-second"))
			return err
		},
		"only the logout record stands": func(f *fixture, iss string) error {
			return f.st.PutLogout(context.Background(), store.Logout{Key: store.SidKey(iss, "s-second"), At: f.b.Now()},
				time.Hour)
		},
	} {
		t.Run(name, func(t *testing.T) {
			f, tok, iss := oidcSession(t)
			nonce := challenge(t, f, tok(nil))
			f.advance(time.Minute)
			fired := false
			f.b.Store = hookStore{Store: f.st, before: map[string]func() error{"RefreshContext": func() error {
				if fired {
					return nil
				}
				fired = true
				return during(f, iss)
			}}}
			w := f.bearer(context.Background(), "POST", "/v1/refresh", "{}", tok(map[string]any{"nonce": nonce,
				"sid": "s-second", "auth_time": f.b.Now().Unix()}))
			if w.Code != 401 || !strings.Contains(w.Body.String(), "credential_revoked") {
				t.Fatalf("a refresh a logout landed during: %s", shown(w))
			}
			c, _ := f.st.GetContext(context.Background(), store.ContextKey{NAS: "leaf1", Username: "alice"})
			if c.RevokedAt.IsZero() {
				t.Fatal("a context the refresh extended outlived a logout that landed during it")
			}
		})
	}
}

func TestAMachineCannotAnswerARefresh(t *testing.T) {
	f := newFixtureWithPolicy(t, 8, machinePolicy)
	iss := f.withOIDC(t)
	now := f.b.Now()
	raw := iss.Token(t, "k1", map[string]any{"iss": iss.URL, "aud": "api://port49-svc", "sub": "svc",
		"azp": "Oxidized-01", "iat": now.Unix(), "exp": now.Add(time.Hour).Unix()})
	if w := f.bearer(context.Background(), "POST", "/v1/refresh", "{}", raw); w.Code != 400 {
		t.Fatalf("%s", shown(w))
	}
}

// A challenge is the issuer's as well as the principal's: the same principal
// from another issuer cannot answer it.
func TestAChallengeIsItsIssuersAlone(t *testing.T) {
	f, tok, _ := oidcSession(t)
	iss2 := oidctest.NewIssuer(t)
	f.addIssuer(t, iss2, "example.com", false)
	nonce := challenge(t, f, tok(nil))
	other := f.idToken(t, iss2, map[string]any{"nonce": nonce, "auth_time": f.b.Now().Unix()})
	if w := f.bearer(context.Background(), "POST", "/v1/refresh", "{}", other); w.Code != 401 ||
		!strings.Contains(w.Body.String(), "refresh_challenge_missing") {
		t.Fatalf("another issuer answering alice's challenge: %s", shown(w))
	}
}

func (h hookStore) GetLogout(ctx context.Context, key string) (store.Logout, error) {
	if f := h.before["GetLogout"]; f != nil {
		if err := f(); err != nil {
			return store.Logout{}, err
		}
	}
	return h.Store.GetLogout(ctx, key)
}

// twoContexts adds alice's live context on nx1 to oidcSession's on leaf1.
func twoContexts(t *testing.T, f *fixture) {
	t.Helper()
	at := f.b.Now().Add(-time.Hour)
	f.liveContextAt(t, "nx1", "alice", alicePrincipal, "", at, at.Add(12*time.Hour))
}

// A refresh with no sid in its token indexes nothing: the per-context
// marking alone ends what it extended, and the operator is told nothing
// (review I1).
func TestASidlessRefreshRacingALogoutSaysNothing(t *testing.T) {
	f, tok, iss := oidcSession(t)
	var said strings.Builder
	f.b.Say = func(format string, args ...any) { said.WriteString(fmt.Sprintf(format, args...) + "\n") }
	nonce := challenge(t, f, tok(nil))
	f.advance(time.Minute)
	f.b.Store = hookStore{Store: f.st, before: map[string]func() error{"RefreshContext": func() error {
		return f.st.PutLogout(context.Background(), store.Logout{Key: store.OIDCKey(store.OIDCSub, iss, "sub-alice"),
			At: f.b.Now()}, time.Hour)
	}}}
	w := f.bearer(context.Background(), "POST", "/v1/refresh", "{}", tok(map[string]any{"nonce": nonce,
		"sid": nil, "auth_time": f.b.Now().Unix()}))
	if w.Code != 401 || !strings.Contains(w.Body.String(), "credential_revoked") {
		t.Fatalf("a sid-less refresh a logout landed during: %s", shown(w))
	}
	c, _ := f.st.GetContext(context.Background(), store.ContextKey{NAS: "leaf1", Username: "alice"})
	if c.RevokedAt.IsZero() {
		t.Fatal("a context the refresh extended outlived the logout")
	}
	if said.Len() != 0 {
		t.Fatalf("the operator was told: %s", said.String())
	}
}

// Review I2: a refresh that extends one context and fails on the next still
// checks the logouts again, and marks what it extended.
func TestAFailedRefreshStillHonoursALogout(t *testing.T) {
	f, tok, iss := oidcSession(t)
	twoContexts(t, f)
	nonce := challenge(t, f, tok(nil))
	f.advance(time.Minute)
	calls := 0
	f.b.Store = hookStore{Store: f.st, before: map[string]func() error{"RefreshContext": func() error {
		calls++
		if calls == 1 {
			return f.st.PutLogout(context.Background(), store.Logout{Key: store.SidKey(iss, "s-second"), At: f.b.Now()},
				time.Hour)
		}
		return store.ErrUnavailable
	}}}
	w := f.bearer(context.Background(), "POST", "/v1/refresh", "{}", tok(map[string]any{"nonce": nonce,
		"sid": "s-second", "auth_time": f.b.Now().Unix()}))
	if w.Code != 401 || !strings.Contains(w.Body.String(), "credential_revoked") {
		t.Fatalf("a refresh that failed part way after a logout: %s", shown(w))
	}
	for _, nas := range []string{"leaf1", "nx1"} {
		c, _ := f.st.GetContext(context.Background(), store.ContextKey{NAS: nas, Username: "alice"})
		if c.AuthTime.After(f.b.Now().Add(-time.Hour)) && c.RevokedAt.IsZero() {
			t.Fatalf("%s: a context the failed refresh extended outlived the logout", nas)
		}
	}
}

// A failed re-read says so, and the answer asks for a new challenge.
func TestAFailedRefreshWhoseLogoutReadFailsSaysSo(t *testing.T) {
	f, tok, _ := oidcSession(t)
	twoContexts(t, f)
	var said strings.Builder
	f.b.Say = func(format string, args ...any) { said.WriteString(fmt.Sprintf(format, args...) + "\n") }
	nonce := challenge(t, f, tok(nil))
	f.advance(time.Minute)
	calls, failed := 0, false
	f.b.Store = hookStore{Store: f.st, before: map[string]func() error{
		"RefreshContext": func() error {
			if calls++; calls > 1 {
				failed = true
				return store.ErrUnavailable
			}
			return nil
		},
		"GetLogout": func() error {
			if failed {
				return store.ErrUnavailable
			}
			return nil
		}}}
	w := f.bearer(context.Background(), "POST", "/v1/refresh", "{}", tok(map[string]any{"nonce": nonce,
		"sid": "s-second", "auth_time": f.b.Now().Unix()}))
	if w.Code != 503 || !strings.Contains(w.Body.String(), "port49 refresh") || strings.Contains(w.Body.String(), "retry after") {
		t.Fatalf("a refresh whose logout re-read failed: %s", shown(w))
	}
	if !strings.Contains(said.String(), "could not be read again") {
		t.Fatalf("the operator was not told the logouts could not be re-read: %q", said.String())
	}
}

// Review M1: a store failure after the challenge is spent asks for a new
// challenge, and its record carries auth.oidc (M4).
func TestAnOIDCRefreshStoreFailureAsksForANewChallenge(t *testing.T) {
	f, tok, _ := oidcSession(t)
	nonce := challenge(t, f, tok(nil))
	f.advance(time.Minute)
	f.b.Store = hookStore{Store: f.st, before: map[string]func() error{"RefreshContext": func() error {
		return store.ErrUnavailable
	}}}
	w := f.bearer(context.Background(), "POST", "/v1/refresh", "{}", tok(map[string]any{"nonce": nonce,
		"sid": "s-second", "auth_time": f.b.Now().Unix()}))
	if w.Code != 503 || !strings.Contains(w.Body.String(), "port49 refresh") || strings.Contains(w.Body.String(), "retry after") {
		t.Fatalf("%s", shown(w))
	}
	recs := eventsOf(f.records(t), decision.EventRefresh)
	last := recs[len(recs)-1]
	a, _ := last["auth"].(map[string]any)
	if last["reason"] != string(decision.StoreUnavailable) || a == nil || a["oidc"] == nil {
		t.Fatalf("the store failure's record: %v", last)
	}
}

// Review M2: a challenge is answerable for 5m.
func TestAChallengeExpiresAfterFiveMinutes(t *testing.T) {
	f, tok, _ := oidcSession(t)
	nonce := challenge(t, f, tok(nil))
	f.advance(5*time.Minute + time.Second)
	w := f.bearer(context.Background(), "POST", "/v1/refresh", "{}", tok(map[string]any{"nonce": nonce,
		"auth_time": f.b.Now().Unix()}))
	if w.Code != 401 || !strings.Contains(w.Body.String(), "refresh_challenge_missing") {
		t.Fatalf("a challenge answered at 5m1s: %s", shown(w))
	}
}

// Review M3: a refresh records its new session's owner for a logout to find.
func TestARefreshRecordsTheNewSessionsOwner(t *testing.T) {
	f, tok, iss := oidcSession(t)
	nonce := challenge(t, f, tok(nil))
	f.advance(time.Minute)
	if w := f.bearer(context.Background(), "POST", "/v1/refresh", "{}", tok(map[string]any{"nonce": nonce,
		"sid": "s-second", "auth_time": f.b.Now().Unix()})); w.Code != 200 {
		t.Fatalf("%s", shown(w))
	}
	o, err := f.st.OIDCOwner(context.Background(), store.SidKey(iss, "s-second"))
	if _, ok := o.Entry(alicePrincipal); err != nil || !ok {
		t.Fatalf("the owner of the new session: %v %v", o, err)
	}
}

// Review M1: a refresh that could not record its owner extends nothing and
// asks for a new challenge: the spent one answers no retry.
func TestARefreshThatCannotRecordItsOwnerAsksForANewChallenge(t *testing.T) {
	f, tok, _ := oidcSession(t)
	nonce := challenge(t, f, tok(nil))
	f.advance(time.Minute)
	f.b.Store = hookStore{Store: f.st, before: map[string]func() error{"PutOIDCOwner": func() error {
		return store.ErrUnavailable
	}}}
	w := f.bearer(context.Background(), "POST", "/v1/refresh", "{}", tok(map[string]any{"nonce": nonce,
		"sid": "s-second", "auth_time": f.b.Now().Unix()}))
	if w.Code != 503 || !strings.Contains(w.Body.String(), "port49 refresh") || strings.Contains(w.Body.String(), "; retry") {
		t.Fatalf("%s", shown(w))
	}
}

func (h hookStore) SetContextPolicy(ctx context.Context, k store.ContextKey, rev uint64, p store.ContextPolicy) error {
	if f := h.before["SetContextPolicy"]; f != nil {
		if err := f(); err != nil {
			return err
		}
	}
	return h.Store.SetContextPolicy(ctx, k, rev, p)
}

// Review N2: a refresh marks what it extended after a logout, not every
// context it visited.
func TestALogoutMarksOnlyWhatTheRefreshExtended(t *testing.T) {
	f, tok, iss := oidcSession(t)
	twoContexts(t, f)
	nonce := challenge(t, f, tok(nil))
	f.advance(time.Minute)
	calls := 0
	f.b.Store = hookStore{Store: f.st, before: map[string]func() error{"RefreshContext": func() error {
		if calls++; calls == 1 {
			return f.st.PutLogout(context.Background(), store.Logout{Key: store.SidKey(iss, "s-second"), At: f.b.Now()},
				time.Hour)
		}
		return store.ErrConflict // not_judged: visited, not extended
	}}}
	w := f.bearer(context.Background(), "POST", "/v1/refresh", "{}", tok(map[string]any{"nonce": nonce,
		"sid": "s-second", "auth_time": f.b.Now().Unix()}))
	if w.Code != 401 {
		t.Fatalf("%s", shown(w))
	}
	revoked := 0
	for _, nas := range []string{"leaf1", "nx1"} {
		if c, _ := f.st.GetContext(context.Background(), store.ContextKey{NAS: nas, Username: "alice"}); !c.RevokedAt.IsZero() {
			revoked++
		}
	}
	if revoked != 1 {
		t.Fatalf("%d contexts marked; only the one the refresh extended may be", revoked)
	}
}

// Review N1: the operator's lines name the check and the two commands: a
// logout is not a ban, and the person may log in again.
func TestTheOperatorLinesNameTheLogoutRecovery(t *testing.T) {
	want := []string{"backchannel_logout", "port49 revoke --principal " + alicePrincipal + "`",
		"port49 revoke --principal " + alicePrincipal + " --lift"}
	check := func(t *testing.T, said string) {
		t.Helper()
		for _, w := range want {
			if !strings.Contains(said, w) {
				t.Fatalf("the operator's line lacks %q: %s", w, said)
			}
		}
	}
	t.Run("the marking failed", func(t *testing.T) {
		f, tok, iss := oidcSession(t)
		var said strings.Builder
		f.b.Say = func(format string, args ...any) { said.WriteString(fmt.Sprintf(format, args...) + "\n") }
		nonce := challenge(t, f, tok(nil))
		f.advance(time.Minute)
		landed := false
		f.b.Store = hookStore{Store: f.st, before: map[string]func() error{
			"RefreshContext": func() error {
				landed = true
				return f.st.PutLogout(context.Background(), store.Logout{Key: store.SidKey(iss, "s-second"),
					At: f.b.Now()}, time.Hour)
			},
			"SetContextPolicy": func() error {
				if landed {
					return store.ErrUnavailable
				}
				return nil
			}}}
		w := f.bearer(context.Background(), "POST", "/v1/refresh", "{}", tok(map[string]any{"nonce": nonce,
			"sid": "s-second", "auth_time": f.b.Now().Unix()}))
		if w.Code != 401 {
			t.Fatalf("%s", shown(w))
		}
		check(t, said.String())
	})
	t.Run("the re-read failed", func(t *testing.T) {
		f, tok, _ := oidcSession(t)
		twoContexts(t, f)
		var said strings.Builder
		f.b.Say = func(format string, args ...any) { said.WriteString(fmt.Sprintf(format, args...) + "\n") }
		nonce := challenge(t, f, tok(nil))
		f.advance(time.Minute)
		calls, failed := 0, false
		f.b.Store = hookStore{Store: f.st, before: map[string]func() error{
			"RefreshContext": func() error {
				if calls++; calls > 1 {
					failed = true
					return store.ErrUnavailable
				}
				return nil
			},
			"GetLogout": func() error {
				if failed {
					return store.ErrUnavailable
				}
				return nil
			}}}
		f.bearer(context.Background(), "POST", "/v1/refresh", "{}", tok(map[string]any{"nonce": nonce,
			"sid": "s-second", "auth_time": f.b.Now().Unix()}))
		check(t, said.String())
	})
}
