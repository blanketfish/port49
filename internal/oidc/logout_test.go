package oidc_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/oidc"
	"github.com/blanketfish/port49/internal/oidc/oidctest"
)

// logoutClaims is a Keycloak-shaped logout token for clientID at now; extra
// overrides, a nil value deleting.
func logoutClaims(iss *oidctest.Issuer, now time.Time, extra map[string]any) map[string]any {
	c := map[string]any{"iss": iss.URL, "aud": clientID, "iat": now.Unix(), "exp": now.Add(2 * time.Minute).Unix(),
		"jti": "j-1", "sub": "8b2e", "sid": "s-8b2e",
		"events": map[string]any{oidc.BackchannelLogoutEvent: map[string]any{}}}
	for k, v := range extra {
		if v == nil {
			delete(c, k)
		} else {
			c[k] = v
		}
	}
	return c
}

func logoutToken(t *testing.T, iss *oidctest.Issuer, now time.Time, extra map[string]any) string {
	return iss.TokenWith(t, "k1", map[string]any{"kid": "k1", "typ": "logout+jwt"}, logoutClaims(iss, now, extra))
}

func TestALogoutTokenVerifies(t *testing.T) {
	iss, c := oidctest.NewIssuer(t), newClock()
	set := newSet(t, iss, c, human(iss, oidc.ClaimEmail))
	l, err := set.VerifyLogout(context.Background(), logoutToken(t, iss, c.Now(), nil))
	if err != nil {
		t.Fatal(err)
	}
	if l.Issuer != iss.URL || l.Subject != "8b2e" || l.Sid != "s-8b2e" || l.JTI != "j-1" || !l.IssuedAt.Equal(c.Now()) {
		t.Fatalf("logout %+v", l)
	}
	// sid alone, sub alone, and no typ at all are each a logout token.
	for _, extra := range []map[string]any{{"sub": nil}, {"sid": nil}} {
		if _, err := set.VerifyLogout(context.Background(), logoutToken(t, iss, c.Now(), extra)); err != nil {
			t.Errorf("%v: %v", extra, err)
		}
	}
	if _, err := set.VerifyLogout(context.Background(), iss.Token(t, "k1", logoutClaims(iss, c.Now(), nil))); err != nil {
		t.Errorf("no typ: %v", err)
	}
}

func TestALogoutTokenNeedsWhatBCLRequires(t *testing.T) {
	iss, c := oidctest.NewIssuer(t), newClock()
	set := newSet(t, iss, c, human(iss, oidc.ClaimEmail))
	for name, extra := range map[string]map[string]any{
		"no jti":                {"jti": nil},
		"no events":             {"events": nil},
		"events without member": {"events": map[string]any{"http://example.com/other": map[string]any{}}},
		"member not an object":  {"events": map[string]any{oidc.BackchannelLogoutEvent: "yes"}},
		"aud an empty string":   {"aud": []string{""}},
		"aud lists an empty":    {"aud": []string{clientID, ""}, "azp": clientID},
		"sid with a space":      {"sid": "s 1"},
		"sub with a NUL":        {"sub": "a\x00b"},
		"jti with a space":      {"jti": "j 1"},
		"jti of 256 bytes":      {"jti": strings.Repeat("j", 256)},
		"jti a number":          {"jti": 5},
		"member null":           {"events": map[string]any{oidc.BackchannelLogoutEvent: nil}},
		"a nonce":               {"nonce": "n"},
		"neither sub nor sid":   {"sub": nil, "sid": nil},
		"no iat":                {"iat": nil},
		"iat a string":          {"iat": fmt.Sprint(c.Now().Unix())},
		"another aud":           {"aud": "other-app"},
		"azp another client":    {"azp": "other-app"},
		"two auds, no azp":      {"aud": []string{clientID, "other-app"}},
		"issued 25h ago":        {"iat": c.Now().Add(-25 * time.Hour).Unix(), "exp": nil},
		"expired":               {"exp": c.Now().Add(-2 * time.Minute).Unix()},
		"issued ahead of skew":  {"iat": c.Now().Add(2 * time.Minute).Unix()},
	} {
		if _, err := set.VerifyLogout(context.Background(), logoutToken(t, iss, c.Now(), extra)); !errors.Is(err, oidc.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := set.VerifyLogout(context.Background(), logoutToken(t, iss, c.Now(), map[string]any{"exp": nil})); err != nil {
		t.Errorf("no exp, iat now: %v", err)
	}
	if _, err := set.VerifyLogout(context.Background(), logoutToken(t, iss, c.Now(), map[string]any{"azp": clientID})); err != nil {
		t.Errorf("azp the client_id: %v", err)
	}
	// The accepting verifier's domains travel with the logout (Ruling 22).
	if l, err := set.VerifyLogout(context.Background(), logoutToken(t, iss, c.Now(), nil)); err != nil ||
		strings.Join(l.Domains, ",") != "corp.example.com" {
		t.Errorf("domains %v, %v", l.Domains, err)
	}
}

// An ID token is not a logout token, a typ that is not a logout's is
// refused, and a forged signature is refused like a bearer's.
func TestALogoutTokenIsNotAnotherJWT(t *testing.T) {
	iss, c := oidctest.NewIssuer(t), newClock()
	set := newSet(t, iss, c, human(iss, oidc.ClaimEmail))
	idToken := iss.IDToken(t, "k1", clientID, "8b2e", c.Now(), map[string]any{"email": "a@b", "email_verified": true})
	if _, err := set.VerifyLogout(context.Background(), idToken); !errors.Is(err, oidc.ErrInvalid) {
		t.Errorf("an ID token: %v", err)
	}
	at := iss.TokenWith(t, "k1", map[string]any{"kid": "k1", "typ": "at+jwt"}, logoutClaims(iss, c.Now(), nil))
	if _, err := set.VerifyLogout(context.Background(), at); !errors.Is(err, oidc.ErrInvalid) {
		t.Errorf("typ at+jwt: %v", err)
	}
	forger := oidctest.NewIssuer(t)
	forged := forger.TokenWith(t, "k1", map[string]any{"kid": "k1", "typ": "logout+jwt"}, logoutClaims(iss, c.Now(), nil))
	if _, err := set.VerifyLogout(context.Background(), forged); !errors.Is(err, oidc.ErrInvalid) {
		t.Errorf("a forged signature: %v", err)
	}
}

// A machine has no session to end: a logout token for a machine verifier's
// audience is no one's.
func TestAMachineVerifierTakesNoLogout(t *testing.T) {
	iss, c := oidctest.NewIssuer(t), newClock()
	set := newSet(t, iss, c, machine(iss))
	raw := logoutToken(t, iss, c.Now(), map[string]any{"aud": "api://port49-svc"})
	if _, err := set.VerifyLogout(context.Background(), raw); !errors.Is(err, oidc.ErrInvalid) {
		t.Fatalf("a logout for a machine audience: %v", err)
	}
	// A machine verifier has no client_id: an aud of "" must not match it.
	raw = logoutToken(t, iss, c.Now(), map[string]any{"aud": []string{""}})
	if _, err := set.VerifyLogout(context.Background(), raw); !errors.Is(err, oidc.ErrInvalid) {
		t.Fatalf("a logout with an empty aud: %v", err)
	}
	// With the provider down, an issuer of machine verifiers alone still
	// refuses a logout 400, never 503: no verifier could ever apply it, so a
	// retry is pointless.
	down, dc := oidctest.NewIssuer(t), newClock()
	downSet := newSet(t, down, dc, machine(down))
	raw = logoutToken(t, down, dc.Now(), map[string]any{"aud": "api://port49-svc"})
	down.Close()
	if _, err := downSet.VerifyLogout(context.Background(), raw); !errors.Is(err, oidc.ErrInvalid) {
		t.Fatalf("a logout to machine verifiers alone, keys down: %v", err)
	}
}

func TestALogoutWithTheProviderDownIsUnavailable(t *testing.T) {
	iss, c := oidctest.NewIssuer(t), newClock()
	set := newSet(t, iss, c, human(iss, oidc.ClaimEmail))
	raw := logoutToken(t, iss, c.Now(), nil)
	iss.Close()
	if _, err := set.VerifyLogout(context.Background(), raw); !errors.Is(err, oidc.ErrUnavailable) {
		t.Fatalf("keys never fetched: %v", err)
	}
}

func TestALogoutTokenWithholdsItsJTI(t *testing.T) {
	l := oidc.LogoutToken{Issuer: "https://i", Sid: "s", JTI: "jti-marker"}
	for _, verb := range []string{"%v", "%+v", "%#v"} {
		if strings.Contains(fmt.Sprintf(verb, l), "jti-marker") {
			t.Fatalf("%s prints the jti", verb)
		}
	}
	if b, err := json.Marshal(l); err != nil || strings.Contains(string(b), "jti-marker") {
		t.Fatalf("json.Marshal encodes the jti: %v", err)
	}
}

// A claim named twice, or named outside ASCII, is no logout token (as for a
// bearer): a repeated member is refused, never last-wins.
func TestALogoutTokenWithRepeatedOrOddClaimsIsRefused(t *testing.T) {
	iss, c := oidctest.NewIssuer(t), newClock()
	set := newSet(t, iss, c, human(iss, oidc.ClaimEmail))
	body := func(extra string) string {
		return fmt.Sprintf(`{"iss":%q,"aud":%q,"iat":%d,"jti":"j-1","sid":"s-1","events":{%q:{}}%s}`,
			iss.URL, clientID, c.Now().Unix(), oidc.BackchannelLogoutEvent, extra)
	}
	if _, err := set.VerifyLogout(context.Background(), iss.TokenRaw(t, "k1", body(""))); err != nil {
		t.Fatalf("the control: %v", err)
	}
	for name, extra := range map[string]string{
		"sid twice":             `,"sid":"s-2"`,
		"sid in two cases":      `,"SID":"s-2"`,
		"a claim outside ASCII": `,"\u212aid":"x"`,
	} {
		if _, err := set.VerifyLogout(context.Background(), iss.TokenRaw(t, "k1", body(extra))); !errors.Is(err, oidc.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := set.VerifyLogout(context.Background(), iss.TokenRaw(t, "k1", body("")+" {}")); !errors.Is(err, oidc.ErrInvalid) {
		t.Errorf("trailing data: %v", err)
	}
}

// typ is compared as a bearer's is: case-insensitively, application/ removed.
func TestALogoutTokenTypIsCaseInsensitive(t *testing.T) {
	iss, c := oidctest.NewIssuer(t), newClock()
	set := newSet(t, iss, c, human(iss, oidc.ClaimEmail))
	for typ, ok := range map[string]bool{"JWT": true, "Logout+JWT": true, "application/logout+jwt": true,
		"secevent+jwt": false, "id_token": false} {
		raw := iss.TokenWith(t, "k1", map[string]any{"kid": "k1", "typ": typ}, logoutClaims(iss, c.Now(), nil))
		if _, err := set.VerifyLogout(context.Background(), raw); (err == nil) != ok {
			t.Errorf("typ %q: %v", typ, err)
		}
	}
}

// Two human verifiers of one issuer that both accept a logout token accept
// none. Task 7 refuses two with one client_id, so this is defense in depth,
// not a reachable config. A logout ends sessions and never grants anything,
// so a verifier that validated it applies it though another verifier of the
// issuer has no keys: refusing it would be the fail-open side.
func TestALogoutIsAppliedByTheVerifierThatValidatedIt(t *testing.T) {
	iss, other, c := oidctest.NewIssuer(t), oidctest.NewIssuer(t), newClock()
	a, b := human(iss, oidc.ClaimEmail), human(iss, oidc.ClaimEmail)
	b.PrincipalDomains = []string{"other.example.com"}
	set := newSet(t, iss, c, a, b)
	raw := logoutToken(t, iss, c.Now(), nil)
	if _, err := set.VerifyLogout(context.Background(), raw); !errors.Is(err, oidc.ErrInvalid) {
		t.Errorf("two accepting verifiers: %v", err)
	}
	// Distinct client_ids, as Task 7 requires: only a's accepts. b's keys are
	// fetched from an issuer that is down.
	set.Verifiers[1].ClientID = "other-app"
	other.Close()
	set.Verifiers[1].Keys = oidc.NewKeySet(oidc.KeySetConfig{Issuer: other.URL, Client: oidc.NewClient(other.Roots()),
		Refresh: time.Hour, MaxAge: 24 * time.Hour, Now: c.Now, M: set.M})
	l, err := set.VerifyLogout(context.Background(), raw)
	if err != nil || strings.Join(l.Domains, ",") != "corp.example.com" {
		t.Errorf("one verifier validated it, the other has no keys: %v, %v", l.Domains, err)
	}
	// Where no verifier validated it and one has no keys, it is unavailable.
	set.Verifiers[0].Keys = set.Verifiers[1].Keys
	if _, err := set.VerifyLogout(context.Background(), raw); !errors.Is(err, oidc.ErrUnavailable) {
		t.Errorf("no keys at all: %v", err)
	}
}

// Keycloak 26.4's logout token, as the L45 run measured it
// (tests/lab/results/L45-keycloak.md): a top-level typ claim "Logout", and an
// events claim holding the back-channel member beside "revoke_offline_access":
// true, which is no JSON object. Built here with the test signer, not
// captured. Every Keycloak logout rests on port49 accepting it, so a tightening
// of the events check (exactly one member, only objects) must fail this.
func TestAKeycloakShapedLogoutTokenVerifies(t *testing.T) {
	iss, c := oidctest.NewIssuer(t), newClock()
	set := newSet(t, iss, c, human(iss, oidc.ClaimEmail))
	extra := map[string]any{"typ": "Logout", "events": map[string]any{
		oidc.BackchannelLogoutEvent: map[string]any{}, "revoke_offline_access": true}}
	l, err := set.VerifyLogout(context.Background(), logoutToken(t, iss, c.Now(), extra))
	if err != nil {
		t.Fatalf("Keycloak's logout token shape is refused: %v", err)
	}
	if l.Sid != "s-8b2e" || l.Subject != "8b2e" {
		t.Fatalf("logout %+v", l)
	}
}
