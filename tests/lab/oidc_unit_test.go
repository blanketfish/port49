//go:build lab

package lab

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/testpki"
	"github.com/rhwendt/port49/tests/lab/labcreds"
)

// jwsOf builds a compact JWS from a header and claims, with a recognizable
// signature part.
func jwsOf(header, claims map[string]any) string {
	enc := func(m map[string]any) string {
		b, _ := json.Marshal(m)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	return enc(header) + "." + enc(claims) + "." + base64.RawURLEncoding.EncodeToString([]byte("not-a-real-signature"))
}

func TestOIDCClaimsOfDecodesHeaderAndClaims(t *testing.T) {
	h, c := claimsOf(jwsOf(map[string]any{"alg": "RS256", "typ": "JWT"}, map[string]any{"sub": "u1", "sid": "s1"}))
	if h["alg"] != "RS256" || h["typ"] != "JWT" || c["sub"] != "u1" || c["sid"] != "s1" {
		t.Fatalf("header %v claims %v", h, c)
	}
	if _, ok := c["signature"]; ok || len(h) != 2 || len(c) != 2 {
		t.Fatalf("the decode returned more than the header and the claims: %v %v", h, c)
	}
}

func TestOIDCClaimsOfIsNilForWhatIsNotAJWS(t *testing.T) {
	for _, in := range []string{"", "abc", "a.b", "a.b.c.d"} {
		if h, c := claimsOf(in); h != nil || c != nil {
			t.Errorf("%q: %v %v", in, h, c)
		}
	}
	// three parts that are not base64 JSON decode to nil maps, not a panic
	if h, c := claimsOf("!.!.!"); h != nil || c != nil {
		t.Errorf("garbage parts: %v %v", h, c)
	}
}

func TestOIDCEvidenceLineHoldsClaimsNeverAJWS(t *testing.T) {
	b, err := oidcEvidenceLine("(a) end-session", map[string]any{"claims": map[string]any{"sid": "s1"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(string(b), "\n") || !strings.Contains(string(b), `"step":"(a) end-session"`) {
		t.Fatalf("line %q", b)
	}
	tok := jwsOf(map[string]any{"alg": "RS256"}, map[string]any{"sub": "u1"})
	if _, err := oidcEvidenceLine("leak", map[string]any{"id_token": tok}, nil); err == nil {
		t.Fatal("a compact JWS was written to evidence")
	} else if strings.Contains(err.Error(), tok) {
		t.Fatal("the refusal repeats the token")
	}
}

func TestOIDCNoteForm(t *testing.T) {
	note := oidcNote("L45", "the claim", "| a | b |", "tests/lab/evidence/L45-keycloak.json", "commit `abc`", "Keycloak 26.4; image sha256:x")
	for _, want := range []string{"# L45 — keycloak", "**Date measured:**", "**Run:** commit `abc`", "**Platform:**",
		"**Image version:** Keycloak 26.4; image sha256:x", "**Capture:** `tests/lab/evidence/L45-keycloak.json`",
		"## Claim\n\nthe claim", "## Observation\n\n| a | b |"} {
		if !strings.Contains(note, want) {
			t.Errorf("the note lacks %q", want)
		}
	}
}

func TestOIDCNoteLeakRefusesTheAdminPasswordAndAnyJWS(t *testing.T) {
	secrets := []string{"adm-secret"}
	if err := oidcNoteLeak("fine", secrets); err != nil {
		t.Fatal(err)
	}
	err := oidcNoteLeak("x adm-secret y", secrets)
	if err == nil || strings.Contains(err.Error(), "adm-secret") {
		t.Fatalf("admin password: %v", err)
	}
	if err := oidcNoteLeak("x "+jwsOf(map[string]any{"alg": "none"}, map[string]any{"a": 1}), nil); err == nil {
		t.Fatal("a compact JWS passed")
	}
	// an empty registered value must not refuse every note
	if err := oidcNoteLeak("anything", []string{""}); err != nil {
		t.Fatal(err)
	}
}

// RedactNote knows Junos credential forms (a quoted secret, a crypt hash); a
// Keycloak line quoted into a note passes through it, and oidcNoteLeak is the
// guard for what it does not know (the admin password, a JWS).
func TestOIDCNoteRedactionRunsOverWhatIsWritten(t *testing.T) {
	note := oidcNote("L46", "c", `secret "hunter2hunter2"`, "e", "r", "v")
	got := labcreds.RedactNote(note)
	if strings.Contains(got, "hunter2hunter2") {
		t.Fatalf("RedactNote left the value: %s", got)
	}
}

func TestOIDCClaimCell(t *testing.T) {
	if got := claimCell(nil, false); got != "absent" {
		t.Errorf("absent: %q", got)
	}
	if got := claimCell("openid", true); got != "`openid`" {
		t.Errorf("short: %q", got)
	}
	if got := claimCell(strings.Repeat("x", 61), true); got != "present" {
		t.Errorf("long: %q", got)
	}
}

// The compose file's image is the reference oidc_test.go records in a note.
func TestOIDCComposeImageIsThePinnedOne(t *testing.T) {
	if !strings.Contains(kcImage, "@sha256:") {
		t.Fatal("kcImage is not pinned by digest")
	}
	// the standalone stack and the end-to-end's overlay run the same image
	for _, name := range []string{filepath.Join("oidc", "compose.yaml"), filepath.Join("compose", "oidc.yaml")} {
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), "image: "+kcImage+"\n") {
			t.Fatalf("%s's image is not kcImage %s", name, kcImage)
		}
		if strings.Contains(string(b), "KC_BOOTSTRAP_ADMIN_PASSWORD:") {
			t.Fatalf("%s holds the admin password", name)
		}
	}
}

// The realm file and the harness's constants name the same client, redirect
// and service-account id.
func TestOIDCRealmMatchesTheHarness(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("oidc", "keycloak", "realm.json"))
	if err != nil {
		t.Fatal(err)
	}
	var realm struct {
		Realm   string `json:"realm"`
		Clients []struct {
			ClientID     string   `json:"clientId"`
			RedirectURIs []string `json:"redirectUris"`
			PublicClient bool     `json:"publicClient"`
		} `json:"clients"`
		Users []struct {
			ID                     string `json:"id"`
			Username               string `json:"username"`
			Email                  string `json:"email"`
			EmailVerified          bool   `json:"emailVerified"`
			ServiceAccountClientID string `json:"serviceAccountClientId"`
			Credentials            []struct {
				Value     string `json:"value"`
				Temporary bool   `json:"temporary"`
			} `json:"credentials"`
		} `json:"users"`
	}
	if err := json.Unmarshal(b, &realm); err != nil {
		t.Fatal(err)
	}
	if realm.Realm != kcRealm {
		t.Errorf("realm %q, harness %q", realm.Realm, kcRealm)
	}
	var cli bool
	for _, c := range realm.Clients {
		if c.ClientID == kcClient {
			cli = c.PublicClient && len(c.RedirectURIs) == 1 && c.RedirectURIs[0] == kcRedirect
		}
	}
	if !cli {
		t.Errorf("%s is not a public client with redirect %s", kcClient, kcRedirect)
	}
	var sa bool
	for _, u := range realm.Users {
		if u.ServiceAccountClientID == "port49-svc" {
			sa = u.ID == kcServiceAccountID
		}
	}
	if !sa {
		t.Errorf("port49-svc's service account does not carry id %s", kcServiceAccountID)
	}
	// The e2e's three people: a verified email the policy subject names, and a
	// permanent password the harness logs in with (and registers as a secret).
	for user, password := range map[string]string{oidcAlice: oidcAlicePassword, oidcBob: oidcBobPassword, oidcCarol: oidcCarolPassword} {
		var found bool
		for _, u := range realm.Users {
			if u.Username != user {
				continue
			}
			found = u.Email == user+"@corp.example.com" && u.EmailVerified && len(u.Credentials) == 1 &&
				u.Credentials[0].Value == password && !u.Credentials[0].Temporary
		}
		if !found {
			t.Errorf("realm.json has no user %s with email %s@corp.example.com, verified, and password %s", user, user, password)
		}
		if !slices.Contains(labSecrets, password) {
			t.Errorf("labSecrets lacks %s's password", user)
		}
	}
}

func TestOIDCKeycloakClientFollowsNoRedirect(t *testing.T) {
	ca, err := testpki.NewCA("unit", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	c := keycloakClient(ca)
	if err := c.CheckRedirect(nil, nil); err == nil {
		t.Fatal("the client follows redirects")
	}
}

// A planted authorization code: three dot-joined UUIDs, no eyJ prefix, which
// the JWS shape does not see.
const plantedCode = "0b1c2d3e-1111-4222-8333-444455556666.9a8b7c6d-1111-4222-8333-444455556666.5f3c2d1e-0000-4000-8000-000000000049"

func TestOIDCKnownSecretsAreRefusedInNotesAndEvidence(t *testing.T) {
	k := &keycloak{}
	k.know("short", plantedCode, plantedCode, "refresh-token-value-0123")
	if got := k.known(); len(got) != 2 {
		t.Fatalf("know kept %d values (short ones skipped, duplicates once): %v", len(got), got)
	}
	for _, text := range []string{"a note with " + plantedCode + " in it", "x refresh-token-value-0123"} {
		err := oidcNoteLeak(text, k.known())
		if err == nil || strings.Contains(err.Error(), plantedCode) || strings.Contains(err.Error(), "refresh-token-value") {
			t.Errorf("note %q: %v", text, err)
		}
		if _, err := oidcEvidenceLine("s", map[string]any{"v": text}, k.known()); err == nil {
			t.Errorf("evidence %q was written", text)
		}
	}
	if err := oidcNoteLeak("a clean note", k.known()); err != nil {
		t.Fatal(err)
	}
}

func TestOIDCErrCauseDropsTheURL(t *testing.T) {
	const tok = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1MSJ9.c2ln"
	err := &url.Error{Op: "Get", URL: "https://keycloak.port49.lab:18443/x?id_token_hint=" + tok + "&state=planted-state-value",
		Err: errors.New("context deadline exceeded")}
	for _, e := range []error{err, fmt.Errorf("wrapped: %w", err)} {
		got := errCause(e)
		if strings.Contains(got, tok) || strings.Contains(got, "planted-state-value") || strings.Contains(got, "keycloak.port49.lab") {
			t.Fatalf("errCause kept the URL: %q", got)
		}
		if !strings.Contains(got, "context deadline exceeded") {
			t.Fatalf("errCause lost the cause: %q", got)
		}
	}
	if errCause(nil) != "" || errCause(errors.New("plain")) != "plain" {
		t.Fatal("errCause on plain errors")
	}
}

type failingTransport struct{ saw *http.Request }

func (f *failingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	f.saw = r
	return nil, errors.New("connection refused")
}

// The ID token goes in the POST body and in no URL, and a failed end-session
// prints neither the token nor a URL.
func TestOIDCEndSessionKeepsTheIDTokenOutOfURLsAndErrors(t *testing.T) {
	const tok = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1MSJ9.c2ln"
	ft := &failingTransport{}
	k := &keycloak{URL: "https://keycloak.port49.lab:18443/realms/port49-lab", HTTP: &http.Client{Transport: ft}}
	req, err := k.endSessionRequest(tok)
	if err != nil {
		t.Fatal(err)
	}
	if req.Method != "POST" || strings.Contains(req.URL.String(), "eyJ") || req.URL.RawQuery != "" {
		t.Fatalf("request %s %s", req.Method, req.URL)
	}
	body, _ := io.ReadAll(req.Body)
	if !strings.Contains(string(body), "id_token_hint=") {
		t.Fatalf("the token is not in the body: %s", body)
	}
	code, err := k.EndSessionStatus(t, tok)
	if code != 0 || err == nil {
		t.Fatalf("code %d err %v", code, err)
	}
	if strings.Contains(err.Error(), tok) || strings.Contains(err.Error(), "keycloak.port49.lab") || strings.Contains(err.Error(), "http") {
		t.Fatalf("the error carries the token or the URL: %v", err)
	}
	if ft.saw == nil || strings.Contains(ft.saw.URL.String(), "eyJ") {
		t.Fatal("the request that went out had the token in its URL")
	}
}

func TestOIDCLocShapeDropsTheQuery(t *testing.T) {
	u, _ := url.Parse("http://127.0.0.1:18749/callback?code=" + plantedCode + "&state=planted-state-value")
	if got := locShape(u); got != "http://127.0.0.1:18749/callback" || locShape(nil) == "" {
		t.Fatalf("locShape %q", got)
	}
}

func TestOIDCCheckLogoutToken(t *testing.T) {
	iss := "https://keycloak.port49.lab:18443/realms/port49-lab"
	ok := func(c map[string]any) received { return received{Claims: c} }
	for name, tc := range map[string]struct {
		g    received
		good bool
	}{
		"string aud":       {ok(map[string]any{"iss": iss, "aud": "port49-cli"}), true},
		"array aud":        {ok(map[string]any{"iss": iss, "aud": []any{"x", "port49-cli"}}), true},
		"no claims":        {received{}, false},
		"another issuer":   {ok(map[string]any{"iss": "https://evil/realms/x", "aud": "port49-cli"}), false},
		"another audience": {ok(map[string]any{"iss": iss, "aud": "other"}), false},
		"no audience":      {ok(map[string]any{"iss": iss}), false},
	} {
		if err := checkLogoutToken(iss, tc.g); (err == nil) != tc.good {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestOIDCLogoutURLProblem(t *testing.T) {
	has := func(u string) map[string]any {
		return map[string]any{"attributes": map[string]any{"backchannel.logout.url": u}}
	}
	for name, tc := range map[string]struct {
		clients []map[string]any
		good    bool
	}{
		"took":          {[]map[string]any{has("https://r/v1/logout")}, true},
		"not taken":     {[]map[string]any{has("https://receiver.invalid/v1/logout")}, false},
		"none":          {nil, false},
		"two":           {[]map[string]any{has("https://r/v1/logout"), has("https://r/v1/logout")}, false},
		"no attributes": {[]map[string]any{{}}, false},
	} {
		if err := logoutURLProblem(tc.clients, "https://r/v1/logout"); (err == nil) != tc.good {
			t.Errorf("%s: %v", name, err)
		}
	}
}
