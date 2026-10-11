//go:build lab

package lab

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"
)

const l55Claim = "Keycloak as port49's public client meets it (plan 9b): which redirect registration admits an " +
	"authorization request naming http://127.0.0.1:<port>/callback, for the registered port and an ephemeral one " +
	"(RFC 8252 §7.3), against a matcher seen to accept the realm's own redirect and refuse another host's; whether a " +
	"code is exchanged with the right S256 verifier, a wrong one and none, for port49-cli as the realm file sets its " +
	"PKCE method, and whether code_challenge_method=plain is accepted; discovery's code_challenge_methods_supported " +
	"and authorization_response_iss_parameter_supported, and whether the authorization response carries iss (RFC " +
	"9207); whether a 43-character base64url nonce, port49's key binding, comes back in the ID token byte for byte, " +
	"and whether a prompt=login sign-in's auth_time is within 10s of it, and over a live SSO session whether " +
	"prompt=login shows the form and moves auth_time on, against the same session with no prompt (policy engine " +
	"spec §15 L55; §13 decision 43 rulings 1, 3, 4 and 8)."

// l55Accepted is whether Keycloak took an authorization request: it showed
// the login form, rather than its "Invalid parameter" page.
func l55Accepted(status int, body []byte) bool {
	return status == http.StatusOK && formAction.Match(body)
}

// l55Word is an authorization request's outcome as a cell says it.
func l55Word(accepted bool) string {
	if accepted {
		return "accepted"
	}
	return "refused"
}

// l55Browser is a browser of its own: a fresh cookie jar, so no SSO session.
func (k *keycloak) l55Browser() *http.Client {
	c := keycloakClient(k.ca)
	c.Jar, _ = cookiejar.New(nil)
	return c
}

// l55Authorize is an authorization request for port49-cli naming redirect,
// with an S256 challenge for verifier, a fresh state, and extra; a parameter
// extra sets to "" is left out.
func (k *keycloak) l55Authorize(t *testing.T, redirect, verifier string, extra url.Values) string {
	t.Helper()
	state := randomSecret(t)
	k.know(verifier, state)
	sum := sha256.Sum256([]byte(verifier))
	q := url.Values{"response_type": {"code"}, "client_id": {kcClient}, "redirect_uri": {redirect},
		"scope": {"openid email"}, "state": {state}, "prompt": {"login"},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"}}
	for key, v := range extra {
		q[key] = v
		if len(v) == 1 && v[0] == "" {
			delete(q, key)
		}
	}
	return k.URL + "/protocol/openid-connect/auth?" + q.Encode()
}

// authorizeAccepted asks with a fresh browser and reports whether Keycloak
// showed the login form.
func (k *keycloak) authorizeAccepted(t *testing.T, redirect string, extra url.Values) bool {
	t.Helper()
	resp, err := k.l55Browser().Get(k.l55Authorize(t, redirect, randomSecret(t)+randomSecret(t), extra))
	if err != nil {
		t.Fatalf("authorize: %s", errCause(err))
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return l55Accepted(resp.StatusCode, body)
}

// l55SignIn signs alice in with browser and returns the code, its verifier,
// and the authorization response's query (the code registered as secret).
func (k *keycloak) l55SignIn(t *testing.T, browser *http.Client, extra url.Values) (string, string, url.Values) {
	t.Helper()
	code, verifier, q, _ := k.l55SignInForm(t, browser, extra)
	return code, verifier, q
}

// l55SignInForm is l55SignIn, and whether Keycloak showed the login form
// (false: an SSO session in browser answered with no password).
func (k *keycloak) l55SignInForm(t *testing.T, browser *http.Client, extra url.Values) (string, string, url.Values,
	bool) {
	t.Helper()
	verifier, form := randomSecret(t)+randomSecret(t), false
	resp, err := browser.Get(k.l55Authorize(t, kcRedirect, verifier, extra))
	if err != nil {
		t.Fatalf("authorize: %s", errCause(err))
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		m := formAction.FindSubmatch(body)
		if m == nil {
			t.Fatalf("INVALID: authorize answered %s with no login form; no note is written", resp.Status)
		}
		form = true
		if resp, err = browser.PostForm(html.UnescapeString(string(m[1])), url.Values{"username": {oidcAlice},
			"password": {oidcAlicePassword}, "credentialId": {""}}); err != nil {
			t.Fatalf("login: %s", errCause(err))
		}
		resp.Body.Close()
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if resp.StatusCode != http.StatusFound || err != nil || loc.Query().Get("code") == "" {
		t.Fatalf("INVALID: no code (%s, redirect %s); no note is written", resp.Status, locShape(loc))
	}
	k.know(loc.Query().Get("code"))
	return loc.Query().Get("code"), verifier, loc.Query(), form
}

// l55Exchange is the code's exchange with verifierSent ("" sends none); it
// registers every token in the answer as secret, and never fails the test.
func (k *keycloak) l55Exchange(t *testing.T, code, verifierSent string) (int, map[string]any) {
	t.Helper()
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {kcRedirect},
		"client_id": {kcClient}}
	if verifierSent != "" {
		form.Set("code_verifier", verifierSent)
	}
	resp, err := k.HTTP.PostForm(k.URL+"/protocol/openid-connect/token", form)
	if err != nil {
		t.Fatalf("token endpoint: %s", errCause(err))
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	for _, key := range []string{"id_token", "access_token", "refresh_token"} {
		if v, ok := out[key].(string); ok {
			k.know(v)
		}
	}
	return resp.StatusCode, out
}

// l55IDClaims is the claims of the ID token the code's exchange answers; a
// cell with no id_token is INVALID, and no note is written.
func (k *keycloak) l55IDClaims(t *testing.T, code, verifier, cell string) map[string]any {
	t.Helper()
	status, out := k.l55Exchange(t, code, verifier)
	id, ok := out["id_token"].(string)
	if !ok {
		t.Fatalf("INVALID: cell %s's exchange gave no id_token (%s); no note is written", cell, l55Said(status, out))
	}
	_, claims := claimsOf(id)
	return claims
}

// l55Said is a token answer as a cell: its status, and its error or what it
// carried.
func l55Said(status int, out map[string]any) string {
	if e, ok := out["error"]; ok {
		return fmt.Sprintf("%d %v", status, e)
	}
	var has []string
	for _, key := range []string{"id_token", "refresh_token"} {
		if _, ok := out[key]; ok {
			has = append(has, key)
		}
	}
	return fmt.Sprintf("%d with %s", status, strings.Join(has, ", "))
}

// redirects and setRedirects read and replace port49-cli's redirect URIs;
// setRedirects reports whether Keycloak took them, read back.
func (k *keycloak) redirects(t *testing.T) (map[string]any, []string) {
	t.Helper()
	var clients []map[string]any
	k.adminDo(t, "GET", "/clients?clientId="+kcClient, nil, &clients)
	if len(clients) != 1 {
		t.Fatalf("%d clients named %s", len(clients), kcClient)
	}
	var uris []string
	for _, u := range clients[0]["redirectUris"].([]any) {
		uris = append(uris, u.(string))
	}
	return clients[0], uris
}

func (k *keycloak) setRedirects(t *testing.T, uris []string) bool {
	t.Helper()
	c, _ := k.redirects(t)
	c["redirectUris"] = uris
	b, _ := json.Marshal(c)
	req, _ := http.NewRequest("PUT", "https://"+kcHost+":"+kcPort+"/admin/realms/"+kcRealm+"/clients/"+c["id"].(string),
		strings.NewReader(string(b)))
	req.Header.Set("Authorization", "Bearer "+k.Admin(t))
	req.Header.Set("Content-Type", "application/json")
	resp, err := k.HTTP.Do(req)
	if err != nil {
		t.Fatalf("PUT the client: %s", errCause(err))
	}
	resp.Body.Close()
	_, got := k.redirects(t)
	return resp.StatusCode/100 == 2 && slices.Equal(got, uris)
}

func l55FreePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func TestL55PublicClient(t *testing.T) {
	k := startKeycloak(t)
	ev, evPath := oidcEvidence(t, k, "L55-keycloak")
	var obs strings.Builder
	obs.WriteString("| step | observed |\n|---|---|\n")
	cell := func(step, what string) {
		fmt.Fprintf(&obs, "| %s | %s |\n", step, wideCell(what))
		ev(step, what)
	}

	// 1. Discovery and the answer's iss.
	var disc map[string]any
	resp, err := k.HTTP.Get(k.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("discovery: %s", errCause(err))
	}
	_ = json.NewDecoder(resp.Body).Decode(&disc)
	resp.Body.Close()
	cell("1a. discovery code_challenge_methods_supported", fmt.Sprint(disc["code_challenge_methods_supported"]))
	cell("1b. discovery authorization_response_iss_parameter_supported",
		fmt.Sprint(disc["authorization_response_iss_parameter_supported"]))
	_, _, q := k.l55SignIn(t, k.l55Browser(), nil)
	cell("1c. the authorization response's iss", fmt.Sprintf("present %v, the issuer %v", q.Has("iss"), q.Get("iss") == k.URL))

	// 2. The redirect registrations, each against the registered port and an
	// ephemeral one. Controls: with the realm's own registration, its own
	// redirect is accepted and another host's refused, so "accepted" rests on
	// a matcher seen to say both.
	if !k.authorizeAccepted(t, kcRedirect, nil) || k.authorizeAccepted(t, "http://evil.example/callback", nil) {
		t.Fatal("INVALID: the realm's own redirect was not accepted, or another host's was; l55Accepted cannot tell")
	}
	cell("2. control: the realm's own redirect, and http://evil.example/callback", "accepted; refused")
	_, orig := k.redirects(t)
	defer k.setRedirects(t, orig)
	ephemeral := l55FreePort(t)
	for _, reg := range []string{kcRedirect, "http://127.0.0.1/callback", "http://127.0.0.1/*", "http://127.0.0.1:*/callback"} {
		if !k.setRedirects(t, []string{reg}) {
			cell("2. registration "+reg, "not taken by the admin API")
			continue
		}
		var parts []string
		for _, port := range []int{18749, ephemeral} {
			parts = append(parts, fmt.Sprintf("port %d %s", port,
				l55Word(k.authorizeAccepted(t, fmt.Sprintf("http://127.0.0.1:%d/callback", port), nil))))
		}
		cell("2. registration "+reg, strings.Join(parts, "; "))
	}
	if !k.setRedirects(t, []string{kcRedirect}) {
		t.Fatal("INVALID: the realm's own redirect could not be put back; no note is written")
	}

	// 3. PKCE, on port49-cli as the realm file configures it.
	client, _ := k.redirects(t)
	attrs, _ := client["attributes"].(map[string]any)
	pkce := fmt.Sprint(attrs["pkce.code.challenge.method"])
	preface := fmt.Sprintf("port49-cli's `pkce.code.challenge.method` attribute is %q (`tests/lab/oidc/keycloak/"+
		"realm.json`), so step 3 measures a client Keycloak is told requires that method; what it does for a client "+
		"set to require none, which decision 43 ruling 1's provider listing no methods resembles, is not measured "+
		"here.\n\n", pkce)
	cell("3. port49-cli's pkce.code.challenge.method attribute", pkce)
	for _, c := range []struct{ name, how string }{{"the right verifier", "right"}, {"a wrong verifier", "wrong"},
		{"no verifier", "none"}} {
		code, verifier, _ := k.l55SignIn(t, k.l55Browser(), nil)
		sent := map[string]string{"right": verifier, "wrong": verifier + "x", "none": ""}[c.how]
		status, out := k.l55Exchange(t, code, sent)
		// The right verifier is the positive control for the other two: a
		// refusal means something only where the right one is taken.
		if _, ok := out["id_token"].(string); c.how == "right" && (status != http.StatusOK || !ok) {
			t.Fatalf("INVALID: cell 3's exchange with the right verifier was not taken (%s); no note is written",
				l55Said(status, out))
		}
		cell("3. the exchange with "+c.name, l55Said(status, out))
	}
	cell("3d. code_challenge_method=plain", l55Word(k.authorizeAccepted(t, kcRedirect,
		url.Values{"code_challenge_method": {"plain"}, "code_challenge": {randomSecret(t) + randomSecret(t)}})))

	// 4. The key binding: a nonce shaped as api.IssuanceNonce's comes back
	// byte for byte, and a prompt=login sign-in's auth_time is the sign-in's.
	sum := sha256.Sum256([]byte(randomSecret(t)))
	nonce := base64.RawURLEncoding.EncodeToString(sum[:])
	signedAt := time.Now()
	code, verifier, _ := k.l55SignIn(t, k.l55Browser(), url.Values{"nonce": {nonce}})
	claims := k.l55IDClaims(t, code, verifier, "4")
	at, _ := claims["auth_time"].(float64)
	cell("4. a 43-character nonce, and auth_time", fmt.Sprintf("nonce echoed byte for byte %v; auth_time %+.0fs "+
		"from the sign-in", claims["nonce"] == nonce, at-float64(signedAt.Unix())))

	// 4b. prompt=login over a live SSO session, which cell 4's fresh browser
	// cannot show: decision 43 ruling 8's freshness check rests on it. One
	// browser signs in with no prompt, and its fresh jar must be shown the
	// form; 15s later, the control: the same session with no prompt shows no
	// form and keeps the first auth_time, or there is no SSO session for
	// prompt=login to be measured over, and the cell is INVALID; then
	// prompt=login, which must show the form and move auth_time on.
	sso, noPrompt := k.l55Browser(), url.Values{"prompt": {""}}
	code, verifier, _, formFirst := k.l55SignInForm(t, sso, noPrompt)
	if !formFirst {
		t.Fatal("INVALID: cell 4b's first sign-in, in a fresh browser, was not shown the login form; no note is written")
	}
	first, _ := k.l55IDClaims(t, code, verifier, "4b")["auth_time"].(float64)
	time.Sleep(15 * time.Second)
	code, verifier, _, formNone := k.l55SignInForm(t, sso, noPrompt)
	again, _ := k.l55IDClaims(t, code, verifier, "4b")["auth_time"].(float64)
	if formNone || again != first {
		t.Fatalf("INVALID: cell 4b's control: no SSO session held (form %v, auth_time %+.0fs); no note is written",
			formNone, again-first)
	}
	code, verifier, _, formLogin := k.l55SignInForm(t, sso, nil)
	login, _ := k.l55IDClaims(t, code, verifier, "4b")["auth_time"].(float64)
	cell("4b. control: the same SSO session 15s later, no prompt", fmt.Sprintf("form shown %v; auth_time %+.0fs "+
		"after the first sign-in's", formNone, again-first))
	cell("4b. prompt=login over that SSO session", fmt.Sprintf("form shown %v; auth_time %+.0fs after the first "+
		"sign-in's (expected 15s or more)", formLogin, login-first))
	writeOIDCResult(t, k, "L55", l55Claim, preface+obs.String(), evPath)
}
