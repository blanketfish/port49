//go:build lab

package lab

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

// flowResult is what one authorization-code flow (or refresh) returned,
// and whether Keycloak asked for the password on the way.
type flowResult struct {
	IDToken, AccessToken, RefreshToken string
	SawLoginForm                       bool
}

var formAction = regexp.MustCompile(`<form[^>]*id="kc-form-login"[^>]*action="([^"]+)"`)

// Login runs the authorization-code flow with PKCE as port49-cli, as plan
// 9's agent will: extra adds prompt, nonce or max_age. The browser's
// cookies persist across calls on k (one jar per keycloak), so a second
// Login is inside the first's SSO session.
func (k *keycloak) Login(t *testing.T, user, pass string, extra url.Values) flowResult {
	t.Helper()
	if k.HTTP.Jar == nil {
		jar, _ := cookiejar.New(nil)
		k.HTTP.Jar = jar
	}
	verifier := randomSecret(t) + randomSecret(t)
	state := randomSecret(t)
	k.know(verifier, state)
	sum := sha256.Sum256([]byte(verifier))
	q := url.Values{"response_type": {"code"}, "client_id": {kcClient}, "redirect_uri": {kcRedirect},
		"scope": {"openid email"}, "state": {state},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"}}
	for k2, v := range extra {
		q[k2] = v
	}
	resp, err := k.HTTP.Get(k.URL + "/protocol/openid-connect/auth?" + q.Encode())
	if err != nil {
		t.Fatalf("authorize: %s", errCause(err))
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	res := flowResult{}
	if resp.StatusCode == http.StatusOK {
		m := formAction.FindSubmatch(body)
		if m == nil {
			// not the page: its form action carries session_code and execution
			t.Fatalf("authorize answered %s with a %d-byte page that has no login form (kc-form-login present: %v)",
				resp.Status, len(body), strings.Contains(string(body), "kc-form-login"))
		}
		res.SawLoginForm = true
		resp, err = k.HTTP.PostForm(html.UnescapeString(string(m[1])), url.Values{"username": {user},
			"password": {pass}, "credentialId": {""}})
		if err != nil {
			t.Fatalf("login: %s", errCause(err))
		}
		resp.Body.Close()
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if resp.StatusCode != http.StatusFound || err != nil || !strings.HasPrefix(loc.String(), kcRedirect) ||
		loc.Query().Get("code") == "" {
		// not the Location's query: it carries the code, or an error's detail
		t.Fatalf("no code: %s, redirect to %s, code present: %v", resp.Status, locShape(loc), loc != nil && loc.Query().Get("code") != "")
	}
	var tok struct {
		IDToken      string `json:"id_token"`
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	k.postForm(t, k.URL+"/protocol/openid-connect/token", url.Values{"grant_type": {"authorization_code"},
		"code": {loc.Query().Get("code")}, "redirect_uri": {kcRedirect}, "client_id": {kcClient},
		"code_verifier": {verifier}}, &tok)
	res.IDToken, res.AccessToken, res.RefreshToken = tok.IDToken, tok.AccessToken, tok.RefreshToken
	k.know(loc.Query().Get("code"), tok.IDToken, tok.AccessToken, tok.RefreshToken)
	if u, err := url.Parse(k.URL); err == nil {
		for _, c := range k.HTTP.Jar.Cookies(u) {
			k.know(c.Value)
		}
	}
	return res
}

// Refresh is the refresh-token grant: no authentication at all.
func (k *keycloak) Refresh(t *testing.T, refresh string) flowResult {
	t.Helper()
	var tok struct {
		IDToken      string `json:"id_token"`
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	k.postForm(t, k.URL+"/protocol/openid-connect/token", url.Values{"grant_type": {"refresh_token"},
		"refresh_token": {refresh}, "client_id": {kcClient}, "scope": {"openid email"}}, &tok)
	k.know(tok.IDToken, tok.AccessToken, tok.RefreshToken)
	return flowResult{IDToken: tok.IDToken, AccessToken: tok.AccessToken, RefreshToken: tok.RefreshToken}
}

// EndSession is an RP-initiated logout with id_token_hint, which must be
// answered 302 or 200.
func (k *keycloak) EndSession(t *testing.T, idToken string) {
	t.Helper()
	code, err := k.EndSessionStatus(t, idToken)
	if err != nil || (code != http.StatusFound && code != http.StatusOK) {
		t.Fatalf("end session: %d %v", code, err)
	}
}

// endSessionRequest is the end-session request: a POST form (OIDC RP-Initiated
// Logout allows it), so the ID token is in the body, never in a URL that an
// error, a proxy or an access log would print.
func (k *keycloak) endSessionRequest(idToken string) (*http.Request, error) {
	form := url.Values{"id_token_hint": {idToken}, "client_id": {kcClient},
		"post_logout_redirect_uri": {"http://127.0.0.1:18749/bye"}}
	req, err := http.NewRequest("POST", k.URL+"/protocol/openid-connect/logout", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req, nil
}

// EndSessionStatus is EndSession that records Keycloak's answer instead of
// failing on it: what the end-session endpoint answers when its
// back-channel delivery fails is what L45 (d) measures, and a fatal there
// would lose the whole note (pre-flight I-11). The error it returns has no URL.
func (k *keycloak) EndSessionStatus(t *testing.T, idToken string) (int, error) {
	t.Helper()
	req, err := k.endSessionRequest(idToken)
	if err != nil {
		return 0, errors.New(errCause(err))
	}
	resp, err := k.HTTP.Do(req)
	if err != nil {
		return 0, errors.New(errCause(err))
	}
	resp.Body.Close()
	return resp.StatusCode, nil
}

// locShape is a redirect's scheme, host and path: what a message may say of a
// Location whose query holds a code.
func locShape(u *url.URL) string {
	if u == nil {
		return "(unparsable)"
	}
	return u.Scheme + "://" + u.Host + u.Path
}

// ServiceToken is the client-credentials grant as port49-svc.
func (k *keycloak) ServiceToken(t *testing.T) string {
	t.Helper()
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	k.postForm(t, k.URL+"/protocol/openid-connect/token", url.Values{"grant_type": {"client_credentials"},
		"client_id": {"port49-svc"}, "client_secret": {"lab-only-svc-secret"}}, &tok)
	k.know(tok.AccessToken)
	return tok.AccessToken
}
