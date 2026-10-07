//go:build lab

package lab

import (
	"crypto/sha256"
	"encoding/base64"
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
	sum := sha256.Sum256([]byte(verifier))
	q := url.Values{"response_type": {"code"}, "client_id": {kcClient}, "redirect_uri": {kcRedirect},
		"scope": {"openid email"}, "state": {randomSecret(t)},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"}}
	for k2, v := range extra {
		q[k2] = v
	}
	resp, err := k.HTTP.Get(k.URL + "/protocol/openid-connect/auth?" + q.Encode())
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	res := flowResult{}
	if resp.StatusCode == http.StatusOK {
		m := formAction.FindSubmatch(body)
		if m == nil {
			t.Fatalf("authorize answered a page with no login form: %s", oneLineMax(string(body), 300))
		}
		res.SawLoginForm = true
		resp, err = k.HTTP.PostForm(html.UnescapeString(string(m[1])), url.Values{"username": {user},
			"password": {pass}, "credentialId": {""}})
		if err != nil {
			t.Fatalf("login: %v", err)
		}
		resp.Body.Close()
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if resp.StatusCode != http.StatusFound || err != nil || !strings.HasPrefix(loc.String(), kcRedirect) ||
		loc.Query().Get("code") == "" {
		t.Fatalf("no code: %s %s", resp.Status, resp.Header.Get("Location"))
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

// EndSessionStatus is EndSession that records Keycloak's answer instead of
// failing on it: what the end-session endpoint answers when its
// back-channel delivery fails is what L45 (d) measures, and a fatal there
// would lose the whole note (pre-flight I-11).
func (k *keycloak) EndSessionStatus(t *testing.T, idToken string) (int, error) {
	t.Helper()
	q := url.Values{"id_token_hint": {idToken}, "client_id": {kcClient},
		"post_logout_redirect_uri": {"http://127.0.0.1:18749/bye"}}
	resp, err := k.HTTP.Get(k.URL + "/protocol/openid-connect/logout?" + q.Encode())
	if err != nil {
		return 0, err
	}
	resp.Body.Close()
	return resp.StatusCode, nil
}

// ServiceToken is the client-credentials grant as port49-svc.
func (k *keycloak) ServiceToken(t *testing.T) string {
	t.Helper()
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	k.postForm(t, k.URL+"/protocol/openid-connect/token", url.Values{"grant_type": {"client_credentials"},
		"client_id": {"port49-svc"}, "client_secret": {"lab-only-svc-secret"}}, &tok)
	return tok.AccessToken
}
