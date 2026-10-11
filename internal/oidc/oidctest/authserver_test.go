package oidctest

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// claimsOf is a JWS's claims, decoded without verification: the test reads
// what the server signed.
func claimsOf(t *testing.T, raw string) map[string]any {
	t.Helper()
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		t.Fatalf("not a compact JWS: %d parts", len(parts))
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var c map[string]any
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	return c
}

// authorize asks i's /authorize for a code with verifier's S256 challenge,
// redirecting to a loopback port nothing listens on, and returns the
// redirect's query without following it.
func authorize(t *testing.T, i *Issuer, verifier, nonce string) (url.Values, string) {
	t.Helper()
	sum := sha256.Sum256([]byte(verifier))
	redirect := "http://127.0.0.1:1/callback"
	q := url.Values{"response_type": {"code"}, "client_id": {"port49-cli"}, "redirect_uri": {redirect},
		"scope": {"openid"}, "state": {"st"}, "nonce": {nonce}, "prompt": {"login"},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"}}
	loc, err := i.Redirected(i.URL + "/authorize?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query(), redirect
}

// token posts form to i's /token and returns the status and the answer.
func token(t *testing.T, i *Issuer, form url.Values) (int, map[string]any) {
	t.Helper()
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: i.Roots()}}}
	resp, err := c.PostForm(i.URL+"/token", form)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func TestTheCodeFlowIssuesAnIDTokenForTheVerifier(t *testing.T) {
	i := NewIssuer(t)
	a := i.AuthServer(t, "port49-cli", "sub-alice", map[string]any{"preferred_username": "alice@example.com"})
	q, redirect := authorize(t, i, "verifier-0123456789-0123456789-0123456789", "n-1")
	if q.Get("state") != "st" || q.Get("iss") != i.URL || q.Get("code") == "" {
		t.Fatalf("the answer: state %q iss %q code present %v", q.Get("state"), q.Get("iss"), q.Get("code") != "")
	}
	code, out := token(t, i, url.Values{"grant_type": {"authorization_code"}, "code": {q.Get("code")},
		"redirect_uri": {redirect}, "client_id": {"port49-cli"},
		"code_verifier": {"verifier-0123456789-0123456789-0123456789"}})
	// A provider's answer carries a refresh token too; port49 drops it.
	if code != 200 || out["refresh_token"] == nil {
		t.Fatalf("exchange: %d, refresh token present %v", code, out["refresh_token"] != nil)
	}
	if c := claimsOf(t, out["id_token"].(string)); c["sub"] != "sub-alice" || c["nonce"] != "n-1" ||
		c["aud"] != "port49-cli" || c["iss"] != i.URL || c["sid"] != "s-sub-alice" {
		t.Fatalf("the ID token's claims: sub %v nonce %v aud %v iss %v sid %v", c["sub"], c["nonce"], c["aud"],
			c["iss"], c["sid"])
	}
	if got := a.Authorizations(); len(got) != 1 || got[0].Get("prompt") != "login" {
		t.Fatalf("authorizations recorded: %d", len(got))
	}
	if n := len(a.Issued()); n != 3 {
		t.Fatalf("issued %d values (code, ID token, refresh token)", n)
	}
}

// A code is exchanged once, with the verifier its challenge was made from
// (RFC 7636 §4.6): a wrong verifier and a second use are invalid_grant.
func TestTheTokenEndpointRefusesAWrongVerifier(t *testing.T) {
	i := NewIssuer(t)
	i.AuthServer(t, "port49-cli", "sub-alice", nil)
	right := "verifier-0123456789-0123456789-0123456789"
	q, redirect := authorize(t, i, right, "n")
	form := url.Values{"grant_type": {"authorization_code"}, "code": {q.Get("code")}, "redirect_uri": {redirect},
		"client_id": {"port49-cli"}, "code_verifier": {right + "x"}}
	if code, out := token(t, i, form); code != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("a wrong verifier: %d %v", code, out["error"])
	}
	form.Set("code_verifier", right)
	if code, out := token(t, i, form); code != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("a code tried once already: %d %v", code, out["error"])
	}
	form.Set("grant_type", "refresh_token")
	if code, out := token(t, i, form); code != 400 || out["error"] != "unsupported_grant_type" {
		t.Fatalf("the refresh grant, which port49 never sends: %d %v", code, out["error"])
	}
}

// SetAuthTime is a provider that reused an old authentication: a
// prompt=login it ignored.
func TestSetAuthTimeIsAReusedAuthentication(t *testing.T) {
	i := NewIssuer(t)
	a := i.AuthServer(t, "port49-cli", "sub-alice", nil)
	at := time.Now().Add(-time.Hour).Truncate(time.Second)
	a.SetAuthTime(at)
	q, redirect := authorize(t, i, "verifier-0123456789-0123456789-0123456789", "n")
	_, out := token(t, i, url.Values{"grant_type": {"authorization_code"}, "code": {q.Get("code")},
		"redirect_uri": {redirect}, "client_id": {"port49-cli"},
		"code_verifier": {"verifier-0123456789-0123456789-0123456789"}})
	if c := claimsOf(t, out["id_token"].(string)); c["auth_time"] != float64(at.Unix()) {
		t.Fatalf("auth_time %v, want %d", c["auth_time"], at.Unix())
	}
}

// Discovery names the endpoints once an authorization server exists, and
// Browser follows the provider's redirect to a loopback listener.
func TestDiscoveryAndTheBrowser(t *testing.T) {
	i := NewIssuer(t)
	i.AuthServer(t, "port49-cli", "sub-alice", nil)
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: i.Roots()}}}
	resp, err := c.Get(i.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&doc)
	resp.Body.Close()
	if doc["authorization_endpoint"] != i.URL+"/authorize" || doc["token_endpoint"] != i.URL+"/token" ||
		doc["authorization_response_iss_parameter_supported"] != true {
		t.Fatalf("discovery: %v", doc)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan url.Values, 1)
	go func() {
		_ = http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got <- r.URL.Query() }))
	}()
	defer ln.Close()
	q := url.Values{"response_type": {"code"}, "client_id": {"port49-cli"}, "state": {"s"},
		"redirect_uri": {"http://" + ln.Addr().String() + "/callback"}, "code_challenge": {"c"},
		"code_challenge_method": {"S256"}}
	if err := i.Browser()(i.URL + "/authorize?" + q.Encode()); err != nil {
		t.Fatal(err)
	}
	if v := <-got; v.Get("code") == "" || !strings.HasPrefix(v.Get("iss"), "https://") {
		t.Fatalf("the callback: code present %v, iss %q", v.Get("code") != "", v.Get("iss"))
	}
}
