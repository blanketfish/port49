package oidctest

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"
)

// AuthServer is the issuer's authorization server for one public client
// (plan 9b): GET /authorize answers at once, as a provider holding a live
// session does, by redirecting to the request's loopback redirect_uri with
// a code for Sub; POST /token takes that code with its PKCE verifier. Its
// answer carries an ID token and a refresh token, as a provider's does;
// port49 exchanges the ID token for a certificate and drops the refresh
// token. Discovery then names both endpoints, S256 and the iss parameter
// (RFC 9207).
type AuthServer struct {
	ClientID string
	Sub      string
	// Claims go into every ID token beside iss, aud, sub, iat, exp,
	// auth_time, sid, jti and the request's nonce.
	Claims map[string]any
	// Now is the provider's clock; nil is time.Now.
	Now func() time.Time

	t        testing.TB
	i        *Issuer
	mu       sync.Mutex
	authTime time.Time
	noIss    bool
	deny     string
	codes    map[string]grant
	asked    []url.Values
	grants   []url.Values
	issued   []string
}

// grant is what a code stands for.
type grant struct {
	redirect, challenge, nonce string
	authTime, expires          time.Time
}

// AuthServer makes i an authorization server for clientID, signing in sub
// with claims. ID tokens live five minutes, and each sign-in is an
// authentication at Now.
func (i *Issuer) AuthServer(t testing.TB, clientID, sub string, claims map[string]any) *AuthServer {
	a := &AuthServer{ClientID: clientID, Sub: sub, Claims: claims, t: t, i: i, codes: map[string]grant{}}
	i.mu.Lock()
	i.auth = a
	i.mu.Unlock()
	return a
}

func (a *AuthServer) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

// SetAuthTime makes every later sign-in reuse an authentication at at, as a
// provider ignoring prompt=login does; the zero time makes each one an
// authentication at Now again.
func (a *AuthServer) SetAuthTime(at time.Time) { a.mu.Lock(); a.authTime = at; a.mu.Unlock() }

// NoIssParameter drops iss from the authorization response and from
// discovery.
func (a *AuthServer) NoIssParameter() { a.mu.Lock(); a.noIss = true; a.mu.Unlock() }

// Deny answers every later authorization with error=code.
func (a *AuthServer) Deny(code string) { a.mu.Lock(); a.deny = code; a.mu.Unlock() }

// Authorizations is every /authorize query, in order.
func (a *AuthServer) Authorizations() []url.Values {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]url.Values(nil), a.asked...)
}

// Grants is every /token form, in order.
func (a *AuthServer) Grants() []url.Values {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]url.Values(nil), a.grants...)
}

// Issued is every code, ID token and refresh token given out: the values no
// output may hold.
func (a *AuthServer) Issued() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.issued...)
}

// signInTime is a new sign-in's auth_time. Called with a.mu held.
func (a *AuthServer) signInTime() time.Time {
	if !a.authTime.IsZero() {
		return a.authTime
	}
	return a.now()
}

func (a *AuthServer) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	a.mu.Lock()
	defer a.mu.Unlock()
	a.asked = append(a.asked, q)
	redirect := q.Get("redirect_uri")
	u, err := url.Parse(redirect)
	if q.Get("client_id") != a.ClientID || err != nil || u.Scheme != "http" || u.Hostname() != "127.0.0.1" ||
		u.Path != "/callback" {
		http.Error(w, "oidctest: an unknown client or a redirect_uri that is not loopback", http.StatusBadRequest)
		return
	}
	back := u.Query()
	back.Set("state", q.Get("state"))
	if !a.noIss {
		back.Set("iss", a.i.URL)
	}
	switch {
	case a.deny != "":
		back.Set("error", a.deny)
		back.Set("error_description", "oidctest: denied")
	case q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "":
		back.Set("error", "invalid_request")
	default:
		code := opaque()
		a.codes[code] = grant{redirect: redirect, challenge: q.Get("code_challenge"), nonce: q.Get("nonce"),
			authTime: a.signInTime(), expires: a.now().Add(time.Minute)}
		a.issued = append(a.issued, code)
		back.Set("code", code)
	}
	u.RawQuery = back.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (a *AuthServer) token(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if err := r.ParseForm(); err != nil {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}
	f := r.PostForm
	a.mu.Lock()
	defer a.mu.Unlock()
	a.grants = append(a.grants, f)
	fail := func(status int, code string) {
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": "oidctest: " + code})
	}
	if f.Get("client_id") != a.ClientID || f.Has("client_secret") {
		fail(http.StatusUnauthorized, "invalid_client")
		return
	}
	if f.Get("grant_type") != "authorization_code" {
		fail(http.StatusBadRequest, "unsupported_grant_type")
		return
	}
	g, ok := a.codes[f.Get("code")]
	delete(a.codes, f.Get("code"))
	sum := sha256.Sum256([]byte(f.Get("code_verifier")))
	if !ok || a.now().After(g.expires) || f.Get("redirect_uri") != g.redirect ||
		base64.RawURLEncoding.EncodeToString(sum[:]) != g.challenge {
		fail(http.StatusBadRequest, "invalid_grant")
		return
	}
	now := a.now()
	// A random jti: RS256 is deterministic, and two sign-ins in one second
	// must not give one JWS.
	c := map[string]any{"iss": a.i.URL, "aud": a.ClientID, "sub": a.Sub, "iat": now.Unix(),
		"exp": now.Add(5 * time.Minute).Unix(), "auth_time": g.authTime.Unix(), "sid": "s-" + a.Sub, "jti": opaque()}
	if g.nonce != "" {
		c["nonce"] = g.nonce
	}
	for k, v := range a.Claims {
		c[k] = v
	}
	id, rt := a.i.Token(a.t, "k1", c), opaque()
	a.issued = append(a.issued, id, rt)
	_ = json.NewEncoder(w).Encode(map[string]any{"token_type": "Bearer", "access_token": opaque(),
		"expires_in": 300, "id_token": id, "refresh_token": rt})
}

// opaque is 32 random bytes, base64url.
func opaque() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// Browser is a browser that trusts the issuer: it opens a URL and follows
// the provider's redirect to the loopback callback, as a person's browser
// does once they have signed in. It errs unless the last answer is 200.
func (i *Issuer) Browser() func(string) error {
	c := &http.Client{Timeout: 10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: i.Roots()}}}
	return func(u string) error {
		resp, err := c.Get(u)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("oidctest browser: %s", resp.Status)
		}
		return nil
	}
}

// Redirected opens u and returns where the provider redirected it, without
// following: what a person on a remote shell copies from the address bar.
func (i *Issuer) Redirected(u string) (string, error) {
	c := &http.Client{Timeout: 10 * time.Second,
		Transport:     &http.Transport{TLSClientConfig: &tls.Config{RootCAs: i.Roots()}},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := c.Get(u)
	if err != nil {
		return "", err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		return "", fmt.Errorf("oidctest: /authorize answered %s", resp.Status)
	}
	return resp.Header.Get("Location"), nil
}
