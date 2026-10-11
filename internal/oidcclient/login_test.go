package oidcclient

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// credentialsNowhere fails if text holds any value the provider issued.
func credentialsNowhere(t *testing.T, text string, issued []string) {
	t.Helper()
	for _, v := range issued {
		if strings.Contains(text, v) {
			t.Fatalf("a code or token was printed")
		}
	}
}

// redirectOf is the redirect_uri an authorization URL names.
func redirectOf(t *testing.T, authURL string) *url.URL {
	t.Helper()
	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatal(err)
	}
	r, err := url.Parse(u.Query().Get("redirect_uri"))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// The request is decision 43 ruling 3's, the redirect a loopback port, and
// the ID token the provider's; nothing printed holds a credential.
func TestASignInReturnsTheIDTokenForTheVerifier(t *testing.T) {
	iss, as, p := provider(t)
	e, _ := Discover(context.Background(), p)
	var out bytes.Buffer
	got, err := Login(context.Background(), p, e, LoginOptions{Browser: iss.Browser(), Out: &out})
	if err != nil || got.ID.Subject != "sub-alice" || got.IDRaw == "" {
		t.Fatalf("%v %v\n%s", got, err, out.String())
	}
	q := as.Authorizations()[0]
	r, _ := url.Parse(q.Get("redirect_uri"))
	for k, want := range map[string]string{"response_type": "code", "client_id": "port49-cli", "scope": "openid",
		"code_challenge_method": "S256", "prompt": "login"} {
		if q.Get(k) != want {
			t.Errorf("%s = %q, want %q", k, q.Get(k), want)
		}
	}
	if len(q.Get("code_challenge")) != 43 || len(q.Get("state")) != 43 || len(q.Get("nonce")) != 43 ||
		r.Scheme != "http" || r.Hostname() != "127.0.0.1" || r.Port() == "0" || r.Path != "/callback" {
		t.Fatalf("the request: challenge %d state %d nonce %d redirect %s", len(q.Get("code_challenge")),
			len(q.Get("state")), len(q.Get("nonce")), r)
	}
	if !strings.Contains(out.String(), "in the browser that opened") {
		t.Fatalf("%s", out.String())
	}
	credentialsNowhere(t, out.String(), as.Issued())
	// The listener is gone once Login returns.
	if c, err := net.DialTimeout("tcp", r.Host, time.Second); err == nil {
		c.Close()
		t.Fatalf("%s still listens", r.Host)
	}
}

// A nonce the caller gives (the key binding, decision 43 ruling 3) is the
// request's, and the ID token must echo it.
func TestTheGivenNonceIsSent(t *testing.T) {
	iss, as, p := provider(t)
	e, _ := Discover(context.Background(), p)
	got, err := Login(context.Background(), p, e, LoginOptions{Nonce: "key-binding-n", Browser: iss.Browser()})
	if err != nil || got.ID.Nonce != "key-binding-n" || as.Authorizations()[0].Get("nonce") != "key-binding-n" {
		t.Fatalf("%v %v", got, err)
	}
}

// An answer with another state is refused and waited past: anyone on the
// host can reach the port (ruling 4).
func TestACallbackWithAnotherStateIsIgnored(t *testing.T) {
	iss, _, p := provider(t)
	e, _ := Discover(context.Background(), p)
	var status int
	browse := func(u string) error {
		r := redirectOf(t, u)
		resp, err := http.Get("http://" + r.Host + "/callback?state=forged&code=x")
		if err != nil {
			return err
		}
		resp.Body.Close()
		status = resp.StatusCode
		return iss.Browser()(u)
	}
	if _, err := Login(context.Background(), p, e, LoginOptions{Browser: browse}); err != nil || status != 400 {
		t.Fatalf("forged answer %d, then %v", status, err)
	}
}

// An answer with this sign-in's state naming another issuer ends it (RFC
// 9207: a mix-up), and so does one with no iss from a provider that sends it.
func TestAnIssParameterNamingAnotherIssuerIsRefused(t *testing.T) {
	_, _, p := provider(t)
	e, _ := Discover(context.Background(), p)
	answer := func(extra string) func(string) error {
		return func(u string) error {
			v, _ := url.Parse(u)
			go func() {
				resp, err := http.Get(fmt.Sprintf("http://%s/callback?state=%s&code=x%s", redirectOf(t, u).Host,
					url.QueryEscape(v.Query().Get("state")), extra))
				if err == nil {
					resp.Body.Close()
				}
			}()
			return nil
		}
	}
	if _, err := Login(context.Background(), p, e, LoginOptions{Browser: answer("&iss=https%3A%2F%2Fevil.example")}); err == nil ||
		!strings.Contains(err.Error(), "RFC 9207") {
		t.Fatalf("another iss: %v", err)
	}
	if _, err := Login(context.Background(), p, e, LoginOptions{Browser: answer("")}); err == nil ||
		!strings.Contains(err.Error(), "carries no iss") {
		t.Fatalf("no iss from a provider that sends it: %v", err)
	}
}

// A redirect repeating iss, state or code is refused whichever copy is
// right, loopback and pasted address alike (RFC 9207: one of each).
func TestARepeatedParameterIsRefused(t *testing.T) {
	w := &waiter{state: "s1", issuer: "https://idp.example", requireIss: true,
		redirect: "http://127.0.0.1:5000/callback"}
	for name, query := range map[string]string{
		"iss":   "state=s1&code=c&iss=https%3A%2F%2Fidp.example&iss=https%3A%2F%2Fevil.example",
		"code":  "state=s1&code=c&code=d&iss=https%3A%2F%2Fidp.example",
		"state": "state=s1&state=other&code=c&iss=https%3A%2F%2Fidp.example",
	} {
		q, _ := url.ParseQuery(query)
		if a, ours := w.judge(q); ours && a.err == nil {
			t.Errorf("repeated %s accepted", name)
		}
		if a, why := w.pasted("http://127.0.0.1:5000/callback?" + query); why == "" && a.err == nil {
			t.Errorf("repeated %s accepted by paste", name)
		}
	}
}

// A repeated state over the loopback is answered 400 and waited past.
func TestARepeatedStateOverTheLoopbackIsIgnored(t *testing.T) {
	iss, _, p := provider(t)
	e, _ := Discover(context.Background(), p)
	var status int
	browse := func(u string) error {
		v, _ := url.Parse(u)
		resp, err := http.Get(fmt.Sprintf("http://%s/callback?state=%s&state=forged&code=x", redirectOf(t, u).Host,
			url.QueryEscape(v.Query().Get("state"))))
		if err != nil {
			return err
		}
		resp.Body.Close()
		status = resp.StatusCode
		return iss.Browser()(u)
	}
	if _, err := Login(context.Background(), p, e, LoginOptions{Browser: browse}); err != nil || status != 400 {
		t.Fatalf("repeated state %d, then %v", status, err)
	}
}

// A repeated iss over the loopback ends the sign-in.
func TestARepeatedIssOverTheLoopbackIsRefused(t *testing.T) {
	_, _, p := provider(t)
	e, _ := Discover(context.Background(), p)
	browse := func(u string) error {
		v, _ := url.Parse(u)
		go func() {
			resp, err := http.Get(fmt.Sprintf("http://%s/callback?state=%s&code=x&iss=%s&iss=https%%3A%%2F%%2Fevil.example",
				redirectOf(t, u).Host, url.QueryEscape(v.Query().Get("state")), url.QueryEscape(p.Issuer)))
			if err == nil {
				resp.Body.Close()
			}
		}()
		return nil
	}
	if _, err := Login(context.Background(), p, e, LoginOptions{Browser: browse}); err == nil ||
		!strings.Contains(err.Error(), "RFC 9207") {
		t.Fatalf("%v", err)
	}
}

// A pasted address with the right host but another sign-in's state is
// refused, saying why.
func TestAPastedAddressWithAnotherStateIsRefused(t *testing.T) {
	w := &waiter{state: "s1", issuer: "https://idp.example", redirect: "http://127.0.0.1:5000/callback"}
	_, why := w.pasted("http://127.0.0.1:5000/callback?state=other&code=c")
	if !strings.Contains(why, "another sign-in") {
		t.Fatalf("%q", why)
	}
}

// A provider's refusal is said by its code.
func TestADeniedSignInSaysTheProvidersCode(t *testing.T) {
	iss, as, p := provider(t)
	e, _ := Discover(context.Background(), p)
	as.Deny("access_denied")
	// The browser opened: the 400 it ends on is port49's own page saying the
	// sign-in failed.
	browse := func(u string) error { _ = iss.Browser()(u); return nil }
	if _, err := Login(context.Background(), p, e, LoginOptions{Browser: browse}); err == nil ||
		!strings.Contains(err.Error(), "access_denied") {
		t.Fatalf("%v", err)
	}
}

// With no browser the address is printed and a pasted one completes the
// sign-in; a paste that is not this sign-in's answer is refused, saying
// why, and asked again (ruling 5).
func TestAPastedAddressCompletesTheSignIn(t *testing.T) {
	iss, as, p := provider(t)
	e, _ := Discover(context.Background(), p)
	authURL := make(chan string, 1)
	var mu sync.Mutex
	var out bytes.Buffer
	pastes := 0
	paste := func() (string, error) {
		mu.Lock()
		pastes++
		n := pastes
		mu.Unlock()
		u := <-authURL
		authURL <- u
		if n == 1 {
			return "http://example.com/elsewhere", nil
		}
		return iss.Redirected(u)
	}
	got, err := Login(context.Background(), p, e, LoginOptions{
		Browser: func(u string) error { authURL <- u; return errors.New("no display") },
		Paste:   paste, Out: &lockedWriter{mu: &mu, w: &out}})
	mu.Lock()
	text := out.String()
	mu.Unlock()
	if err != nil || got.ID.Subject != "sub-alice" {
		t.Fatalf("%v %v\n%s", got, err, text)
	}
	for _, want := range []string{"open this address in a browser", "paste it here (it is not shown)",
		"that is not the address the sign-in was sent back to", "paste the address again"} {
		if !strings.Contains(text, want) {
			t.Errorf("no %q in %s", want, text)
		}
	}
	credentialsNowhere(t, text, as.Issued())
}

// A fixed port is the one the redirect names (oidc_redirect_port).
func TestAFixedPortIsUsed(t *testing.T) {
	iss, as, p := provider(t)
	e, _ := Discover(context.Background(), p)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	if _, err := Login(context.Background(), p, e, LoginOptions{Port: port, Browser: iss.Browser()}); err != nil {
		t.Fatal(err)
	}
	if r, _ := url.Parse(as.Authorizations()[0].Get("redirect_uri")); r.Port() != fmt.Sprint(port) {
		t.Fatalf("redirect %s, want port %d", r, port)
	}
}

// A cancelled sign-in stops listening and says so.
func TestACancelledSignInStops(t *testing.T) {
	_, _, p := provider(t)
	e, _ := Discover(context.Background(), p)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if _, err := Login(ctx, p, e, LoginOptions{Browser: func(string) error { return nil }}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("%v", err)
	}
}

// No browser, no terminal and an ephemeral port is said at once; with a
// fixed port, which ssh -L can forward, the sign-in waits and says how
// (ruling 5).
func TestNoBrowserAndNoTerminalIsSaidAtOnce(t *testing.T) {
	_, as, p := provider(t)
	e, _ := Discover(context.Background(), p)
	none := func(string) error { return errors.New("no display") }
	start := time.Now()
	var out bytes.Buffer
	if _, err := Login(context.Background(), p, e, LoginOptions{Browser: none, Out: &out}); !errors.Is(err, ErrNoWayBack) ||
		time.Since(start) > 5*time.Second || out.Len() != 0 {
		t.Fatalf("%v after %s, printed %q", err, time.Since(start), out.String())
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if _, err := Login(ctx, p, e, LoginOptions{Browser: none, Port: port, Out: &out}); !errors.Is(err, context.DeadlineExceeded) ||
		!strings.Contains(out.String(), fmt.Sprintf("ssh -L %d:127.0.0.1:%d", port, port)) {
		t.Fatalf("a fixed port: %v\n%s", err, out.String())
	}
	if n := len(as.Authorizations()); n != 0 {
		t.Fatalf("%d authorizations with no browser", n)
	}
}

// lockedWriter serializes writes from Login and its paste reader.
type lockedWriter struct {
	mu *sync.Mutex
	w  *bytes.Buffer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}
