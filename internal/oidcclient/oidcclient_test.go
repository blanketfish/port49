package oidcclient

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/oidc"
	"github.com/blanketfish/port49/internal/oidc/oidctest"
)

// provider is iss as port49-cli's provider, with an authorization server
// signing in sub-alice.
func provider(t *testing.T) (*oidctest.Issuer, *oidctest.AuthServer, Provider) {
	t.Helper()
	iss := oidctest.NewIssuer(t)
	as := iss.AuthServer(t, "port49-cli", "sub-alice", map[string]any{"preferred_username": "alice@example.com"})
	return iss, as, Provider{Issuer: iss.URL, ClientID: "port49-cli", Scopes: []string{"openid"}, Roots: iss.Roots()}
}

func TestDiscoverReadsTheEndpoints(t *testing.T) {
	iss, _, p := provider(t)
	e, err := Discover(context.Background(), p)
	if err != nil || e.Authorization != iss.URL+"/authorize" || e.Token != iss.URL+"/token" || !e.IssParameter {
		t.Fatalf("%+v %v", e, err)
	}
}

// A provider offering PKCE methods without S256 is refused; one listing none
// is used (decision 43 ruling 1).
func TestAProviderWithoutS256IsRefused(t *testing.T) {
	iss, _, p := provider(t)
	iss.Discovery(func(d map[string]any) { d["code_challenge_methods_supported"] = []string{"plain"} })
	if _, err := Discover(context.Background(), p); err == nil || !strings.Contains(err.Error(), "S256") {
		t.Fatalf("plain only: %v", err)
	}
	iss.Discovery(func(d map[string]any) { delete(d, "code_challenge_methods_supported") })
	if _, err := Discover(context.Background(), p); err != nil {
		t.Fatalf("none listed: %v", err)
	}
}

func TestAProviderThatDoesNotAnswerIsUnreachable(t *testing.T) {
	iss, _, p := provider(t)
	iss.Close()
	var u *UnreachableError
	if _, err := Discover(context.Background(), p); !errors.As(err, &u) || u.Issuer != iss.URL {
		t.Fatalf("%v", err)
	}
}

// codeFor signs in at iss with nonce and returns the code, redirected to a
// loopback port nothing listens on.
func codeFor(t *testing.T, iss *oidctest.Issuer, p Provider, e Endpoints, verifier, nonce string) string {
	t.Helper()
	sum := sha256.Sum256([]byte(verifier))
	u, err := AuthorizationURL(p, e, "http://127.0.0.1:1/callback", "st", nonce, base64.RawURLEncoding.EncodeToString(sum[:]))
	if err != nil {
		t.Fatal(err)
	}
	loc, err := iss.Redirected(u)
	if err != nil {
		t.Fatal(err)
	}
	v, _ := url.Parse(loc)
	return v.Query().Get("code")
}

// The code is exchanged with its verifier and no secret, and the ID token's
// nonce must be the request's.
func TestTheExchangeChecksTheNonce(t *testing.T) {
	iss, as, p := provider(t)
	e, err := Discover(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	verifier := "verifier-0123456789-0123456789-0123456789"
	got, err := exchange(context.Background(), p, e, codeFor(t, iss, p, e, verifier, "n-1"),
		"http://127.0.0.1:1/callback", verifier, "n-1", time.Now)
	if err != nil || got.ID.Subject != "sub-alice" || got.IDRaw == "" || got.Received.IsZero() {
		t.Fatalf("%v %v", got, err)
	}
	if g := as.Grants(); g[0].Get("code_verifier") != verifier || g[0].Has("client_secret") {
		t.Fatalf("the exchange sent a secret or no verifier")
	}
	if _, err := exchange(context.Background(), p, e, codeFor(t, iss, p, e, verifier, "n-1"),
		"http://127.0.0.1:1/callback", verifier, "n-2", time.Now); err == nil || !strings.Contains(err.Error(), "nonce") {
		t.Fatalf("another nonce: %v", err)
	}
}

// A refusal at the token endpoint is the provider's code, never its body;
// the answer's refresh token is never kept.
func TestAnExchangeRefusalSaysTheProvidersCode(t *testing.T) {
	iss, _, p := provider(t)
	e, _ := Discover(context.Background(), p)
	verifier := "verifier-0123456789-0123456789-0123456789"
	_, err := exchange(context.Background(), p, e, codeFor(t, iss, p, e, verifier, "n"), "http://127.0.0.1:1/callback",
		verifier+"x", "n", time.Now)
	var pe *ProviderError
	if !errors.As(err, &pe) || pe.Code != "invalid_grant" || pe.Status != 400 {
		t.Fatalf("%v", err)
	}
}

// Every request asks for openid, whatever the verifier's scopes leave out
// (OIDC Core §3.1.2.1).
func TestTheScopeAlwaysAsksForOpenID(t *testing.T) {
	_, _, p := provider(t)
	p.Scopes = []string{"email"}
	u, err := AuthorizationURL(p, Endpoints{Authorization: "https://kc.example/r/auth?kc_idp_hint=x"}, "http://127.0.0.1:1/callback",
		"st", "n", "c")
	if err != nil {
		t.Fatal(err)
	}
	q, _ := url.Parse(u)
	if q.Query().Get("scope") != "openid email" || q.Query().Get("kc_idp_hint") != "x" || q.Query().Get("prompt") != "login" {
		t.Fatalf("%s", u)
	}
}

// Tokens never prints its token.
func TestTokensWithholdThemselves(t *testing.T) {
	h := Tokens{ID: oidc.IDToken{Subject: "sub-alice"}, IDRaw: "eyJ-the-id-token", Received: time.Now()}
	if s := h.String() + h.GoString(); strings.Contains(s, "eyJ-the-id-token") {
		t.Fatalf("%s", s)
	}
}

func TestSkew(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	if s := Skew(Tokens{ID: oidc.IDToken{IssuedAt: at}, Received: at.Add(7 * time.Minute)}); s != 7*time.Minute {
		t.Fatalf("%v", s)
	}
}

func TestAnEmptyNonceIsRefusedBeforeAnyRequest(t *testing.T) {
	_, as, p := provider(t)
	e := Endpoints{Token: "https://127.0.0.1:1/token"}
	if _, err := exchange(context.Background(), p, e, "c", "http://127.0.0.1:1/callback", "v", "", time.Now); err == nil ||
		!strings.Contains(err.Error(), "nonce") {
		t.Fatalf("%v", err)
	}
	if len(as.Grants()) != 0 {
		t.Fatalf("a request was made")
	}
}

// tokenServer answers every token request with h and is a Provider's anchor.
func tokenServer(t *testing.T, h http.HandlerFunc) (Provider, Endpoints) {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return Provider{Issuer: "https://idp.example", ClientID: "port49-cli", Roots: pool}, Endpoints{Token: srv.URL}
}

// Whatever the token endpoint answers, an error holds none of the code, the
// verifier or the raw ID token, even when the provider echoes them.
func TestNoExchangeErrorHoldsASecret(t *testing.T) {
	iss := oidctest.NewIssuer(t)
	const code, verifier = "code-canary-8841", "verifier-canary-0123456789-0123456789-0123456789"
	now := time.Now()
	raw := iss.Token(t, "k1", map[string]any{"iss": iss.URL, "aud": "other", "sub": "s", "iat": now.Unix(),
		"exp": now.Add(time.Minute).Unix(), "auth_time": now.Unix(), "nonce": "n"})
	echo := code + " " + verifier + " " + raw
	for name, h := range map[string]http.HandlerFunc{
		"json 4xx": func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(400)
			fmt.Fprintf(w, `{"error":"invalid_grant","error_description":%q}`, "bad "+code+" and "+verifier)
		},
		"json 4xx with the secrets as the code": func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(400)
			fmt.Fprintf(w, `{"error":%q}`, code)
		},
		"non-json 4xx": func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(403); fmt.Fprint(w, echo) },
		"5xx":          func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(502); fmt.Fprint(w, echo) },
		"oversize":     func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, echo+strings.Repeat("x", maxBody)) },
		"not json":     func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, echo) },
		"no id_token":  func(w http.ResponseWriter, r *http.Request) { fmt.Fprintf(w, `{"access_token":%q}`, echo) },
		"bad id_token": func(w http.ResponseWriter, r *http.Request) { fmt.Fprintf(w, `{"id_token":%q}`, raw) },
	} {
		p, e := tokenServer(t, h)
		p.Issuer = iss.URL
		_, err := exchange(context.Background(), p, e, code, "http://127.0.0.1:1/callback", verifier, "n", time.Now)
		if err == nil {
			t.Errorf("%s: no error", name)
			continue
		}
		for _, s := range []string{code, verifier, raw} {
			if strings.Contains(err.Error(), s) {
				t.Errorf("%s: the error holds a secret: %v", name, err)
			}
		}
	}
}

func TestANonJSONRefusalSaysTheStatus(t *testing.T) {
	p, e := tokenServer(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(403) })
	_, err := exchange(context.Background(), p, e, "c", "http://127.0.0.1:1/callback", "v", "n", time.Now)
	var pe *ProviderError
	if !errors.As(err, &pe) || pe.Code != "forbidden" || !strings.Contains(err.Error(), "403") {
		t.Fatalf("%v", err)
	}
}
