// Package oidcclient is port49's OpenID Connect public client (plan 9b; spec
// §13 decision 43): the authorization-code flow with PKCE (S256) over a
// loopback redirect (RFC 8252), which `port49 login --oidc` runs in its own
// process to get an ID token it exchanges for a certificate. There is no
// client secret, and no refresh token is kept. The ID token, the code and
// the verifier go nowhere but the token endpoint and the broker; an error
// names the provider and its OAuth error code, never a token or a body.
package oidcclient

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/rhwendt/port49/internal/oidc"
	"github.com/rhwendt/port49/internal/printsafe"
)

// maxBody bounds a discovery document and a token response.
const maxBody = 1 << 20

// Provider is one identity provider as the broker's /v1/config names it, and
// the anchor port49 reaches it with.
type Provider struct {
	Issuer   string
	ClientID string
	Scopes   []string
	// Roots is the provider's TLS anchor (oidc_ca); nil is the system's roots.
	Roots *x509.CertPool
}

// Endpoints is what discovery gives the client (decision 43 ruling 2).
type Endpoints struct {
	Authorization string
	Token         string
	// IssParameter is whether the provider puts iss in its authorization
	// response (RFC 9207), which the callback then requires.
	IssParameter bool
}

// Tokens is a sign-in's answer: the ID token, read, and its raw form, and
// when it arrived on this host's wall clock. A refresh token in the answer
// is dropped unread (decision 43 ruling 6).
type Tokens struct {
	ID       oidc.IDToken
	IDRaw    string
	Received time.Time
}

// String withholds the ID token.
func (t Tokens) String() string {
	return fmt.Sprintf("Tokens{%v received %s}", t.ID, t.Received.UTC().Format(time.RFC3339))
}

// GoString is String.
func (t Tokens) GoString() string { return t.String() }

// Skew is how far this host's clock was from the provider's when t arrived:
// positive when this host is ahead (decision 43 ruling 6).
func Skew(t Tokens) time.Duration { return t.Received.Sub(t.ID.IssuedAt) }

// UnreachableError is a provider that did not answer: a transport fault, a
// timeout, or a 5xx. A held certificate outlives it (decision 43 ruling 17).
type UnreachableError struct {
	Issuer string
	Err    error
}

func (e *UnreachableError) Error() string {
	return fmt.Sprintf("your identity provider at %s did not answer: %v", e.Issuer, e.Err)
}

func (e *UnreachableError) Unwrap() error { return e.Err }

// ProviderError is the token endpoint refusing (RFC 6749 §5.2): its status,
// error code and description, made printable.
type ProviderError struct {
	Issuer      string
	Status      int
	Code        string
	Description string
}

func (e *ProviderError) Error() string {
	s := fmt.Sprintf("your identity provider at %s refused: %s (HTTP %d)", e.Issuer, e.Code, e.Status)
	if e.Description != "" {
		s += ": " + e.Description
	}
	return s
}

// Discover reads p's discovery document (oidc.ReadDiscovery) and refuses a
// provider that offers PKCE methods without S256; one that lists none is
// used, S256 sent (decision 43 ruling 1).
func Discover(ctx context.Context, p Provider) (Endpoints, error) {
	raw, err := get(ctx, p, strings.TrimSuffix(p.Issuer, "/")+"/.well-known/openid-configuration")
	if err != nil {
		return Endpoints{}, err
	}
	d, err := oidc.ReadDiscovery(raw, p.Issuer)
	if err != nil {
		return Endpoints{}, fmt.Errorf("%s: %w", p.Issuer, err)
	}
	if d.CodeChallengeMethods != nil && !slices.Contains(d.CodeChallengeMethods, "S256") {
		return Endpoints{}, fmt.Errorf("%s does not offer PKCE with S256 (it lists %s); port49 signs in with S256 only",
			p.Issuer, printsafe.Line(strings.Join(d.CodeChallengeMethods, ", "), 100))
	}
	return Endpoints{Authorization: d.AuthorizationEndpoint, Token: d.TokenEndpoint, IssParameter: d.IssParameter}, nil
}

// get is one GET of u at p: oidc.NewClient's TLS, timeout, proxy and no
// redirect; 200 and 1 MiB at most.
func get(ctx context.Context, p Provider, u string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := oidc.NewClient(p.Roots).Do(req)
	if err != nil {
		return nil, &UnreachableError{Issuer: p.Issuer, Err: err}
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	switch {
	case err != nil:
		return nil, &UnreachableError{Issuer: p.Issuer, Err: err}
	case resp.StatusCode >= 500:
		return nil, &UnreachableError{Issuer: p.Issuer, Err: fmt.Errorf("GET %s answered %s", u, resp.Status)}
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("%s: GET %s answered %s", p.Issuer, u, resp.Status)
	case len(body) > maxBody:
		return nil, fmt.Errorf("%s: GET %s: over %d bytes", p.Issuer, u, maxBody)
	}
	return body, nil
}

// errNoIDToken is a token response with no id_token.
var errNoIDToken = errors.New("the token endpoint's answer carries no id_token")

// exchange is the code's exchange (RFC 6749 §4.1.3, RFC 7636 §4.5): the
// verifier, no secret, and an ID token whose nonce is the request's. A
// transport fault or a 5xx is an *UnreachableError, any other refusal a
// *ProviderError; neither holds the form or the body.
func exchange(ctx context.Context, p Provider, e Endpoints, code, redirect, verifier, nonce string,
	now func() time.Time) (Tokens, error) {
	if nonce == "" {
		return Tokens{}, errors.New("the code exchange needs the request's nonce")
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirect},
		"client_id": {p.ClientID}, "code_verifier": {verifier}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.Token, strings.NewReader(form.Encode()))
	if err != nil {
		return Tokens{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := oidc.NewClient(p.Roots).Do(req)
	if err != nil {
		return Tokens{}, &UnreachableError{Issuer: p.Issuer, Err: err}
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	switch {
	case err != nil:
		return Tokens{}, &UnreachableError{Issuer: p.Issuer, Err: err}
	case len(body) > maxBody:
		return Tokens{}, &UnreachableError{Issuer: p.Issuer, Err: errors.New("the token endpoint's answer is over 1 MiB")}
	case resp.StatusCode >= 500:
		return Tokens{}, &UnreachableError{Issuer: p.Issuer, Err: fmt.Errorf("the token endpoint answered %s", resp.Status)}
	case resp.StatusCode != http.StatusOK:
		var oe struct {
			Error       string `json:"error"`
			Description string `json:"error_description"`
		}
		_ = json.Unmarshal(body, &oe)
		// A provider's text may echo the code or the verifier: neither is
		// printed. A body with no error code says the HTTP status instead.
		scrub := strings.NewReplacer(code, "[redacted]", verifier, "[redacted]").Replace
		if code == "" || verifier == "" {
			scrub = func(s string) string { return s }
		}
		pe := &ProviderError{Issuer: p.Issuer, Status: resp.StatusCode,
			Code:        printsafe.Line(scrub(oe.Error), 64),
			Description: printsafe.Line(scrub(oe.Description), 200)}
		if pe.Code == "" {
			pe.Code = strings.ToLower(strings.ReplaceAll(http.StatusText(resp.StatusCode), " ", "_"))
			if pe.Code == "" {
				pe.Code = "http_status"
			}
		}
		return Tokens{}, pe
	}
	// Only id_token is read: a refresh token in the answer is not kept
	// (decision 43 ruling 6).
	var t struct {
		IDToken string `json:"id_token"`
	}
	if json.Unmarshal(body, &t) != nil {
		return Tokens{}, fmt.Errorf("%s: the token endpoint's answer is not a JSON object", p.Issuer)
	}
	if t.IDToken == "" {
		return Tokens{}, fmt.Errorf("%s: %w", p.Issuer, errNoIDToken)
	}
	id, err := oidc.ReadIDToken(t.IDToken, p.Issuer, p.ClientID, nonce)
	if err != nil {
		return Tokens{}, fmt.Errorf("%s: %w", p.Issuer, err)
	}
	return Tokens{ID: id, IDRaw: t.IDToken, Received: now().Round(0)}, nil
}
