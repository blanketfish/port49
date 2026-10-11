package oidcclient

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/url"
	"slices"
	"strings"
)

// AuthorizationURL is the sign-in's request (decision 43 ruling 3) on e's
// authorization endpoint, keeping any query it already has: the code flow,
// the verifier's S256 challenge, state, nonce, the verifier's scopes with
// openid first, and prompt=login.
func AuthorizationURL(p Provider, e Endpoints, redirect, state, nonce, challenge string) (string, error) {
	u, err := url.Parse(e.Authorization)
	if err != nil {
		return "", fmt.Errorf("%s's authorization_endpoint: %w", p.Issuer, err)
	}
	q := u.Query()
	for k, v := range map[string]string{"response_type": "code", "client_id": p.ClientID, "redirect_uri": redirect,
		"scope": scopeOf(p), "state": state, "nonce": nonce, "code_challenge": challenge,
		"code_challenge_method": "S256", "prompt": "login"} {
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// scopeOf is the scope a sign-in sends: the verifier's scopes, openid first
// when they leave it out (OIDC Core §3.1.2.1).
func scopeOf(p Provider) string {
	scopes := p.Scopes
	if !slices.Contains(scopes, "openid") {
		scopes = append([]string{"openid"}, scopes...)
	}
	return strings.Join(scopes, " ")
}

// challengeOf is verifier's S256 code challenge (RFC 7636 §4.2).
func challengeOf(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// opaque is 32 random bytes, base64url: a verifier, a state or a nonce of
// 43 characters (RFC 7636 §4.1).
func opaque() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
