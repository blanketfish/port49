package oidc

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"time"
)

// IDToken is an ID token as port49's public client reads it (plan 9b; spec
// §13 decision 43 ruling 6): the claims it checks, from a token it does not
// verify by signature. The token came from the provider's token endpoint
// over TLS, which OIDC Core §3.1.3.7 item 6 allows in place of the
// signature, and the broker verifies it when it is exchanged for a
// certificate. Nothing here authorizes anything.
type IDToken struct {
	Issuer   string
	Subject  string
	Sid      string
	Nonce    string
	AuthTime time.Time
	IssuedAt time.Time
	Expires  time.Time
}

// String withholds the nonce.
func (t IDToken) String() string {
	return fmt.Sprintf("IDToken{issuer %s sub %s sid %s auth_time %s iat %s exp %s}", t.Issuer, t.Subject, t.Sid,
		t.AuthTime.UTC().Format(time.RFC3339), t.IssuedAt.UTC().Format(time.RFC3339), t.Expires.UTC().Format(time.RFC3339))
}

// GoString is String.
func (t IDToken) GoString() string { return t.String() }

// ReadIDToken reads raw as an ID token issued to clientID by issuer: a
// compact JWS whose alg is one Ruling 3 accepts (none and the HMACs are
// ErrAlgorithm); iss exactly issuer; aud naming clientID, and azp as
// humanAudience reads it; sub, iat, exp and auth_time present and iat no
// later than exp; every claim by its exact name; and, when nonce is not "",
// a nonce claim equal to it. It compares no date with a clock: the broker's
// clock judges the token (decision 43 ruling 6).
func ReadIDToken(raw, issuer, clientID, nonce string) (IDToken, error) {
	j, err := ParseCompact(raw)
	if err != nil {
		return IDToken{}, fmt.Errorf("the ID token: %w", err)
	}
	if !slices.Contains(known, j.Header.Alg) {
		return IDToken{}, fmt.Errorf("the ID token's alg: %w", ErrAlgorithm)
	}
	all, err := payload(j.Payload)
	if err != nil {
		return IDToken{}, fmt.Errorf("the ID token: %w", err)
	}
	var c claims
	if err := exact(all, &c, claimNames); err != nil {
		return IDToken{}, errors.New("the ID token: a claim is not of its type")
	}
	auds, ok := audiences(c.Aud)
	switch {
	case c.Iss != issuer:
		return IDToken{}, fmt.Errorf("the ID token was not issued by %s", issuer)
	case !ok:
		return IDToken{}, errors.New("the ID token has no aud")
	}
	if r := humanAudience(auds, c.Azp, clientID); r != nil {
		return IDToken{}, fmt.Errorf("the ID token: %s", r.why)
	}
	iat, okIat := numericDate(c.Iat)
	exp, okExp := numericDate(c.Exp)
	at, okAt := numericDate(c.AuthTime)
	switch {
	case !printableID(c.Sub):
		return IDToken{}, errors.New("the ID token has no usable sub")
	case !okIat || !okExp:
		return IDToken{}, errors.New("the ID token's iat or exp is not a NumericDate")
	case len(c.AuthTime) == 0:
		return IDToken{}, errors.New("the ID token has no auth_time")
	case !okAt:
		return IDToken{}, errors.New("the ID token's auth_time is not a NumericDate")
	case exp.Before(iat):
		return IDToken{}, errors.New("the ID token expires before it was issued")
	case nonce != "" && c.Nonce != nonce:
		return IDToken{}, errors.New("the ID token's nonce is not the one port49 sent")
	case c.Sid != "" && !printableID(c.Sid):
		return IDToken{}, errors.New("the ID token's sid is not printable")
	}
	return IDToken{Issuer: c.Iss, Subject: c.Sub, Sid: c.Sid, Nonce: c.Nonce, AuthTime: at, IssuedAt: iat,
		Expires: exp}, nil
}

// Discovery is what port49's public client reads of a provider's discovery
// document (OIDC Discovery §3; RFC 8414 §2; RFC 9207 §3), each member by its
// exact name and none repeated, as the key fetch reads issuer and jwks_uri.
type Discovery struct {
	AuthorizationEndpoint string
	TokenEndpoint         string
	// CodeChallengeMethods is code_challenge_methods_supported; nil when the
	// document does not list it.
	CodeChallengeMethods []string
	// IssParameter is authorization_response_iss_parameter_supported.
	IssParameter bool
}

// ReadDiscovery reads raw as issuer's discovery document: its issuer must be
// issuer exactly (OIDC Discovery §4.3), and the two endpoints https URLs with
// a host and no credentials.
func ReadDiscovery(raw []byte, issuer string) (Discovery, error) {
	doc, err := exactObject(raw)
	if err != nil {
		return Discovery{}, errors.New("the discovery document is not a JSON object of distinct members")
	}
	if iss, _ := discoveryMember(doc, "issuer"); iss != issuer {
		return Discovery{}, errors.New("the discovery document names another issuer (OpenID Connect Discovery §4.3)")
	}
	var d Discovery
	d.AuthorizationEndpoint, _ = discoveryMember(doc, "authorization_endpoint")
	d.TokenEndpoint, _ = discoveryMember(doc, "token_endpoint")
	for _, m := range []struct{ name, u string }{{"authorization_endpoint", d.AuthorizationEndpoint},
		{"token_endpoint", d.TokenEndpoint}} {
		u, err := url.Parse(m.u)
		if m.u == "" || err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" {
			return Discovery{}, fmt.Errorf("the discovery document's %s is not an https URL without credentials", m.name)
		}
	}
	if v, ok := doc["code_challenge_methods_supported"]; ok && json.Unmarshal(v, &d.CodeChallengeMethods) != nil {
		return Discovery{}, errors.New("the discovery document's code_challenge_methods_supported is not a list of strings")
	}
	if v, ok := doc["authorization_response_iss_parameter_supported"]; ok && json.Unmarshal(v, &d.IssParameter) != nil {
		return Discovery{}, errors.New("the discovery document's authorization_response_iss_parameter_supported is not a boolean")
	}
	return d, nil
}
