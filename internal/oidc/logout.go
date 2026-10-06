package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/rhwendt/port49/internal/printsafe"
)

// BackchannelLogoutEvent is the events member a logout token carries
// (OpenID Connect Back-Channel Logout 1.0 §2.4).
const BackchannelLogoutEvent = "http://schemas.openid.net/event/backchannel-logout"

// MaxLogoutAge bounds a logout token's iat: one older is refused, and a jti
// is remembered this long (Ruling 12).
const MaxLogoutAge = 24 * time.Hour

// LogoutToken is a validated logout token. Sid or Subject may be empty,
// never both. Expires is zero when the token carried no exp. Domains is the
// accepting verifier's principal_domains: a logout reaches no principal
// outside them (Ruling 22).
type LogoutToken struct {
	Issuer, Subject, Sid, JTI string
	IssuedAt, Expires         time.Time
	Domains                   []string
}

// String withholds the jti, which a replay check keys on (Ruling 18).
func (l LogoutToken) String() string {
	return fmt.Sprintf("LogoutToken{issuer %s sub %s sid %s iat %s}", l.Issuer, l.Subject, l.Sid,
		l.IssuedAt.UTC().Format(time.RFC3339))
}

// GoString is String.
func (l LogoutToken) GoString() string { return l.String() }

// logoutClaims is what port49 reads of a logout token's payload, by exact
// name (exact). The dates are raw, so a JSON string is told from a number.
type logoutClaims struct {
	Iss    string                     `json:"iss"`
	Sub    string                     `json:"sub"`
	Sid    string                     `json:"sid"`
	Jti    string                     `json:"jti"`
	Aud    json.RawMessage            `json:"aud"`
	Azp    string                     `json:"azp"`
	Iat    json.RawMessage            `json:"iat"`
	Exp    json.RawMessage            `json:"exp"`
	Events map[string]json.RawMessage `json:"events"`
}

var logoutClaimNames = []string{"iss", "sub", "sid", "jti", "aud", "azp", "iat", "exp", "events"}

// VerifyLogout is Back-Channel Logout 1.0 §2.6 against the human verifiers
// whose issuer is the token's (Ruling 12): exactly one must accept it.
func (s *Set) VerifyLogout(ctx context.Context, raw string) (LogoutToken, error) {
	j, err := ParseCompact(raw)
	if err != nil {
		return LogoutToken{}, refuse(ErrInvalid, "invalid", "it is not a compact JWS")
	}
	// The iss only routes the token to its verifiers; each reads every claim
	// again, after its signature. A repeated member is no one's token.
	var iss string
	if all, err := exactObject(j.Payload); err == nil {
		_ = json.Unmarshal(all["iss"], &iss)
	}
	var vs []*Verifier
	for _, v := range s.ByIssuer(iss) {
		if v.Domain == Humans {
			vs = append(vs, v)
		}
	}
	if len(vs) == 0 {
		return LogoutToken{}, refuse(ErrInvalid, "invalid", "no human OIDC verifier accepts its issuer")
	}
	var got []LogoutToken
	var first *refusal
	unavailable := false
	for _, v := range vs {
		l, err := v.logout(ctx, j, s.Timing, s.Now())
		var r *refusal
		switch {
		case err == nil:
			got = append(got, l)
		case errors.As(err, &r):
			if errors.Is(r, ErrUnavailable) {
				unavailable = true
			}
			if first == nil {
				first = r
			}
		}
	}
	// An issuer whose keys one verifier could not get is unavailable, whatever
	// another accepted: a lost race is never a pass (fail closed).
	switch {
	case unavailable:
		return LogoutToken{}, refuse(ErrUnavailable, "unavailable", "the keys of %s are not available", iss)
	case len(got) == 1:
		return got[0], nil
	case len(got) > 1:
		return LogoutToken{}, refuse(ErrInvalid, "invalid", "two human verifiers of %s accept it", iss)
	case first == nil:
		return LogoutToken{}, refuse(ErrInvalid, "invalid", "no human OIDC verifier accepts it")
	}
	return LogoutToken{}, first
}

func (v *Verifier) logout(ctx context.Context, j *JWS, t Timing, now time.Time) (LogoutToken, error) {
	if err := v.signature(ctx, j); err != nil {
		return LogoutToken{}, err
	}
	// typ: logout+jwt or JWT when present (BCL §2.4; decision 39 ruling 12).
	switch typ := strings.TrimPrefix(strings.ToLower(j.Header.Typ), "application/"); typ {
	case "", "logout+jwt", "jwt":
	default:
		return LogoutToken{}, refuse(ErrInvalid, "invalid", "its typ %q is not a logout token's", printsafe.Line(typ, 40))
	}
	all, err := payload(j.Payload)
	if err != nil {
		return LogoutToken{}, refuse(ErrInvalid, "invalid", "%s", err.Error())
	}
	var c logoutClaims
	if exact(all, &c, logoutClaimNames) != nil {
		return LogoutToken{}, refuse(ErrInvalid, "invalid", "its claims are not a JSON object of the expected types")
	}
	_, hasNonce := all["nonce"]
	auds, ok := audiences(c.Aud)
	if !ok {
		return LogoutToken{}, refuse(ErrInvalid, "invalid", "its aud is absent or not a string or a list of strings")
	}
	if r := humanAudience(auds, c.Azp, v.ClientID); r != nil {
		return LogoutToken{}, r // BCL §2.6 step 3: aud and azp as for an ID token (pre-flight M-6)
	}
	switch {
	case c.Iss != v.Issuer:
		return LogoutToken{}, refuse(ErrInvalid, "invalid", "its iss is not %s", v.Issuer)
	case hasNonce:
		return LogoutToken{}, refuse(ErrInvalid, "invalid", "it carries a nonce, which a logout token must not "+
			"(Back-Channel Logout §2.4)")
	case !printableID(c.Jti):
		return LogoutToken{}, refuse(ErrInvalid, "invalid", "it has no jti")
	case c.Sub == "" && c.Sid == "":
		return LogoutToken{}, refuse(ErrInvalid, "invalid", "it names neither a sub nor a sid")
	case c.Sub != "" && !printableID(c.Sub), c.Sid != "" && !printableID(c.Sid):
		return LogoutToken{}, refuse(ErrInvalid, "invalid", "its sub or sid is not 1 to 255 printable ASCII characters")
	}
	member, ok := c.Events[BackchannelLogoutEvent]
	var obj map[string]json.RawMessage
	if !ok || json.Unmarshal(member, &obj) != nil || obj == nil {
		return LogoutToken{}, refuse(ErrInvalid, "invalid", "its events claim has no back-channel logout member "+
			"holding a JSON object")
	}
	iat, ok := numericDate(c.Iat)
	switch {
	case !ok:
		return LogoutToken{}, refuse(ErrInvalid, "invalid", "it has no iat")
	case iat.After(now.Add(t.ClockSkew)):
		return LogoutToken{}, refuse(ErrInvalid, "invalid", "it was issued ahead of the broker's clock by more than "+
			"broker.identity.clock_skew")
	case now.Sub(iat) > MaxLogoutAge:
		return LogoutToken{}, refuse(ErrInvalid, "expired", "it was issued %s ago, more than %s", now.Sub(iat).Round(time.Minute),
			MaxLogoutAge)
	}
	l := LogoutToken{Issuer: v.Issuer, Subject: c.Sub, Sid: c.Sid, JTI: c.Jti, IssuedAt: iat,
		Domains: slices.Clone(v.PrincipalDomains)}
	if len(c.Exp) != 0 {
		exp, ok := numericDate(c.Exp)
		if !ok || !now.Before(exp.Add(t.ClockSkew)) {
			return LogoutToken{}, refuse(ErrInvalid, "expired", "it has expired")
		}
		l.Expires = exp
	}
	return l, nil
}
