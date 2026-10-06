package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/printsafe"
	"github.com/rhwendt/port49/internal/store"
)

var (
	// ErrInvalid is a token no configured verifier accepts, or two do:
	// trust_domain_unresolved, 401 (Rulings 2, 3, 5).
	ErrInvalid = errors.New("oidc: no configured verifier accepts the token")
	// ErrUnmapped is a token that verified and names no usable principal:
	// identity_unmapped, 401 (Ruling 6).
	ErrUnmapped = errors.New("oidc: the token names no usable principal")
)

// refusal is a Verify error: its kind (ErrInvalid, ErrUnmapped,
// ErrUnavailable) and why, in words safe to log: an issuer from
// configuration, a check's name, a validated time, never a claim of a token
// that did not verify.
type refusal struct {
	kind error
	why  string
	// outcome is the metric's: invalid, expired, unavailable, unmapped.
	outcome string
}

func (r *refusal) Error() string { return r.why }
func (r *refusal) Unwrap() error { return r.kind }

func refuse(kind error, outcome, format string, args ...any) *refusal {
	return &refusal{kind: kind, outcome: outcome, why: fmt.Sprintf(format, args...)}
}

// Verifier is one oidc verifier and its issuer's keys, which the issuer's
// other verifier shares.
type Verifier struct {
	VerifierConfig
	Keys *KeySet
}

// Set is broker.identity's oidc verifiers.
type Set struct {
	Verifiers []*Verifier
	Timing    Timing
	Now       func() time.Time
	M         *metrics.Metrics
}

// Humans is the human verifiers, for /v1/config and logout tokens.
func (s *Set) Humans() []*Verifier {
	var out []*Verifier
	for _, v := range s.Verifiers {
		if v.Domain == Humans {
			out = append(out, v)
		}
	}
	return out
}

// ByIssuer is the verifiers whose issuer is iss, byte for byte.
func (s *Set) ByIssuer(iss string) []*Verifier {
	var out []*Verifier
	for _, v := range s.Verifiers {
		if v.Issuer == iss {
			out = append(out, v)
		}
	}
	return out
}

// HumanDomains is the principal_domains of iss's human verifiers: whose
// principals a logout from iss may reach (Ruling 22).
func (s *Set) HumanDomains(iss string) []string {
	var out []string
	for _, v := range s.ByIssuer(iss) {
		if v.Domain == Humans {
			out = append(out, v.PrincipalDomains...)
		}
	}
	return out
}

// Assertion is a verified token as port49 uses it. Every field is a
// validated value.
type Assertion struct {
	Domain    Domain
	Principal string
	Issuer    string
	Subject   string
	Sid       string // the provider's own; Credential qualifies it
	Nonce     string `json:"-"`
	AMR       []string
	ACR       string
	AuthTime  time.Time
	IssuedAt  time.Time
	Expires   time.Time
}

// String withholds the nonce, which answers a refresh challenge (Ruling 18).
func (a Assertion) String() string {
	return fmt.Sprintf("Assertion{%s %s issuer %s sub %s sid %s auth_time %s}", a.Domain, a.Principal, a.Issuer,
		a.Subject, a.Sid, a.AuthTime.UTC().Format(time.RFC3339))
}

// GoString is String.
func (a Assertion) GoString() string { return a.String() }

// Credential is what a token and its login context record (spec §5.1.4;
// Ruling 10): the sid issuer-qualified, no certificate.
func (a Assertion) Credential() store.Credential {
	return store.Credential{Method: "oidc", Iss: a.Issuer, Sub: a.Subject, Sid: store.SidKey(a.Issuer, a.Sid),
		AMR: slices.Clone(a.AMR), ACR: a.ACR}
}

// Verify is Ruling 2: the token is offered to every verifier whose issuer
// is its iss, and exactly one must accept it.
func (s *Set) Verify(ctx context.Context, raw string) (Assertion, error) {
	a, iss, err := s.verify(ctx, raw)
	label := "unknown"
	if len(s.ByIssuer(iss)) > 0 {
		label = iss
	}
	outcome := "accepted"
	var r *refusal
	if errors.As(err, &r) {
		outcome = r.outcome
	}
	s.M.OIDCTokens.WithLabelValues(label, outcome).Inc()
	return a, err
}

func (s *Set) verify(ctx context.Context, raw string) (Assertion, string, error) {
	j, err := ParseCompact(raw)
	if err != nil {
		if errors.Is(err, ErrCrit) {
			return Assertion{}, "", refuse(ErrInvalid, "invalid", "it names a critical header extension")
		}
		return Assertion{}, "", refuse(ErrInvalid, "invalid", "it is not a compact JWS (an encrypted, unsigned or "+
			"malformed token, or over %d bytes)", MaxToken)
	}
	// The iss only routes the token to its verifiers; each reads every claim
	// again, after its signature. A repeated member is no one's token.
	var head struct{ Iss string }
	if all, err := exactObject(j.Payload); err == nil {
		_ = json.Unmarshal(all["iss"], &head.Iss)
	}
	vs := s.ByIssuer(head.Iss)
	if len(vs) == 0 {
		return Assertion{}, "", refuse(ErrInvalid, "invalid", "no configured verifier accepts its issuer")
	}
	var accepted []Assertion
	var first *refusal
	unavailable := false
	for _, v := range vs {
		a, err := v.verify(ctx, j, s.Timing, s.Now())
		var r *refusal
		switch {
		case err == nil:
			accepted = append(accepted, a)
		case errors.As(err, &r):
			if errors.Is(r, ErrUnavailable) {
				unavailable = true
			}
			if first == nil || errors.Is(r, ErrUnmapped) {
				first = r // a verifier that verified the signature says the more useful why
			}
		}
	}
	if first == nil {
		first = refuse(ErrInvalid, "invalid", "no configured verifier accepts it")
	}
	// An issuer whose keys one verifier could not get is unavailable, whatever
	// another accepted: a lost race is never a pass (fail closed).
	switch {
	case unavailable && (len(accepted) > 0 || !errors.Is(first, ErrUnmapped)):
		return Assertion{}, head.Iss, refuse(ErrUnavailable, "unavailable", "the keys of %s are not available "+
			"(none fetched, or none refreshed within broker.identity.jwks_max_age)", head.Iss)
	case len(accepted) == 1:
		return accepted[0], head.Iss, nil
	case len(accepted) > 1:
		return Assertion{}, head.Iss, refuse(ErrInvalid, "invalid", "two verifiers of %s accept it, so neither "+
			"does (decision 39)", head.Iss)
	}
	return Assertion{}, head.Iss, first
}

// claims is what port49 reads of a payload, taken from it by exact name
// (exact); every field is checked before use. The dates are raw, so a JSON
// string is told from a number (pre-flight M-5).
type claims struct {
	Iss           string          `json:"iss"`
	Sub           string          `json:"sub"`
	Aud           json.RawMessage `json:"aud"`
	Azp           string          `json:"azp"`
	ClientID      string          `json:"client_id"`
	Exp           json.RawMessage `json:"exp"`
	Nbf           json.RawMessage `json:"nbf"`
	Iat           json.RawMessage `json:"iat"`
	AuthTime      json.RawMessage `json:"auth_time"`
	Nonce         string          `json:"nonce"`
	Sid           string          `json:"sid"`
	Idtyp         string          `json:"idtyp"`
	AMR           json.RawMessage `json:"amr"`
	ACR           json.RawMessage `json:"acr"`
	Events        json.RawMessage `json:"events"`
	EmailVerified json.RawMessage `json:"email_verified"`
}

// claimNames are claims' members, the names exact reads.
var claimNames = []string{"iss", "sub", "aud", "azp", "client_id", "exp", "nbf", "iat", "auth_time", "nonce", "sid",
	"idtyp", "amr", "acr", "events", "email_verified"}

// payload is a token's claims by exact name. A payload naming one claim
// twice, exactly or in two cases, is refused (exactObject refuses the
// first; a map would keep the last of two "sub"s): encoding/json would read "ISS" as iss
// while the principal claim is read exactly, two rules for one token
// (pre-flight M-4).
func payload(b []byte) (map[string]json.RawMessage, error) {
	all, err := exactObject(b)
	if err != nil {
		return nil, errors.New("its claims are not a JSON object of distinct members")
	}
	seen := make(map[string]bool, len(all))
	for k := range all {
		// encoding/json folds ſ to s and K to k; no claim name is outside ASCII.
		if strings.IndexFunc(k, func(r rune) bool { return r < 0x20 || r > 0x7e }) >= 0 {
			return nil, errors.New("it names a claim outside printable ASCII")
		}
		l := strings.ToLower(k)
		if seen[l] {
			return nil, errors.New("it names one claim twice, in two cases")
		}
		seen[l] = true
	}
	return all, nil
}

// exact decodes into v the members of all named in names, by exact name
// alone: encoding/json matches a field's name ignoring case, so only the
// exactly named members are handed to it.
func exact(all map[string]json.RawMessage, v any, names []string) error {
	pick := make(map[string]json.RawMessage, len(names))
	for _, n := range names {
		if raw, ok := all[n]; ok {
			pick[n] = raw
		}
	}
	b, err := json.Marshal(pick)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// humanAudience is OIDC Core §3.1.3.7's aud and azp rule for client_id, an
// ID token's and a logout token's alike (pre-flight M-6): aud holds it,
// several audiences need an azp, and an azp is it.
func humanAudience(auds []string, azp, clientID string) *refusal {
	switch {
	case !slices.Contains(auds, clientID):
		return refuse(ErrInvalid, "invalid", "its aud does not name client_id %s", clientID)
	case len(auds) > 1 && azp == "":
		return refuse(ErrInvalid, "invalid", "it names several audiences and no azp (OIDC Core §3.1.3.7)")
	case azp != "" && azp != clientID:
		return refuse(ErrInvalid, "invalid", "its azp is not client_id %s", clientID)
	}
	return nil
}

// verify is one verifier's whole check of j (Rulings 2, 3, 5, 6, 21, 22).
func (v *Verifier) verify(ctx context.Context, j *JWS, t Timing, now time.Time) (Assertion, error) {
	iss := v.Issuer
	if !slices.Contains(v.Algorithms, j.Header.Alg) {
		return Assertion{}, refuse(ErrInvalid, "invalid", "its algorithm is not one %s's %s verifier pins", iss, v.Domain)
	}
	key, err := v.Keys.Key(ctx, j.Header.Kid, j.Header.Alg)
	switch {
	case errors.Is(err, ErrUnavailable), err != nil && ctx.Err() != nil:
		// A caller's own deadline waiting on a refetch is the provider's
		// unavailability to it, to be retried, never a bad token.
		return Assertion{}, refuse(ErrUnavailable, "unavailable", "the keys of %s are not available", iss)
	case err != nil:
		return Assertion{}, refuse(ErrInvalid, "invalid", "no one key of %s matches its key id", iss)
	}
	if err := j.Verify(key, v.Algorithms); err != nil {
		return Assertion{}, refuse(ErrInvalid, "invalid", "its signature does not verify under the keys of %s", iss)
	}
	// From here every claim is the provider's, and may be said.
	// typ is an allowlist (RFC 8725 §3.11; decision 39 ruling 2).
	typ := strings.TrimPrefix(strings.ToLower(j.Header.Typ), "application/")
	if !(typ == "" || typ == "jwt" || (v.Domain == Machines && typ == "at+jwt")) {
		return Assertion{}, refuse(ErrInvalid, "invalid", "its typ %q is not one a %s verifier accepts (RFC 8725 §3.11)",
			printsafe.Line(typ, 40), v.Domain)
	}
	all, err := payload(j.Payload)
	if err != nil {
		return Assertion{}, refuse(ErrInvalid, "invalid", "%s", err.Error())
	}
	var c claims
	if exact(all, &c, claimNames) != nil {
		return Assertion{}, refuse(ErrInvalid, "invalid", "its claims are not a JSON object of the expected types")
	}
	if c.Events != nil {
		return Assertion{}, refuse(ErrInvalid, "invalid", "it carries an events claim: a logout token is never a bearer")
	}
	if c.Iss != iss {
		return Assertion{}, refuse(ErrInvalid, "invalid", "its iss is not %s", iss)
	}
	auds, ok := audiences(c.Aud)
	if !ok {
		return Assertion{}, refuse(ErrInvalid, "invalid", "its aud is absent or not a string or a list of strings")
	}
	switch v.Domain {
	case Humans:
		if r := humanAudience(auds, c.Azp, v.ClientID); r != nil {
			return Assertion{}, r
		}
	case Machines:
		if !slices.Contains(auds, v.Audience) {
			return Assertion{}, refuse(ErrInvalid, "invalid", "its aud does not name audience %s", v.Audience)
		}
	}
	exp, ok := numericDate(c.Exp)
	if !ok {
		return Assertion{}, refuse(ErrInvalid, "invalid", "it has no exp, or its exp is not a number")
	}
	if !now.Before(exp.Add(t.ClockSkew)) {
		return Assertion{}, refuse(ErrInvalid, "expired", "it expired at %s (broker.identity.clock_skew %s)",
			exp.UTC().Format(time.RFC3339), t.ClockSkew)
	}
	if nbf, ok := numericDate(c.Nbf); ok && now.Before(nbf.Add(-t.ClockSkew)) {
		return Assertion{}, refuse(ErrInvalid, "invalid", "it is not valid until %s", nbf.UTC().Format(time.RFC3339))
	} else if len(c.Nbf) != 0 && !ok {
		return Assertion{}, refuse(ErrInvalid, "invalid", "its nbf is not a time")
	}
	iat, ok := numericDate(c.Iat)
	switch {
	case !ok:
		return Assertion{}, refuse(ErrInvalid, "invalid", "it has no iat, or its iat is not a number")
	case iat.After(now.Add(t.ClockSkew)):
		return Assertion{}, refuse(ErrInvalid, "invalid", "it was issued at %s, ahead of the broker's clock by more "+
			"than broker.identity.clock_skew (%s)", iat.UTC().Format(time.RFC3339), t.ClockSkew)
	case now.Sub(iat) > t.MaxTokenAge:
		return Assertion{}, refuse(ErrInvalid, "expired", "issued %s ago, past broker.identity.max_token_age (%s)",
			now.Sub(iat).Round(time.Minute), t.MaxTokenAge)
	}
	if !printableID(c.Sub) {
		return Assertion{}, refuse(ErrInvalid, "invalid", "its sub is absent or not 1 to 255 printable ASCII characters")
	}
	if c.Sid != "" && !printableID(c.Sid) {
		return Assertion{}, refuse(ErrInvalid, "invalid", "its sid is not 1 to 255 printable ASCII characters")
	}
	a := Assertion{Domain: v.Domain, Issuer: iss, Subject: c.Sub, Sid: c.Sid, Nonce: c.Nonce, IssuedAt: iat,
		Expires: exp, AMR: amr(c.AMR), ACR: acr(c.ACR)}
	switch v.Domain {
	case Humans:
		at, ok := numericDate(c.AuthTime)
		switch {
		case !ok:
			return Assertion{}, refuse(ErrInvalid, "invalid", "it has no auth_time, so no session ceiling can be set "+
				"(spec §5.6)")
		case at.After(now.Add(t.ClockSkew)):
			return Assertion{}, refuse(ErrInvalid, "invalid", "its auth_time is ahead of the broker's clock by more "+
				"than broker.identity.clock_skew")
		}
		a.AuthTime = at
		p, why := humanPrincipal(all, v.PrincipalClaim, c.EmailVerified)
		if why != "" {
			return Assertion{}, refuse(ErrUnmapped, "unmapped", "%s (broker.identity.humans principal_claim %s)", why,
				v.PrincipalClaim)
		}
		if !v.Owns(p) {
			return Assertion{}, refuse(ErrUnmapped, "unmapped", "its principal %s is outside the principal_domains "+
				"of %s's human verifier (%s): an issuer gives only its own domains' people (decision 39 ruling 22)",
				printsafe.Line(p, 120), iss, strings.Join(v.PrincipalDomains, ", "))
		}
		a.Principal = p
	case Machines:
		// Ruling 21: a client-credentials token of a listed client, never a
		// person's delegated token for it.
		for _, name := range MachineSessionClaims {
			if _, ok := all[name]; ok {
				return Assertion{}, refuse(ErrInvalid, "invalid", "it carries %s, a person's session or delegated "+
					"grant: a person's token is never a machine's (decision 39 ruling 21)", name)
			}
		}
		if c.Idtyp != "" && c.Idtyp != "app" {
			return Assertion{}, refuse(ErrInvalid, "invalid", "its idtyp %q is not app: a person's token is never a "+
				"machine's (decision 39 ruling 21)", printsafe.Line(c.Idtyp, 20))
		}
		if c.Azp != "" && c.ClientID != "" && c.Azp != c.ClientID {
			return Assertion{}, refuse(ErrInvalid, "invalid", "its azp and client_id name two clients")
		}
		id := c.Azp
		if id == "" {
			id = c.ClientID
		}
		if !printableID(id) {
			return Assertion{}, refuse(ErrUnmapped, "unmapped", "it names no client: neither azp nor client_id is 1 to "+
				"255 printable ASCII characters")
		}
		mc, listed := v.Client(id)
		switch {
		case !listed:
			return Assertion{}, refuse(ErrInvalid, "invalid", "its client %s is not one %s's machine verifier "+
				"(audience %s) lists in clients", id, iss, v.Audience)
		case c.Sub != mc.Sub:
			return Assertion{}, refuse(ErrInvalid, "invalid", "its sub is not the one pinned for client %s: a token "+
				"another identity obtained through the client is not the client's (decision 39 ruling 21)", id)
		}
		a.Principal, a.AuthTime = "app:"+id, iat
	}
	return a, nil
}

func audiences(raw json.RawMessage) ([]string, bool) {
	var one string
	if json.Unmarshal(raw, &one) == nil && one != "" {
		return []string{one}, true
	}
	var many []string
	if json.Unmarshal(raw, &many) == nil && len(many) > 0 {
		return many, true
	}
	return nil, false
}

// numericDate is a JWT NumericDate (RFC 7519 §2): a JSON number, never a
// string (pre-flight M-5), of whole or fractional seconds in a range a
// clock can hold.
func numericDate(raw json.RawMessage) (time.Time, bool) {
	if len(raw) == 0 || raw[0] == '"' {
		return time.Time{}, false
	}
	f, err := strconv.ParseFloat(string(raw), 64)
	if err != nil || f < 0 || f > math.MaxInt32*4 || math.IsNaN(f) {
		return time.Time{}, false
	}
	sec, frac := math.Modf(f)
	return time.Unix(int64(sec), int64(frac*1e9)).UTC(), true
}

// printableID is 1 to 255 bytes of printable ASCII with no space: a sub, a
// sid or a client id, each of which becomes a store key or a principal.
func printableID(s string) bool {
	return s != "" && len(s) <= 255 && strings.IndexFunc(s, func(r rune) bool { return r < 0x21 || r > 0x7e }) < 0
}

// humanPrincipal is user: and the claim's value lower-cased, or why not
// (Ruling 6).
func humanPrincipal(all map[string]json.RawMessage, claim string, verified json.RawMessage) (string, string) {
	var v string
	if json.Unmarshal(all[claim], &v) != nil || v == "" {
		return "", "the token has no " + claim + " string"
	}
	if claim == ClaimEmail {
		var ok bool
		if json.Unmarshal(verified, &ok) != nil || !ok {
			return "", "its email is not verified (email_verified is not true)"
		}
	}
	if len(v) > 255 || strings.IndexFunc(v, func(r rune) bool { return r < 0x21 || r > 0x7e }) >= 0 ||
		!strings.Contains(v, "@") {
		return "", "its " + claim + " is not printable ASCII with an @ (" + printsafe.Line(v, 80) + ")"
	}
	return "user:" + strings.ToLower(v), ""
}

// amr is the claim when it is up to 16 printable strings of up to 64
// bytes; anything else is not recorded (Ruling 10).
func amr(raw json.RawMessage) []string {
	var out []string
	if json.Unmarshal(raw, &out) != nil || len(out) > 16 {
		return nil
	}
	for _, m := range out {
		if len(m) > 64 || !printableID(m) {
			return nil
		}
	}
	return out
}

// acr is the claim when it is one printable string of up to 255 bytes.
func acr(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) != nil || !printableID(s) {
		return ""
	}
	return s
}
