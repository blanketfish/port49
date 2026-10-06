package oidc_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/oidc"
	"github.com/rhwendt/port49/internal/oidc/oidctest"
	"github.com/rhwendt/port49/internal/store"
)

const clientID = "port49-cli"

func human(iss *oidctest.Issuer, claim string) oidc.VerifierConfig {
	return oidc.VerifierConfig{Domain: oidc.Humans, Issuer: iss.URL, ClientID: clientID, PrincipalClaim: claim,
		PrincipalDomains: []string{"corp.example.com"}, Algorithms: []oidc.Alg{oidc.RS256}}
}

// machine lists two clients, each with the sub its client-credentials
// tokens carry (Ruling 21).
func machine(iss *oidctest.Issuer) oidc.VerifierConfig {
	return oidc.VerifierConfig{Domain: oidc.Machines, Issuer: iss.URL, Audience: "api://port49-svc",
		Clients:    []oidc.MachineClient{{ClientID: "Oxidized-01", Sub: "svc-sub"}, {ClientID: "svc-a", Sub: "s"}},
		Algorithms: []oidc.Alg{oidc.RS256}}
}

// newSet is a Set over iss's keys, one KeySet shared by every verifier.
func newSet(t *testing.T, iss *oidctest.Issuer, c *clock, vs ...oidc.VerifierConfig) *oidc.Set {
	t.Helper()
	m := metrics.New(prometheus.NewRegistry())
	ks := oidc.NewKeySet(oidc.KeySetConfig{Issuer: iss.URL, Client: oidc.NewClient(iss.Roots()),
		Refresh: time.Hour, MaxAge: 24 * time.Hour, Now: c.Now, M: m})
	set := &oidc.Set{Timing: oidc.DefaultTiming, Now: c.Now, M: m}
	for _, v := range vs {
		set.Verifiers = append(set.Verifiers, &oidc.Verifier{VerifierConfig: v, Keys: ks})
	}
	return set
}

func TestAHumansIDTokenVerifies(t *testing.T) {
	iss, c := oidctest.NewIssuer(t), newClock()
	set := newSet(t, iss, c, human(iss, oidc.ClaimPreferredUsername))
	raw := iss.IDToken(t, "k1", clientID, "8b2e", c.Now(), map[string]any{
		"preferred_username": "Alice@Corp.Example.com", "amr": []string{"pwd", "otp"}, "acr": "1", "nonce": "n0"})
	a, err := set.Verify(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	if a.Domain != oidc.Humans || a.Principal != "user:alice@corp.example.com" || a.Subject != "8b2e" ||
		a.Sid != "s-8b2e" || !a.AuthTime.Equal(c.Now()) || a.Nonce != "n0" || a.ACR != "1" {
		t.Fatalf("assertion %+v", a)
	}
	cred := a.Credential()
	if cred.Method != "oidc" || cred.Iss != iss.URL || cred.Sub != "8b2e" || cred.Sid != store.SidKey(iss.URL, "s-8b2e") ||
		len(cred.AMR) != 2 || cred.Fingerprint != "" || cred.Issuer != "" || cred.Serial != "" {
		t.Fatalf("credential %+v", cred)
	}
}

func TestAMachinesAccessTokenVerifies(t *testing.T) {
	iss, c := oidctest.NewIssuer(t), newClock()
	set := newSet(t, iss, c, machine(iss))
	raw := iss.Token(t, "k1", map[string]any{"iss": iss.URL, "aud": []string{"api://port49-svc"}, "sub": "svc-sub",
		"azp": "Oxidized-01", "iat": c.Now().Unix(), "exp": c.Now().Add(time.Hour).Unix()})
	a, err := set.Verify(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	if a.Domain != oidc.Machines || a.Principal != "app:Oxidized-01" || !a.AuthTime.Equal(c.Now()) {
		t.Fatalf("assertion %+v: a client id is kept verbatim, and auth_time is iat", a)
	}
}

// Review Focus 4: two machine verifiers at one issuer listing one client; a
// token whose aud names both audiences is two verifiers' and so no one's.
// A human and a machine verifier never both accept one token (Ruling 2): an
// ID token naming both keys is the human's alone, since a machine verifier
// refuses its auth_time and sid.
func TestATokenTwoVerifiersAcceptIsRefused(t *testing.T) {
	iss, c := oidctest.NewIssuer(t), newClock()
	other := machine(iss)
	other.Audience = "api://port49-other"
	set := newSet(t, iss, c, machine(iss), other)
	now := c.Now()
	raw := iss.Token(t, "k1", map[string]any{"iss": iss.URL, "aud": []string{"api://port49-svc", "api://port49-other"},
		"sub": "svc-sub", "azp": "Oxidized-01", "iat": now.Unix(), "exp": now.Add(time.Hour).Unix()})
	_, err := set.Verify(context.Background(), raw)
	if !errors.Is(err, oidc.ErrInvalid) || !strings.Contains(err.Error(), "two verifiers") {
		t.Fatalf("a token two machine verifiers accept: %v", err)
	}
	both := newSet(t, iss, c, human(iss, oidc.ClaimPreferredUsername), machine(iss))
	id := iss.IDToken(t, "k1", clientID, "x", now, map[string]any{"aud": []string{clientID, "api://port49-svc"},
		"azp": clientID, "preferred_username": "alice@corp.example.com"})
	if a, err := both.Verify(context.Background(), id); err != nil || a.Domain != oidc.Humans {
		t.Fatalf("an ID token naming both keys: %+v %v", a, err)
	}
}

// Ruling 21, pre-flight C-1: a person's delegated access token for a machine
// client (aud the API, azp a listed client) is refused, whatever session
// claim marks it, and so is one whose azp and client_id disagree. The
// client's own client-credentials token is accepted, idtyp app included.
func TestADelegatedTokenIsNotAMachine(t *testing.T) {
	iss, c := oidctest.NewIssuer(t), newClock()
	set := newSet(t, iss, c, machine(iss))
	now := c.Now()
	base := func() map[string]any {
		return map[string]any{"iss": iss.URL, "aud": "api://port49-svc", "sub": "svc-sub", "azp": "Oxidized-01",
			"iat": now.Unix(), "exp": now.Add(time.Hour).Unix()}
	}
	if _, err := set.Verify(context.Background(), iss.Token(t, "k1", base())); err != nil {
		t.Fatalf("the client's own token: %v", err)
	}
	for claim, v := range map[string]any{"sid": "s-1", "auth_time": now.Unix(), "scp": "port49.api",
		"nonce": "n-1", "amr": []string{"pwd"}, "idtyp": "user"} {
		m := base()
		m[claim] = v
		if _, err := set.Verify(context.Background(), iss.Token(t, "k1", m)); !errors.Is(err, oidc.ErrInvalid) ||
			!strings.Contains(err.Error(), claim) {
			t.Errorf("a machine token carrying %s: %v", claim, err)
		}
	}
	m := base()
	m["client_id"] = "svc-a"
	if _, err := set.Verify(context.Background(), iss.Token(t, "k1", m)); !errors.Is(err, oidc.ErrInvalid) {
		t.Errorf("azp and client_id naming two clients: %v", err)
	}
	m = base()
	m["idtyp"] = "app"
	if a, err := set.Verify(context.Background(), iss.Token(t, "k1", m)); err != nil || a.Principal != "app:Oxidized-01" {
		t.Errorf("idtyp app: %+v %v", a, err)
	}
}

// Ruling 21: the client must be listed, and the token's sub must be the one
// pinned for it; a person's sub never is.
func TestAMachineSubIsPinned(t *testing.T) {
	iss, c := oidctest.NewIssuer(t), newClock()
	set := newSet(t, iss, c, machine(iss))
	now := c.Now()
	for name, k := range map[string]struct{ azp, sub, want string }{
		"an unlisted client":          {"someone-else", "svc-sub", "lists in clients"},
		"a listed client, wrong sub":  {"Oxidized-01", "alice-object-id", "pinned"},
		"another listed client's sub": {"Oxidized-01", "s", "pinned"},
	} {
		raw := iss.Token(t, "k1", map[string]any{"iss": iss.URL, "aud": "api://port49-svc", "sub": k.sub, "azp": k.azp,
			"iat": now.Unix(), "exp": now.Add(time.Hour).Unix()})
		if _, err := set.Verify(context.Background(), raw); !errors.Is(err, oidc.ErrInvalid) ||
			!strings.Contains(err.Error(), k.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// Ruling 22, pre-flight C-2: a verifier gives principals in its own domains
// alone, so a second issuer cannot mint as another's person, and no
// subdomain is implied.
func TestAnIssuerNamesOnlyItsOwnDomains(t *testing.T) {
	corp, contractor, c := oidctest.NewIssuer(t), oidctest.NewIssuer(t), newClock()
	m := metrics.New(prometheus.NewRegistry())
	set := &oidc.Set{Timing: oidc.DefaultTiming, Now: c.Now, M: m}
	for iss, domain := range map[*oidctest.Issuer]string{corp: "corp.example.com", contractor: "contractor.example.net"} {
		ks := oidc.NewKeySet(oidc.KeySetConfig{Issuer: iss.URL, Client: oidc.NewClient(iss.Roots()),
			Refresh: time.Hour, MaxAge: 24 * time.Hour, Now: c.Now, M: m})
		vc := human(iss, oidc.ClaimEmail)
		vc.PrincipalDomains = []string{domain}
		set.Verifiers = append(set.Verifiers, &oidc.Verifier{VerifierConfig: vc, Keys: ks})
	}
	alice := map[string]any{"email": "alice@corp.example.com", "email_verified": true}
	if a, err := set.Verify(context.Background(), corp.IDToken(t, "k1", clientID, "a", c.Now(), alice)); err != nil ||
		a.Principal != "user:alice@corp.example.com" {
		t.Fatalf("corp's own: %+v %v", a, err)
	}
	_, err := set.Verify(context.Background(), contractor.IDToken(t, "k1", clientID, "a", c.Now(), alice))
	if !errors.Is(err, oidc.ErrUnmapped) || !strings.Contains(err.Error(), "principal_domains") {
		t.Fatalf("the contractor issuer naming corp's alice: %v", err)
	}
	eu := map[string]any{"email": "alice@eu.corp.example.com", "email_verified": true}
	if _, err := set.Verify(context.Background(), corp.IDToken(t, "k1", clientID, "a", c.Now(), eu)); !errors.Is(err, oidc.ErrUnmapped) {
		t.Fatalf("a subdomain: %v", err)
	}
}

// Every claim is read by its exact name, and a claim named twice in two
// cases is refused (pre-flight M-4); a date is a JSON number (M-5).
func TestClaimsAreReadByExactName(t *testing.T) {
	iss, c := oidctest.NewIssuer(t), newClock()
	set := newSet(t, iss, c, human(iss, oidc.ClaimEmail))
	now := c.Now()
	base := func() map[string]any {
		return map[string]any{"iss": iss.URL, "aud": clientID, "sub": "x", "iat": now.Unix(),
			"exp": now.Add(time.Minute).Unix(), "auth_time": now.Unix(), "email": "alice@corp.example.com",
			"email_verified": true}
	}
	if _, err := set.Verify(context.Background(), iss.Token(t, "k1", base())); err != nil {
		t.Fatal(err)
	}
	for name, edit := range map[string]func(map[string]any){
		"ISS in place of iss":     func(m map[string]any) { m["ISS"] = m["iss"]; delete(m, "iss") },
		"email in two cases":      func(m map[string]any) { m["Email"] = "mallory@corp.example.com" },
		"exp a string":            func(m map[string]any) { m["exp"] = fmt.Sprint(now.Add(time.Minute).Unix()) },
		"auth_time a string":      func(m map[string]any) { m["auth_time"] = fmt.Sprint(now.Unix()) },
		"EMAIL_VERIFIED in place": func(m map[string]any) { m["EMAIL_VERIFIED"] = true; delete(m, "email_verified") },
	} {
		m := base()
		edit(m)
		_, err := set.Verify(context.Background(), iss.Token(t, "k1", m))
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestAnotherClientsIDTokenIsRefused(t *testing.T) {
	iss, c := oidctest.NewIssuer(t), newClock()
	set := newSet(t, iss, c, human(iss, oidc.ClaimPreferredUsername))
	for name, extra := range map[string]map[string]any{
		"another aud":           {"aud": "other-app"},
		"two auds, no azp":      {"aud": []string{clientID, "other-app"}},
		"azp another client":    {"azp": "other-app"},
		"two auds, azp another": {"aud": []string{clientID, "other-app"}, "azp": "other-app"},
	} {
		extra["preferred_username"] = "alice@corp.example.com"
		if _, err := set.Verify(context.Background(), iss.IDToken(t, "k1", clientID, "x", c.Now(), extra)); !errors.Is(err, oidc.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// Review Focus 4: an access token is not a person's ID token, and a logout
// token is never a bearer.
func TestAnAccessTokenIsNotAHumansToken(t *testing.T) {
	iss, c := oidctest.NewIssuer(t), newClock()
	set := newSet(t, iss, c, human(iss, oidc.ClaimPreferredUsername))
	claims := map[string]any{"iss": iss.URL, "aud": clientID, "sub": "x", "iat": c.Now().Unix(),
		"exp": c.Now().Add(time.Minute).Unix(), "auth_time": c.Now().Unix(), "preferred_username": "alice@corp.example.com"}
	for _, typ := range []string{"at+jwt", "application/at+jwt", "AT+JWT", "logout+jwt"} {
		raw := iss.TokenWith(t, "k1", map[string]any{"kid": "k1", "typ": typ}, claims)
		if _, err := set.Verify(context.Background(), raw); !errors.Is(err, oidc.ErrInvalid) {
			t.Errorf("typ %s: %v", typ, err)
		}
	}
	claims["events"] = map[string]any{"http://schemas.openid.net/event/backchannel-logout": map[string]any{}}
	if _, err := set.Verify(context.Background(), iss.Token(t, "k1", claims)); !errors.Is(err, oidc.ErrInvalid) {
		t.Errorf("a token with events: %v", err)
	}
}

// Review Focus 6: skew is allowed, and no more.
func TestClockSkewIsAllowedAndNoMore(t *testing.T) {
	iss, c := oidctest.NewIssuer(t), newClock()
	set := newSet(t, iss, c, human(iss, oidc.ClaimPreferredUsername))
	now := c.Now()
	ok := func(extra map[string]any) error {
		extra["preferred_username"] = "alice@corp.example.com"
		_, err := set.Verify(context.Background(), iss.IDToken(t, "k1", clientID, "x", now, extra))
		return err
	}
	if err := ok(map[string]any{"exp": now.Add(-30 * time.Second).Unix()}); err != nil {
		t.Errorf("expired 30s ago, within skew: %v", err)
	}
	if err := ok(map[string]any{"exp": now.Add(-61 * time.Second).Unix()}); !errors.Is(err, oidc.ErrInvalid) ||
		!strings.Contains(err.Error(), "expired") {
		t.Errorf("expired 61s ago: %v", err)
	}
	if err := ok(map[string]any{"iat": now.Add(30 * time.Second).Unix(), "auth_time": now.Unix()}); err != nil {
		t.Errorf("issued 30s ahead: %v", err)
	}
	if err := ok(map[string]any{"iat": now.Add(61 * time.Second).Unix()}); !errors.Is(err, oidc.ErrInvalid) {
		t.Errorf("issued 61s ahead: %v", err)
	}
	if err := ok(map[string]any{"nbf": now.Add(61 * time.Second).Unix()}); !errors.Is(err, oidc.ErrInvalid) {
		t.Errorf("not valid for 61s: %v", err)
	}
	if err := ok(map[string]any{"auth_time": now.Add(61 * time.Second).Unix()}); !errors.Is(err, oidc.ErrInvalid) {
		t.Errorf("authenticated 61s ahead: %v", err)
	}
}

func TestATokenOlderThanMaxTokenAgeIsRefused(t *testing.T) {
	iss, c := oidctest.NewIssuer(t), newClock()
	set := newSet(t, iss, c, human(iss, oidc.ClaimPreferredUsername))
	now := c.Now()
	raw := iss.IDToken(t, "k1", clientID, "x", now, map[string]any{"preferred_username": "alice@corp.example.com",
		"iat": now.Add(-2*time.Hour - time.Second).Unix(), "exp": now.Add(time.Hour).Unix()})
	if _, err := set.Verify(context.Background(), raw); !errors.Is(err, oidc.ErrInvalid) ||
		!strings.Contains(err.Error(), "max_token_age") {
		t.Fatalf("a token issued 2h1s ago: %v", err)
	}
}

func TestRequiredClaims(t *testing.T) {
	iss, c := oidctest.NewIssuer(t), newClock()
	set := newSet(t, iss, c, human(iss, oidc.ClaimPreferredUsername))
	for _, claim := range []string{"exp", "iat", "sub", "auth_time", "iss", "aud"} {
		raw := iss.IDToken(t, "k1", clientID, "x", c.Now(), map[string]any{"preferred_username": "alice@corp.example.com",
			claim: nil})
		if _, err := set.Verify(context.Background(), raw); !errors.Is(err, oidc.ErrInvalid) {
			t.Errorf("no %s: %v", claim, err)
		}
	}
}

func TestThePrincipalClaim(t *testing.T) {
	iss, c := oidctest.NewIssuer(t), newClock()
	for _, k := range []struct {
		claim string
		extra map[string]any
		want  string // "" is ErrUnmapped
	}{
		{oidc.ClaimPreferredUsername, map[string]any{"preferred_username": "alice@corp.example.com"}, "user:alice@corp.example.com"},
		{oidc.ClaimPreferredUsername, map[string]any{"preferred_username": "alice"}, ""},
		{oidc.ClaimPreferredUsername, map[string]any{"preferred_username": []string{"a@b"}}, ""},
		{oidc.ClaimPreferredUsername, map[string]any{"preferred_username": "al ice@b"}, ""},
		{oidc.ClaimPreferredUsername, map[string]any{}, ""},
		{oidc.ClaimEmail, map[string]any{"email": "Alice@Corp.Example.com", "email_verified": true}, "user:alice@corp.example.com"},
		{oidc.ClaimEmail, map[string]any{"email": "alice@corp.example.com", "email_verified": false}, ""},
		{oidc.ClaimEmail, map[string]any{"email": "alice@corp.example.com"}, ""},
		{oidc.ClaimEmail, map[string]any{"email": "alice@corp.example.com", "email_verified": "true"}, ""},
		{oidc.ClaimUPN, map[string]any{"upn": "alice@corp.example.com"}, "user:alice@corp.example.com"},
	} {
		set := newSet(t, iss, c, human(iss, k.claim))
		a, err := set.Verify(context.Background(), iss.IDToken(t, "k1", clientID, "x", c.Now(), k.extra))
		switch {
		case k.want == "" && !errors.Is(err, oidc.ErrUnmapped):
			t.Errorf("%s %v: %v %+v", k.claim, k.extra, err, a)
		case k.want != "" && (err != nil || a.Principal != k.want):
			t.Errorf("%s %v: %q %v", k.claim, k.extra, a.Principal, err)
		}
	}
}

func TestAMachineWithNoClientIsUnmapped(t *testing.T) {
	iss, c := oidctest.NewIssuer(t), newClock()
	set := newSet(t, iss, c, machine(iss))
	base := map[string]any{"iss": iss.URL, "aud": "api://port49-svc", "sub": "s", "iat": c.Now().Unix(),
		"exp": c.Now().Add(time.Hour).Unix()}
	if _, err := set.Verify(context.Background(), iss.Token(t, "k1", base)); !errors.Is(err, oidc.ErrUnmapped) {
		t.Fatalf("no azp and no client_id: %v", err)
	}
	base["client_id"] = "svc-a"
	if a, err := set.Verify(context.Background(), iss.Token(t, "k1", base)); err != nil || a.Principal != "app:svc-a" {
		t.Fatalf("client_id alone: %q %v", a.Principal, err)
	}
}

// A refusal names no claim of a token that did not verify: not its iss, not
// its sub, not its kid (Global Constraints).
func TestARefusalNeverQuotesAnUnverifiedToken(t *testing.T) {
	iss, c := oidctest.NewIssuer(t), newClock()
	set := newSet(t, iss, c, human(iss, oidc.ClaimPreferredUsername))
	forger := oidctest.NewIssuer(t)
	forger.AddKey(t, "kid-marker", oidc.RS256)
	for name, raw := range map[string]string{
		"an unknown issuer": forger.Token(t, "kid-marker", map[string]any{"iss": "https://iss-marker.example",
			"sub": "sub-marker", "aud": clientID}),
		"a forged signature": forger.TokenWith(t, "kid-marker", map[string]any{"kid": "k1"}, map[string]any{
			"iss": iss.URL, "sub": "sub-marker", "aud": clientID, "iat": c.Now().Unix(),
			"exp": c.Now().Add(time.Minute).Unix(), "auth_time": c.Now().Unix(), "preferred_username": "pu-marker@x"}),
	} {
		_, err := set.Verify(context.Background(), raw)
		if !errors.Is(err, oidc.ErrInvalid) {
			t.Fatalf("%s: %v", name, err)
		}
		for _, m := range []string{"iss-marker", "sub-marker", "kid-marker", "pu-marker"} {
			if strings.Contains(err.Error(), m) {
				t.Errorf("%s: the refusal %q quotes %s", name, err, m)
			}
		}
	}
}

func TestAnAlgorithmTheVerifierDoesNotPinIsRefused(t *testing.T) {
	iss, c := oidctest.NewIssuer(t), newClock()
	iss.AddKey(t, "e1", oidc.ES256)
	set := newSet(t, iss, c, human(iss, oidc.ClaimPreferredUsername))
	raw := iss.IDToken(t, "e1", clientID, "x", c.Now(), map[string]any{"preferred_username": "alice@corp.example.com"})
	if _, err := set.Verify(context.Background(), raw); !errors.Is(err, oidc.ErrInvalid) {
		t.Fatalf("ES256 under algorithms [RS256]: %v", err)
	}
}

func TestAProviderNeverReachedIsUnavailable(t *testing.T) {
	iss, c := oidctest.NewIssuer(t), newClock()
	set := newSet(t, iss, c, human(iss, oidc.ClaimPreferredUsername))
	raw := iss.IDToken(t, "k1", clientID, "x", c.Now(), map[string]any{"preferred_username": "alice@corp.example.com"})
	iss.Close()
	if _, err := set.Verify(context.Background(), raw); !errors.Is(err, oidc.ErrUnavailable) {
		t.Fatalf("no keys ever fetched: %v", err)
	}
}

func TestTheAssertionWithholdsItsNonce(t *testing.T) {
	a := oidc.Assertion{Principal: "user:a@b", Nonce: "nonce-marker"}
	for _, verb := range []string{"%v", "%+v", "%s", "%#v"} {
		if strings.Contains(fmt.Sprintf(verb, a), "nonce-marker") {
			t.Fatalf("%s prints the nonce", verb)
		}
	}
}

// A payload naming a member twice is refused whatever the case or the value:
// which of two a consumer reads is a difference between parsers, and a repeated
// sub would let a token say two people. The refusal is the verifier's, after
// the signature, so the raw payload is signed by hand here.
func TestARepeatedClaimIsRefused(t *testing.T) {
	iss, c := oidctest.NewIssuer(t), newClock()
	set := newSet(t, iss, c, human(iss, oidc.ClaimPreferredUsername), machine(iss))
	now := c.Now()
	// A raw payload cannot go through a map, so it is spliced in as text.
	member := func(name, v string) string { return fmt.Sprintf(`,"%s":%s`, name, v) }
	tail := fmt.Sprintf(`"iat":%d,"exp":%d,"auth_time":%d,"preferred_username":"alice@corp.example.com"`,
		now.Unix(), now.Add(time.Minute).Unix(), now.Unix())
	humanBody := func(extra string) string {
		return fmt.Sprintf(`{"iss":%q,"aud":%q,"sub":"me",%s%s}`, iss.URL, clientID, tail, extra)
	}
	machineBody := func(extra string) string {
		return fmt.Sprintf(`{"iss":%q,"aud":"api://port49-svc","sub":"svc-sub","azp":"Oxidized-01","iat":%d,"exp":%d%s}`,
			iss.URL, now.Unix(), now.Add(time.Hour).Unix(), extra)
	}
	if _, err := set.Verify(context.Background(), iss.TokenRaw(t, "k1", humanBody(""))); err != nil {
		t.Fatalf("the spliced baseline: %v", err)
	}
	if _, err := set.Verify(context.Background(), iss.TokenRaw(t, "k1", machineBody(""))); err != nil {
		t.Fatalf("the spliced machine baseline: %v", err)
	}
	for name, body := range map[string]string{
		"sub twice":                humanBody(member("sub", `"victim"`)),
		"iss twice":                humanBody(member("iss", fmt.Sprintf("%q", iss.URL))),
		"aud twice":                humanBody(member("aud", fmt.Sprintf("%q", clientID))),
		"sid twice":                humanBody(member("sid", `"a"`) + member("sid", `"b"`)),
		"azp twice":                humanBody(member("azp", fmt.Sprintf("%q", clientID)) + member("azp", fmt.Sprintf("%q", clientID))),
		"Sub in two cases":         humanBody(member("Sub", `"victim"`)),
		"machine sub":              machineBody(member("sub", `"svc-sub"`)),
		"machine azp":              machineBody(member("azp", `"Oxidized-01"`)),
		"machine client_id":        machineBody(member("client_id", `"Oxidized-01"`) + member("client_id", `"Oxidized-01"`)),
		"machine Sub":              machineBody(member("Sub", `"svc-sub"`)),
		"preferred_username twice": humanBody(member("preferred_username", `"mallory@corp.example.com"`)),
		"ISS and iss":              humanBody(member("ISS", fmt.Sprintf("%q", iss.URL))),
		"Aud and aud":              humanBody(member("Aud", fmt.Sprintf("%q", clientID))),
		"AZP and azp":              humanBody(member("azp", fmt.Sprintf("%q", clientID)) + member("AZP", fmt.Sprintf("%q", clientID))),
		"SID and sid":              humanBody(member("sid", `"a"`) + member("SID", `"b"`)),
		"Preferred_Username":       humanBody(member("Preferred_Username", `"mallory@corp.example.com"`)),
		"a long-s sub":             humanBody(member("\u017fub", `"victim"`)),
		"a kelvin-sign kid":        humanBody(member("\u212aid", `"x"`)),
		"machine client_id no azp": strings.Replace(machineBody(member("client_id", `"Oxidized-01"`)+member("client_id", `"Oxidized-01"`)),
			`"azp":"Oxidized-01",`, "", 1),
		"machine Client_ID": machineBody(member("client_id", `"Oxidized-01"`) + member("Client_ID", `"Oxidized-01"`)),
	} {
		_, err := set.Verify(context.Background(), iss.TokenRaw(t, "k1", body))
		if !errors.Is(err, oidc.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// The repeats that matter most: the claim the principal comes from, and the
// one that makes an email trustworthy (an earlier last-wins read took the
// second email_verified).
func TestARepeatedPrincipalClaimIsRefused(t *testing.T) {
	iss, c := oidctest.NewIssuer(t), newClock()
	now := c.Now()
	body := func(extra string) string {
		return fmt.Sprintf(`{"iss":%q,"aud":%q,"sub":"x","iat":%d,"exp":%d,"auth_time":%d%s}`, iss.URL, clientID,
			now.Unix(), now.Add(time.Minute).Unix(), now.Unix(), extra)
	}
	for name, k := range map[string]struct{ claim, extra string }{
		"email twice":          {oidc.ClaimEmail, `,"email":"a@corp.example.com","email":"b@corp.example.com","email_verified":true`},
		"email_verified twice": {oidc.ClaimEmail, `,"email":"a@corp.example.com","email_verified":false,"email_verified":true`},
		"Email_Verified pair":  {oidc.ClaimEmail, `,"email":"a@corp.example.com","email_verified":false,"Email_Verified":true`},
		"upn twice":            {oidc.ClaimUPN, `,"upn":"a@corp.example.com","upn":"b@corp.example.com"`},
	} {
		set := newSet(t, iss, c, human(iss, k.claim))
		if _, err := set.Verify(context.Background(), iss.TokenRaw(t, "k1", body(k.extra))); !errors.Is(err, oidc.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// Ruling 2: typ is an allowlist, compared case-insensitively after an
// application/ prefix.
func TestTheTypIsAnAllowlist(t *testing.T) {
	iss, c := oidctest.NewIssuer(t), newClock()
	set := newSet(t, iss, c, human(iss, oidc.ClaimPreferredUsername))
	mset := newSet(t, iss, c, machine(iss))
	now := c.Now()
	hc := map[string]any{"iss": iss.URL, "aud": clientID, "sub": "x", "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(),
		"auth_time": now.Unix(), "preferred_username": "alice@corp.example.com"}
	mc := map[string]any{"iss": iss.URL, "aud": "api://port49-svc", "sub": "svc-sub", "azp": "Oxidized-01",
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix()}
	for typ, humanOK := range map[string]bool{"JWT": true, "application/jwt": true, "jwt": true, "at+jwt": false,
		"secevent+jwt": false, "dpop+jwt": false, "token-introspection+jwt": false, "logout+jwt": false, "x": false} {
		_, err := set.Verify(context.Background(), iss.TokenWith(t, "k1", map[string]any{"kid": "k1", "typ": typ}, hc))
		if (err == nil) != humanOK || (err != nil && !errors.Is(err, oidc.ErrInvalid)) {
			t.Errorf("human, typ %s: %v", typ, err)
		}
	}
	for typ, ok := range map[string]bool{"JWT": true, "at+jwt": true, "application/at+jwt": true, "secevent+jwt": false,
		"dpop+jwt": false, "token-introspection+jwt": false, "logout+jwt": false} {
		_, err := mset.Verify(context.Background(), iss.TokenWith(t, "k1", map[string]any{"kid": "k1", "typ": typ}, mc))
		if (err == nil) != ok {
			t.Errorf("machine, typ %s: %v", typ, err)
		}
	}
	long := strings.Repeat("A", 5000) + "+jwt"
	_, err := set.Verify(context.Background(), iss.TokenWith(t, "k1", map[string]any{"kid": "k1", "typ": long}, hc))
	if err == nil || len(err.Error()) > 400 {
		t.Errorf("an unbounded typ in the refusal: %v", err)
	}
}

// Ruling 21: delegation markers (RFC 8693) are a person's.
func TestAMachineTokenWithActIsRefused(t *testing.T) {
	iss, c := oidctest.NewIssuer(t), newClock()
	set := newSet(t, iss, c, machine(iss))
	for _, claim := range []string{"act", "may_act"} {
		raw := iss.Token(t, "k1", map[string]any{"iss": iss.URL, "aud": "api://port49-svc", "sub": "svc-sub",
			"azp": "Oxidized-01", "iat": c.Now().Unix(), "exp": c.Now().Add(time.Hour).Unix(),
			claim: map[string]any{"sub": "alice"}})
		if _, err := set.Verify(context.Background(), raw); !errors.Is(err, oidc.ErrInvalid) || !strings.Contains(err.Error(), claim) {
			t.Errorf("%s: %v", claim, err)
		}
	}
}

// M2: an issuer one of whose verifiers cannot get its keys is unavailable,
// whatever another accepted.
func TestAnUnavailableVerifierBeatsAnAcceptance(t *testing.T) {
	iss, c := oidctest.NewIssuer(t), newClock()
	m := metrics.New(prometheus.NewRegistry())
	good := oidc.NewKeySet(oidc.KeySetConfig{Issuer: iss.URL, Client: oidc.NewClient(iss.Roots()),
		Refresh: time.Hour, MaxAge: 24 * time.Hour, Now: c.Now, M: m})
	// bad's provider is a closed one: its keys are never fetched.
	dead := oidctest.NewIssuer(t)
	dead.Close()
	bad := oidc.NewKeySet(oidc.KeySetConfig{Issuer: dead.URL, Client: oidc.NewClient(dead.Roots()),
		Refresh: time.Hour, MaxAge: 24 * time.Hour, Now: c.Now, M: m})
	other := machine(iss)
	other.Audience = "api://port49-other"
	set := &oidc.Set{Timing: oidc.DefaultTiming, Now: c.Now, M: m, Verifiers: []*oidc.Verifier{
		{VerifierConfig: machine(iss), Keys: good}, {VerifierConfig: other, Keys: bad}}}
	raw := iss.Token(t, "k1", map[string]any{"iss": iss.URL, "aud": "api://port49-svc", "sub": "svc-sub",
		"azp": "Oxidized-01", "iat": c.Now().Unix(), "exp": c.Now().Add(time.Hour).Unix()})
	if _, err := set.Verify(context.Background(), raw); !errors.Is(err, oidc.ErrUnavailable) {
		t.Fatalf("one accepts, one has no keys: %v", err)
	}
}

func TestPrincipalNormalizationAndBoundaries(t *testing.T) {
	iss, c := oidctest.NewIssuer(t), newClock()
	set := newSet(t, iss, c, human(iss, oidc.ClaimPreferredUsername))
	now := c.Now()
	try := func(extra map[string]any) error {
		_, err := set.Verify(context.Background(), iss.IDToken(t, "k1", clientID, "x", now, extra))
		return err
	}
	for name, pu := range map[string]string{"NUL": "alice\x00@corp.example.com", "tab": "al\tice@corp.example.com",
		"trailing newline": "alice@corp.example.com\n", "cyrillic a": "\u0430lice@corp.example.com"} {
		if err := try(map[string]any{"preferred_username": pu}); !errors.Is(err, oidc.ErrUnmapped) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := try(map[string]any{"preferred_username": "alice@corp.example.com", "nbf": now.Add(30 * time.Second).Unix()}); err != nil {
		t.Errorf("nbf 30s ahead: %v", err)
	}
	if err := try(map[string]any{"preferred_username": "alice@corp.example.com", "iat": now.Add(-time.Hour - 59*time.Minute).Unix(),
		"exp": now.Add(time.Hour).Unix()}); err != nil {
		t.Errorf("iat 1h59m ago: %v", err)
	}
}

func TestTheAssertionIsNeverJSONWithItsNonce(t *testing.T) {
	b, err := json.Marshal(oidc.Assertion{Principal: "user:a@b", Nonce: "nonce-marker"})
	if err != nil || strings.Contains(string(b), "nonce-marker") {
		t.Fatalf("%s %v", b, err)
	}
}

// A refusal for a claim name says which, bounded: an operator whose provider
// adds a mapper needs to find it.
func TestAClaimNameRefusalNamesTheClaim(t *testing.T) {
	iss, c := oidctest.NewIssuer(t), newClock()
	set := newSet(t, iss, c, human(iss, oidc.ClaimPreferredUsername))
	now := c.Now()
	body := func(extra string) string {
		return fmt.Sprintf(`{"iss":%q,"aud":%q,"sub":"x","iat":%d,"exp":%d,"auth_time":%d,"preferred_username":"a@corp.example.com"%s}`,
			iss.URL, clientID, now.Unix(), now.Add(time.Minute).Unix(), now.Unix(), extra)
	}
	_, err := set.Verify(context.Background(), iss.TokenRaw(t, "k1", body(`,"Sub":"y"`)))
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), `"sub"`) {
		t.Errorf("a two-case pair: %v", err)
	}
	_, err = set.Verify(context.Background(), iss.TokenRaw(t, "k1", body(`,"roles\u00e9":"y"`)))
	if err == nil || !strings.Contains(err.Error(), "rolesé") {
		t.Errorf("a non-ASCII name: %v", err)
	}
	_, err = set.Verify(context.Background(), iss.TokenRaw(t, "k1", body(`,"`+strings.Repeat("\u00e9", 3000)+`":"y"`)))
	if err == nil || len(err.Error()) > 300 {
		t.Errorf("an unbounded claim name: %v", err)
	}
}
