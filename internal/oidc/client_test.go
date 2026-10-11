package oidc_test

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/oidc"
	"github.com/rhwendt/port49/internal/oidc/oidctest"
)

// ReadIDToken checks what a public client checks (decision 43 ruling 6), and
// never a date against a clock.
func TestReadIDTokenChecksWhatAClientChecks(t *testing.T) {
	iss := oidctest.NewIssuer(t)
	now := time.Now()
	good := map[string]any{"iss": iss.URL, "aud": "port49-cli", "sub": "sub-alice", "iat": now.Unix(),
		"exp": now.Add(5 * time.Minute).Unix(), "auth_time": now.Unix(), "nonce": "n-1", "sid": "s-1"}
	with := func(k string, v any) map[string]any {
		c := map[string]any{}
		for kk, vv := range good {
			c[kk] = vv
		}
		if v == nil {
			delete(c, k)
		} else {
			c[k] = v
		}
		return c
	}
	id, err := oidc.ReadIDToken(iss.Token(t, "k1", good), iss.URL, "port49-cli", "n-1")
	if err != nil || id.Subject != "sub-alice" || id.Sid != "s-1" || id.Nonce != "n-1" ||
		id.AuthTime.Unix() != now.Unix() {
		t.Fatalf("a good token: %v %v", id, err)
	}
	// An expired token is read: the client judges no date by its clock.
	old := with("exp", now.Add(-time.Hour).Unix())
	old["iat"] = now.Add(-2 * time.Hour).Unix()
	if _, err := oidc.ReadIDToken(iss.Token(t, "k1", old), iss.URL, "port49-cli", "n-1"); err != nil {
		t.Fatalf("an expired token is the broker's to refuse: %v", err)
	}
	for name, c := range map[string]struct {
		claims map[string]any
		nonce  string
		want   string
	}{
		"another issuer":               {with("iss", "https://evil.example"), "", "was not issued by"},
		"another audience":             {with("aud", "other"), "", "aud does not name"},
		"several audiences and no azp": {with("aud", []string{"port49-cli", "other"}), "", "no azp"},
		"another azp":                  {with("azp", "other"), "", "azp is not"},
		"no sub":                       {with("sub", nil), "", "no usable sub"},
		"no auth_time":                 {with("auth_time", nil), "", "no auth_time"},
		"a date as a string":           {with("iat", "1700000000"), "", "NumericDate"},
		"exp before iat":               {with("exp", now.Add(-time.Minute).Unix()), "", "expires before"},
		"another nonce":                {good, "n-2", "nonce is not"},
		"no nonce when one was sent":   {with("nonce", nil), "n-1", "nonce is not"},
		"a claim named twice in cases": {with("SUB", "x"), "", "twice"},
	} {
		if c.nonce == "" {
			c.nonce = "n-1"
		}
		_, err := oidc.ReadIDToken(iss.Token(t, "k1", c.claims), iss.URL, "port49-cli", c.nonce)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
	// alg none and an HMAC are refused before any claim is read.
	body := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"x"}`))
	for _, alg := range []string{"none", "HS256"} {
		head := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"` + alg + `"}`))
		if _, err := oidc.ReadIDToken(head+"."+body+".c2ln", iss.URL, "port49-cli", "n-1"); !errors.Is(err, oidc.ErrAlgorithm) {
			t.Errorf("alg %s: %v", alg, err)
		}
	}
	// An empty expected nonce is refused, not skipped (fail closed).
	if _, err := oidc.ReadIDToken(iss.Token(t, "k1", with("nonce", nil)), iss.URL, "port49-cli", ""); err == nil ||
		!strings.Contains(err.Error(), "nonce") {
		t.Errorf("an empty expected nonce: %v", err)
	}
	// String withholds the nonce.
	if s := id.String() + id.GoString(); strings.Contains(s, "n-1") {
		t.Fatalf("String holds the nonce: %s", s)
	}
}

func TestReadDiscovery(t *testing.T) {
	ok := `{"issuer":"https://kc.example/r","authorization_endpoint":"https://kc.example/r/auth",` +
		`"token_endpoint":"https://kc.example/r/token","code_challenge_methods_supported":["plain","S256"],` +
		`"authorization_response_iss_parameter_supported":true}`
	d, err := oidc.ReadDiscovery([]byte(ok), "https://kc.example/r")
	if err != nil || d.AuthorizationEndpoint != "https://kc.example/r/auth" || d.TokenEndpoint != "https://kc.example/r/token" ||
		len(d.CodeChallengeMethods) != 2 || !d.IssParameter {
		t.Fatalf("%+v %v", d, err)
	}
	for name, c := range map[string]struct{ doc, want string }{
		"another issuer":         {strings.Replace(ok, `"issuer":"https://kc.example/r"`, `"issuer":"https://kc.example/x"`, 1), "another issuer"},
		"an http token endpoint": {strings.Replace(ok, `"https://kc.example/r/token"`, `"http://kc.example/r/token"`, 1), "token_endpoint"},
		"credentials in a URL":   {strings.Replace(ok, `"https://kc.example/r/auth"`, `"https://u:p@kc.example/r/auth"`, 1), "authorization_endpoint"},
		"a member twice":         {strings.Replace(ok, `{"issuer"`, `{"token_endpoint":"https://x/t","issuer"`, 1), "distinct members"},
		"methods not a list":     {strings.Replace(ok, `["plain","S256"]`, `"S256"`, 1), "code_challenge_methods_supported"},
	} {
		if _, err := oidc.ReadDiscovery([]byte(c.doc), "https://kc.example/r"); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
}
