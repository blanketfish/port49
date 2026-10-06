package api

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// A mint item printed with any verb withholds its tokens, in a slice and
// behind a pointer too, while its JSON, the wire form, keeps them (plan 7b
// final review M-1).
func TestAMintItemPrintsNoToken(t *testing.T) {
	it := MintItem{Device: "leaf1", Verdict: "permit", Login: "LOGINSECRET", Enable: "ENABLESECRET"}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		for _, v := range []any{it, &it, []MintItem{it}, MintResponse{Results: []MintItem{it}}} {
			if got := fmt.Sprintf(verb, v); strings.Contains(got, "SECRET") || !strings.Contains(got, "leaf1") {
				t.Fatalf("%s of %T printed a token, or nothing: %d bytes", verb, v, len(got))
			}
		}
	}
	if b, _ := json.Marshal(it); !strings.Contains(string(b), `"login":"LOGINSECRET"`) {
		t.Fatal("the wire form lost its login token")
	}
}

func TestConfigNamesHumanOIDCVerifiers(t *testing.T) {
	b, err := json.Marshal(Config{Methods: []string{"x509", "oidc"},
		OIDC: []OIDCProvider{{Issuer: "https://sso.example.com/realms/corp", ClientID: "port49-cli",
			Scopes: []string{"openid", "email"}}}})
	if err != nil {
		t.Fatal(err)
	}
	want := `"oidc":[{"issuer":"https://sso.example.com/realms/corp","client_id":"port49-cli","scopes":["openid","email"]}]`
	if !strings.Contains(string(b), want) {
		t.Fatalf("%s lacks %s", b, want)
	}
	b, _ = json.Marshal(Config{Methods: []string{"x509"}})
	if strings.Contains(string(b), `"oidc"`) {
		t.Fatalf("a certificate-only config names oidc: %s", b)
	}
}

func TestRevokeRequestTakesAnIssuer(t *testing.T) {
	var r RevokeRequest
	if err := json.Unmarshal([]byte(`{"sid":"3c1f","issuer":"https://sso.example.com/realms/corp"}`), &r); err != nil {
		t.Fatal(err)
	}
	if r.Sid != "3c1f" || r.Issuer != "https://sso.example.com/realms/corp" {
		t.Fatalf("decoded %+v", r)
	}
}
