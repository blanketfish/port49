//go:build lab

package lab

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/testpki"
	"github.com/rhwendt/port49/tests/lab/labcreds"
)

// jwsOf builds a compact JWS from a header and claims, with a recognizable
// signature part.
func jwsOf(header, claims map[string]any) string {
	enc := func(m map[string]any) string {
		b, _ := json.Marshal(m)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	return enc(header) + "." + enc(claims) + "." + base64.RawURLEncoding.EncodeToString([]byte("not-a-real-signature"))
}

func TestOIDCClaimsOfDecodesHeaderAndClaims(t *testing.T) {
	h, c := claimsOf(jwsOf(map[string]any{"alg": "RS256", "typ": "JWT"}, map[string]any{"sub": "u1", "sid": "s1"}))
	if h["alg"] != "RS256" || h["typ"] != "JWT" || c["sub"] != "u1" || c["sid"] != "s1" {
		t.Fatalf("header %v claims %v", h, c)
	}
	if _, ok := c["signature"]; ok || len(h) != 2 || len(c) != 2 {
		t.Fatalf("the decode returned more than the header and the claims: %v %v", h, c)
	}
}

func TestOIDCClaimsOfIsNilForWhatIsNotAJWS(t *testing.T) {
	for _, in := range []string{"", "abc", "a.b", "a.b.c.d"} {
		if h, c := claimsOf(in); h != nil || c != nil {
			t.Errorf("%q: %v %v", in, h, c)
		}
	}
	// three parts that are not base64 JSON decode to nil maps, not a panic
	if h, c := claimsOf("!.!.!"); h != nil || c != nil {
		t.Errorf("garbage parts: %v %v", h, c)
	}
}

func TestOIDCEvidenceLineHoldsClaimsNeverAJWS(t *testing.T) {
	b, err := oidcEvidenceLine("(a) end-session", map[string]any{"claims": map[string]any{"sid": "s1"}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(string(b), "\n") || !strings.Contains(string(b), `"step":"(a) end-session"`) {
		t.Fatalf("line %q", b)
	}
	tok := jwsOf(map[string]any{"alg": "RS256"}, map[string]any{"sub": "u1"})
	if _, err := oidcEvidenceLine("leak", map[string]any{"id_token": tok}); err == nil {
		t.Fatal("a compact JWS was written to evidence")
	} else if strings.Contains(err.Error(), tok) {
		t.Fatal("the refusal repeats the token")
	}
}

func TestOIDCNoteForm(t *testing.T) {
	note := oidcNote("L45", "the claim", "| a | b |", "tests/lab/evidence/L45-keycloak.json", "commit `abc`", "Keycloak 26.4; image sha256:x")
	for _, want := range []string{"# L45 — keycloak", "**Date measured:**", "**Run:** commit `abc`", "**Platform:**",
		"**Image version:** Keycloak 26.4; image sha256:x", "**Capture:** `tests/lab/evidence/L45-keycloak.json`",
		"## Claim\n\nthe claim", "## Observation\n\n| a | b |"} {
		if !strings.Contains(note, want) {
			t.Errorf("the note lacks %q", want)
		}
	}
}

func TestOIDCNoteLeakRefusesTheAdminPasswordAndAnyJWS(t *testing.T) {
	if err := oidcNoteLeak("fine", "adm-secret"); err != nil {
		t.Fatal(err)
	}
	err := oidcNoteLeak("x adm-secret y", "adm-secret")
	if err == nil || strings.Contains(err.Error(), "adm-secret") {
		t.Fatalf("admin password: %v", err)
	}
	if err := oidcNoteLeak("x "+jwsOf(map[string]any{"alg": "none"}, map[string]any{"a": 1}), ""); err == nil {
		t.Fatal("a compact JWS passed")
	}
	// an unset admin password must not refuse every note
	if err := oidcNoteLeak("anything", ""); err != nil {
		t.Fatal(err)
	}
}

// RedactNote knows Junos credential forms (a quoted secret, a crypt hash); a
// Keycloak line quoted into a note passes through it, and oidcNoteLeak is the
// guard for what it does not know (the admin password, a JWS).
func TestOIDCNoteRedactionRunsOverWhatIsWritten(t *testing.T) {
	note := oidcNote("L46", "c", `secret "hunter2hunter2"`, "e", "r", "v")
	got := labcreds.RedactNote(note)
	if strings.Contains(got, "hunter2hunter2") {
		t.Fatalf("RedactNote left the value: %s", got)
	}
}

func TestOIDCClaimCell(t *testing.T) {
	if got := claimCell(nil, false); got != "absent" {
		t.Errorf("absent: %q", got)
	}
	if got := claimCell("openid", true); got != "`openid`" {
		t.Errorf("short: %q", got)
	}
	if got := claimCell(strings.Repeat("x", 61), true); got != "present" {
		t.Errorf("long: %q", got)
	}
}

// The compose file's image is the reference oidc_test.go records in a note.
func TestOIDCComposeImageIsThePinnedOne(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("oidc", "compose.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "image: "+kcImage+"\n") {
		t.Fatalf("compose.yaml's image is not kcImage %s", kcImage)
	}
	if !strings.Contains(kcImage, "@sha256:") {
		t.Fatal("kcImage is not pinned by digest")
	}
	if strings.Contains(string(b), "KC_BOOTSTRAP_ADMIN_PASSWORD:") {
		t.Fatal("compose.yaml holds the admin password")
	}
}

// The realm file and the harness's constants name the same client, redirect
// and service-account id.
func TestOIDCRealmMatchesTheHarness(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("oidc", "keycloak", "realm.json"))
	if err != nil {
		t.Fatal(err)
	}
	var realm struct {
		Realm   string `json:"realm"`
		Clients []struct {
			ClientID     string   `json:"clientId"`
			RedirectURIs []string `json:"redirectUris"`
			PublicClient bool     `json:"publicClient"`
		} `json:"clients"`
		Users []struct {
			ID                     string `json:"id"`
			ServiceAccountClientID string `json:"serviceAccountClientId"`
		} `json:"users"`
	}
	if err := json.Unmarshal(b, &realm); err != nil {
		t.Fatal(err)
	}
	if realm.Realm != kcRealm {
		t.Errorf("realm %q, harness %q", realm.Realm, kcRealm)
	}
	var cli bool
	for _, c := range realm.Clients {
		if c.ClientID == kcClient {
			cli = c.PublicClient && len(c.RedirectURIs) == 1 && c.RedirectURIs[0] == kcRedirect
		}
	}
	if !cli {
		t.Errorf("%s is not a public client with redirect %s", kcClient, kcRedirect)
	}
	var sa bool
	for _, u := range realm.Users {
		if u.ServiceAccountClientID == "port49-svc" {
			sa = u.ID == kcServiceAccountID
		}
	}
	if !sa {
		t.Errorf("port49-svc's service account does not carry id %s", kcServiceAccountID)
	}
}

func TestOIDCKeycloakClientFollowsNoRedirect(t *testing.T) {
	ca, err := testpki.NewCA("unit", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	c := keycloakClient(ca)
	if err := c.CheckRedirect(nil, nil); err == nil {
		t.Fatal("the client follows redirects")
	}
}
