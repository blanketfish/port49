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

	"github.com/rhwendt/port49/internal/config"
	"github.com/rhwendt/port49/internal/testpki"
)

// The claim in the harness is spec §15's L69 row, word for word.
func TestL69ClaimIsTheRegisters(t *testing.T) {
	spec, err := os.ReadFile("../../docs/design/2026-08-23-policy-engine-spec.md")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(spec), "| **L69** | "+l69Claim+" |") {
		t.Fatal("l69Claim differs from spec §15's L69 row")
	}
}

// tokenFacts decodes a token's header and claims and keeps its sha256, never
// the token or its signature.
func TestTokenFactsKeepsNoToken(t *testing.T) {
	h := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"abc"}`))
	p := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"https://l69-a.port49.lab","aud":["port49-lab"],"iat":100,"exp":700}`))
	raw := h + "." + p + ".c2lnbmF0dXJl"
	f, err := tokenFacts(raw)
	if err != nil {
		t.Fatal(err)
	}
	if f.Header["kid"] != "abc" || f.Claims["iss"] != "https://l69-a.port49.lab" || f.Lifetime != 600 ||
		len(f.SHA256) != 64 {
		t.Fatalf("%+v", f)
	}
	if b, _ := json.Marshal(f); strings.Contains(string(b), "c2lnbmF0dXJl") || strings.Contains(string(b), raw) {
		t.Fatal("the facts carry the signature or the token")
	}
}

// rotationFraction is when the file changed, as a fraction of the lifetime
// of the token it replaced.
func TestRotationFraction(t *testing.T) {
	iat := time.Unix(1000, 0)
	if got := rotationFraction(iat, 600*time.Second, iat.Add(480*time.Second)); got != 0.8 {
		t.Fatalf("%v", got)
	}
}

func TestKindAndNodeArePinned(t *testing.T) {
	for _, f := range []string{"k8s/kind-a.yaml", "k8s/kind-b.yaml"} {
		b, err := os.ReadFile(f)
		if err != nil || !strings.Contains(string(b), "image: "+l69NodeImage) {
			t.Fatalf("%s: %v", f, err)
		}
	}
	if l69KindVersion != "v0.29.0" {
		t.Fatal(l69KindVersion)
	}
}

// The configuration the harness runs port49d on is one the real loader
// accepts: two clusters, one admin socket, no x509 machine verifier.
func TestL69BrokerFilesLoad(t *testing.T) {
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(ca, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	pki := filepath.Join(dir, "pki")
	if err := testpki.WriteLab(pki, sliceEmail, time.Now()); err != nil {
		t.Fatal(err)
	}
	cfg, policy, inventory := k8sBrokerFiles(dir, pki, []k8sVerifier{
		{Cluster: "l69_a", Issuer: l69IssuerA, JWKS: "https://127.0.0.1:16443/openid/v1/jwks", CAFile: ca, Namespaces: []string{"netops"}},
		{Cluster: "l69_b", Issuer: l69IssuerB, JWKS: "https://127.0.0.1:16444/openid/v1/jwks", CAFile: ca, Namespaces: []string{"netops", "backup"}},
	})
	for name, body := range map[string]string{"port49d.yaml": cfg, "policy.yaml": policy, "inventory.yaml": inventory} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PORT49_LAB_KEY", labKeyDefault)
	t.Setenv("PORT49_LAB_ENC_KEY", labEncKeyDefault)
	if _, err := config.Load(filepath.Join(dir, "port49d.yaml")); err != nil {
		t.Fatal(err)
	}
}
