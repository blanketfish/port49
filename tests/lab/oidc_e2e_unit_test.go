//go:build lab

package lab

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/config"
	"github.com/rhwendt/port49/internal/oidc"
	"github.com/rhwendt/port49/internal/policy"
	"github.com/rhwendt/port49/internal/testpki"
	"gopkg.in/yaml.v3"
)

// The OIDC end-to-end's broker config and policy, derived from the compose
// lab's, load under the real loaders: the x509 human anchor kept beside the
// Keycloak verifiers, a machine verifier with the pinned service account, and
// the two subjects granted. A run that fails here would fail minutes into a
// stack's start.
func TestOIDCE2EConfigAndPolicyLoad(t *testing.T) {
	read := func(name string) string {
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	files, err := composeLabFiles(read("port49d-lab.yaml"), read(filepath.Join("slice", "broker.yaml")),
		read(filepath.Join("slice", "policy.yaml")), read("inventory-lab.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := oidcE2EFiles(files); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	t.Setenv("PORT49_LAB_KEY", "labsecret")
	t.Setenv("PORT49_LAB_ENC_KEY", labEncKeyDefault)
	for _, d := range []string{"etc/etcd", "etc/broker", "oidc", "run", "state", "spool"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{"etc/etcd/ca.pem", "etc/etcd/port49d.pem", "etc/etcd/port49d-key.pem", "etc/etcd/port49-broker.pem",
		"etc/etcd/port49-broker-key.pem", "etc/broker/broker.pem", "etc/broker/broker-key.pem", "etc/broker/broker-ca.pem",
		"oidc/idp-ca.pem"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	moved := func(s string) string {
		// /etc/port49-oidc first: /etc/port49 is its prefix
		s = strings.ReplaceAll(s, "/etc/port49-oidc", filepath.Join(dir, "oidc"))
		s = strings.ReplaceAll(s, "/etc/port49", filepath.Join(dir, "etc"))
		s = strings.ReplaceAll(s, "/var/lib/port49-broker", filepath.Join(dir, "state"))
		s = strings.ReplaceAll(s, "/var/spool/port49d", filepath.Join(dir, "spool"))
		return strings.ReplaceAll(s, "/run/port49", filepath.Join(dir, "run"))
	}
	for name, body := range files {
		if strings.HasSuffix(name, ".yaml") {
			if err := os.WriteFile(filepath.Join(dir, "etc", name), []byte(moved(body)), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	b, err := config.LoadBroker(filepath.Join(dir, "etc", "port49-broker.yaml"))
	if err != nil {
		t.Fatalf("the broker's config does not load: %v\n%s", err, moved(files["port49-broker.yaml"]))
	}
	id := b.Broker.Identity
	if id == nil || id.Shorthand || id.X509AnchorFile != filepath.Join(dir, "etc", "broker", "broker-ca.pem") || len(id.OIDC) != 2 {
		t.Fatalf("the identity block resolved to %+v", id)
	}
	issuer := "https://" + kcHost + ":" + kcPort + "/realms/" + kcRealm
	h, m := id.OIDC[0], id.OIDC[1]
	if h.Domain != oidc.Humans || h.Issuer != issuer || h.ClientID != kcClient || h.PrincipalClaim != oidc.ClaimEmail ||
		len(h.PrincipalDomains) != 1 || h.PrincipalDomains[0] != "corp.example.com" || h.CAFile != filepath.Join(dir, "oidc", "idp-ca.pem") {
		t.Errorf("the human verifier resolved to %+v", h)
	}
	if m.Domain != oidc.Machines || m.Issuer != issuer || m.Audience != "api://port49-svc" || len(m.Clients) != 1 ||
		m.Clients[0].ClientID != "port49-svc" || m.Clients[0].Sub != kcServiceAccountID {
		t.Errorf("the machine verifier resolved to %+v", m)
	}
	if _, err := config.Load(filepath.Join(dir, "etc", "port49d.yaml")); err != nil {
		t.Fatalf("port49d's config does not load: %v", err)
	}
	if strings.Contains(files["port49d.yaml"], "keycloak") {
		t.Error("port49d.yaml names the provider; the broker's alone does")
	}

	p, err := policy.Parse([]byte(files["policy.yaml"]), policy.Env{})
	if err != nil || p == nil {
		t.Fatalf("the lab policy does not load: %v", err)
	}
	for _, want := range []string{"user:alice@corp.example.com", "app:port49-svc", "username: alice", "slice_operator"} {
		if !strings.Contains(files["policy.yaml"], want) {
			t.Errorf("policy.yaml lacks %q", want)
		}
	}
}

func TestOIDCE2EFilesRefuseAFileTheyCannotEdit(t *testing.T) {
	if err := oidcE2EFiles(map[string]string{"port49-broker.yaml": "broker: {}\n", "policy.yaml": "scopes: []\n"}); err == nil {
		t.Error("a broker config with no client_ca_file was edited")
	}
	if err := oidcE2EFiles(map[string]string{"port49-broker.yaml": "broker:\n  client_ca_file: /x.pem\n",
		"policy.yaml": "scopes: []\n"}); err == nil {
		t.Error("a policy with no subjects block was edited")
	}
}

// The lab broker's certificate, which Keycloak's logout POST checks, and the
// files the overlay mounts: Keycloak's certificate verifies for its issuer's
// host under the run's CA, the key is not the CA's, the admin password is in
// an 0600 env file and nowhere else, and the broker's CA is Keycloak's
// truststore.
func TestOIDCE2EPKIWritesWhatTheOverlayMounts(t *testing.T) {
	now := time.Now()
	ca, err := testpki.NewCA("test oidc CA", now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := oidcE2EPKI(dir, ca, []byte("BROKER-CA\n"), now); err != nil {
		t.Fatal(err)
	}
	pair, err := tls.LoadX509KeyPair(filepath.Join(dir, "pki", "keycloak.pem"), filepath.Join(dir, "pki", "keycloak-key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: kcHost, Roots: ca.Pool()}); err != nil {
		t.Fatalf("Keycloak's certificate does not verify for %s: %v", kcHost, err)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "pki", "broker-ca.pem")); string(got) != "BROKER-CA\n" {
		t.Errorf("Keycloak's truststore is %q", got)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "idp-ca.pem")); string(got) != string(ca.PEM()) {
		t.Error("the broker's idp-ca.pem is not the run's CA")
	}
	env, err := os.ReadFile(filepath.Join(dir, "admin.env"))
	if err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(filepath.Join(dir, "admin.env")); fi.Mode().Perm() != 0o600 {
		t.Errorf("admin.env is %v", fi.Mode().Perm())
	}
	pass := strings.TrimPrefix(strings.TrimSpace(string(env)), "KC_BOOTSTRAP_ADMIN_PASSWORD=")
	if len(pass) < 32 || strings.Contains(pass, "\n") {
		t.Errorf("the admin password is %d bytes", len(pass))
	}
	for _, f := range []string{"pki/keycloak.pem", "pki/keycloak-key.pem", "pki/broker-ca.pem", "idp-ca.pem"} {
		if raw, _ := os.ReadFile(filepath.Join(dir, f)); strings.Contains(string(raw), pass) {
			t.Errorf("%s holds the admin password", f)
		}
	}
	// adminFromEnv, the e2e's own reader, reads it back.
	k := &keycloak{}
	k.adminFromEnv(t, filepath.Join(dir, "admin.env"))
	if k.admin != pass {
		t.Error("adminFromEnv does not read what oidcE2EPKI wrote")
	}
}

// The overlay names every file the test writes and the broker reads, the
// alias Keycloak's issuer is reached by, and the pinned image; it holds no
// admin password.
func TestOIDCE2EOverlayNamesWhatTheTestWrites(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("compose", "oidc.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	o := string(raw)
	for _, want := range []string{"oidc/admin.env", "oidc/pki:/pki:ro", "oidc/idp-ca.pem:/etc/port49-oidc/idp-ca.pem:ro",
		"--https-certificate-file=/pki/keycloak.pem", "--https-certificate-key-file=/pki/keycloak-key.pem",
		"--truststore-paths=/pki/broker-ca.pem", "--hostname=https://" + kcHost + ":" + kcPort,
		"aliases: [" + kcHost + "]", `"127.0.0.1:` + kcPort + ":" + kcPort + `"`} {
		if !strings.Contains(o, want) {
			t.Errorf("tests/lab/compose/oidc.yaml lacks %q", want)
		}
	}
	if strings.Contains(o, "KC_BOOTSTRAP_ADMIN_PASSWORD:") {
		t.Error("oidc.yaml holds the admin password")
	}
	var y struct {
		Services map[string]struct {
			Image     string         `yaml:"image"`
			DependsOn map[string]any `yaml:"depends_on"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal(raw, &y); err != nil {
		t.Fatalf("oidc.yaml is not YAML: %v", err)
	}
	if y.Services["keycloak"].Image != kcImage {
		t.Errorf("the overlay's image is not kcImage")
	}
	if _, ok := y.Services["port49-broker"].DependsOn["keycloak"]; !ok {
		t.Error("the broker does not depend on keycloak")
	}
}

// What a person's or a machine's mint answer says holds the decision and never
// the device token, which comes back apart for the caller to register.
func TestOIDCMintSaidNeverHoldsTheToken(t *testing.T) {
	secret := "device-token-0123456789"
	body := `{"principal":"user:alice@corp.example.com","results":[{"device":"leaf1","verdict":"permit","reason":"ok",` +
		`"username":"alice","login":"` + secret + `"}]}`
	login, said := mintSaid(200, body, nil)
	if login != secret {
		t.Fatalf("login %q", login)
	}
	if strings.Contains(said, secret) || !strings.Contains(said, "user:alice@corp.example.com") || !strings.Contains(said, "permit") {
		t.Errorf("said %q", said)
	}
	// a body that is not one result is never echoed
	if _, said := mintSaid(200, `{"results":[],"x":"`+secret+`"}`, nil); strings.Contains(said, secret) {
		t.Errorf("an unexpected 200 body is echoed: %q", said)
	}
	// an item fault is said without its login, and its text is scrubbed
	_, said = mintSaid(200, `{"principal":"p","results":[{"device":"d","error":"store_unavailable","detail":"`+secret+`"}]}`,
		[]string{secret})
	if strings.Contains(said, secret) || !strings.Contains(said, "store_unavailable") {
		t.Errorf("item fault said %q", said)
	}
}

func TestOIDCBrokerSaidIsTheErrorAndNeverABody(t *testing.T) {
	if got := brokerSaid(503, `{"error":"identity_provider_unavailable","detail":"try again"}`, nil); got !=
		"503 identity_provider_unavailable: try again" {
		t.Errorf("%q", got)
	}
	tok := jwsOf(map[string]any{"alg": "RS256"}, map[string]any{"sub": "u1"})
	got := brokerSaid(401, `{"error":"identity_unmapped","detail":"token `+tok+` and nonce-abcdef12"}`, []string{"nonce-abcdef12"})
	if strings.Contains(got, tok) || strings.Contains(got, "nonce-abcdef12") || strings.Contains(got, "eyJ") {
		t.Errorf("an error's detail holds a token or a registered value: %q", got)
	}
	// a challenge's own body is no error, so it is never echoed
	if got := brokerSaid(200, `{"nonce":"nonce-abcdef12","expires_at":"x"}`, nil); strings.Contains(got, "nonce-abcdef12") {
		t.Errorf("a non-error body is echoed: %q", got)
	}
	if got := brokerSaid(0, "tls: failed", nil); got != "no answer: tls: failed" {
		t.Errorf("%q", got)
	}
}

func TestOIDCRefreshSaid(t *testing.T) {
	resp, said := refreshSaid(200, `{"auth_time":"2026-10-07T01:02:03Z","session_ends_at":"x","sessions":[`+
		`{"device":"leaf1","username":"alice","outcome":"extended"}]}`, nil)
	if resp.AuthTime != "2026-10-07T01:02:03Z" || len(resp.Sessions) != 1 || !strings.Contains(said, "leaf1/alice extended") {
		t.Errorf("%+v %q", resp, said)
	}
	_, said = refreshSaid(401, `{"error":"refresh_not_fresh","detail":"your identity provider did not authenticate you again"}`, nil)
	if !strings.HasPrefix(said, "401 refresh_not_fresh:") {
		t.Errorf("%q", said)
	}
}

// The bearer is in the Authorization header and in no URL, a transport
// failure says no URL, and a refusal's nonce is a value the run registered.
func TestOIDCBrokerCallPutsTheBearerInTheHeaderAlone(t *testing.T) {
	bearer := "bearer-0123456789-abcdef"
	var gotURL, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotURL, gotAuth = r.URL.String(), r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"nonce": "n-0123456789", "expires_at": "x"})
	}))
	defer srv.Close()
	kc := &keycloak{}
	br := oidcBroker{c: srv.Client(), kc: kc, base: srv.URL}
	if n := br.challenge(t, bearer); n != "n-0123456789" {
		t.Fatalf("nonce %q", n)
	}
	if strings.Contains(gotURL, bearer) || gotAuth != "Bearer "+bearer {
		t.Errorf("url %q, Authorization %q", gotURL, gotAuth)
	}
	if known := kc.known(); len(known) != 1 || known[0] != "n-0123456789" {
		t.Errorf("the nonce is not registered as a secret: %v", known)
	}
	srv.Close()
	code, text := br.post("/v1/tokens", bearer, "{}")
	if code != 0 || strings.Contains(text, bearer) || strings.Contains(text, srv.URL) {
		t.Errorf("a failed call: %d %q", code, text)
	}
}

func TestOIDCRetryMintRetriesOnlyWhileTheProviderIsUnavailable(t *testing.T) {
	calls := 0
	tok, said := retryMint(func() (string, string) {
		calls++
		if calls < 3 {
			return "", "503 identity_provider_unavailable: the provider's keys are not fetched"
		}
		return "t0k3n-token", "200 ok"
	}, time.Minute, time.Millisecond)
	if tok != "t0k3n-token" || calls != 3 || said != "200 ok" {
		t.Errorf("tok %q said %q after %d calls", tok, said, calls)
	}
	calls = 0
	if tok, _ := retryMint(func() (string, string) { calls++; return "", "401 identity_unmapped: no" }, time.Minute, time.Millisecond); tok != "" || calls != 1 {
		t.Errorf("another refusal was retried: %d calls", calls)
	}
	calls = 0
	retryMint(func() (string, string) { calls++; return "", "503 identity_provider_unavailable: x" }, 20*time.Millisecond, 5*time.Millisecond)
	if calls < 2 || calls > 6 {
		t.Errorf("a provider that never came up was called %d times in the window", calls)
	}
}

func TestOIDCRevokeBySid(t *testing.T) {
	recs := []map[string]any{
		{"event": "revoke", "revocation": map[string]any{"by": "principal"}},
		{"event": "mint"},
		{"event": "revoke", "revocation": map[string]any{"by": "sid", "sid": "s1"}},
	}
	if rv := revokeBySid(recs); rv == nil || sub(rv, "revocation")["sid"] != "s1" {
		t.Errorf("%v", rv)
	}
	if revokeBySid(recs[:2]) != nil || revokeBySid(nil) != nil {
		t.Error("a revoke by another key counted as a logout")
	}
	if jsonCell(nil) != "absent" || !strings.Contains(jsonCell(map[string]any{"by": "sid"}), `"by":"sid"`) {
		t.Error("jsonCell")
	}
}
