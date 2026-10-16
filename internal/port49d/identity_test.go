package port49d

import (
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/rhwendt/port49/internal/config"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/oidc"
	"github.com/rhwendt/port49/internal/oidc/oidctest"
	"github.com/rhwendt/port49/internal/policy"
	"github.com/rhwendt/port49/internal/store/memory"
)

// identityCfg is broker.identity with a human and a machine verifier at
// iss, its CA in a file, on a broker whose state is kept in dir.
func identityCfg(t *testing.T, iss *oidctest.Issuer, dir string) *oidc.Config {
	t.Helper()
	ca := writeFile(t, dir, "idp-ca.pem", iss.CertPEM())
	return &oidc.Config{X509AnchorFile: "/etc/port49/clients-ca.pem", Timing: oidc.DefaultTiming, OIDC: []oidc.VerifierConfig{
		{Domain: oidc.Humans, Issuer: iss.URL, ClientID: "port49-cli", PrincipalClaim: oidc.ClaimEmail,
			PrincipalDomains: []string{"corp.example.com"}, Scopes: []string{"openid", "email"},
			Algorithms: []oidc.Alg{oidc.RS256}, CAFile: ca},
		{Domain: oidc.Machines, Issuer: iss.URL, Audience: "api://port49-svc",
			Clients:    []oidc.MachineClient{{ClientID: "oxidized", Sub: "5f3c2d1e-0000-4000-8000-000000000049"}},
			Algorithms: []oidc.Alg{oidc.RS256}, CAFile: ca}}}
}

func TestTheIdentityStartLines(t *testing.T) {
	iss := oidctest.NewIssuer(t)
	dir := t.TempDir()
	cfg := brokerConfig(t, directoryPolicy)
	cfg.Broker.Identity = identityCfg(t, iss, dir)
	cfg.Broker.Identity.OIDC[1].CAFile = "" // the machine verifier trusts the system roots
	var out syncBuffer
	announceIdentity(&out, "port49-broker", cfg, nil)
	got := out.String()
	for _, want := range []string{
		"port49-broker: identity: humans: x509 (trust anchor /etc/port49/clients-ca.pem); oidc " + iss.URL +
			" (client_id port49-cli, principal from email in corp.example.com, email_verified required; algorithms RS256)\n",
		"port49-broker: identity: machines: oidc " + iss.URL + " (audience api://port49-svc; clients oxidized (sub " +
			"5f3c2d1e-0000-4000-8000-000000000049); principal app:<azp>; algorithms RS256)\n",
		"the principal claim must be one only the identity provider's administrators can set",
		"turn off \"trust email\"",
		"port49-broker: identity: " + iss.URL + " is fetched ",
		"port49-broker: identity: " + iss.URL + " is trusted through the system's root certificates (no ca_file)\n",
		"port49-broker: identity: keys refreshed every 1h0m0s; trusted without a refresh until 24h0m0s after the last " +
			"(broker.identity.jwks_max_age); clock_skew 1m0s; max_token_age 2h0m0s\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the start lines lack %q:\n%s", want, got)
		}
	}
	cfg.Broker.Identity = &oidc.Config{X509AnchorFile: "/etc/port49/clients-ca.pem", Shorthand: true}
	out = syncBuffer{}
	announceIdentity(&out, "port49d", cfg, nil)
	if !strings.Contains(out.String(), "identity: humans: x509 from broker.client_ca_file (no broker.identity is "+
		"configured); no OIDC verifier") {
		t.Fatalf("the shorthand's line:\n%s", out.String())
	}
}

// oidcOnly is broker.identity with one OIDC human verifier and no x509
// anchor: ClientCAFile is "" as config resolves it.
func oidcOnly(t *testing.T, iss *oidctest.Issuer, dir string) *oidc.Config {
	t.Helper()
	id := identityCfg(t, iss, dir)
	id.X509AnchorFile = ""
	id.OIDC = id.OIDC[:1]
	return id
}

// The operator's view of an OIDC-only broker (Task 14, decision 3): it
// starts, says it takes no certificate, and a refusal never prints an empty
// client_ca_file.
func TestAnOIDCOnlyBrokerStartsAndSaysSo(t *testing.T) {
	iss := oidctest.NewIssuer(t)
	cfg := brokerConfig(t, minimalPolicy)
	cfg.Broker.ClientCAFile = ""
	cfg.Broker.StateDir = t.TempDir()
	cfg.Broker.Identity = oidcOnly(t, iss, t.TempDir())
	out := captureStderr(t)
	srv, b, err := buildBroker(cfg, "inventory_file x", memory.New(time.Now), seedMinter(), decision.NewJSONLines(io.Discard), metrics.New(prometheus.NewRegistry()))
	if err != nil {
		t.Fatalf("an OIDC-only broker did not start: %v", err)
	}
	if srv == nil || !b.NoX509 || b.Identity == nil {
		t.Fatalf("server %v NoX509 %v identity %v", srv, b.NoX509, b.Identity)
	}
	if !strings.Contains(out.String(), "identity: humans: oidc "+iss.URL) || strings.Contains(out.String(), "x509 (trust anchor") {
		t.Fatalf("the start lines:\n%s", out.String())
	}
}

func TestAnOIDCOnlyBrokersRefusalsNameTheKeyNotAnEmptyFile(t *testing.T) {
	iss := oidctest.NewIssuer(t)
	cfg := brokerConfig(t, minimalPolicy)
	cfg.Broker.ClientCAFile = ""
	cfg.Broker.StateDir = t.TempDir()
	cfg.Broker.Identity = oidcOnly(t, iss, t.TempDir())
	cfg.Broker.TLSCertFile = "/nonexistent/server.pem"
	captureStderr(t)
	_, _, err := buildBroker(cfg, "inventory_file x", memory.New(time.Now), seedMinter(), decision.NewJSONLines(io.Discard), metrics.New(prometheus.NewRegistry()))
	if err == nil {
		t.Fatal("a missing server certificate started")
	}
	if !strings.Contains(err.Error(), "tls_cert_file /nonexistent/server.pem") || strings.Contains(err.Error(), "client_ca_file") ||
		strings.Contains(err.Error(), "open :") {
		t.Fatalf("the refusal: %v", err)
	}

	// No identity and no anchor is a config load's refusal; reaching the
	// server anyway, the line still names a key an operator can edit.
	cfg = brokerConfig(t, minimalPolicy)
	cfg.Broker.ClientCAFile = ""
	captureStderr(t)
	_, _, err = buildBroker(cfg, "inventory_file x", memory.New(time.Now), seedMinter(), decision.NewJSONLines(io.Discard), metrics.New(prometheus.NewRegistry()))
	if err == nil {
		t.Fatal("a broker with neither an anchor nor an identity started")
	}
	if strings.Contains(err.Error(), "client_ca_file  ") || strings.Contains(err.Error(), "client_ca_file :") ||
		!strings.Contains(err.Error(), "broker.identity") {
		t.Fatalf("the refusal: %v", err)
	}
}

func fmtLine(format string, args ...any) string { return fmt.Sprintf(format, args...) + "\n" }

// An HTTPS_PROXY that does not parse is said to be malformed, not "no
// HTTPS_PROXY": the transport would drop or misread it, and the operator of a
// proxy-only egress must not be told none is set (final review F3). The
// value, a password included, is never in the line.
func TestAMalformedProxyIsSaidMalformedNotAbsent(t *testing.T) {
	iss := oidctest.NewIssuer(t)
	cfg := brokerConfig(t, directoryPolicy)
	cfg.Broker.Identity = identityCfg(t, iss, t.TempDir())
	for _, tc := range []struct{ name, value string }{
		{"a bad percent escape", "http://svc:p%zzsecret@proxy.example.com:3128"},
		{"a slash in the password", "http://svc:pa/ssecret@proxy.example.com:3128"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("HTTPS_PROXY", tc.value)
			t.Setenv("https_proxy", "")
			var out syncBuffer
			announceIdentity(&out, "port49d", cfg, nil)
			line := ""
			for _, l := range strings.Split(out.String(), "\n") {
				if strings.Contains(l, iss.URL+" is fetched ") {
					line = l
				}
			}
			if line == "" || strings.Contains(line, "no HTTPS_PROXY") || !strings.Contains(line, "HTTPS_PROXY that is set but does not parse") ||
				!strings.Contains(line, "proxy-only egress") || strings.Contains(line, "secret") {
				t.Fatalf("the fetch line for a malformed proxy: %q", line)
			}
		})
	}
	t.Setenv("HTTPS_PROXY", "")
	var out syncBuffer
	announceIdentity(&out, "port49d", cfg, nil)
	if !strings.Contains(out.String(), "is fetched directly (no HTTPS_PROXY)") {
		t.Fatalf("with no proxy set the line must say so:\n%s", out.String())
	}
}

func k8sConfig() config.Config {
	return config.Config{Broker: &config.BrokerConfig{Identity: &oidc.Config{Timing: oidc.DefaultTiming,
		K8s: []oidc.VerifierConfig{{Domain: oidc.Machines, Kind: oidc.KindK8s, Cluster: "l69_a", Issuer: "https://l69-a.port49.lab",
			JWKS: "https://10.0.0.10:6443/openid/v1/jwks", Audience: "port49", Namespaces: []string{"netops"},
			Algorithms: []oidc.Alg{oidc.RS256}, CAFile: "/etc/port49/l69-a-ca.pem"}}}}}
}

func TestTheStartSaysEachCluster(t *testing.T) {
	var out strings.Builder
	announceIdentity(&out, "port49-broker", k8sConfig(), nil)
	for _, want := range []string{
		"port49-broker: identity: machines: k8s cluster l69_a (issuer https://l69-a.port49.lab; keys from " +
			"https://10.0.0.10:6443/openid/v1/jwks; audience port49; namespaces netops; principal " +
			"system:serviceaccount:<namespace>:<name>; algorithms RS256)",
		"port49-broker: identity: k8s namespaces: netops: l69_a\n",
		"a k8s verifier trusts its cluster's administrators: whoever can create a pod or a token for a service account in a " +
			"listed namespace mints as it",
		"a token stays valid here until its exp or max_token_age after its pod or service account is deleted; " +
			"port49 revoke --principal ends it at once",
		// The egress line is computed for the jwks host the fetch dials, and
		// names it (pre-flight I9).
		"identity: cluster l69_a (https://l69-a.port49.lab) is fetched directly (no HTTPS_PROXY) (its jwks host 10.0.0.10:6443)",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String(), "is trusted through the system's root certificates") {
		t.Fatal("a ca_file was set")
	}
}

// The egress line is for the jwks host, not the issuer: NO_PROXY naming only
// the jwks host makes the fetch direct though the issuer would be proxied.
func TestTheClusterEgressLineIsComputedForTheJWKSHost(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://proxy.example:3128")
	t.Setenv("https_proxy", "")
	t.Setenv("NO_PROXY", "10.0.0.10")
	t.Setenv("no_proxy", "")
	var out strings.Builder
	announceIdentity(&out, "port49-broker", k8sConfig(), nil)
	if !strings.Contains(out.String(), "is fetched directly (no HTTPS_PROXY) (its jwks host 10.0.0.10:6443)") {
		t.Fatalf("the proxy was computed for the issuer:\n%s", out.String())
	}
}

func TestAClusterWithNoCAFileIsSaidToUseTheSystemRoots(t *testing.T) {
	cfg := k8sConfig()
	cfg.Broker.Identity.K8s[0].CAFile = ""
	var out strings.Builder
	announceIdentity(&out, "port49-broker", cfg, nil)
	if !strings.Contains(out.String(), "identity: cluster l69_a (https://l69-a.port49.lab) is trusted through the system's root certificates (no ca_file)") {
		t.Fatal(out.String())
	}
}

// Every cluster vouching for a namespace is named, so an overlap is seen at
// every start (decision 49 rulings 4 and 13); a migration's two verifiers on
// one jwks are one cluster, named once.
func TestTheStartNamesEveryClusterVouchingForANamespace(t *testing.T) {
	cfg := k8sConfig()
	a := cfg.Broker.Identity.K8s[0]
	b := a
	b.Cluster, b.Issuer, b.JWKS, b.Namespaces = "eu_west", "https://eu-west.port49.lab", "https://10.1.0.10:6443/openid/v1/jwks", []string{"backup", "netops"}
	m := a
	m.Issuer = "https://l69-a-new.port49.lab" // l69_a migrating its issuer
	cfg.Broker.Identity.K8s = []oidc.VerifierConfig{a, b, m}
	var out strings.Builder
	announceIdentity(&out, "port49-broker", cfg, nil)
	if want := "port49-broker: identity: k8s namespaces: backup: eu_west; netops: eu_west, l69_a\n"; !strings.Contains(out.String(), want) {
		t.Fatalf("missing %q in\n%s", want, out.String())
	}
}

func TestServiceAccountsNoClusterCanGiveAreSaid(t *testing.T) {
	pol, err := policy.Parse([]byte(`
scopes: [{name: all_devices, match: {}}]
roles: [{name: r, privilege: admin, permit: ["**"]}]
subjects:
  - {name: a, identity: ["system:serviceaccount:netops:oxidized"], username: a, token_ttl: 60s}
  - {name: b, identity: ["system:serviceaccount:kube-system:default"], username: b, token_ttl: 60s}
grants:
  - {subject: a, scope: all_devices, roles: [r], max_privilege: admin}
  - {subject: b, scope: all_devices, roles: [r], max_privilege: admin}
`), policy.Env{})
	if err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	announceServiceAccountIdentities(&out, "port49d", k8sConfig(), pol)
	want := "port49d: policy: 1 service account identities mint for no one: system:serviceaccount:kube-system:default " +
		"(subject b): no k8s verifier lists namespace kube-system\n"
	if out.String() != want {
		t.Fatalf("%q", out.String())
	}
	out.Reset()
	cfg := k8sConfig()
	cfg.Broker.Identity.K8s = nil
	cfg.Broker.Identity.X509AnchorFile = "/a.pem"
	announceServiceAccountIdentities(&out, "port49d", cfg, pol)
	if !strings.Contains(out.String(), "2 service account identities mint for no one") ||
		!strings.Contains(out.String(), "no broker.identity.machines k8s verifier is configured") {
		t.Fatalf("%q", out.String())
	}
}

// A cluster changing its issuer is two verifiers on one jwks: each key set is
// told the other's issuer, so discovery naming either is not a mismatch; a
// verifier on another jwks, or an oidc one, is not one.
func TestAMigratingClustersKeySetsAreToldTheOtherIssuer(t *testing.T) {
	a := k8sConfig().Broker.Identity.K8s[0]
	m := a
	m.Issuer = "https://l69-a-new.port49.lab"
	other := a
	other.Cluster, other.Issuer, other.JWKS = "eu_west", "https://eu-west.port49.lab", "https://10.1.0.10:6443/openid/v1/jwks"
	ks := []oidc.VerifierConfig{a, m, other}
	if got := migrating(ks, a); len(got) != 1 || got[0] != m.Issuer {
		t.Fatalf("a: %v", got)
	}
	if got := migrating(ks, other); len(got) != 0 {
		t.Fatalf("other: %v", got)
	}
	if got := migrating(ks, oidc.VerifierConfig{Issuer: "https://idp.example.com"}); got != nil {
		t.Fatalf("oidc: %v", got)
	}
}
