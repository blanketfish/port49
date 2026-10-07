package port49d

import (
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/oidc"
	"github.com/rhwendt/port49/internal/oidc/oidctest"
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
