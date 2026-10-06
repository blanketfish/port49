package config

import (
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/oidc"
)

// brokerWithIdentity is brokerBlock with client_ca_file replaced by an
// identity block.
func brokerWithIdentity(identity string) string {
	return strings.Replace(brokerBlock, "  client_ca_file: /etc/port49/clients-ca.pem\n", identity, 1)
}

const twoLists = `  identity:
    humans:
      - {type: x509, trust_anchor_file: /etc/port49/clients-ca.pem}
      - type: oidc
        issuer: https://sso.corp.example.com/realms/corp
        client_id: port49-cli
        principal_claim: email
        principal_domains: [Corp.Example.com, corp.example.com, eng.corp.example.com]
        scopes: [email]
    machines:
      - type: oidc
        issuer: https://sso.corp.example.com/realms/corp
        audience: "api://port49-svc"
        clients: [{client_id: oxidized, sub: 5f3c2d1e-0000-4000-8000-000000000049}]
`

func TestTheTwoListsLoad(t *testing.T) {
	c, err := loadWith(t, brokerWithIdentity(twoLists))
	if err != nil {
		t.Fatal(err)
	}
	id := c.Broker.Identity
	if id == nil || id.Shorthand || id.X509AnchorFile != "/etc/port49/clients-ca.pem" ||
		c.Broker.ClientCAFile != "/etc/port49/clients-ca.pem" || len(id.OIDC) != 2 || id.Timing != oidc.DefaultTiming {
		t.Fatalf("identity %+v", id)
	}
	h, m := id.OIDC[0], id.OIDC[1]
	if h.Domain != oidc.Humans || h.ClientID != "port49-cli" || h.PrincipalClaim != oidc.ClaimEmail ||
		strings.Join(h.PrincipalDomains, " ") != "corp.example.com eng.corp.example.com" ||
		strings.Join(h.Scopes, " ") != "openid email" || len(h.Algorithms) != 1 || h.Algorithms[0] != oidc.RS256 {
		t.Fatalf("human %+v: domains lower-cased, once each", h)
	}
	if m.Domain != oidc.Machines || m.Audience != "api://port49-svc" || m.PrincipalClaim != "" ||
		len(m.Clients) != 1 || m.Clients[0] != (oidc.MachineClient{ClientID: "oxidized", Sub: "5f3c2d1e-0000-4000-8000-000000000049"}) {
		t.Fatalf("machine %+v", m)
	}
}

// With no broker.identity, broker.client_ca_file is the one human verifier,
// exactly as before plan 7h.
func TestNoIdentityIsTheShorthand(t *testing.T) {
	c, err := loadWith(t, brokerBlock)
	if err != nil {
		t.Fatal(err)
	}
	if id := c.Broker.Identity; id == nil || !id.Shorthand || id.X509AnchorFile != "/etc/port49/clients-ca.pem" ||
		len(id.OIDC) != 0 {
		t.Fatalf("identity %+v", id)
	}
}

func TestAnOIDCOnlyBrokerLoadsWithoutCertificateStatus(t *testing.T) {
	block := `  identity:
    humans:
      - {type: oidc, issuer: "https://sso.corp.example.com/realms/corp", client_id: port49-cli,
         principal_claim: upn, principal_domains: [corp.example.com]}
`
	noStatus := strings.Replace(brokerWithIdentity(block), "  certificate_status: {disabled: true}\n", "", 1)
	c, err := loadWith(t, noStatus)
	if err != nil {
		t.Fatal(err)
	}
	if c.Broker.ClientCAFile != "" || c.Broker.CertificateStatus != nil || c.Broker.Identity.OIDC[0].PrincipalClaim != oidc.ClaimUPN {
		t.Fatalf("broker %+v identity %+v", c.Broker, c.Broker.Identity)
	}
	if _, err := loadWith(t, brokerWithIdentity(block)); err == nil ||
		!strings.Contains(err.Error(), "broker.certificate_status: no x509 verifier") {
		t.Fatalf("certificate_status on an OIDC-only broker: %v", err)
	}
}

func TestIdentityRefusals(t *testing.T) {
	iss := `issuer: "https://sso.corp.example.com/realms/corp"`
	// hum and mach are complete verifiers, so each case fails on the one
	// thing it names.
	hum := "type: oidc, " + iss + ", client_id: c, principal_claim: email, principal_domains: [corp.example.com]"
	mach := "type: oidc, " + iss + ", audience: a, clients: [{client_id: svc, sub: s1}]"
	other := `type: oidc, issuer: "https://contractor.example.net/realms/x", client_id: c, principal_claim: email`
	for name, c := range map[string]struct{ block, want string }{
		"client_ca_file beside identity": {strings.Replace(twoLists, "  identity:", "  client_ca_file: /etc/port49/clients-ca.pem\n  identity:", 1),
			"broker.client_ca_file: moved to broker.identity.humans[].trust_anchor_file"},
		"workload x509": {"  identity:\n    humans: [{type: x509, trust_anchor_file: /a.pem}]\n    machines: [{type: x509, trust_anchor_file: /b.pem}]\n",
			"broker.identity.machines[0]: type x509 (workload certificates) is plan 8's"},
		"k8s": {"  identity:\n    machines: [{type: k8s}]\n", "broker.identity.machines[0]: type k8s is plan 10's"},
		"two anchors": {"  identity:\n    humans: [{type: x509, trust_anchor_file: /a.pem}, {type: x509, trust_anchor_file: /b.pem}]\n",
			"broker.identity.humans: at most one x509 verifier"},
		"domains on an x509 verifier": {"  identity:\n    humans: [{type: x509, trust_anchor_file: /a.pem, principal_domains: [corp.example.com]}]\n",
			"broker.identity.humans[0]: type x509 takes trust_anchor_file alone"},
		"none": {"  identity:\n    humans: []\n", "broker.identity accepts no one"},
		"HS256": {"  identity:\n    humans: [{" + hum + ", algorithms: [HS256]}]\n",
			"broker.identity.humans[0].algorithms: HS256 is refused"},
		"none alg": {"  identity:\n    humans: [{" + hum + ", algorithms: [none]}]\n",
			"broker.identity.humans[0].algorithms: none is refused"},
		"http issuer": {"  identity:\n    humans: [{type: oidc, issuer: \"http://sso.example.com\", client_id: c}]\n",
			"broker.identity.humans[0].issuer"},
		"ca_file unreadable": {"  identity:\n    humans: [{" + hum + ", ca_file: /nonexistent/port49-idp-ca.pem}]\n",
			"broker.identity.humans[0].ca_file /nonexistent/port49-idp-ca.pem"},
		"no client_id": {"  identity:\n    humans: [{type: oidc, " + iss + "}]\n", "broker.identity.humans[0].client_id is required"},
		"audience on a human": {"  identity:\n    humans: [{type: oidc, " + iss + ", client_id: c, audience: a}]\n",
			"broker.identity.humans[0].audience"},
		"clients on a human": {"  identity:\n    humans: [{" + hum + ", clients: [{client_id: svc, sub: s1}]}]\n",
			"broker.identity.humans[0].clients is a machine verifier's"},
		"no principal_claim": {"  identity:\n    humans: [{type: oidc, " + iss + ", client_id: c, principal_domains: [corp.example.com]}]\n",
			"broker.identity.humans[0].principal_claim is required: one of preferred_username, email or upn"},
		"bad claim": {"  identity:\n    humans: [{type: oidc, " + iss + ", client_id: c, principal_claim: groups}]\n",
			"broker.identity.humans[0].principal_claim groups: one of preferred_username, email or upn"},
		"no principal_domains": {"  identity:\n    humans: [{type: oidc, " + iss + ", client_id: c, principal_claim: email}]\n",
			"broker.identity.humans[0].principal_domains is required"},
		"a domain with an @": {"  identity:\n    humans: [{type: oidc, " + iss + ", client_id: c, principal_claim: email, principal_domains: [a@corp.example.com]}]\n",
			"broker.identity.humans[0].principal_domains: a@corp.example.com is not a domain"},
		"domains overlap across issuers": {"  identity:\n    humans: [{" + hum + "}, {" + other + ", principal_domains: [Corp.Example.com]}]\n",
			"broker.identity.humans[1].principal_domains: corp.example.com is also broker.identity.humans[0]'s, at another issuer"},
		"two claims at one issuer": {"  identity:\n    humans: [{" + hum + "}, {type: oidc, " + iss + ", client_id: c2, principal_claim: upn, principal_domains: [corp.example.com]}]\n",
			"broker.identity.humans[1].principal_claim upn differs from broker.identity.humans[0]'s (email) at one issuer"},
		"client_id on a machine": {"  identity:\n    machines: [{type: oidc, " + iss + ", audience: a, client_id: c}]\n",
			"broker.identity.machines[0].client_id"},
		"domains on a machine": {"  identity:\n    machines: [{" + mach + ", principal_domains: [corp.example.com]}]\n",
			"broker.identity.machines[0].client_id, principal_claim, principal_domains and scopes are a human verifier's"},
		"no clients": {"  identity:\n    machines: [{type: oidc, " + iss + ", audience: a}]\n",
			"broker.identity.machines[0].clients is required"},
		"a client without its sub": {"  identity:\n    machines: [{type: oidc, " + iss + ", audience: a, clients: [{client_id: svc}]}]\n",
			"broker.identity.machines[0].clients[0].sub is required"},
		"one client at two issuers": {"  identity:\n    machines: [{" + mach + "}, {type: oidc, issuer: \"https://contractor.example.net/realms/x\", audience: a, clients: [{client_id: svc, sub: s9}]}]\n",
			"broker.identity.machines[1].clients: svc is also broker.identity.machines[0]'s, at another issuer"},
		"a client twice": {"  identity:\n    machines: [{type: oidc, " + iss + ", audience: a, clients: [{client_id: svc, sub: s1}, {client_id: svc, sub: s2}]}]\n",
			"broker.identity.machines[0].clients[1] repeats client_id svc"},
		"one key twice": {"  identity:\n    humans: [{" + hum + "}]\n    machines: [{type: oidc, " + iss + ", audience: c, clients: [{client_id: svc, sub: s1}]}]\n",
			"broker.identity.machines[0].audience c is broker.identity.humans[0]'s client_id"},
		"a verifier twice": {"  identity:\n    humans: [{" + hum + "}, {" + hum + "}]\n",
			"broker.identity.humans[1] repeats broker.identity.humans[0]"},
		"skew": {"  identity:\n    clock_skew: 10m\n    humans: [{" + hum + "}]\n",
			"broker.identity.clock_skew"},
		"max age under twice the refresh": {"  identity:\n    jwks_refresh_interval: 1h\n    jwks_max_age: 90m\n    humans: [{" + hum + "}]\n",
			"broker.identity.jwks_max_age 1h30m0s is under twice jwks_refresh_interval"},
		"empty client_id": {"  identity:\n    humans: [{type: oidc, " + iss + ", client_id: \"\", principal_claim: email, principal_domains: [corp.example.com]}]\n",
			"broker.identity.humans[0].client_id is required"},
		"blank client_id": {"  identity:\n    humans: [{type: oidc, " + iss + ", client_id: \"  \", principal_claim: email, principal_domains: [corp.example.com]}]\n",
			"broker.identity.humans[0].client_id is required"},
		"empty audience": {"  identity:\n    machines: [{type: oidc, " + iss + ", audience: \"\", clients: [{client_id: svc, sub: s1}]}]\n",
			"broker.identity.machines[0].audience is required"},
		"blank audience": {"  identity:\n    machines: [{type: oidc, " + iss + ", audience: \" \\t\", clients: [{client_id: svc, sub: s1}]}]\n",
			"broker.identity.machines[0].audience is required"},
		"empty sub": {"  identity:\n    machines: [{type: oidc, " + iss + ", audience: a, clients: [{client_id: svc, sub: \"\"}]}]\n",
			"broker.identity.machines[0].clients[0].sub is required"},
		"blank sub": {"  identity:\n    machines: [{type: oidc, " + iss + ", audience: a, clients: [{client_id: svc, sub: \"   \"}]}]\n",
			"broker.identity.machines[0].clients[0].sub is required"},
		"empty client client_id": {"  identity:\n    machines: [{type: oidc, " + iss + ", audience: a, clients: [{client_id: \"\", sub: s1}]}]\n",
			"broker.identity.machines[0].clients[0].client_id is required"},
		"blank client client_id": {"  identity:\n    machines: [{type: oidc, " + iss + ", audience: a, clients: [{client_id: \" \", sub: s1}]}]\n",
			"broker.identity.machines[0].clients[0].client_id is required"},
		// Task 6's logout acceptance names one verifier by (issuer, client_id):
		// two human verifiers of one issuer and one client_id are refused even
		// with different principal_domains.
		"humans at one issuer and client_id, other domains": {"  identity:\n    humans: [{" + hum + "}, {type: oidc, " + iss +
			", client_id: c, principal_claim: email, principal_domains: [eng.corp.example.com]}]\n",
			"broker.identity.humans[1] repeats broker.identity.humans[0]"},
		"unknown type": {"  identity:\n    humans: [{type: saml}]\n", "broker.identity.humans[0].type saml"},
	} {
		block := c.block
		cfg := brokerWithIdentity(block) // the client_ca_file case carries its own line in block
		if !strings.Contains(block, "x509") {
			cfg = strings.Replace(cfg, "  certificate_status: {disabled: true}\n", "", 1)
		}
		_, err := loadWith(t, cfg)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v; want %q", name, err, c.want)
		}
	}
}

func TestIdentityTimingDefaultsAndBounds(t *testing.T) {
	block := `  identity:
    clock_skew: 0s
    max_token_age: 1h
    jwks_refresh_interval: 30m
    jwks_max_age: 72h
    humans: [{type: oidc, issuer: "https://sso.corp.example.com/realms/corp", client_id: c, principal_claim: email,
              principal_domains: [corp.example.com], algorithms: [ES256, RS256]}]
`
	c, err := loadWith(t, strings.Replace(brokerWithIdentity(block), "  certificate_status: {disabled: true}\n", "", 1))
	if err != nil {
		t.Fatal(err)
	}
	want := oidc.Timing{ClockSkew: 0, MaxTokenAge: time.Hour, JWKSRefresh: 30 * time.Minute, JWKSMaxAge: 72 * time.Hour}
	if c.Broker.Identity.Timing != want || len(c.Broker.Identity.OIDC[0].Algorithms) != 2 {
		t.Fatalf("identity %+v", c.Broker.Identity)
	}
}

// An issuer's kept key file collides with no file another key names
// (pre-flight M-11): it sits beside revocations_file in port49d.
func TestAKeptKeyFileCollidesWithNothing(t *testing.T) {
	cfg := strings.Replace(brokerWithIdentity(twoLists), "/var/lib/port49/revocations.json",
		"/var/lib/port49/"+oidc.KeyFileName("https://sso.corp.example.com/realms/corp"), 1)
	if _, err := loadWith(t, cfg); err == nil || !strings.Contains(err.Error(), "kept keys") {
		t.Fatalf("a revocations_file that is an issuer's kept key file: %v", err)
	}
}
