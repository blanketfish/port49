package config

import (
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/directory"
	"github.com/rhwendt/port49/internal/testpki"
)

func writeTemp(t *testing.T, name string, body []byte) string { return write(t, name, string(body)) }

func testCAPEM(t *testing.T) []byte {
	t.Helper()
	ca, err := testpki.NewCA("directory test CA", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return ca.PEM()
}

func dur(d time.Duration) *time.Duration { return &d }

func dirYAML(t *testing.T) directoryYAML {
	t.Helper()
	ca := writeTemp(t, "ca.pem", testCAPEM(t))
	return directoryYAML{
		Servers: []serverYAML{
			{URI: "ldaps://dc-01.corp.example.com", Priority: 100, Site: "us-west"},
			{URI: "ldaps://dc-03.corp.example.com", Priority: 50, Site: "us-east"},
		},
		CAFile:             ca,
		Bind:               bindYAML{Mechanism: "simple", BindDN: "CN=port49,DC=corp", PasswordEnv: "PORT49_LDAP_PASSWORD"},
		BaseDN:             "DC=corp,DC=example,DC=com",
		CertificateMapping: mappingYAML{Kind: "issuer_serial"},
		NestedGroups:       "in_chain",
	}
}

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

// The defaults of Rulings 6–10 and 20, and the site from the environment
// (design §10: "derive its own site from the environment").
func TestDirectoryDefaults(t *testing.T) {
	d, err := checkDirectory(dirYAML(t), env(map[string]string{"PORT49_SITE": "us-west", "PORT49_LDAP_PASSWORD": "x"}))
	if err != nil {
		t.Fatal(err)
	}
	if d.Site != "us-west" || d.SiteFrom != "PORT49_SITE" || d.GroupsBaseDN != d.BaseDN ||
		d.PrincipalAttribute != "userPrincipalName" || d.UsernameAttribute != "sAMAccountName" ||
		d.GroupNameAttribute != "cn" || d.MemberAttribute != "member" || d.Mapping.Attribute != "altSecurityIdentities" ||
		d.MaxDepth != 16 || d.QueryTimeout != 5*time.Second || d.HealthInterval != 30*time.Second ||
		d.HealthTimeout != 2*time.Second || d.FailureThreshold != 3 || d.ProbeInterval != time.Minute ||
		d.StabilityWindow != 5*time.Minute || d.Grace != 4*time.Hour || d.PrewarmInterval != time.Hour ||
		d.PrewarmMax != 10000 || d.UserFilter != "(objectClass=person)" {
		t.Fatalf("%+v", d)
	}
}

func TestDirectoryRefusals(t *testing.T) {
	for _, c := range []struct {
		name string
		edit func(*directoryYAML)
		want string
	}{
		{"no nested_groups", func(d *directoryYAML) { d.NestedGroups = "" },
			"broker.directory.nested_groups is required: in_chain (Active Directory), recursive (port49 walks member) or direct (the groups are flat); design §10"},
		{"a weak mapping without opt-in", func(d *directoryYAML) { d.CertificateMapping = mappingYAML{Kind: "san_email"} },
			"broker.directory.certificate_mapping.kind san_email is a weak mapping: set allow_weak: true and list the issuers it is pinned to (design §7)"},
		{"a weak mapping with no issuers", func(d *directoryYAML) {
			d.CertificateMapping = mappingYAML{Kind: "san_upn", AllowWeak: true}
		}, "certificate_mapping.issuers"},
		{"plain LDAP", func(d *directoryYAML) { d.Servers[0].URI = "ldap://dc-01:389" },
			"broker.directory.servers[0].uri ldap://dc-01:389: plain LDAP is refused; use ldaps:// or set start_tls: true"},
		{"no bind mechanism", func(d *directoryYAML) { d.Bind = bindYAML{} },
			"broker.directory.bind.mechanism is required: external, gssapi or simple"},
		{"a simple bind with no password in the environment", func(d *directoryYAML) { d.Bind.PasswordEnv = "UNSET_VAR" },
			"broker.directory.bind.password_env UNSET_VAR is not set"},
		{"an unknown kind", func(d *directoryYAML) { d.CertificateMapping.Kind = "email" },
			"broker.directory.certificate_mapping.kind email: one of issuer_serial, sid, san_upn, san_email, subject_dn, cn"},
		{"grace too long", func(d *directoryYAML) { d.Grace = dur(25 * time.Hour) },
			"broker.directory.grace 25h0m0s: must be 0s to 24h"},
		{"a timeout above its interval", func(d *directoryYAML) {
			d.HealthCheck = &healthYAML{Interval: 10 * time.Second, Timeout: 20 * time.Second}
		}, "broker.directory.health_check.timeout 20s: must be at most health_check.interval (10s)"},
		{"no servers", func(d *directoryYAML) { d.Servers = nil }, "broker.directory.servers: list at least one"},
		{"no base", func(d *directoryYAML) { d.BaseDN = "" }, "broker.directory.base_dn is required"},
		{"a negative depth under recursive", func(d *directoryYAML) { d.NestedGroups = "recursive"; d.MaxDepth = -1 },
			"broker.directory.max_depth -1: must be 1 to 64"},
		{"a user_filter that does not compile", func(d *directoryYAML) { d.UserFilter = "(objectClass=person" },
			`broker.directory.user_filter "(objectClass=person": `},
		{"a group_filter that does not compile", func(d *directoryYAML) { d.GroupFilter = "objectClass=group" },
			`broker.directory.group_filter "objectClass=group": `},
		{"an attribute that is no descriptor", func(d *directoryYAML) { d.PrincipalAttribute = "mail)(uid=*" },
			`broker.directory.principal_attribute "mail)(uid=*": not an attribute descriptor`},
		{"a strong kind repointed without opt-in", func(d *directoryYAML) {
			d.CertificateMapping = mappingYAML{Kind: "sid", Attribute: "description"}
		}, "broker.directory.certificate_mapping.attribute description: repointing sid makes it as strong as description; " +
			"set allow_weak: true and list the issuers it is pinned to (design §7)"},
		{"a strong kind repointed with opt-in and no issuers", func(d *directoryYAML) {
			d.CertificateMapping = mappingYAML{Kind: "issuer_serial", Attribute: "description", AllowWeak: true}
		}, "certificate_mapping.issuers"},
	} {
		t.Run(c.name, func(t *testing.T) {
			d := dirYAML(t)
			c.edit(&d)
			_, err := checkDirectory(d, env(map[string]string{"PORT49_LDAP_PASSWORD": "x"}))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("%v, want %q", err, c.want)
			}
		})
	}
}

// Each kind's default attribute (Ruling 1), and the weak kinds' pin parsed
// as DNs, so a pin with a typo is a load error, not a pin nothing matches.
func TestMappingKindsAndPins(t *testing.T) {
	for kind, attr := range map[string]string{"issuer_serial": "altSecurityIdentities", "sid": "objectSid",
		"san_upn": "userPrincipalName", "san_email": "mail", "subject_dn": "distinguishedName", "cn": "cn"} {
		d := dirYAML(t)
		d.CertificateMapping = mappingYAML{Kind: kind, AllowWeak: true, Issuers: []string{"CN=Corp Users CA,O=Example"}}
		got, err := checkDirectory(d, env(map[string]string{"PORT49_LDAP_PASSWORD": "x"}))
		if err != nil || got.Mapping.Attribute != attr || got.Mapping.Kind.Strong() != (kind == "issuer_serial" || kind == "sid") {
			t.Errorf("%s: %+v %v", kind, got, err)
		}
	}
	d := dirYAML(t)
	d.CertificateMapping = mappingYAML{Kind: "cn", AllowWeak: true, Issuers: []string{"not a dn"}}
	if _, err := checkDirectory(d, env(map[string]string{"PORT49_LDAP_PASSWORD": "x"})); err == nil ||
		!strings.Contains(err.Error(), `broker.directory.certificate_mapping.issuers[0] "not a dn"`) {
		t.Fatalf("%v", err)
	}
}

// A pin that is a DN but names an attribute type no pin can match is a load
// error (directory.ValidPin), not a pin that refuses every certificate.
func TestAnIssuerPinNoCertificateCanMatchIsRefused(t *testing.T) {
	d := dirYAML(t)
	d.CertificateMapping = mappingYAML{Kind: "cn", AllowWeak: true, Issuers: []string{"SERIALNUMBER=1,DC=corp"}}
	if _, err := checkDirectory(d, env(map[string]string{"PORT49_LDAP_PASSWORD": "x"})); err == nil ||
		!strings.Contains(err.Error(), `broker.directory.certificate_mapping.issuers[0] "SERIALNUMBER=1,DC=corp"`) {
		t.Fatalf("%v", err)
	}
}

// broker.refresh_interval: 5m by default, 1m to 1h (Ruling 12).
func TestRefreshIntervalBounds(t *testing.T) {
	for _, c := range []struct {
		in   time.Duration
		want time.Duration
		err  string
	}{{0, 5 * time.Minute, ""}, {time.Minute, time.Minute, ""}, {30 * time.Second, 0, "broker.refresh_interval 30s: must be 1m to 1h"},
		{2 * time.Hour, 0, "broker.refresh_interval 2h0m0s: must be 1m to 1h"}} {
		got, err := refreshInterval(c.in)
		if c.err != "" {
			if err == nil || !strings.Contains(err.Error(), c.err) {
				t.Errorf("%v: %v", c.in, err)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("%v: %v %v", c.in, got, err)
		}
	}
}

// A server uri carrying userinfo is refused before any other uri check, and
// no uri error prints the userinfo (plan 7g, PF7g-c): credentials belong in
// bind, read from a secret, never in a line an operator pastes into a ticket.
func TestServerURICredentialsAreRefusedAndNeverPrinted(t *testing.T) {
	const want = "config: broker.directory.servers[1].uri: credentials in the URI are refused; use broker.directory.bind"
	for _, uri := range []string{
		"ldaps://svc:hunter2secret@dc-01.corp.example.com",
		"ldaps://hunter2secret@dc-01.corp.example.com",
		"ldap://svc:hunter2secret@dc-01:389", // would also be plain LDAP
		"ldaps://svc:hunter2secret@",         // no host
		"ldaps://svc:hunter2secret@dc 01",    // does not parse
		"http://svc:hunter2secret@dc-01",     // wrong scheme
		"ldaps:svc:hunter2secret@dc-01",      // opaque, no //
	} {
		d := dirYAML(t)
		d.Servers[1].URI = uri
		_, err := checkDirectory(d, env(map[string]string{"PORT49_LDAP_PASSWORD": "x"}))
		if err == nil || err.Error() != want {
			t.Errorf("%q: %v", uri, err)
		}
		if err != nil && strings.Contains(err.Error(), "hunter2secret") {
			t.Errorf("%q: the error prints the secret: %v", uri, err)
		}
	}
	// The other uri errors still name the (userinfo-free) URI.
	d := dirYAML(t)
	d.Servers[0].URI = "ldap://dc-01:389"
	if _, err := checkDirectory(d, env(map[string]string{"PORT49_LDAP_PASSWORD": "x"})); err == nil ||
		!strings.Contains(err.Error(), "ldap://dc-01:389") {
		t.Fatalf("%v", err)
	}
}

var _ = directory.MapCN

// The site is logged as auth.directory.site, so it may never be read from the
// variable that holds the bind password.
func TestSiteEnvIsNotThePasswordEnv(t *testing.T) {
	for _, siteEnv := range []string{"PORT49_LDAP_PASSWORD", ""} {
		d := dirYAML(t)
		d.SiteEnv = siteEnv
		if siteEnv == "" {
			d.Bind.PasswordEnv = "PORT49_SITE"
		}
		_, err := checkDirectory(d, env(map[string]string{"PORT49_LDAP_PASSWORD": "hunter2secret", "PORT49_SITE": "hunter2secret"}))
		if err == nil || !strings.Contains(err.Error(), "is also bind.password_env") || strings.Contains(err.Error(), "hunter2secret") {
			t.Errorf("site_env %q: %v", siteEnv, err)
		}
	}
}

// A bind's key and keytab are checked at load: a missing file stops the
// start, not the first bind.
func TestBindFilesAreCheckedAtLoad(t *testing.T) {
	ok := writeTemp(t, "f", []byte("x"))
	for _, c := range []struct {
		name string
		bind bindYAML
		want string
	}{
		{"external cert", bindYAML{Mechanism: "external", TLSCertFile: "/nonexistent/c.pem", TLSKeyFile: ok}, "broker.directory.bind.tls_cert_file"},
		{"external key", bindYAML{Mechanism: "external", TLSCertFile: ok, TLSKeyFile: "/nonexistent/k.pem"}, "broker.directory.bind.tls_key_file"},
		{"gssapi keytab", bindYAML{Mechanism: "gssapi", KeytabFile: "/nonexistent/kt", Principal: "p@R", KRB5Conf: ok}, "broker.directory.bind.keytab_file"},
	} {
		d := dirYAML(t)
		d.Bind = c.bind
		if _, err := checkDirectory(d, env(nil)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	d := dirYAML(t)
	d.Bind = bindYAML{Mechanism: "external", TLSCertFile: ok, TLSKeyFile: ok}
	if _, err := checkDirectory(d, env(nil)); err != nil {
		t.Fatal(err)
	}
}

// broker.directory through Load, the whole path from YAML to Broker.Directory.
func TestALoadedBrokerResolvesItsDirectory(t *testing.T) {
	ca := writeTemp(t, "ca.pem", testCAPEM(t))
	t.Setenv("PORT49_LDAP_PASSWORD", "x")
	c, err := loadWith(t, strings.Replace(brokerBlock, "  certificate_status: {disabled: true}\n", `  certificate_status: {disabled: true}
  refresh_interval: 10m
  directory:
    servers:
      - {uri: "ldaps://dc-01.corp.example.com", priority: 100}
    ca_file: `+ca+`
    bind: {mechanism: simple, bind_dn: "CN=port49,DC=corp", password_env: PORT49_LDAP_PASSWORD}
    base_dn: "DC=corp,DC=example,DC=com"
    certificate_mapping: {kind: issuer_serial}
    nested_groups: in_chain
`, 1))
	if err != nil {
		t.Fatal(err)
	}
	if b := c.Broker; b == nil || b.Directory == nil || b.RefreshInterval != 10*time.Minute ||
		b.Directory.Grace != defaultGrace || b.Directory.Nested != directory.Nested("in_chain") ||
		len(b.Directory.Servers) != 1 {
		t.Fatalf("%+v", c.Broker)
	}
}

// Two servers that share a host:port would share one metric label and one
// selection gauge: refused at load.
func TestServersSharingAHostPortAreRefused(t *testing.T) {
	d := dirYAML(t)
	d.Servers[1].URI = d.Servers[0].URI + "/"
	if _, err := checkDirectory(d, env(map[string]string{"PORT49_LDAP_PASSWORD": "x"})); err == nil ||
		!strings.Contains(err.Error(), "servers[1]") || !strings.Contains(err.Error(), "same host:port") {
		t.Fatalf("%v", err)
	}
}
