package config

import (
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/blanketfish/port49/internal/directory"
	"github.com/blanketfish/port49/internal/oidc"
)

// A key whose description names the values it takes must name the values the loader takes. Each entry
// is one such key of port49d.yaml: accept is the set (a constant of the loader's package, or a literal
// that the loader's own check is asked about), and others are the backticked words that are not
// values. internal/docgen/enums_test.go does the same for the other four files; it cannot reach the
// loader's unexported checks, so this half lives here.
type portEnum struct {
	key    string
	accept []string
	others []string
	// takes asks the loader's check about v; nil when accept comes from constants alone.
	takes func(t *testing.T, v string) bool
}

// unless is "the loader took v": no error, or an error that is not the one a value it does not know gets.
func unless(err error, marker string) bool {
	return err == nil || !strings.Contains(err.Error(), marker)
}

var enumBackticked = regexp.MustCompile("`([A-Za-z][A-Za-z0-9_-]*)`")

func status(onUnavailable, hash string) error {
	cs := &CertificateStatusConfig{OnUnavailable: onUnavailable,
		OCSP: &CertificateStatusOCSP{UseAIA: true, Hash: hash}}
	return checkStatusBlock(cs, "tls_listener.certificate_status", "", nil)
}

func portEnums() []portEnum {
	statusOnUnavailable := func(t *testing.T, v string) bool { return unless(status(v, ""), "on_unavailable must be") }
	return []portEnum{
		{key: "tls_listener.device_identity.match", accept: []string{"dns_name", "ip_address"},
			takes: func(t *testing.T, v string) bool {
				_, err := Load(tlsBase(t, "listen: 127.0.0.1:0\n", tlsMinimal+"  device_identity: {match: ["+v+"]}\n"))
				return err == nil
			}},
		{key: "tls_listener.certificate_status.on_unavailable", accept: []string{"refuse", "allow"}, takes: statusOnUnavailable},
		{key: "broker.certificate_status.on_unavailable", accept: []string{"refuse", "allow"}, takes: statusOnUnavailable},
		{key: "tls_listener.certificate_status.ocsp.hash", accept: []string{"sha256", "sha1"},
			takes: func(t *testing.T, v string) bool { return unless(status("", v), "ocsp.hash must be") }},
		{key: "stores.directory.backend", accept: []string{BackendMemory, BackendEtcd},
			takes: storeBackend},
		{key: "stores.session.backend", accept: []string{BackendMemory, BackendEtcd},
			takes: storeBackend},
		{key: "broker.identity.humans.[].type", accept: []string{"x509", "oidc", "directory_password", "k8s"},
			others: []string{"humans", "machines"}, takes: identityType},
		{key: "broker.identity.machines.[].type", accept: []string{"x509", "oidc", "directory_password", "k8s"},
			others: []string{"humans", "machines"}, takes: identityType},
		{key: "broker.identity.humans.[].principal_claim",
			accept: []string{oidc.ClaimPreferredUsername, oidc.ClaimEmail, oidc.ClaimUPN}, others: []string{"oidc", "humans"},
			takes: func(t *testing.T, v string) bool {
				_, err := checkOIDCVerifier("broker.identity.humans[0]", oidc.Humans, identityVerifierYAML{Type: "oidc",
					Issuer: "https://sso.example.com/realms/corp", ClientID: "c", PrincipalClaim: v,
					PrincipalDomains: []string{"corp.example.com"}})
				return unless(err, "principal_claim \"")
			}},
		{key: "broker.identity.humans.[].algorithms",
			accept: []string{string(oidc.RS256), string(oidc.PS256), string(oidc.ES256), string(oidc.ES384), string(oidc.EdDSA)},
			others: []string{"oidc", "k8s", "none", "HS"},
			takes: func(t *testing.T, v string) bool {
				_, err := oidc.ParseAlgs([]string{v})
				return err == nil
			}},
		{key: "broker.identity.humans.[].directory.kind", accept: []string{string(directory.MapSPIFFEID)},
			others: []string{"x509", "machines"}},
		{key: "broker.directory.certificate_mapping.kind", accept: kindNames(), others: []string{"allow_weak", "issuers"},
			takes: func(t *testing.T, v string) bool {
				_, err := checkMapping(mappingYAML{Kind: v})
				return unless(err, "one of ")
			}},
		{key: "broker.directory.bind.mechanism", accept: []string{"external", "gssapi", "simple"},
			takes: func(t *testing.T, v string) bool {
				_, err := checkBind(bindYAML{Mechanism: v})
				return unless(err, "mechanism \"")
			}},
	}
}

func kindNames() []string {
	var out []string
	for _, k := range directory.Kinds {
		out = append(out, string(k))
	}
	return out
}

func storeBackend(t *testing.T, v string) bool {
	_, err := checkStoreShape("stores.directory", storeYAML{Backend: v}, false)
	return unless(err, "must be memory or etcd")
}

func identityType(t *testing.T, v string) bool {
	_, err := checkIdentity(&identityYAML{Humans: []identityVerifierYAML{{Type: v}}}, "")
	return unless(err, "one of x509, oidc, k8s or directory_password")
}

func TestPort49dEnumeratedValuesAreTheLoadersValues(t *testing.T) {
	raw, err := os.ReadFile(descriptionsFile)
	if err != nil {
		t.Fatal(err)
	}
	desc := map[string]string{}
	if err := yaml.Unmarshal(raw, &desc); err != nil {
		t.Fatal(err)
	}
	for _, e := range portEnums() {
		d, ok := desc[e.key]
		if !ok {
			t.Errorf("%s: no description", e.key)
			continue
		}
		if e.takes != nil {
			for _, v := range e.accept {
				if !e.takes(t, v) {
					t.Errorf("%s: the loader refuses %q, which the test lists as accepted", e.key, v)
				}
			}
			if e.takes(t, "zz_not_a_value") {
				t.Errorf("%s: the loader takes a value that is none, so the probe proves nothing", e.key)
			}
		}
		var named []string
		for _, m := range enumBackticked.FindAllStringSubmatch(d, -1) {
			named = append(named, m[1])
		}
		for _, v := range e.accept {
			if !slices.Contains(named, v) {
				t.Errorf("%s: the description does not name `%s`", e.key, v)
			}
		}
		var stray []string
		for _, w := range named {
			if !slices.Contains(e.accept, w) && !slices.Contains(e.others, w) {
				stray = append(stray, w)
			}
		}
		sort.Strings(stray)
		if len(stray) > 0 {
			t.Errorf("%s: the description names %s, which the loader does not take (accepted: %s)", e.key,
				strings.Join(stray, ", "), strings.Join(e.accept, ", "))
		}
	}
}
