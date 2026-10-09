package config

import (
	"slices"
	"strings"
	"testing"
)

const mappedLists = `  identity:
    humans:
      - {type: x509, trust_anchor_file: /etc/port49/clients-ca.pem}
    machines:
      - type: x509
        trust_anchor_file: /etc/port49/workloads-ca.pem
        spiffe_trust_domains: [corp.example.com]
        directory:
          kind: spiffe_id
          attribute: uid
          allow_weak: true
          issuers: ["CN=Workloads Issuing CA,O=Corp"]
`

// withDirectoryBlock is cfg with a minimal broker.directory after
// certificate_status.
func withDirectoryBlock(t *testing.T, cfg string) string {
	t.Helper()
	ca := writeTemp(t, "ca.pem", testCAPEM(t))
	t.Setenv("PORT49_LDAP_PASSWORD", "x")
	return strings.Replace(cfg, "  certificate_status: {disabled: true}\n", `  certificate_status: {disabled: true}
  directory:
    servers:
      - {uri: "ldaps://dc-01.corp.example.com", priority: 100}
    ca_file: `+ca+`
    bind: {mechanism: simple, bind_dn: "CN=port49,DC=corp", password_env: PORT49_LDAP_PASSWORD}
    base_dn: "DC=corp,DC=example,DC=com"
    certificate_mapping: {kind: issuer_serial}
    nested_groups: in_chain
`, 1)
}

// The block resolves into broker.directory's Workload (decision 41 rulings 1
// and 2): user_filter defaults to broker.directory's, and the trust domains
// are the verifier's.
func TestAWorkloadDirectoryLoads(t *testing.T) {
	c, err := loadWith(t, withDirectoryBlock(t, brokerWithIdentity(mappedLists)))
	if err != nil {
		t.Fatal(err)
	}
	w := c.Broker.Directory.Workload
	if w == nil || w.Attribute != "uid" || !slices.Equal(w.Issuers, []string{"CN=Workloads Issuing CA,O=Corp"}) ||
		w.UserFilter != "(objectClass=person)" || !slices.Equal(w.TrustDomains, []string{"corp.example.com"}) {
		t.Fatalf("%+v", w)
	}
	own := strings.Replace(mappedLists, "          attribute: uid\n", "          attribute: uid\n          user_filter: \"(objectClass=user)\"\n", 1)
	c, err = loadWith(t, withDirectoryBlock(t, brokerWithIdentity(own)))
	if err != nil || c.Broker.Directory.Workload.UserFilter != "(objectClass=user)" {
		t.Fatalf("its own user_filter: %v", err)
	}
	// Without the block, no workload is mapped: plan 8's behaviour.
	plain := strings.Split(mappedLists, "        directory:\n")[0]
	c, err = loadWith(t, withDirectoryBlock(t, brokerWithIdentity(plain)))
	if err != nil || c.Broker.Directory.Workload != nil {
		t.Fatalf("no block: %+v %v", c.Broker.Directory, err)
	}
}

func TestWorkloadDirectoryRefusals(t *testing.T) {
	edit := func(old, new string) string { return strings.Replace(mappedLists, old, new, 1) }
	for name, c := range map[string]struct {
		lists string
		dir   bool
		want  string
	}{
		"no broker.directory": {mappedLists, false,
			"broker.identity.machines[].directory maps workload certificates through broker.directory, which is not configured"},
		"no kind":    {edit("          kind: spiffe_id\n", ""), true, `broker.identity.machines[].directory.kind "": spiffe_id`},
		"other kind": {edit("kind: spiffe_id", "kind: issuer_serial"), true, `directory.kind "issuer_serial": spiffe_id`},
		"no attribute": {edit("          attribute: uid\n", ""), true,
			"broker.identity.machines[].directory.attribute is required: no schema has one for a SPIFFE ID"},
		"a bad attribute": {edit("attribute: uid", "attribute: \"u id\""), true, "not an attribute descriptor"},
		"not weak":        {edit("          allow_weak: true\n", ""), true, "spiffe_id is a weak mapping: set allow_weak: true"},
		"no issuers": {edit("          issuers: [\"CN=Workloads Issuing CA,O=Corp\"]\n", ""), true,
			"directory.issuers: a weak mapping is pinned to its issuers"},
		"a bad pin": {edit("CN=Workloads Issuing CA,O=Corp", "no equals sign"), true, "is not an RFC 4514 DN"},
		"a pin naming a type no pin matches": {edit("CN=Workloads Issuing CA,O=Corp", "favouriteColour=Blue,O=Corp"),
			true, "is not an RFC 4514 DN"},
		"a bad user_filter": {edit("          attribute: uid\n", "          attribute: uid\n          user_filter: \"(objectClass=user\"\n"),
			true, "directory.user_filter"},
		"on a human x509": {"  identity:\n    humans: [{type: x509, trust_anchor_file: /a.pem, directory: {kind: spiffe_id}}]\n",
			true, "broker.identity.humans[0]: type x509 takes trust_anchor_file alone"},
		"on an oidc verifier": {"  identity:\n    machines: [{type: oidc, issuer: \"https://sso.corp.example.com/realms/corp\", audience: a, clients: [{client_id: svc, sub: s1}], directory: {kind: spiffe_id}}]\n",
			true, "broker.identity.machines[0].directory is an x509 machine verifier's"},
	} {
		cfg := brokerWithIdentity(c.lists)
		if c.dir {
			cfg = withDirectoryBlock(t, cfg)
		}
		if _, err := loadWith(t, cfg); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want %q", name, err, c.want)
		}
	}
}

// spiffe_id is a workload's mapping, never a person's (decision 38 ruling 1
// amended by decision 41 ruling 2).
func TestSPIFFEIDIsNoPersonsMapping(t *testing.T) {
	_, err := checkMapping(mappingYAML{Kind: "spiffe_id", AllowWeak: true, Issuers: []string{"CN=X"}})
	if err == nil || !strings.Contains(err.Error(), "spiffe_id is a workload certificate's mapping: set it under "+
		"broker.identity.machines[].directory") {
		t.Fatalf("%v", err)
	}
}
