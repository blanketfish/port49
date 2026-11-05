package policy

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/blanketfish/port49/internal/admission"
	"github.com/blanketfish/port49/internal/platform"
)

// inventory is the devices the policy tests load against: one of each
// shipped platform with a command path, and an SRX, with the attributes spec
// §11's scopes read.
func inventory() []admission.Device {
	dev := func(name, platform, addr string, attrs map[string]string) admission.Device {
		return admission.Device{Name: name, Platform: platform, Addresses: []netip.Addr{netip.MustParseAddr(addr)},
			Attributes: attrs}
	}
	return []admission.Device{
		dev("leaf-01", "arista_eos", "10.0.1.1", map[string]string{"site": "dc1", "role": "leaf"}),
		dev("campus-sw-7", "arista_eos", "10.0.2.7", map[string]string{"site": "campus"}),
		dev("nx-01", "cisco_nxos", "10.0.3.1", map[string]string{"site": "dc2", "role": "spine"}),
		dev("xe-01", "cisco_iosxe", "10.0.4.1", map[string]string{"site": "campus"}),
		dev("srx-fw-04", "juniper_junos", "10.0.5.4", map[string]string{"site": "edge", "os_version": "21.4R3-S4"}),
		dev("srx-fw-05", "juniper_junos", "10.0.5.5", map[string]string{"site": "edge", "os_version": "22.2R1"}),
		dev("srx-fw-22", "juniper_junos", "10.0.5.22", map[string]string{"site": "edge", "os_version": "21.4X75-D40"}),
		dev("srx-lab-01", "juniper_junos", "10.0.5.99", map[string]string{"site": "lab"}),
	}
}

// env is the test environment, its joint checks fixed at noon: a test never
// reads the wall clock, or the corpus grant that expires 2026-12-01 would
// change the answers after that day.
func env() Env { return Env{Now: noon, Devices: inventory()} }

func mustParse(t *testing.T, body string) *Policy {
	t.Helper()
	p, err := Parse([]byte(body), env())
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// unmappedLevel declares a level, between operator and admin, that no
// built-in platform renders or numbers: a role landing a session there
// quarantines every device whose platform renders levels — arista_eos,
// cisco_nxos and cisco_iosxe since plan 5 — and a ceiling naming it loads
// nowhere. juniper_junos renders no level, and a projected set gives that
// subject alone the fail-closed reply there (decision 26), so its devices are
// the tests' devices that still mint.
const unmappedLevel = "privilege_levels: [{name: readonly}, {name: operator}, {name: unmapped}, {name: admin}]\n"

// good is spec §11's shape, cut to what every platform in inventory() can
// render with the built-in adapters.
const good = `
scopes:
  - {name: all_devices, match: {}}
  - {name: dc_fabric, match: {site: [dc1, dc2], role: [leaf, spine]}}
roles:
  - {name: read_only, privilege: readonly, permit: [show **, terminal length *]}
  - {name: network_admin, privilege: admin, permit: ["**"], pipe: {permit: ["**"]}}
  - {name: no_disruptive, deny: [reload **, write erase **]}
subjects:
  - {name: netops_admins, group: "CN=netops-admins,OU=Groups,DC=example,DC=com", enable: token, token_ttl: 60s}
  - {name: alice, identity: "user:alice@example.com", username: alice, enable: token, token_ttl: 60s}
  - {name: svc_oxidized, identity: ["system:serviceaccount:netops:oxidized", "spiffe://port49/host/oxidized-01"],
     username: svc-config-backup, token_ttl: 900s, api: [sync]}
grants:
  - {subject: netops_admins, scope: all_devices, roles: [network_admin], max_privilege: admin}
  - {subject: alice, scope: all_devices, roles: [read_only, no_disruptive], expires: 2026-12-01}
  - {subject: svc_oxidized, scope: all_devices, roles: [read_only]}
tests:
  - {subject: alice, device: leaf-01, command: "show version", expect: permit}
`

func TestAGoodPolicyLoads(t *testing.T) {
	p := mustParse(t, good)
	if !strings.HasPrefix(p.Bundle, "sha256:") {
		t.Fatalf("the bundle names the file: %q", p.Bundle)
	}
	for id, want := range map[string]string{"user:alice@example.com": "alice",
		"system:serviceaccount:netops:oxidized": "svc_oxidized", "spiffe://port49/host/oxidized-01": "svc_oxidized"} {
		if got, ok := p.SubjectOf(id); !ok || got != want {
			t.Errorf("SubjectOf(%q) = %q %v, want %q", id, got, ok, want)
		}
	}
	if _, ok := p.SubjectOf("CN=netops-admins,OU=Groups,DC=example,DC=com"); ok {
		t.Error("a group is matched through the directory, never as an identity")
	}
	s, _ := p.Subject("svc_oxidized")
	if s.Domain != "machines" || s.Enable != "none" {
		t.Errorf("svc_oxidized: domain %q enable %q", s.Domain, s.Enable)
	}
	if g, _ := p.Subject("netops_admins"); g.Domain != "humans" {
		t.Errorf("a group's members are people: %q", g.Domain)
	}
	if gs := p.Grants("alice"); len(gs) != 1 || gs[0].Expires.Format("2006-01-02T15:04Z07:00") != "2026-12-01T00:00Z" {
		t.Errorf("a date expires at the start of its day, UTC: %+v", gs)
	}
	if r := p.roles["network_admin"]; len(r.Pipe) != 1 || p.roles["read_only"].Pipe != nil {
		t.Error("a declared pipe list replaces the default; an absent one inherits it")
	}
	if len(p.Tests()) != 1 {
		t.Errorf("tests: %+v", p.Tests())
	}
}

// Load names the file on every error, and reads the same bytes Parse does.
func TestLoadNamesTheFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte("subjects: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path, env()); err == nil || !strings.Contains(err.Error(), path) {
		t.Fatalf("Load = %v, want an error naming %s", err, path)
	}
}

const roleOK = "roles:\n  - {name: r, privilege: admin, permit: [\"**\"]}\n"
const scopeOK = "scopes:\n  - {name: all_devices, match: {}}\n"
const subjOK = "subjects:\n  - {name: s, identity: [\"user:a@example.com\"], username: a, token_ttl: 60s}\n"
const grantOK = "grants:\n  - {subject: s, scope: all_devices, roles: [r]}\n"

// A role's max_session_age is a duration of at least a minute, or never;
// anything else refuses the policy, naming the role (spec §5.6; decision 33).
func TestARolesMaxSessionAgeIsADurationOrNever(t *testing.T) {
	base := "scopes: [{name: all_devices, match: {}}]\n" +
		"subjects: [{name: s, identity: [\"user:a@example.com\"], username: a, token_ttl: 60s}]\n" +
		"grants: [{subject: s, scope: all_devices, roles: [r]}]\n"
	for value, ok := range map[string]bool{"8h": true, "never": true, "1m": true, "30s": false, "soon": false,
		"\"\"": false, "-1h": false} {
		_, err := Parse([]byte(base+"roles: [{name: r, privilege: admin, permit: [\"**\"], max_session_age: "+value+"}]\n"), env())
		if ok != (err == nil) {
			t.Errorf("max_session_age %s: %v", value, err)
		}
		if err != nil && !strings.Contains(err.Error(), `role "r"`) {
			t.Errorf("%s: the refusal names no role: %v", value, err)
		}
	}
}

// Every refusal names what is wrong and, where another plan owns the key, which
// plan lifts it.
func TestLoadRefusesByName(t *testing.T) {
	for _, tt := range []struct{ name, yaml, want string }{
		{"a platform set this binary does not ship", "platform_set: 1.4.0\n" + roleOK + subjOK, "it ships 1.0.0"},
		{"a null max_session_age", "roles:\n  - {name: r, max_session_age: null}\n" + subjOK, `role "r": max_session_age is null`},
		{"an unknown key", scopeOK + roleOK + subjOK + "gratns: []\n", "line 7: an unknown field in type policy.file"},
		{"an acknowledgment of two shapes", scopeOK + roleOK + subjOK +
			"acknowledge: [{role: r, rule: x, platform: arista_eos, field: supports, reason: y}]\n", "one of the two"},
		{"an acknowledgment of no adapter key", scopeOK + roleOK + subjOK +
			"acknowledge: [{platform: arista_eos, field: suports, reason: y}]\n", "field is one of an adapter's keys"},
		{"an adapter acknowledgment with no digest", scopeOK + roleOK + subjOK +
			"acknowledge: [{platform: arista_eos, field: supports, reason: y}]\n", "sha256 is required"},
		{"an adapter acknowledgment with a short digest", scopeOK + roleOK + subjOK +
			"acknowledge: [{platform: arista_eos, field: supports, sha256: abc123, reason: y}]\n", "sha256 is required"},
		{"a deny acknowledgment with a digest", scopeOK + roleOK + subjOK + "acknowledge: [{role: r, rule: x, sha256: " +
			strings.Repeat("0", 64) + ", reason: y}]\n", "one of the two"},
		{"a second document", scopeOK + roleOK + subjOK + grantOK + "---\nscopes: []\n", "one YAML document"},
		{"an empty file", "", "declares no subjects"},
		{"a duration with no unit", roleOK + "subjects:\n  - {name: s, identity: [\"user:a@example.com\"], username: a, token_ttl: 60}\n", "need a unit"},
		{"a level missing a reserved name", "privilege_levels: [{name: readonly}, {name: admin}]\n" + subjOK, "must list operator"},
		{"a reserved level with a parent", "privilege_levels: [{name: readonly, parent: admin}, {name: operator}, {name: admin}]\n" + subjOK, "reserved"},
		{"an undeclared parent", "privilege_levels: [{name: readonly}, {name: x, parent: y}, {name: operator}, {name: admin}]\n" + subjOK, "parent \"y\""},
		{"a parent cycle", "privilege_levels: [{name: readonly}, {name: x, parent: y}, {name: y, parent: x}, {name: operator}, {name: admin}]\n" + subjOK, "cycle"},
		{"an unknown level", "roles:\n  - {name: r, privilege: root}\n" + subjOK, "not a privilege level"},
		{"a duplicate role", "roles:\n  - {name: r}\n  - {name: r}\n" + subjOK, "declared twice"},
		{"a non-trailing **", "roles:\n  - {name: r, permit: [\"show ** detail\"]}\n" + subjOK, "trailing-only"},
		{"a regex that is *", "roles:\n  - {name: r, permit: [\"show /^.*$/\"]}\n" + subjOK, "is `*`"},
		{"a regex that is a word", "roles:\n  - {name: r, deny: [\"/^reload$/ **\"]}\n" + subjOK, "deny #1: term 1 is a regex that is one word"},
		{"a case-sensitive regex", "roles:\n  - {name: r, deny: [\"* * /(?-i)^TFTP:/\"]}\n" + subjOK, "case-insensitively"},
		{"a case-sensitive group", "roles:\n  - {name: r, deny: [\"interface /(?s-i:^Mgmt)/\"]}\n" + subjOK, "case-insensitively"},
		{"a class no platform defines", "roles:\n  - {name: r, permit: [\"interface @uplinks\"]}\n" + subjOK, "which no platform defines"},
		{"a ceiling no platform numbers", unmappedLevel + scopeOK + roleOK + subjOK +
			"grants:\n  - {subject: s, scope: all_devices, roles: [r], max_privilege: unmapped}\n", "no priv-lvl number on any platform"},
		{"a bad pipe rule", "roles:\n  - {name: r, pipe: {permit: [\"inc*\"]}}\n" + subjOK, "pipe"},
		{"an attribute with no separator", "roles:\n  - {name: r, attributes: {all: [idletime]}}\n" + subjOK, "separator"},
		{"an attribute for no platform", "roles:\n  - {name: r, attributes: {junos: [\"idletime*30\"]}}\n" + subjOK, "neither `all`"},
		{"a placeholder in priv-lvl", "roles:\n  - {name: r, attributes: {all: [\"priv-lvl={username}\"]}}\n" + subjOK, "priv-lvl carries privilege and takes no placeholder"},
		{"a placeholder in local-user-name", "roles:\n  - {name: r, attributes: {juniper_junos: [\"local-user-name*{principal}\"]}}\n" + subjOK, "local-user-name carries privilege"},
		{"a placeholder in a grant's roles", scopeOK + roleOK + subjOK + "grants:\n  - {subject: s, scope: all_devices, roles: [r], attributes: {arista_eos: [\"roles={device}\"]}}\n", "roles carries privilege"},
		{"a placeholder in allow-commands", "roles:\n  - {name: r, attributes: {juniper_junos: [\"allow-commands={principal}\"]}}\n" + subjOK, "allow-commands carries privilege"},
		{"a placeholder in allow-configuration", "roles:\n  - {name: r, attributes: {juniper_junos: [\"allow-configuration={username}\"]}}\n" + subjOK, "allow-configuration carries privilege"},
		{"a placeholder in an attribute no adapter lists", "roles:\n  - {name: r, attributes: {all: [\"note*{device}\"]}}\n" + subjOK, "note is not listed inert on"},
		{"an unknown substitution", "roles:\n  - {name: r, attributes: {all: [\"home*{home}\"]}}\n" + subjOK, "not a substitution"},
		{"a scope match comparison", "scopes:\n  - {name: x, match: {os_version: {newer: \"1\"}}}\n" + subjOK, "not a comparison"},
		{"a scope regex RE2 refuses", "scopes:\n  - {name: x, match: {site: {re: \"(?!x)\"}}}\n" + subjOK, "match.site.re"},
		{"on_missing", "scopes:\n  - {name: x, match: {site: dc1}, on_missing: maybe}\n" + subjOK, "include or exclude"},
		{"a deny-bearing scope without on_missing", roleOK + "  - {name: d, deny: [reload]}\n" +
			"scopes:\n  - {name: x, match: {site: dc1}, attached_roles: {humans: [d]}}\n" + subjOK, "declare on_missing"},
		{"a deny granted on a keyed scope without on_missing", scopeOK + "  - {name: x, match: {site: dc1}}\n" + roleOK +
			"  - {name: d, deny: [reload]}\n" + subjOK + "grants:\n  - {subject: s, scope: x, roles: [r, d]}\n", "declare on_missing"},
		{"an undeclared attached role", "scopes:\n  - {name: x, match: {}, attached_roles: {machines: [nope]}}\n" + subjOK, "attached_roles.machines"},
		{"a group and identities", roleOK + "subjects:\n  - {name: s, group: G, identity: [\"user:a@example.com\"], username: a, token_ttl: 60s}\n", "not both"},
		{"neither", roleOK + "subjects:\n  - {name: s, username: a, token_ttl: 60s}\n", "group or an identity"},
		{"a group with a username", roleOK + "subjects:\n  - {name: s, group: G, username: a, token_ttl: 60s}\n", "from the directory"},
		{"a human and a machine", roleOK + "subjects:\n  - {name: s, identity: [\"user:a@example.com\", \"app:ci\"], username: a, token_ttl: 60s}\n", "trust domains"},
		{"an identity in no form", roleOK + "subjects:\n  - {name: s, identity: [\"alice\"], username: a, token_ttl: 60s}\n", "no recognized form"},
		{"an upper-case identity", roleOK + "subjects:\n  - {name: s, identity: [\"user:Alice@Example.com\"], username: a, token_ttl: 60s}\n", `write "user:alice@example.com"`},
		{"one identity, two subjects", roleOK + subjOK + "  - {name: t, identity: [\"user:a@example.com\"], username: b, token_ttl: 60s}\n", "listed by both"},
		{"a machine without a username", scopeOK + roleOK + "subjects:\n  - {name: s, identity: \"app:ci\", token_ttl: 60s}\n" + grantOK, "username is required"},
		{"a minting subject with no token_ttl", scopeOK + roleOK + "subjects:\n  - {name: s, identity: [\"user:a@example.com\"], username: a}\n" + grantOK, "token_ttl is required"},
		{"a non-canonical username", roleOK + "subjects:\n  - {name: s, identity: [\"user:a@example.com\"], username: 'CORP\\alice', token_ttl: 60s}\n", "already canonical"},
		{"a shared username", roleOK + subjOK + "  - {name: t, identity: [\"user:b@example.com\"], username: a, token_ttl: 60s}\n", "unique across"},
		{"enable nonsense", roleOK + "subjects:\n  - {name: s, identity: [\"user:a@example.com\"], username: a, enable: maybe, token_ttl: 60s}\n", "none, auto or token"},
		{"a short token_ttl", roleOK + "subjects:\n  - {name: s, identity: [\"user:a@example.com\"], username: a, token_ttl: 10s}\n", "between 30s and 15m0s"},
		{"an unknown api right", roleOK + "subjects:\n  - {name: s, identity: [\"user:a@example.com\"], username: a, token_ttl: 60s, api: [root]}\n", "not a right"},
		{"all_devices undeclared", roleOK + subjOK + grantOK, "add `scopes: [{name: all_devices"},
		{"an undeclared scope", scopeOK + roleOK + subjOK + "grants:\n  - {subject: s, scope: dc, roles: [r]}\n", `scope "dc"`},
		{"a grant to nobody", scopeOK + roleOK + subjOK + "grants:\n  - {subject: x, scope: all_devices, roles: [r]}\n", `subject "x"`},
		{"a grant with no roles", scopeOK + roleOK + subjOK + "grants:\n  - {subject: s, scope: all_devices}\n", "at least one role"},
		{"an undeclared role", scopeOK + roleOK + subjOK + "grants:\n  - {subject: s, scope: all_devices, roles: [x]}\n", `role "x"`},
		{"a bad max_privilege", scopeOK + roleOK + subjOK + "grants:\n  - {subject: s, scope: all_devices, roles: [r], max_privilege: root}\n", "max_privilege"},
		{"a bad expiry", scopeOK + roleOK + subjOK + "grants:\n  - {subject: s, scope: all_devices, roles: [r], expires: soon}\n", "expires"},
		{"a test with both", scopeOK + roleOK + subjOK + grantOK + "tests:\n  - {subject: s, principal: p, device: leaf-01, command: x, expect: permit}\n", "one of the two"},
		{"a test expecting maybe", scopeOK + roleOK + subjOK + grantOK + "tests:\n  - {subject: s, device: leaf-01, command: x, expect: maybe}\n", "permit or deny"},
		{"a test principal in no form", scopeOK + roleOK + subjOK + grantOK + "tests:\n  - {principal: alice, device: leaf-01, command: x, expect: deny}\n", "no recognized form"},
		{"an upper-case test principal", scopeOK + roleOK + subjOK + grantOK + "tests:\n  - {principal: \"user:A@example.com\", device: leaf-01, command: x, expect: deny}\n", `write "user:a@example.com"`},
		{"a test reason outside spec §5.7", scopeOK + roleOK + subjOK + grantOK + "tests:\n  - {subject: s, device: leaf-01, command: reload, expect: deny, reason: no_grant_matched}\n", "the reason is not in spec §5.7's vocabulary"},
		{"a test with no command and nothing asserted", scopeOK + roleOK + subjOK + grantOK + "tests:\n  - {subject: s, device: leaf-01}\n", "command is required, or a session test's level, max_privilege, priv_lvl, enable, reply, api or per_login_mfa"},
		{"a session test with an expect", scopeOK + roleOK + subjOK + grantOK + "tests:\n  - {subject: s, device: leaf-01, level: admin, expect: permit}\n", "a session test takes no expect"},
		{"a test level that is not a level", scopeOK + roleOK + subjOK + grantOK + "tests:\n  - {subject: s, device: leaf-01, level: root}\n", `level: "root" is not a privilege level`},
		{"a test max_privilege that is not a level", scopeOK + roleOK + subjOK + grantOK + "tests:\n  - {subject: s, device: leaf-01, max_privilege: root}\n", `max_privilege: "root" is not a privilege level`},
		{"an acknowledgment with no reason", "acknowledge:\n  - {role: guard, rule: \"reload **\"}\n" + subjOK, "acknowledge[0]: reason is required"},
		{"an acknowledgment with a blank reason", "acknowledge:\n  - {role: guard, rule: \"reload **\", reason: \"  \"}\n" + subjOK, "reason is required"},
		{"an acknowledgment with no rule", "acknowledge:\n  - {role: guard, reason: why}\n" + subjOK, "acknowledge[0]: role and rule are required"},
		{"a test api right that is not a right", scopeOK + roleOK + subjOK + grantOK + "tests:\n  - {subject: s, device: leaf-01, api: [root]}\n", `api[0] is not a right`},
		{"a test error names its row", scopeOK + roleOK + subjOK + grantOK + "tests:\n  - {subject: s, device: leaf-01, command: reload, expect: maybe}\n", `tests[0] (subject s, device leaf-01): `},
		{"a grant error names its row", scopeOK + roleOK + subjOK + "grants:\n  - {subject: s, scope: all_devices, roles: [x]}\n", `grants[0] (subject s, scope all_devices): role "x"`},
		{"the same grant twice", scopeOK + roleOK + "  - {name: q, permit: [show **]}\n" + subjOK +
			"grants:\n  - {subject: s, scope: all_devices, roles: [r, q]}\n  - {subject: s, scope: all_devices, roles: [q, r], expires: 2026-12-01}\n",
			"grants[1] (subject s, scope all_devices) repeats grants[0]"},
		{"a role twice in one grant", scopeOK + roleOK + subjOK + "grants:\n  - {subject: s, scope: all_devices, roles: [r, r]}\n", "listed twice"},
		{"a null match value", "scopes:\n  - {name: x, match: {site: null}}\n" + subjOK, "a match value is a string"},
		{"an unnamed role's null max_session_age", "roles:\n  - {max_session_age: }\n" + subjOK, "roles[0]: max_session_age is null"},
		{"the reserved levels reordered", "privilege_levels: [{name: admin}, {name: operator}, {name: readonly}]\n" + subjOK, "keep their order: readonly, then operator, then admin"},
		{"two reserved levels swapped", "privilege_levels: [{name: readonly}, {name: admin}, {name: x}, {name: operator}]\n" + subjOK, "keep their order"},
		{"a level ordered before its parent", "privilege_levels: [{name: readonly}, {name: x, parent: operator}, {name: operator}, {name: admin}]\n" + subjOK, "after its parent"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.yaml), env())
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Parse = %v, want an error containing %q", err, tt.want)
			}
		})
	}
}

// Spec §2's own example loads: a subject no grant names mints nothing, so it
// needs neither a username nor a token_ttl.
func TestSpecSection2ExamplesLoad(t *testing.T) {
	p := mustParse(t, `
subjects:
  - name: netops_oncall
    group: NetOps-OnCall
    api: [revoke_others, explain_others]
  - name: ci_policy_bot
    identity: ["app:port49-ci"]
    api: [sync, replay]
`)
	if s, _ := p.Subject("ci_policy_bot"); s.Domain != "machines" || len(s.API) != 2 {
		t.Fatalf("ci_policy_bot: %+v", s)
	}
}

// A test's reason is one of spec §5.7's.
func TestATestReasonFromTheVocabularyLoads(t *testing.T) {
	p := mustParse(t, scopeOK+roleOK+subjOK+grantOK+
		"tests:\n  - {subject: s, device: leaf-01, command: reload, expect: permit, reason: permit_dominates}\n")
	if got := p.Tests()[0].Reason; got != "permit_dominates" {
		t.Fatalf("reason %q", got)
	}
}

// A deny regex that sets flags without turning case-insensitivity off loads,
// and a permit or pipe entry may opt out with (?-i): that only narrows what
// it permits, so it fails closed (spec §3 rule 3).
func TestOnlyADenyMustStayCaseInsensitive(t *testing.T) {
	mustParse(t, "roles:\n  - {name: r, deny: [\"* * /(?i)^tftp:/\", \"* * /(?s)^ftp:/\", \"* * /[(?-i)]/\"]}\n"+subjOK)
	// A one-rune class is rewritten to a literal that does not fold case, and
	// a rune with no other case has none to fold: nothing can walk past it.
	mustParse(t, "roles:\n  - {name: r, deny: [\"interface /^Ethernet1[.]1$/\", \"copy /[/_]x/ *\", \"* /(?-i)[0-9.]+/\"]}\n"+subjOK)
	p := mustParse(t, scopeOK+`roles:
  - {name: r, privilege: readonly, permit: ["show ip access-list /(?-i)^MGMT$/"], pipe: {permit: ["include /(?U-i)x/"]}}
`+subjOK+grantOK)
	d := deviceNamed(t, "leaf-01")
	for command, want := range map[string]bool{"show ip access-list MGMT": true, "show ip access-list mgmt": false} {
		if _, o, err := p.Decide("s", "", d, command, noon); err != nil || o.Permit != want {
			t.Errorf("%q: permit %v, err %v; want %v", command, o.Permit, err, want)
		}
	}
}

// On a platform that may send what was typed — the generic adapter, which
// nothing has measured — an abbreviated interface cannot slip past a deny
// naming it by pattern; on EOS, which L21 measured sending the resolved name,
// what arrives is matched as written (spec §3 rule 4).
func TestAnAbbreviatedNameIsDeniedWhereAbbreviationsAreAssumed(t *testing.T) {
	p := mustParse(t, scopeOK+`roles:
  - {name: r, privilege: admin, permit: ["**"]}
  - {name: no_mgmt, deny: ["interface /^Management[0-9]+$/"]}
`+subjOK+"grants:\n  - {subject: s, scope: all_devices, roles: [r, no_mgmt]}\n")
	generic := admission.Device{Name: "ntp-01", Platform: "meinberg_lantime", Addresses: []netip.Addr{netip.MustParseAddr("10.0.9.1")}}
	for _, tt := range []struct {
		d       admission.Device
		command string
		want    bool
	}{
		{generic, "int ma1", false}, {generic, "interface Ma1", false}, {generic, "interface Management1", false},
		{generic, "interface Ethernet1", true},
		{deviceNamed(t, "leaf-01"), "interface Ma1", true}, {deviceNamed(t, "leaf-01"), "interface Management1", false},
	} {
		if _, o, err := p.Decide("s", "", tt.d, tt.command, noon); err != nil || o.Permit != tt.want {
			t.Errorf("%s %q: permit %v (%s), err %v; want %v", tt.d.Platform, tt.command, o.Permit, o.Reason, err, tt.want)
		}
	}
}

// A deny pattern whose abbreviations port49 cannot list quarantines nothing:
// spec-style exfiltration denies load with EOS, NX-OS, IOS-XE and Junos
// devices, and on the generic adapter, the one platform that may send what was
// typed, the pattern matches any argument in its position — logins keep
// working, the commands its other terms reach are denied, and the report names
// the term and the platform (spec §3 rule 4, §10, §13 decision 20).
func TestAnUnreadableDenyPatternMatchesAnythingWhereAbbreviationsAreAssumed(t *testing.T) {
	body := scopeOK + `roles:
  - {name: r, privilege: admin, permit: ["**"]}
  - {name: no_exfil, deny: ["* * /tftp/", "copy * /^tftp:/"]}
  - {name: no_mgmt, deny: ["interface /^Management[0-9]+$/"]}
` + subjOK + "grants:\n  - {subject: s, scope: all_devices, roles: [r, no_exfil, no_mgmt]}\n"
	p := mustParse(t, body)
	if q := p.Quarantines(noon); len(q) != 0 {
		t.Fatalf("quarantined %+v", q)
	}
	if got := findings(p, FindingDenyWidened); len(got) != 0 {
		t.Fatalf("no platform in the inventory widens: %q", got)
	}
	if _, o, err := p.Decide("s", "", deviceNamed(t, "xe-01"), "copy running-config tftp://x/y", noon); err != nil || o.Permit {
		t.Fatalf("the deny binds on IOS-XE: %+v %v", o, err)
	}
	generic := admission.Device{Name: "ntp-01", Platform: "meinberg_lantime", Addresses: []netip.Addr{netip.MustParseAddr("10.0.9.1")}}
	p, err := Parse([]byte(body), Env{Devices: append(inventory(), generic)})
	if err != nil {
		t.Fatalf("the policy loads with a generic device present: %v", err)
	}
	if q := p.Quarantines(noon); len(q) != 0 {
		t.Fatalf("nothing is quarantined: %+v", q)
	}
	if _, err := p.Resolve("user:a@example.com", generic, noon); err != nil {
		t.Fatalf("the generic device still mints: %v", err)
	}
	for command, want := range map[string]bool{"copy running-config startup-config": false, "int ma1": false,
		"interface Ethernet1": true, "show version": true} {
		if _, o, err := p.Decide("s", "", generic, command, noon); err != nil || o.Permit != want {
			t.Errorf("generic %q: permit %v (%s), err %v; want %v", command, o.Permit, o.Reason, err, want)
		}
	}
	got := findings(p, FindingDenyWidened)
	if len(got) != 1 || !strings.Contains(got[0], `"* * /tftp/"`) || !strings.Contains(got[0], "meinberg_lantime") ||
		!strings.Contains(got[0], "any argument") {
		t.Errorf("the report names the term and the platform: %q", got)
	}
	// A platform the operator marks as sending what was typed is the same.
	xe, _ := platform.DialectFor("cisco_iosxe")
	xe.ExpandsAbbreviations = false
	p, err = Parse([]byte(body), Env{Devices: inventory(), Dialects: map[string]platform.Dialect{"cisco_iosxe": xe}})
	if err != nil {
		t.Fatalf("an operator's dialect does not refuse the policy: %v", err)
	}
	if q := p.Quarantines(noon); len(q) != 0 {
		t.Fatalf("nothing is quarantined: %+v", q)
	}
	if got := findings(p, FindingDenyWidened); len(got) != 1 || !strings.Contains(got[0], "cisco_iosxe") {
		t.Errorf("%q", got)
	}
}

func findings(p *Policy, kind string) []string {
	var out []string
	for _, f := range p.Lint(noon) {
		if f.Kind == kind {
			out = append(out, f.Message)
		}
	}
	return out
}

// IOS-XE sends a typed `int Gi1` as `GigabitEthernet`, `1`
// (tests/lab/results/L21-cisco_iosxe.md), so a deny written with the name
// joined still binds there, and EOS, which sends one argument, is unchanged
// (spec §3 rule 5).
func TestADenyBindsTheSplitInterfaceOnIOSXE(t *testing.T) {
	p := mustParse(t, scopeOK+`roles:
  - {name: r, privilege: admin, permit: ["**"]}
  - {name: no_gi1, deny: ["interface GigabitEthernet1 **"]}
`+subjOK+"grants:\n  - {subject: s, scope: all_devices, roles: [r, no_gi1]}\n")
	for _, tt := range []struct {
		device, command string
		want            bool
	}{
		{"xe-01", "interface GigabitEthernet 1", false}, {"xe-01", "interface GigabitEthernet 2", true},
		{"leaf-01", "interface GigabitEthernet1", false}, {"leaf-01", "interface GigabitEthernet 1", true},
	} {
		if _, o, err := p.Decide("s", "", deviceNamed(t, tt.device), tt.command, noon); err != nil || o.Permit != tt.want {
			t.Errorf("%s %q: permit %v (%s), err %v; want %v", tt.device, tt.command, o.Permit, o.Reason, err, tt.want)
		}
	}
}

// The rank lint catches the usual spellings of `*` and of a word, and leaves
// alone a regex that constrains something a simpler term cannot say.
func TestRankLint(t *testing.T) {
	for body, want := range map[string]bool{
		`^.*$`: true, `.*`: true, `.+`: true, `^.+$`: true, `(.*)`: true, `^(.*)$`: true,
		`^show$`: true, `^(show)$`: true, `^[s]how$`: true, `(^show$)`: true,
		`^sh(ow|ut)$`: false, `(?-i)^show$`: false, `^[st]how$`: false, `eth[0-9]+`: false, `^show`: false,
		`^tftp:`: false,
	} {
		if _, got := rankLint(body); got != want {
			t.Errorf("rankLint(%q) = %v, want %v", body, got, want)
		}
	}
}

// Declaring privilege_levels replaces the ordering, and a custom level may
// hang off a reserved one (spec §6).
func TestCustomLevelsReplaceTheOrdering(t *testing.T) {
	p := mustParse(t, `
privilege_levels:
  - {name: readonly}
  - {name: read_only_limited, parent: readonly}
  - {name: operator}
  - {name: senior_operator, parent: operator}
  - {name: admin}
roles:
  - {name: r, privilege: senior_operator}
`+subjOK)
	if strings.Join(p.levels, " ") != "readonly read_only_limited operator senior_operator admin" ||
		p.parents["senior_operator"] != "operator" {
		t.Fatalf("levels %q parents %v", p.levels, p.parents)
	}
}

// A scope with several faults is refused for the same one every time, so an
// operator fixing a file sees a stable error, not whichever the map yielded.
func TestAScopeErrorIsTheSameEveryLoad(t *testing.T) {
	body := "scopes:\n  - {name: x, match: {zone: {re: \"(?!z)\"}, site: {re: \"(?!s)\", lt: \"\"}}}\n" + subjOK
	for i := 0; i < 50; i++ {
		_, err := Parse([]byte(body), env())
		if err == nil || !strings.Contains(err.Error(), "match.site.lt needs a version") {
			t.Fatalf("load %d: %v", i, err)
		}
	}
}

// A placeholder goes only in an attribute listed inert: home-directory, spec
// §6's motivating case, on every platform that holds it inert (review I4).
// IOS-XE does not: the C8000V refused a session for it
// (tests/lab/results/L22-cisco_iosxe.md), so there, and under `all`, which
// reaches IOS-XE, a placeholder in it is refused.
func TestAPlaceholderGoesOnlyInAnInertAttribute(t *testing.T) {
	parse := func(key string) error {
		_, err := Parse([]byte("roles:\n  - {name: r, attributes: {"+key+": [\"home-directory*/home/{username}\"]}}\n"+subjOK), env())
		return err
	}
	for _, key := range []string{"arista_eos", "cisco_nxos", "juniper_junos"} {
		if err := parse(key); err != nil {
			t.Errorf("%s: %v", key, err)
		}
	}
	for _, key := range []string{"all", "cisco_iosxe"} {
		if err := parse(key); err == nil || !strings.Contains(err.Error(),
			"home-directory is not listed inert on cisco_iosxe, so it takes no placeholder") {
			t.Errorf("%s: %v", key, err)
		}
	}
}

// A policy pins the platform set it renders with (spec §8). One that pins none
// renders with 1.0.0, the first set, on every binary; a set this binary does
// not ship is refused by name (TestLoadRefusesByName).
func TestAPolicyPinsItsPlatformSet(t *testing.T) {
	body := scopeOK + roleOK + subjOK + grantOK
	if p := mustParse(t, body); p.PlatformSet() != platform.UnpinnedSet || p.PlatformSet() != "1.0.0" {
		t.Fatalf("unpinned: %q", p.PlatformSet())
	}
	p := mustParse(t, "platform_set: 1.0.0\n"+body)
	if p.PlatformSet() != "1.0.0" {
		t.Fatalf("pinned: %q", p.PlatformSet())
	}
	want, _ := platform.Set("1.0.0")
	if got := p.Dialect("cisco_iosxe"); !reflect.DeepEqual(got, want["cisco_iosxe"]) {
		t.Fatalf("the pinned set's adapter: %+v", got)
	}
}

// A refused policy's error is printed by port49d at start and on every
// reload, and by policy test, diff and explain, and it goes to logs. It
// quotes no rule text and no term: it names the role, the list, the rule's
// position and the problem, and the operator finds the rule in the file.
// Redacting the quote is not enough: the refused file's own redaction
// patterns never loaded (spec §5.8; task 11 review C2, fail closed).
func TestALoadErrorQuotesNoRuleText(t *testing.T) {
	for _, tt := range []struct{ name, yaml, want string }{
		{"a regex that is a word", `deny: [reload, "snmp-server community /^Hunter2$/"]`,
			`role "r": deny #2: term 3 is a regex that is one word; write the word instead`},
		{"a case-sensitive deny", `deny: ["snmp-server community /(?-i)Hunter2/"]`,
			`role "r": deny #1: term 3 turns case-insensitivity off`},
		{"a regex that does not compile", `permit: [show, "crypto psk /Hunter2(/"]`,
			`role "r": permit #2: term 3 is a regex that does not compile`},
		{"a class no platform defines", `permit: ["snmp-server community @hunter2_list"]`,
			`role "r": permit #1: term 3 names a class which no platform defines`},
		{"a term that is not a class name", `deny: ["snmp-server community @Hunter2"]`,
			`role "r": deny #1: term 3 is not a class name`},
		{"a wildcard inside a word", `deny: ["snmp-server community Hunt*er2"]`,
			`role "r": deny #1: term 3 puts a wildcard inside a word`},
		{"a non-trailing **", `permit: ["crypto psk ** Hunter2"]`, `role "r": permit #1: term 3: `},
		{"a pipe permit", `pipe: {permit: ["include /^Hunter2$/"]}`,
			`role "r": pipe #1: term 2 is a regex that is one word`},
		{"a string where a list goes", `deny: "snmp-server community Hunter2"`, "cannot unmarshal"},
		{"a short string where a list goes", `deny: Hunter2`, "cannot unmarshal"},
	} {
		_, err := Parse([]byte("roles:\n  - {name: r, "+tt.yaml+"}\n"+subjOK), env())
		if err == nil || !strings.Contains(err.Error(), tt.want) || strings.Contains(strings.ToLower(err.Error()), "hunt") {
			t.Errorf("%s: %v", tt.name, err)
		}
	}
}

// A block with two bad keys names the same one every run, the first in name
// order: a map's order is random, and a refusal that changes from run to run
// reads as a flaky check (final review M10).
func TestAnAttributeRefusalNamesTheSameKeyEveryRun(t *testing.T) {
	body := `
scopes: [{name: all_devices, match: {}}]
roles: [{name: r, privilege: readonly, permit: [show **], attributes: {zz_os: ["a=1"], mm_os: ["b=2"], aa_os: ["c=3"]}}]
subjects: [{name: s, identity: "user:s@example.com", username: s, token_ttl: 60s}]
grants: [{subject: s, scope: all_devices, roles: [r]}]`
	for range 30 {
		if _, err := Parse([]byte(body), env()); err == nil || !strings.Contains(err.Error(), `"aa_os"`) {
			t.Fatalf("%v", err)
		}
	}
}

// A rule that fails to load or compile is named by its role and position,
// never quoted: it may carry a value redaction hides (spec §5.8; plan 5a).
// The load error of a deny whose regex does not compile, and the quarantine
// cause of one that splits past the matcher's bound on IOS-XE, print no
// secret (task 12b review).
func TestALoadErrorOnASecretRuleQuotesNoSecret(t *testing.T) {
	_, err := Parse([]byte(scopeOK+`roles:
  - {name: r, privilege: readonly, permit: ["show **"], deny: ["show secret /HUNTER2((/"]}
`+subjOK+grantOK), env())
	if err == nil || !strings.Contains(err.Error(), `role "r": deny #1: term 3`) || strings.Contains(err.Error(), "HUNTER2") {
		t.Errorf("load: %v", err)
	}
	p := mustParse(t, scopeOK+`roles:
  - {name: r, privilege: readonly, permit: ["show **"], deny: ["show * * * * * * * * * * * secret HUNTER2"]}
`+subjOK+grantOK)
	var causes []string
	for _, q := range p.Quarantines(noon) {
		for _, e := range q.Entries {
			causes = append(causes, e.Cause)
		}
	}
	if text := strings.Join(causes, "\n"); !strings.Contains(text, `rule #1 (role "r"): the deny splits more than`) ||
		strings.Contains(text, "HUNTER2") {
		t.Errorf("quarantine: %s", text)
	}
}

// A spiffe:// identity outside SPIFFE ID §2 is a load error, never folded
// (decision 40 ruling 4); one inside it is a machine's.
func TestASpiffeIdentityMustBeAWorkloadID(t *testing.T) {
	const tmpl = `
scopes: [{name: all_devices, match: {}}]
roles: [{name: r, privilege: readonly, permit: ["show **"]}]
subjects: [{name: svc, identity: ["%s"], username: svc-backup, token_ttl: 60s}]
grants: [{subject: svc, scope: all_devices, roles: [r]}]
`
	for id, want := range map[string]string{
		"spiffe://Corp.example.com/host/x": "a workload certificate's principal is its SPIFFE ID",
		"spiffe://corp.example.com":        "names the trust domain itself, not a workload",
		"SPIFFE://corp.example.com/host/x": "a workload certificate's principal is its SPIFFE ID",
	} {
		if _, err := loadText(t, fmt.Sprintf(tmpl, id), DirectoryOff); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v", id, err)
		}
	}
	p, err := loadText(t, fmt.Sprintf(tmpl, "spiffe://corp.example.com/host/oxidized-01"), DirectoryOff)
	if err != nil {
		t.Fatal(err)
	}
	if got := p.SPIFFEIdentities(); len(got) != 1 || got["spiffe://corp.example.com/host/oxidized-01"] != "svc" {
		t.Fatalf("SPIFFEIdentities %v", got)
	}
}

// The policy's load reads a service account as the verifier will give it
// (decision 49 ruling 8): one that no cluster can name fails CI.
func TestAServiceAccountIdentityIsTheVerifiersForm(t *testing.T) {
	for _, id := range []string{"system:serviceaccount:NetOps:oxidized", "system:serviceaccount:netops:a_b",
		"system:serviceaccount:netops:oxidized:x"} {
		src := strings.Replace(good, "system:serviceaccount:netops:oxidized", id, 1)
		if _, err := Parse([]byte(src), env()); err == nil || !strings.Contains(err.Error(), "system:serviceaccount:<namespace>:<name>") {
			t.Errorf("%s: %v", id, err)
		}
	}
}

func TestServiceAccountIdentities(t *testing.T) {
	p := mustParse(t, good)
	if got := p.ServiceAccountIdentities(); len(got) != 1 || got["system:serviceaccount:netops:oxidized"] != "svc_oxidized" {
		t.Fatalf("%v", got)
	}
}

// includeProbe is a mitigation scope that also carries a grant, the shape policy I1 found:
// dc_admin hands a permit to whatever device the inventory cannot describe.
const includeProbe = `
scopes:
  - {name: dc_fabric, match: {site: [dc1, dc2]}, on_missing: include}
roles:
  - {name: dc_admin, privilege: admin, permit: ["**"]}
  - {name: dc_read, privilege: readonly}
  - {name: no_reload, deny: [reload **]}
subjects:
  - {name: noc, identity: ["user:noc@example.com"], username: noc, token_ttl: 60s}
`

func TestAGrantOnAnIncludeScopeIsRefusedAtLoad(t *testing.T) {
	_, err := Parse([]byte(includeProbe+"grants:\n  - {subject: noc, scope: dc_fabric, roles: [dc_admin]}\n"), env())
	if err == nil {
		t.Fatal("a grant of a permit on an on_missing: include scope loaded")
	}
	for _, want := range []string{"grants[0] (subject noc, scope dc_fabric)", "on_missing: include", "exclude",
		"attached_roles", "§5.5"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal lacks %q: %v", want, err)
		}
	}
}

func TestAGrantWithOnlyAMaxPrivilegeOnAnIncludeScopeIsRefused(t *testing.T) {
	_, err := Parse([]byte(includeProbe+"grants:\n  - {subject: noc, scope: dc_fabric, roles: [dc_read], max_privilege: admin}\n"), env())
	if err == nil || !strings.Contains(err.Error(), "on_missing: include") {
		t.Fatalf("a max_privilege on an include scope loaded or was refused for another reason: %v", err)
	}
}

func TestADenyOnlyGrantOnAnIncludeScopeLoads(t *testing.T) {
	if _, err := Parse([]byte(includeProbe+"grants:\n  - {subject: noc, scope: dc_fabric, roles: [no_reload]}\n"), env()); err != nil {
		t.Fatalf("a deny-only grant on an include scope is the mitigation shape: %v", err)
	}
}

func TestTheRefusalForAnUndeclaredOnMissingRecommendsExcludeForAGrant(t *testing.T) {
	_, err := Parse([]byte(scopeOK+"  - {name: x, match: {site: dc1}}\n"+roleOK+"  - {name: d, deny: [reload]}\n"+subjOK+
		"grants:\n  - {subject: s, scope: x, roles: [r, d]}\n"), env())
	if err == nil || !strings.Contains(err.Error(), "exclude for a grant; put a mitigation's deny in attached_roles on an include scope") {
		t.Fatalf("the refusal does not steer a grant to exclude: %v", err)
	}
}

// Every policy the repository ships loads: a new load refusal must not break
// the examples an operator copies, nor the policies the qualification suite and
// the lab load.
func TestEveryShippedPolicyLoads(t *testing.T) {
	root := filepath.Join("..", "..")
	files := []string{filepath.Join(root, "tests", "qual", "qual-policy.yaml")}
	for _, pat := range []string{"deploy/*/config/policy.yaml", "deploy/examples/*/policy.yaml", "deploy/examples/*/*/policy.yaml"} {
		m, err := filepath.Glob(filepath.Join(root, pat))
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, m...)
	}
	if len(files) < 3 {
		t.Fatalf("expected the qual policy and the deploy policies, found %v", files)
	}
	for _, f := range files {
		if _, err := Load(f, env()); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
}
