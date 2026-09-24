package policy

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rhwendt/port49/internal/admission"
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

func env() Env { return Env{Devices: inventory()} }

func mustParse(t *testing.T, body string) *Policy {
	t.Helper()
	p, err := Parse([]byte(body), env())
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// good is spec §11's shape, cut to what every platform in inventory() can
// render with the built-in adapters: `operator` has no mapping on arista_eos
// (internal/platform), so no role here lands an EOS session there.
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
		t.Error("a group is matched through the directory (plan 7), never as an identity")
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

// Every refusal names what is wrong and, where another plan owns the key, which
// plan lifts it.
func TestLoadRefusesByName(t *testing.T) {
	for _, tt := range []struct{ name, yaml, want string }{
		{"platform_set", "platform_set: 1.4.0\n" + roleOK + subjOK, "plan 5"},
		{"key_groups", "key_groups: []\n" + roleOK + subjOK, "inventory file"},
		{"platforms", "platforms: {arista_eos: {}}\n" + roleOK + subjOK, "plan 5"},
		{"a role's max_session_age", "roles:\n  - {name: r, max_session_age: 8h}\n" + subjOK, "plan 7"},
		{"an unknown key", scopeOK + roleOK + subjOK + "gratns: []\n", "field gratns not found"},
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
		{"a regex that is a word", "roles:\n  - {name: r, deny: [\"/^reload$/ **\"]}\n" + subjOK, "the word `reload`"},
		{"a case-sensitive regex", "roles:\n  - {name: r, deny: [\"* * /(?-i)^TFTP:/\"]}\n" + subjOK, "case-insensitively"},
		{"a case-sensitive group", "roles:\n  - {name: r, deny: [\"interface /(?s-i:^Mgmt)/\"]}\n" + subjOK, "case-insensitively"},
		{"a deny pattern whose abbreviations cannot be read", "roles:\n  - {name: r, deny: [\"interface /Management/\"]}\n" + subjOK,
			"on juniper_junos, deny \"interface /Management/\": /Management/: the platform may send it abbreviated"},
		{"a class no platform defines", "roles:\n  - {name: r, permit: [\"interface @uplinks\"]}\n" + subjOK, "which no platform defines"},
		{"a ceiling no platform numbers", scopeOK + roleOK + subjOK +
			"grants:\n  - {subject: s, scope: all_devices, roles: [r], max_privilege: operator}\n", "no priv-lvl number on any platform"},
		{"a bad pipe rule", "roles:\n  - {name: r, pipe: {permit: [\"inc*\"]}}\n" + subjOK, "pipe"},
		{"an attribute with no separator", "roles:\n  - {name: r, attributes: {all: [idletime]}}\n" + subjOK, "separator"},
		{"an attribute for no platform", "roles:\n  - {name: r, attributes: {junos: [\"idletime*30\"]}}\n" + subjOK, "neither `all`"},
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
		{"a test on no device", scopeOK + roleOK + subjOK + grantOK + "tests:\n  - {subject: s, device: nowhere, command: x, expect: permit}\n", "not in the inventory"},
		{"a test expecting maybe", scopeOK + roleOK + subjOK + grantOK + "tests:\n  - {subject: s, device: leaf-01, command: x, expect: maybe}\n", "permit or deny"},
		{"a test principal in no form", scopeOK + roleOK + subjOK + grantOK + "tests:\n  - {principal: alice, device: leaf-01, command: x, expect: deny}\n", "no recognized form"},
		{"an upper-case test principal", scopeOK + roleOK + subjOK + grantOK + "tests:\n  - {principal: \"user:A@example.com\", device: leaf-01, command: x, expect: deny}\n", `write "user:a@example.com"`},
		{"a test reason outside spec §5.7", scopeOK + roleOK + subjOK + grantOK + "tests:\n  - {subject: s, device: leaf-01, command: reload, expect: deny, reason: no_grant_matched}\n", "not a reason"},
		{"a test error names its row", scopeOK + roleOK + subjOK + grantOK + "tests:\n  - {subject: s, device: leaf-01, command: reload, expect: maybe}\n", `tests[0] (subject s, device leaf-01, "reload"): `},
		{"a grant error names its row", scopeOK + roleOK + subjOK + "grants:\n  - {subject: s, scope: all_devices, roles: [x]}\n", `grants[0] (subject s, scope all_devices): role "x"`},
		{"the same grant twice", scopeOK + roleOK + "  - {name: q, permit: [show **]}\n" + subjOK +
			"grants:\n  - {subject: s, scope: all_devices, roles: [r, q]}\n  - {subject: s, scope: all_devices, roles: [q, r], expires: 2026-12-01}\n",
			"grants[1] (subject s, scope all_devices) repeats grants[0]"},
		{"a role twice in one grant", scopeOK + roleOK + subjOK + "grants:\n  - {subject: s, scope: all_devices, roles: [r, r]}\n", "listed twice"},
		{"a null match value", "scopes:\n  - {name: x, match: {site: null}}\n" + subjOK, "a match value is a string"},
		{"an unnamed role's max_session_age", "roles:\n  - {max_session_age: 8h}\n" + subjOK, "roles[0]: max_session_age"},
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

// Declaring privilege_levels replaces the ordering, and a custom level may
// hang off a reserved one (spec §6).
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
// it permits, so it fails closed (spec §3 rule 3). Each deny is anchored, as
// a deny's pattern must be where abbreviations are read (spec §3 rule 4).
func TestOnlyADenyMustStayCaseInsensitive(t *testing.T) {
	mustParse(t, "roles:\n  - {name: r, deny: [\"* * /(?i)^tftp:/\", \"* * /(?s)^ftp:/\", \"* * /^0[(?-i)]/\"]}\n"+subjOK)
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
