package policy

import (
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/admission"
)

var now = noon

// minimalGrant grants subject a, which each test declares, on every device.
const minimalGrant = `
scopes: [{name: all_devices, match: {}}]
roles: [{name: ro, privilege: readonly, permit: ["show **"]}]
grants: [{subject: a, scope: all_devices, roles: [ro]}]
`

func loadText(t *testing.T, body string, mode DirectoryMode) (*Policy, error) {
	t.Helper()
	e := env()
	// Added here, not to inventory(): quarantine tests list every device.
	e.Devices = append(e.Devices, admission.Device{Name: "spine-01", Platform: "arista_eos",
		Addresses: []netip.Addr{netip.MustParseAddr("10.0.1.2")}, Attributes: map[string]string{"site": "dc1", "role": "spine"}})
	e.Directory = mode
	return Parse([]byte(body), e)
}

func device(t *testing.T, p *Policy, name string) admission.Device {
	t.Helper()
	d, ok := p.Device(name)
	if !ok {
		t.Fatalf("no device %s", name)
	}
	return d
}

const memberYAML = `
scopes: [{name: all_devices, match: {}}, {name: leaf, match: {role: leaf}}]
roles:
  - {name: ro, privilege: readonly, permit: ["show **"]}
  - {name: ops, privilege: operator, permit: ["clear counters"]}
subjects:
  - {name: netops_ro, group: netops-ro, enable: auto, token_ttl: 15m}
  - {name: netops_oncall, group: "CN=netops-oncall,OU=G,DC=corp", enable: token, token_ttl: 5m,
     api: [revoke_others]}
  - {name: alice_direct, identity: ["user:alice@corp.example.com"], token_ttl: 10m}
grants:
  - {subject: netops_ro, scope: all_devices, roles: [ro]}
  - {subject: netops_oncall, scope: leaf, roles: [ops]}
  - {subject: alice_direct, scope: leaf, roles: [ro]}
`

// ceilingYAML: netops_ro is capped at readonly; netops_ops is not capped, so
// the union caps ops at readonly.
const ceilingYAML = `
scopes: [{name: all_devices, match: {}}]
roles:
  - {name: ro, privilege: readonly, permit: ["show **"]}
  - {name: ops, privilege: operator, permit: ["clear counters"]}
subjects:
  - {name: netops_ro, group: netops-ro, token_ttl: 5m}
  - {name: netops_ops, group: netops-ops, token_ttl: 5m}
grants:
  - {subject: netops_ro, scope: all_devices, roles: [ro], max_privilege: readonly}
  - {subject: netops_ops, scope: all_devices, roles: [ops]}
`

func memberPolicy(t *testing.T, mode DirectoryMode) *Policy {
	t.Helper()
	p, err := loadText(t, memberYAML, mode)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func ceilingPolicy(t *testing.T) *Policy {
	t.Helper()
	p, err := loadText(t, ceilingYAML, DirectoryOn)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// A member in a named group, a DN-named group and an identity subject
// matches all three; on a leaf every grant composes, with the least
// token_ttl and the most demanding enable among those granting there
// (Ruling 5).
func TestEverySubjectComposes(t *testing.T) {
	p := memberPolicy(t, DirectoryOn)
	m := Member{Principal: "user:alice@corp.example.com", Directory: true, Username: "alice",
		GroupDNs: []string{"cn=NetOps-OnCall,ou=G,dc=corp"}, GroupNames: []string{"NetOps-RO"}}
	if got := p.SubjectsOf(m); !slices.Equal(got, []string{"alice_direct", "netops_oncall", "netops_ro"}) {
		t.Fatalf("subjects %v", got)
	}
	res, err := p.ResolveMember(m, device(t, p, "leaf-01"), now)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(res.Subjects, []string{"alice_direct", "netops_oncall", "netops_ro"}) || res.Subject != "" ||
		!slices.Equal(res.Roles, []string{"ops", "ro"}) || res.Level != "operator" || res.Username != "alice" ||
		res.TokenTTL != 5*time.Minute || res.Enable != "token" {
		t.Fatalf("%+v", res)
	}
	// On a spine only netops_ro grants: one subject, its own fields.
	res, err = p.ResolveMember(m, device(t, p, "spine-01"), now)
	if err != nil || res.Subject != "netops_ro" || res.Subjects != nil || res.Enable != "auto" || res.TokenTTL != 15*time.Minute {
		t.Fatalf("%+v %v", res, err)
	}
}

// A group name the directory did not verify unique is not in GroupNames,
// so a name subject does not match; with no groups, only the identity
// subject does (Ruling 7; fail closed).
func TestOnlyVerifiedNamesMatch(t *testing.T) {
	p := memberPolicy(t, DirectoryOn)
	m := Member{Principal: "user:bob@corp.example.com", Directory: true, Username: "bob"}
	if got := p.SubjectsOf(m); len(got) != 0 {
		t.Fatalf("%v", got)
	}
	if _, err := p.ResolveMember(m, device(t, p, "leaf-01"), now); !errors.Is(err, ErrNoGrants) {
		t.Fatalf("%v", err)
	}
}

// Rights through a group (7c's carry; Ruling 13).
func TestARightHeldThroughAGroup(t *testing.T) {
	p := memberPolicy(t, DirectoryOn)
	in := Member{Principal: "user:carol@corp.example.com", Directory: true, Username: "carol",
		GroupDNs: []string{"CN=netops-oncall,OU=G,DC=corp"}}
	if !p.HasRightOf(in, RightRevokeOthers) || p.HasRightOf(Member{Principal: in.Principal, Directory: true}, RightRevokeOthers) {
		t.Fatal("revoke_others through netops_oncall")
	}
}

// Two subjects whose union lands above a ceiling neither alone exceeds is
// composition_refused, for that member on that device alone (Ruling 5).
func TestACompositionAJointCheckRefusesIsRefused(t *testing.T) {
	p := ceilingPolicy(t) // netops_ro: ro capped at readonly; netops_ops: ops, no ceiling: the union caps ops at readonly
	m := Member{Principal: "user:dan@corp.example.com", Directory: true, Username: "dan",
		GroupNames: []string{"netops-ro", "netops-ops"}}
	_, err := p.ResolveMember(m, device(t, p, "leaf-01"), now)
	if !errors.Is(err, ErrCompositionRefused) || !strings.Contains(err.Error(), "max_privilege") {
		t.Fatalf("%v", err)
	}
	if _, err := p.ResolveMember(Member{Principal: m.Principal, Directory: true, Username: "dan",
		GroupNames: []string{"netops-ops"}}, device(t, p, "leaf-01"), now); err != nil {
		t.Fatalf("one subject alone: %v", err)
	}
}

// With a directory, a human identity subject declares no username; without
// one it must; offline, either loads (Ruling 16).
func TestAHumanUsernameAndTheDirectory(t *testing.T) {
	with := "subjects: [{name: a, identity: [\"user:a@x.com\"], username: a, token_ttl: 5m}]\n" + minimalGrant
	without := "subjects: [{name: a, identity: [\"user:a@x.com\"], token_ttl: 5m}]\n" + minimalGrant
	if _, err := loadText(t, with, DirectoryOn); err == nil || !strings.Contains(err.Error(), "the directory supplies human usernames") {
		t.Fatalf("on: %v", err)
	}
	if _, err := loadText(t, without, DirectoryOff); err == nil || !strings.Contains(err.Error(), "username is required") {
		t.Fatalf("off: %v", err)
	}
	for _, text := range []string{with, without} {
		if _, err := loadText(t, text, DirectoryUnknown); err != nil {
			t.Fatalf("offline: %v", err)
		}
	}
}

// A group subject never matches a machine principal, whatever the member's
// groups say; a directory-less member matches identity subjects alone.
func TestAGroupSubjectNeverMatchesAMachine(t *testing.T) {
	p := memberPolicy(t, DirectoryOn)
	m := Member{Principal: "spiffe://port49/host/x", Directory: true, Username: "x", GroupNames: []string{"netops-ro"}}
	if got := p.SubjectsOf(m); len(got) != 0 {
		t.Fatalf("%v", got)
	}
	if got := p.SubjectsOf(Member{Principal: "user:alice@corp.example.com", GroupNames: []string{"netops-ro"}}); !slices.Equal(got, []string{"alice_direct"}) {
		t.Fatalf("no directory: %v", got)
	}
}

// A group DN is compared as a DN: case, spacing and attribute-type spelling
// do not matter, and a DN that merely contains the text does not match.
func TestAGroupDNIsComparedCanonically(t *testing.T) {
	p := memberPolicy(t, DirectoryOn)
	for dn, want := range map[string]bool{
		"cn=NetOps-OnCall, ou=G, dc=corp":       true,
		"2.5.4.3=netops-oncall,OU=G,DC=corp":    true,
		"CN=x,CN=netops-oncall,OU=G,DC=corp":    false,
		"CN=netops-oncall,OU=G,DC=corp,DC=more": false,
		"not a dn":                              false,
	} {
		m := Member{Principal: "user:z@corp.example.com", Directory: true, Username: "z", GroupDNs: []string{dn}}
		if got := slices.Contains(p.SubjectsOf(m), "netops_oncall"); got != want {
			t.Errorf("%q: matched %v, want %v", dn, got, want)
		}
	}
}

// A group naming something with = that is not a DN is refused at load.
func TestAGroupWithEqualsMustBeADN(t *testing.T) {
	body := "subjects: [{name: g, group: \"CN=a,,\", token_ttl: 5m}]\n" + strings.ReplaceAll(minimalGrant, "subject: a", "subject: g")
	if _, err := loadText(t, body, DirectoryOn); err == nil || !strings.Contains(err.Error(), "holds = but is not a DN") {
		t.Fatalf("%v", err)
	}
}

// Explain says what the mint would: a refused composition is
// composition_refused, and ResolveSubjects (replay's recompile) does not
// re-run the joint check on a record the broker already minted.
func TestExplainMemberRefusedComposition(t *testing.T) {
	p := ceilingPolicy(t)
	m := Member{Principal: "user:dan@corp.example.com", Directory: true, Username: "dan",
		GroupNames: []string{"netops-ro", "netops-ops"}}
	e, err := p.ExplainMember(m, "leaf-01", "", now)
	if err != nil || e.MintError != "composition_refused" || e.NoGrants {
		t.Fatalf("%+v %v", e, err)
	}
	if _, err := p.ResolveSubjects([]string{"netops_ops", "netops_ro"}, "dan", device(t, p, "leaf-01"), now); err != nil {
		t.Fatalf("replay: %v", err)
	}
}
