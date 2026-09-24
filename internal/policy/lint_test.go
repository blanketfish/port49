package policy

import (
	"strings"
	"testing"
)

// A policy test on a quarantined device is a deny, device_quarantined: the
// mint refuses it and the daemon closes the connection (spec §10). The other
// devices answer as ever.
func TestATestOnAQuarantinedDeviceIsADeny(t *testing.T) {
	p := mustParse(t, `
scopes: [{name: all_devices, match: {}}]
roles: [{name: op, privilege: operator, permit: [show **]}]
subjects: [{name: s, identity: "user:s@example.com", username: s, token_ttl: 60s}]
grants: [{subject: s, scope: all_devices, roles: [op]}]
tests:
  - {subject: s, device: leaf-01, command: "show version", expect: deny, reason: device_quarantined}
  - {subject: s, device: nx-01, command: "show version", expect: permit}
`)
	results := p.RunTests(noon)
	if len(results) != 2 {
		t.Fatalf("%d results, want 2", len(results))
	}
	for _, r := range results {
		if !r.Pass {
			t.Errorf("%s on %s: permit=%v %s %v", r.Test.Subject, r.Test.Device, r.Permit, r.Reason, r.Err)
		}
	}
}

// Every kind of finding, once: what CI reports about a policy that loads
// (spec §5.5, §6, §12; §14, "Attached roles").
func TestLintReportsWhatAReviewerMustSee(t *testing.T) {
	p := mustParse(t, `
scopes:
  - {name: all_devices, match: {}}
  - {name: baseline, match: {}, attached_roles: {humans: [look], machines: [deny_only]}, on_missing: include}
roles:
  - {name: look, permit: [show version]}
  - {name: deny_only, deny: [reload **]}
  - {name: ro, privilege: readonly, permit: [show **], attributes: {arista_eos: ["priv-lvl*2"], all: ["idletime=30"]}}
subjects:
  - {name: s, identity: "user:s@example.com", username: s, token_ttl: 60s, api: [revoke_others]}
  - {name: gone, identity: "user:gone@example.com", username: gone, token_ttl: 60s}
grants:
  - {subject: s, scope: all_devices, roles: [ro]}
`)
	got := map[string][]string{}
	for _, f := range p.Lint(noon) {
		got[f.Kind] = append(got[f.Kind], f.Message)
	}
	for kind, want := range map[string]string{
		FindingAttachedPermit:     `scope "baseline" attaches role "look"`,
		FindingGrantlessSubject:   `subject "gone" has no grant`,
		FindingAPIRights:          `subject "s" holds api: [revoke_others]`,
		FindingMandatoryAttribute: `role "ro" sends idletime=30 mandatory`,
		FindingAttributeShadowed:  `priv-lvl*2 (role ro) shadows priv-lvl=1 (platform arista_eos, level readonly)`,
	} {
		if len(got[kind]) != 1 || !strings.Contains(got[kind][0], want) {
			t.Errorf("%s: %q, want one finding containing %q", kind, got[kind], want)
		}
	}
	if _, ok := got[FindingGroupSubject]; ok {
		t.Error("no group subject here")
	}
	// A deny-only attached role is routine and is not reported.
	for _, m := range got[FindingAttachedPermit] {
		if strings.Contains(m, "deny_only") {
			t.Errorf("a deny-only attached role was reported: %s", m)
		}
	}
}

// Lint reads the compositions reachable from now, as the shadowed-deny
// report does: a grant that has already lapsed shadows nothing, and one that
// is live, or lapses later, does.
func TestLintReadsOnlyLiveGrants(t *testing.T) {
	const body = `
scopes: [{name: all_devices, match: {}}]
roles:
  - {name: ro, privilege: readonly, permit: [show **]}
  - {name: ir, permit: [show version]}
subjects: [{name: s, identity: "user:s@example.com", username: s, token_ttl: 60s}]
grants:
  - {subject: s, scope: all_devices, roles: [ro]}
  - {subject: s, scope: all_devices, roles: [ir], attributes: {arista_eos: ["priv-lvl*0"]}, expires: EXPIRES}
`
	shadowed := func(expires string) int {
		n := 0
		for _, f := range mustParse(t, strings.Replace(body, "EXPIRES", expires, 1)).Lint(noon) {
			if f.Kind == FindingAttributeShadowed {
				n++
			}
		}
		return n
	}
	if n := shadowed("2026-01-01"); n != 0 {
		t.Errorf("a lapsed grant shadows %d", n)
	}
	if n := shadowed("2027-01-01"); n == 0 {
		t.Error("a live grant shadows nothing")
	}
}
