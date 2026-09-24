package policy

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/decision"
)

func explained(t *testing.T, p *Policy, subject, principal, device, line string, attrs bool) (Explanation, string) {
	t.Helper()
	e, err := p.Explain(subject, principal, device, line, noon)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	e.Render(&buf, attrs)
	oneVerdict(t, buf.String())
	return e, buf.String()
}

// oneVerdict checks spec §12's "exactly one reason": one line of the output
// is a verdict.
func oneVerdict(t *testing.T, out string) {
	t.Helper()
	n := 0
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "permit ") || strings.HasPrefix(l, "deny ") || strings.HasPrefix(l, "refused ") {
			n++
		}
	}
	if n != 1 {
		t.Errorf("explain printed %d verdicts, not one:\n%s", n, out)
	}
}

func mustContain(t *testing.T, out string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(out, w) {
			t.Errorf("explain output lacks %q:\n%s", w, out)
		}
	}
}

// explain names exactly one reason and the rule and role behind it, and for a
// denied command, the roles that would permit it (spec §12).
func TestExplainNamesOneReasonAndWhoWouldPermit(t *testing.T) {
	p := spec11(t, spec11Raw(t))
	e, out := explained(t, p, "noc_tier1", "", "leaf-01", "reload", false)
	if e.Outcome.Reason != decision.NoRuleMatched {
		t.Fatalf("%+v", e.Outcome)
	}
	mustContain(t, out, "deny no_rule_matched", "rule        no permit matches", "permitted by network_admin",
		"grants      all_devices [no_disruptive read_only]; dc_fabric [interface_tech] expires 2026-12-01T00:00:00.000Z")
	_, out = explained(t, p, "noc_tier1", "", "srx-fw-04", "show chassis cluster status", false)
	mustContain(t, out, "deny no_permit_dominates_deny",
		"rule        show chassis cluster ** (cve_2026_xxxx) [3 3 3 0]",
		"permit      show ** (read_only) [3 0 0 0] does not dominate it",
		"cve_2026_xxxx (attached by srx_unpatched)",
		"permitted by cve_2026_xxxx_assess, network_admin, read_only")
}

// explain says what the device will not honor rather than reporting a
// decision it will not see (spec §4, §5.6, §12): a pipeline on a platform that
// applies modifiers itself, and any command, a revocation or a ceiling on a
// platform that authorizes sessions only.
func TestExplainSaysWhatTheDeviceWillNotHonor(t *testing.T) {
	p := spec11(t, spec11Raw(t))
	_, out := explained(t, p, "netops_admins", "", "leaf-01", "show run | redirect ftp://x", false)
	mustContain(t, out, "permit permit_dominates", "note: arista_eos applies output modifiers itself",
		"note: arista_eos does not declare config_commands")
	_, out = explained(t, p, "svc_oxidized", "", "srx-fw-04", "show chassis hardware", false)
	mustContain(t, out, "note: juniper_junos does not send per-command authorization",
		"a revocation or a session ceiling does not reach a live session")
	_, out = explained(t, p, "noc_tier1", "", "srx-fw-22", "", false)
	mustContain(t, out, "srx_unpatched selected this device because its version could not be compared")
}

// With no command, explain shows what the login would be told, each attribute
// with where it came from (spec §6, "Diagnosing an unfamiliar vendor").
func TestExplainShowsTheSessionAttributes(t *testing.T) {
	p := spec11(t, spec11Raw(t))
	_, out := explained(t, p, "svc_oxidized", "", "leaf-01", "", false)
	mustContain(t, out, "permit context_matched (session)", "level       admin; max_privilege none",
		"priv-lvl=15", "(mandatory)  <- platform arista_eos, level admin")
	_, out = explained(t, p, "noc_tier1", "", "leaf-01", "show version", true)
	mustContain(t, out, "permit permit_dominates", "session attributes that would be returned:", "priv-lvl=7")
}

// A quarantined device is explained as the mint answers it, with every cause
// the device failed at load (spec §10).
func TestExplainNamesAQuarantinedDevice(t *testing.T) {
	p := mustParse(t, `
scopes: [{name: all_devices, match: {}}]
roles: [{name: op, privilege: operator, permit: [show **]}]
subjects: [{name: s, identity: "user:s@example.com", username: s, token_ttl: 60s}]
grants: [{subject: s, scope: all_devices, roles: [op]}]`)
	_, out := explained(t, p, "s", "", "leaf-01", "show version", false)
	mustContain(t, out, "deny device_quarantined", "leaf-01 (arista_eos) fails a joint check now",
		"level operator has no rendering on arista_eos")
	_, out = explained(t, p, "s", "", "nx-01", "show version", false)
	mustContain(t, out, "permit permit_dominates")
}

// Quarantine is time-scoped: explain answers at the time it is asked about. A
// quarantine an expiry will bring on is a note beside the answer that holds
// until then; after it, the device is explained as quarantined.
func TestExplainAnswersAQuarantineAtTheTimeAsked(t *testing.T) {
	p := mustParse(t, `
scopes: [{name: all_devices, match: {}}, {name: dc, match: {site: dc1}}]
roles:
  - {name: op, privilege: operator, permit: [show **]}
  - {name: adm, privilege: admin, permit: ["**"]}
subjects: [{name: s, identity: "user:s@example.com", username: s, token_ttl: 60s}]
grants:
  - {subject: s, scope: all_devices, roles: [op], expires: 2026-11-01}
  - {subject: s, scope: dc, roles: [adm], expires: 2026-10-01}`)
	_, out := explained(t, p, "s", "", "leaf-01", "show version", false)
	mustContain(t, out, "permit permit_dominates",
		"note: will be quarantined from 2026-10-01T00:00:00.000Z, when grant dc [adm] expires: ")
	e, err := p.Explain("s", "", "leaf-01", "show version", time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	e.Render(&buf, false)
	oneVerdict(t, buf.String())
	mustContain(t, buf.String(), "deny device_quarantined", "level operator has no rendering on arista_eos")
	if strings.Contains(buf.String(), "will be quarantined") {
		t.Errorf("a current entry is a cause, not a note:\n%s", buf.String())
	}
}

// A principal with no subject and a subject with no grant on the device are
// no_grants_matched; a device not in inventory is an error, not a denial.
func TestExplainNoGrants(t *testing.T) {
	p := spec11(t, spec11Raw(t))
	_, out := explained(t, p, "", "user:mallory@example.com", "leaf-01", "show version", false)
	mustContain(t, out, "deny no_grants_matched")
	_, out = explained(t, p, "security_ir", "", "leaf-01", "show version", false)
	mustContain(t, out, "deny no_grants_matched", "security_ir holds no grant whose scope selects leaf-01")
	if _, err := p.Explain("noc_tier1", "", "nowhere", "show version", noon); err == nil {
		t.Fatal("a device not in inventory is an error")
	}
	if _, err := p.Explain("nobody", "", "leaf-01", "show version", noon); err == nil {
		t.Fatal("an undeclared subject is an error")
	}
}

// A permit explain cannot compile is a defect it reports, never a role it
// drops: "permitted by none" would send an operator after the wrong thing.
func TestExplainReportsAPermitItCannotCompile(t *testing.T) {
	p := spec11(t, spec11Raw(t))
	p.roles["network_admin"].Permit = append(p.roles["network_admin"].Permit, "** reload")
	if _, err := p.Explain("noc_tier1", "", "leaf-01", "reload", noon); err == nil {
		t.Fatal("a permit that does not parse was dropped silently")
	}
}

// explain answers what the mint would: where the broker refuses the session
// reply, explain says refused with the mint item error, not permit, on the
// session and on a command alike.
func TestExplainNamesTheMintItemError(t *testing.T) {
	policy := func(attr string) *Policy {
		p, err := Parse([]byte(`
scopes: [{name: all_devices, match: {}}]
roles: [{name: r, privilege: admin, permit: ["**"], attributes: {all: ["`+attr+`"]}}]
subjects: [{name: s, identity: "user:s@example.com", username: a_rather_long_username, token_ttl: 60s}]
grants: [{subject: s, scope: all_devices, roles: [r]}]`), Env{Devices: append(inventory(),
			admission.Device{Name: "sw=1", Platform: "arista_eos", Addresses: []netip.Addr{netip.MustParseAddr("10.9.9.9")}})})
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	long, unsafe := policy("note*"+strings.Repeat("x", 230)+"{username}"), policy("where*{device}")
	for _, line := range []string{"", "show version"} {
		_, out := explained(t, long, "s", "", "leaf-01", line, false)
		mustContain(t, out, "refused attribute_too_long", "the broker mints no token")
		_, out = explained(t, unsafe, "", "user:s@example.com", "sw=1", line, false)
		mustContain(t, out, "refused attribute_unsafe")
		_, out = explained(t, unsafe, "s", "", "leaf-01", line, false)
		mustContain(t, out, "permit ")
	}
}

// NX-OS never displays server_msg (spec §15, L2), so the ceiling warning and
// the revocation notices reach nobody there, and explain says so.
func TestExplainSaysNXOSShowsNoServerMsg(t *testing.T) {
	p := mustParse(t, `
scopes: [{name: all_devices, match: {}}]
roles: [{name: ro, privilege: readonly, permit: [show **]}]
subjects: [{name: s, identity: "user:s@example.com", username: s, token_ttl: 60s}]
grants: [{subject: s, scope: all_devices, roles: [ro]}]`)
	for _, line := range []string{"", "show version"} {
		_, out := explained(t, p, "s", "", "nx-01", line, false)
		mustContain(t, out, "note: cisco_nxos never displays port49's server_msg",
			"tests/lab/results/L2-cisco_nxos.md")
		_, out = explained(t, p, "s", "", "leaf-01", line, false)
		if strings.Contains(out, "server_msg") {
			t.Errorf("arista_eos displays server_msg:\n%s", out)
		}
	}
}

// A pipe stage denial names the stage; "permitted by" is about command
// permits, which already match, so it is not printed.
func TestExplainAPipeDenialNamesNoPermitters(t *testing.T) {
	p := mustParse(t, `
scopes: [{name: all_devices, match: {}}]
roles: [{name: ro, privilege: readonly, permit: [show **], pipe: {permit: [include *]}}]
subjects: [{name: s, identity: "user:s@example.com", username: s, token_ttl: 60s}]
grants: [{subject: s, scope: all_devices, roles: [ro]}]`)
	_, out := explained(t, p, "s", "", "leaf-01", "show run | redirect x", false)
	mustContain(t, out, "deny pipe_stage_denied", "stage       1")
	if strings.Contains(out, "permitted by") {
		t.Errorf("a pipe denial printed permitted by:\n%s", out)
	}
}

// An inventory device with no platform is answered as the broker answers it,
// device_unconfigured, after the grants and before the quarantine; a subject
// with no grant there still hears no_grants_matched.
func TestExplainNamesADeviceWithNoPlatform(t *testing.T) {
	p, err := Parse([]byte(`
scopes: [{name: all_devices, match: {}}, {name: nx, match: {platform: cisco_nxos}}]
roles: [{name: ro, privilege: readonly, permit: [show **]}]
subjects:
  - {name: s, identity: "user:s@example.com", username: s, token_ttl: 60s}
  - {name: other, identity: "user:o@example.com", username: o, token_ttl: 60s}
grants: [{subject: s, scope: all_devices, roles: [ro]}, {subject: other, scope: nx, roles: [ro]}]`),
		Env{Devices: append(inventory(), admission.Device{Name: "bare", Addresses: []netip.Addr{netip.MustParseAddr("10.9.9.8")}})})
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{"", "show version"} {
		_, out := explained(t, p, "s", "", "bare", line, false)
		mustContain(t, out, "refused device_unconfigured", "inventory gives this device no platform")
		if strings.Contains(out, "device_quarantined") {
			t.Errorf("the broker answers device_unconfigured, not the quarantine:\n%s", out)
		}
		_, out = explained(t, p, "other", "", "bare", line, false)
		mustContain(t, out, "deny no_grants_matched")
	}
}

// A group subject has no principal until plan 7 reads the directory, so a
// session attribute naming {principal} is checked with it empty, and explain
// says so rather than promise a member's longer principal fits.
func TestExplainSaysAGroupSubjectIsCheckedWithoutAPrincipal(t *testing.T) {
	p := mustParse(t, `
scopes: [{name: all_devices, match: {}}]
roles: [{name: ro, privilege: readonly, permit: [show **], attributes: {all: ["who*{principal}"]}}]
subjects:
  - {name: g, group: "CN=g,OU=Groups,DC=example,DC=com", token_ttl: 60s}
  - {name: s, identity: "user:s@example.com", username: s, token_ttl: 60s}
grants: [{subject: g, scope: all_devices, roles: [ro]}, {subject: s, scope: all_devices, roles: [ro]}]`)
	_, out := explained(t, p, "g", "", "nx-01", "", false)
	mustContain(t, out, "note: g is a group subject", "{principal} was filled in empty", "--principal")
	_, out = explained(t, p, "s", "", "nx-01", "", false)
	if strings.Contains(out, "filled in empty") {
		t.Errorf("a subject with an identity is checked with it:\n%s", out)
	}
}
