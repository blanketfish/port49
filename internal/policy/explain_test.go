package policy

import (
	"bytes"
	"strings"
	"testing"
	"time"

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
	return e, buf.String()
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
	mustContain(t, out, "deny device_quarantined", "leaf-01 (arista_eos) failed a joint check at load",
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
