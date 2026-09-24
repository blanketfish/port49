package policy

import (
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/admission"
)

func deviceNamed(t *testing.T, name string) admission.Device {
	t.Helper()
	for _, d := range inventory() {
		if d.Name == name {
			return d
		}
	}
	t.Fatalf("no device %s", name)
	return admission.Device{}
}

// scoped is spec §11's scopes and the roles they attach, with one grant per
// subject on each scope that matters.
const scoped = `
scopes:
  - {name: all_devices, match: {}}
  - {name: dc_fabric, match: {site: [dc1, dc2], role: [leaf, spine]}}
  - name: srx_unpatched
    match: {platform: juniper_junos, os_version: {lt: "21.4R3-S5"}}
    on_missing: include
    security_log: true
    attached_roles: {humans: [cve_2026_xxxx], machines: [cve_2026_xxxx_machines]}
  - {name: eos_only, match: {platform: arista_eos, site: {re: "^dc"}}}
roles:
  - {name: read_only, privilege: readonly, permit: [show **]}
  - {name: dc_admin, privilege: admin, permit: ["**"]}
  - {name: cve_2026_xxxx, deny: [show chassis cluster **]}
  - {name: cve_2026_xxxx_machines, deny: [show chassis cluster **]}
subjects:
  - {name: noc, identity: "user:noc@example.com", username: noc, token_ttl: 60s}
  - {name: svc, identity: "app:backup", username: svc-backup, token_ttl: 60s}
  - {name: temp, identity: "user:temp@example.com", username: temp, token_ttl: 60s}
  - {name: idle, identity: "user:idle@example.com", username: idle, token_ttl: 60s}
grants:
  - {subject: noc, scope: all_devices, roles: [read_only]}
  - {subject: noc, scope: dc_fabric, roles: [dc_admin], max_privilege: admin}
  - {subject: svc, scope: all_devices, roles: [read_only]}
  - {subject: temp, scope: eos_only, roles: [read_only], expires: "2026-10-01T00:00:00Z"}
`

func composed(t *testing.T, p *Policy, subject, device string, now time.Time) composition {
	t.Helper()
	s, ok := p.Subject(subject)
	if !ok {
		t.Fatalf("no subject %s", subject)
	}
	return p.compose(s, deviceNamed(t, device), now)
}

// Roles are the union across the grants whose scope selects the device, the
// level is the max over them, and the ceiling the max over the grants (spec
// §5.1).
func TestAPrincipalHoldsTheGrantsWhoseScopeSelectsTheDevice(t *testing.T) {
	p := mustParse(t, scoped)
	c := composed(t, p, "noc", "leaf-01", time.Time{})
	if strings.Join(c.roles, ",") != "dc_admin,read_only" || c.level != "admin" || c.ceiling != "admin" ||
		len(c.grants) != 2 || c.grants[0].Scope != "all_devices" {
		t.Fatalf("noc on leaf-01: %+v", c)
	}
	c = composed(t, p, "noc", "campus-sw-7", time.Time{})
	if strings.Join(c.roles, ",") != "read_only" || c.level != "readonly" || c.ceiling != "" {
		t.Fatalf("noc on a campus switch: %+v", c)
	}
}

// Attached roles compose into a grant for the principal's trust domain only,
// and never create access (spec §5.5; §14, "Attached roles").
func TestAttachedRolesFollowTheTrustDomainAndNeverAddADevice(t *testing.T) {
	p := mustParse(t, scoped)
	human := composed(t, p, "noc", "srx-fw-04", time.Time{})
	if strings.Join(human.roles, ",") != "cve_2026_xxxx,read_only" ||
		strings.Join(human.attached["cve_2026_xxxx"], ",") != "srx_unpatched" {
		t.Fatalf("a human on an unpatched SRX: %+v", human)
	}
	machine := composed(t, p, "svc", "srx-fw-04", time.Time{})
	if strings.Join(machine.roles, ",") != "cve_2026_xxxx_machines,read_only" {
		t.Fatalf("a machine on an unpatched SRX gets the machines list: %+v", machine)
	}
	if c := composed(t, p, "idle", "srx-fw-04", time.Time{}); len(c.grants) != 0 || len(c.roles) != 0 {
		t.Fatalf("no declared grant, so the attached role attaches to nothing: %+v", c)
	}
}

// A version the comparator cannot order is a missing one: included by a
// scope that says on_missing: include, and reported as such (spec §5.5). A
// device leaving the scope on the next sync regains the command with no policy
// change (§14, "State-scoped mitigation").
func TestAnIncomparableVersionIsIncludedAndSaysSo(t *testing.T) {
	p := mustParse(t, scoped)
	s := p.scopes["srx_unpatched"]
	for _, tt := range []struct {
		device             string
		selected, reported bool
	}{
		{"srx-fw-04", true, false},  // 21.4R3-S4 < 21.4R3-S5
		{"srx-fw-05", false, false}, // 22.2R1: patched, out of the scope
		{"srx-fw-22", true, true},   // 21.4X75-D40 cannot be ordered against 21.4R3-S5
		{"srx-lab-01", true, false}, // no os_version at all: on_missing
		{"leaf-01", false, false},   // wrong platform
	} {
		sel, rep := s.selects(deviceNamed(t, tt.device))
		if sel != tt.selected || rep != tt.reported {
			t.Errorf("%s: selected %v reported %v, want %v %v", tt.device, sel, rep, tt.selected, tt.reported)
		}
	}
	if c := composed(t, p, "noc", "srx-fw-22", time.Time{}); strings.Join(c.incomparable, ",") != "srx_unpatched" {
		t.Errorf("the composition says which scope took the device in on an incomparable version: %+v", c.incomparable)
	}
	if c := composed(t, p, "noc", "srx-fw-04", time.Time{}); len(c.incomparable) != 0 {
		t.Errorf("a comparable version is not reported: %+v", c.incomparable)
	}
	patched := deviceNamed(t, "srx-fw-04")
	patched.Attributes = map[string]string{"os_version": "21.4R3-S5"}
	if sel, _ := s.selects(patched); sel {
		t.Error("the upgrade lifts the mitigation for that device alone")
	}
}

// A permit-bearing scope excludes what it cannot see, the safe direction for
// a grant (spec §5.5), and on_missing defaults to exclude where no deny is
// attached.
func TestOnMissingExcludesByDefault(t *testing.T) {
	p := mustParse(t, scoped)
	if sel, _ := p.scopes["dc_fabric"].selects(deviceNamed(t, "srx-lab-01")); sel {
		t.Fatal("a device with no site is not in dc_fabric")
	}
	if p.scopes["dc_fabric"].OnMissing != "exclude" {
		t.Fatal("the default is exclude")
	}
	if sel, _ := p.scopes["eos_only"].selects(deviceNamed(t, "leaf-01")); !sel {
		t.Fatal("platform and a regex on site both hold on leaf-01")
	}
}

// A grant that has expired stops matching; `expires` is the grant's, not the
// subject's (spec §5.1).
func TestAnExpiredGrantMatchesNothing(t *testing.T) {
	p := mustParse(t, scoped)
	before := time.Date(2026, 9, 30, 23, 59, 0, 0, time.UTC)
	if c := composed(t, p, "temp", "leaf-01", before); len(c.grants) != 1 {
		t.Fatalf("before expiry: %+v", c)
	}
	if c := composed(t, p, "temp", "leaf-01", before.Add(time.Minute)); len(c.grants) != 0 {
		t.Fatalf("at expiry: %+v", c)
	}
}
