package policy

import (
	"strings"
	"testing"
)

// §11 shadows exactly one deny, and says so: the CVE deny does not bind
// security_ir on `show chassis cluster status`. That is §5.4's deliberate
// exemption, and §11's own test for it is the acknowledgment (spec §12).
func TestTheCompletePolicyExampleShadowsOneDenyAndItsTestAcknowledgesIt(t *testing.T) {
	p := spec11(t, spec11Raw(t))
	got := p.ShadowedDenies()
	if len(got) != 1 {
		t.Fatalf("shadows %+v", got)
	}
	s := got[0]
	if s.Subject != "security_ir" || s.Deny != "show chassis cluster **" || s.DenyRole != "cve_2026_xxxx" ||
		s.Permit != "show chassis cluster status" || s.PermitRole != "cve_2026_xxxx_assess" ||
		strings.Join(s.Platforms, ",") != "juniper_junos" || s.Possible || !s.Acknowledged {
		t.Fatalf("%+v", s)
	}
}

// A shadow no test exercises is reported unacknowledged, and a permit test on
// a command where the permit wins over the deny acknowledges it. A test on
// another command, or another subject, does not.
func TestAShadowIsAcknowledgedOnlyByATestThatExercisesIt(t *testing.T) {
	const body = `
scopes: [{name: all_devices, match: {}}]
roles:
  - {name: backup, privilege: readonly, permit: [show chassis hardware, show version]}
  - {name: cve, deny: [show chassis **]}
subjects:
  - {name: svc, identity: "app:backup", username: svc-backup, token_ttl: 60s}
  - {name: other, identity: "app:other", username: svc-other, token_ttl: 60s}
grants:
  - {subject: svc, scope: all_devices, roles: [backup, cve]}
  - {subject: other, scope: all_devices, roles: [backup, cve]}
`
	p := mustParse(t, body+`tests:
  - {subject: svc, device: leaf-01, command: "show version", expect: permit}
`)
	got := p.ShadowedDenies()
	if len(got) != 2 || got[0].Subject != "other" || got[1].Subject != "svc" || got[0].Acknowledged || got[1].Acknowledged {
		t.Fatalf("%+v", got)
	}
	if len(got[1].Platforms) != 4 {
		t.Fatalf("the pair meets on every platform in inventory: %+v", got[1].Platforms)
	}
	p = mustParse(t, body+`tests:
  - {subject: svc, device: leaf-01, command: "show chassis hardware", expect: permit}
`)
	got = p.ShadowedDenies()
	if len(got) != 2 || got[0].Acknowledged || !got[1].Acknowledged {
		t.Fatalf("%+v", got)
	}
}
