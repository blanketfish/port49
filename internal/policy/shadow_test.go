package policy

import (
	"strings"
	"testing"

	"github.com/rhwendt/port49/internal/admission"
)

// §11 shadows exactly one deny, and says so: the CVE deny does not bind
// security_ir on `show chassis cluster status`. That is §5.4's deliberate
// exemption, and §11's own test for it is the acknowledgment (spec §12).
func TestTheCompletePolicyExampleShadowsOneDenyAndItsTestAcknowledgesIt(t *testing.T) {
	p := spec11(t, spec11Raw(t))
	got := p.ShadowedDenies(noon)
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
	got := p.ShadowedDenies(noon)
	if len(got) != 2 || got[0].Subject != "other" || got[1].Subject != "svc" || got[0].Acknowledged || got[1].Acknowledged {
		t.Fatalf("%+v", got)
	}
	if len(got[1].Platforms) != 4 {
		t.Fatalf("the pair meets on every platform in inventory: %+v", got[1].Platforms)
	}
	p = mustParse(t, body+`tests:
  - {subject: svc, device: leaf-01, command: "show chassis hardware", expect: permit}
`)
	got = p.ShadowedDenies(noon)
	if len(got) != 2 || got[0].Acknowledged || !got[1].Acknowledged {
		t.Fatalf("%+v", got)
	}
}

// A device quarantined now comes back when the grant that quarantines it
// expires, with the composition that is left: the report covers that one too,
// or the shadow would go live unreported the day the grant lapses.
func TestAShadowOnADeviceAnExpiryReturnsIsReported(t *testing.T) {
	p, err := Parse([]byte(`
scopes: [{name: all_devices, match: {}}]
roles:
  - {name: op, privilege: operator, permit: [show version]}
  - {name: ro, privilege: readonly, permit: [show chassis hardware]}
  - {name: cve, deny: [show chassis **]}
subjects: [{name: s, identity: "user:s@example.com", username: s, token_ttl: 60s}]
grants:
  - {subject: s, scope: all_devices, roles: [op], expires: 2026-10-01}
  - {subject: s, scope: all_devices, roles: [ro, cve]}
`), Env{Devices: []admission.Device{deviceNamed(t, "campus-sw-7")}, Now: noon})
	if err != nil {
		t.Fatal(err)
	}
	if _, q := p.Quarantined("campus-sw-7", noon); !q {
		t.Fatal("operator has no rendering on arista_eos: the device should be quarantined now")
	}
	got := p.ShadowedDenies(noon)
	if len(got) != 1 || got[0].Subject != "s" || got[0].DenyRole != "cve" || got[0].PermitRole != "ro" ||
		strings.Join(got[0].Platforms, ",") != "arista_eos" || got[0].Acknowledged {
		t.Fatalf("%+v", got)
	}
}

// Every permit that beats the deny on a tested command is acknowledged by the
// test, not only the one that decided it: two roles carrying the same permit
// would otherwise leave one pair no test could ever acknowledge (spec §12).
func TestATestAcknowledgesEveryPermitThatBeatsTheDeny(t *testing.T) {
	p := mustParse(t, `
scopes: [{name: all_devices, match: {}}]
roles:
  - {name: backup, privilege: readonly, permit: [show version]}
  - {name: noc, privilege: readonly, permit: [show version]}
  - {name: cve, deny: [show **]}
subjects: [{name: svc, identity: "app:backup", username: svc-backup, token_ttl: 60s}]
grants: [{subject: svc, scope: all_devices, roles: [backup, noc, cve]}]
tests:
  - {subject: svc, device: leaf-01, command: "show version", expect: permit}
`)
	got := p.ShadowedDenies(noon)
	if len(got) != 2 || got[0].PermitRole != "backup" || got[1].PermitRole != "noc" ||
		!got[0].Acknowledged || !got[1].Acknowledged {
		t.Fatalf("%+v", got)
	}
}

// Acknowledgments are read at the gate's present, like its tests: a grant
// already expired does not compose, so the deny it carried cannot make a test
// that passes now look as if it fails.
func TestAnAcknowledgmentIsReadAtThePresent(t *testing.T) {
	e := env()
	e.Now = noon
	p, err := Parse([]byte(`
scopes: [{name: all_devices, match: {}}]
roles:
  - {name: ro, privilege: readonly, permit: [show chassis hardware]}
  - {name: cve, deny: [show chassis **]}
  - {name: blk, deny: [show chassis hardware]}
subjects: [{name: s, identity: "user:s@example.com", username: s, token_ttl: 60s}]
grants:
  - {subject: s, scope: all_devices, roles: [ro, cve]}
  - {subject: s, scope: all_devices, roles: [blk], expires: 2026-09-01}
tests:
  - {subject: s, device: leaf-01, command: "show chassis hardware", expect: permit}
`), e)
	if err != nil {
		t.Fatal(err)
	}
	got := p.ShadowedDenies(noon)
	if len(got) != 1 || got[0].DenyRole != "cve" || !got[0].Acknowledged {
		t.Fatalf("%+v", got)
	}
}
