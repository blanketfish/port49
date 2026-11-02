package policy

import (
	"strings"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/platform"
)

// classAgesBody is three roles at three levels, each granted to its own
// subject: ops caps its session at 1h, view names no cap, forever says never.
const classAgesBody = scopeOK + `roles:
  - {name: ops, privilege: operator, permit: ["show **"], max_session_age: 1h}
  - {name: view, privilege: readonly, permit: ["show **"]}
  - {name: forever, privilege: admin, permit: ["**"], max_session_age: never}
subjects:
  - {name: s_ops, identity: ["user:ops@example.com"], username: ops, token_ttl: 60s}
  - {name: s_view, identity: ["user:view@example.com"], username: view, token_ttl: 60s}
  - {name: s_forever, identity: ["user:forever@example.com"], username: forever, token_ttl: 60s}
grants:
  - {subject: s_ops, scope: all_devices, roles: [ops]}
  - {subject: s_view, scope: all_devices, roles: [view]}
  - {subject: s_forever, scope: all_devices, roles: [forever]}
`

func classAges(t *testing.T, delivery, body string) platform.ClassAges {
	t.Helper()
	p := parseProjected(t, delivery, body)
	ages, err := p.ClassAges("juniper_junos", 12*time.Hour, noon)
	if err != nil {
		t.Fatal(err)
	}
	return ages
}

func TestAClassTakesTheLeastCeilingLandingInIt(t *testing.T) {
	ages := classAges(t, platform.BitDeliveryLocalUserName, classAgesBody)
	if got := ages.ByClass["p49-operator"]; got != time.Hour {
		t.Errorf("p49-operator = %v, want 1h", got)
	}
	if got := ages.ByClass["p49-readonly"]; got != 12*time.Hour {
		t.Errorf("p49-readonly = %v, want the 12h default", got)
	}
}

func TestANeverClassWritesNoIdleTimeout(t *testing.T) {
	ages := classAges(t, platform.BitDeliveryLocalUserName, classAgesBody)
	if got, ok := ages.ByClass["p49-admin"]; !ok || got != 0 {
		t.Fatalf("p49-admin = %v (present %v), want 0", got, ok)
	}
	d := projectedEnv(platform.BitDeliveryLocalUserName).Sets[projectedSet]["juniper_junos"]
	lines, err := platform.ReferenceClasses(d, ages)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range lines {
		if strings.HasPrefix(l, "set system login class p49-admin idle-timeout") {
			t.Errorf("a never class carries %q", l)
		}
	}
	if !contains(lines, "set system login class p49-operator idle-timeout 60") {
		t.Errorf("p49-operator lost its line:\n%s", strings.Join(lines, "\n"))
	}
}

func TestASharedClassTakesTheLeast(t *testing.T) {
	body := strings.Replace(classAgesBody, "  - {name: view,", "  - {name: brief, privilege: operator, permit: [\"show **\"], "+
		"max_session_age: 30m}\n  - {name: view,", 1)
	body = strings.Replace(body, "subjects:\n", "subjects:\n  - {name: s_brief, identity: [\"user:brief@example.com\"], username: brief, token_ttl: 60s}\n", 1)
	body += "  - {subject: s_brief, scope: all_devices, roles: [brief]}\n"
	if got := classAges(t, platform.BitDeliveryLocalUserName, body).ByClass["p49-operator"]; got != 30*time.Minute {
		t.Errorf("p49-operator = %v, want 30m", got)
	}
}

func TestAClassNoSessionLandsInKeepsTheDefault(t *testing.T) {
	ages := classAges(t, platform.BitDeliveryLocalUserName, classAgesBody)
	if _, ok := ages.ByClass[platform.RemoteClass]; ok {
		t.Errorf("p49-remote has an entry, but no session lands in it: %v", ages.ByClass)
	}
	d := projectedEnv(platform.BitDeliveryLocalUserName).Sets[projectedSet]["juniper_junos"]
	lines, err := platform.ReferenceClasses(d, ages)
	if err != nil {
		t.Fatal(err)
	}
	if !contains(lines, "set system login class p49-remote idle-timeout 720") {
		t.Errorf("p49-remote is not at the default:\n%s", strings.Join(lines, "\n"))
	}
}

func TestTheDefaultDeliveryLandsEverySessionInRemote(t *testing.T) {
	ages := classAges(t, platform.BitDeliveryUserPermissions, classAgesBody)
	if len(ages.ByClass) != 1 || ages.ByClass[platform.RemoteClass] != time.Hour {
		t.Errorf("ByClass = %v, want p49-remote alone at 1h", ages.ByClass)
	}
}

func TestASessionOffAProjectedPlatformIsSkipped(t *testing.T) {
	p := parseProjected(t, platform.BitDeliveryLocalUserName, classAgesBody)
	ages, err := p.ClassAges("arista_eos", 12*time.Hour, noon)
	if err != nil {
		t.Fatal(err)
	}
	if len(ages.ByClass) != 0 {
		t.Errorf("ByClass = %v, want none: arista_eos projects nothing", ages.ByClass)
	}
}

func contains(lines []string, want string) bool {
	for _, l := range lines {
		if l == want {
			return true
		}
	}
	return false
}

// A quarantined device mints nothing, so its would-be sessions land in no
// class and it never fails the export or the check for the rest of the fleet
// (ShadowedDenies, lint and intersect skip it the same way).
func TestAQuarantinedDeviceLandsNoSessionAndFailsNothing(t *testing.T) {
	body := strings.Replace(classAgesBody, "roles:\n", "roles:\n  - {name: risky, privilege: admin, permit: [\"**\"], max_session_age: 5m}\n", 1)
	body = strings.Replace(body, "scopes:\n", "scopes:\n  - {name: lab, match: {site: lab}}\n", 1)
	body = strings.Replace(body, "subjects:\n", "subjects:\n  - {name: s_risky, identity: [\"user:risky@example.com\"], username: risky, token_ttl: 60s}\n", 1)
	body += "  - {subject: s_risky, scope: lab, roles: [risky], max_privilege: operator}\n"
	p := parseProjected(t, platform.BitDeliveryLocalUserName, body)
	if _, q := p.Quarantined("srx-lab-01", noon); !q {
		t.Fatal("the fixture does not quarantine srx-lab-01")
	}
	ages, err := p.ClassAges("juniper_junos", 12*time.Hour, noon)
	if err != nil {
		t.Fatalf("a quarantined device failed ClassAges: %v", err)
	}
	want := classAges(t, platform.BitDeliveryLocalUserName, classAgesBody)
	if len(ages.ByClass) != len(want.ByClass) {
		t.Fatalf("ByClass = %v, want %v", ages.ByClass, want.ByClass)
	}
	for class, age := range want.ByClass {
		if ages.ByClass[class] != age {
			t.Errorf("%s = %v, want %v: the quarantined device's sessions counted", class, ages.ByClass[class], age)
		}
	}
}
