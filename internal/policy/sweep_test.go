package policy

import (
	"slices"
	"testing"
)

// sweepYAML grants alice on the edge site alone. inventory() puts srx-fw-04,
// srx-fw-05 and srx-fw-22 at site edge, srx-lab-01 at site lab, and the rest
// elsewhere.
const sweepYAML = `
scopes:
  - {name: all_devices, match: {}}
  - {name: edge, match: {site: [edge]}}
  - {name: campus, match: {site: [campus]}}
roles: [{name: ro, privilege: readonly, permit: ["show **"]}]
subjects:
  - {name: fw_ops, identity: ["user:alice@corp.example.com"], username: alice, token_ttl: 5m}
grants:
  - {subject: fw_ops, scope: edge, roles: [ro]}
`

var sweepAlice = MemberOf("user:alice@corp.example.com")

// A sweep lists the devices its scope selects on which the member holds a
// grant, by name, and nothing else: all_devices from a caller granted one
// site is that site (decision 42 ruling 1).
func TestASweepListsOnlyGrantedDevicesTheScopeSelects(t *testing.T) {
	p := mustParse(t, sweepYAML)
	for _, scope := range []string{"all_devices", "edge"} {
		got, next := p.SweepPage(sweepAlice, scope, "", 10, now)
		if want := []string{"srx-fw-04", "srx-fw-05", "srx-fw-22"}; !slices.Equal(got, want) || next != "" {
			t.Errorf("%s: %v next %q, want %v", scope, got, next, want)
		}
	}
}

// An undeclared scope, a declared one selecting no granted device, and an
// unknown principal all answer an empty page (decision 42 ruling 2).
func TestAnUndeclaredScopeAndAnUngrantedOneAnswerAlike(t *testing.T) {
	p := mustParse(t, sweepYAML)
	for name, c := range map[string]struct {
		m     Member
		scope string
	}{
		"undeclared":        {sweepAlice, "nope"},
		"no granted device": {sweepAlice, "campus"},
		"unknown principal": {MemberOf("user:mallory@corp.example.com"), "edge"},
	} {
		if got, next := p.SweepPage(c.m, c.scope, "", 10, now); got != nil || next != "" {
			t.Errorf("%s: %v next %q", name, got, next)
		}
	}
}

// Pages are by name, after the cursor, and the last page names no next.
// A cursor that names no device starts at the next name after it.
func TestASweepPagesByName(t *testing.T) {
	p := mustParse(t, sweepYAML)
	got, next := p.SweepPage(sweepAlice, "edge", "", 2, now)
	if !slices.Equal(got, []string{"srx-fw-04", "srx-fw-05"}) || next != "srx-fw-05" {
		t.Fatalf("page 1: %v next %q", got, next)
	}
	got, next = p.SweepPage(sweepAlice, "edge", next, 2, now)
	if !slices.Equal(got, []string{"srx-fw-22"}) || next != "" {
		t.Fatalf("page 2: %v next %q", got, next)
	}
	got, _ = p.SweepPage(sweepAlice, "edge", "srx-fw-045", 2, now)
	if !slices.Equal(got, []string{"srx-fw-05", "srx-fw-22"}) {
		t.Fatalf("a cursor between names: %v", got)
	}
	if got, next := p.SweepPage(sweepAlice, "edge", "srx-fw-22", 2, now); got != nil || next != "" {
		t.Fatalf("past the end: %v next %q", got, next)
	}
}

// An expired grant selects nothing, as it mints nothing.
func TestAnExpiredGrantSweepsNothing(t *testing.T) {
	p := mustParse(t, `
scopes: [{name: edge, match: {site: [edge]}}]
roles: [{name: ro, privilege: readonly, permit: ["show **"]}]
subjects: [{name: fw_ops, identity: ["user:alice@corp.example.com"], username: alice, token_ttl: 5m}]
grants: [{subject: fw_ops, scope: edge, roles: [ro], expires: 2020-01-01}]
`)
	if got, _ := p.SweepPage(sweepAlice, "edge", "", 10, now); got != nil {
		t.Fatalf("an expired grant: %v", got)
	}
}

// A page walks the member's own granted devices and nothing else, so an
// undeclared scope and a declared one selecting no granted device cost the
// same, and neither walks the inventory (decision 42 ruling 2, "nor a timing
// oracle"). A member with no grant walks nothing.
func TestASweepVisitsOnlyGrantedDevices(t *testing.T) {
	p := mustParse(t, sweepYAML)
	_, _, undeclared := p.sweepPage(sweepAlice, "nope", "", 10, now)
	_, _, ungranted := p.sweepPage(sweepAlice, "campus", "", 10, now)
	_, _, granted := p.sweepPage(sweepAlice, "edge", "", 10, now)
	if undeclared != 3 || ungranted != 3 || granted != 3 {
		t.Fatalf("visits: undeclared %d, ungranted %d, granted %d; want 3, alice's three edge devices, each",
			undeclared, ungranted, granted)
	}
	if _, _, none := p.sweepPage(MemberOf("user:mallory@corp.example.com"), "all_devices", "", 10, now); none != 0 {
		t.Fatalf("a member with no grant visited %d devices", none)
	}
	if n := len(inventory()); n <= 3 {
		t.Fatalf("the inventory has %d devices: the test needs more than alice's three to mean anything", n)
	}
}
