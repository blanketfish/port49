package policy

import (
	"strings"
	"testing"

	"github.com/rhwendt/port49/internal/decision"
)

const diffBase = `
scopes: [{name: all_devices, match: {}}]
roles:
  - {name: read_only, privilege: readonly, permit: [show **]}
  - {name: cve, deny: [show chassis **]}
subjects:
  - {name: noc, identity: "user:noc@example.com", username: noc, token_ttl: 60s}
grants:
  - {subject: noc, scope: all_devices, roles: [read_only, cve]}
`

// The gate spec §12 states directly: this change makes command C permitted
// where a deny refused it. It is found on every device group, and a policy
// test in the new version that exercises the permit over the deny is the
// acknowledgment.
func TestTheGateFindsAPermitThatBeatsADeny(t *testing.T) {
	before := mustParse(t, diffBase)
	after := mustParse(t, strings.Replace(diffBase, "permit: [show **]}", "permit: [show **, show chassis hardware]}", 1))
	d := Compare(before, after)
	if len(d.Changes) == 0 || d.Unacknowledged() != len(d.Changes) {
		t.Fatalf("changes %+v", d.Changes)
	}
	devices := 0
	for _, c := range d.Changes {
		if c.Command != "show chassis hardware" || !c.Gated || c.Old.Permit || !c.New.Permit ||
			c.Old.Deny.Role != "cve" || c.New.Decided.Role != "read_only" {
			t.Errorf("%+v", c)
		}
		devices += len(c.Devices)
	}
	if devices != len(inventory()) {
		t.Fatalf("every device is covered once: %d", devices)
	}
	acked := mustParse(t, strings.Replace(diffBase, "permit: [show **]}", "permit: [show **, show chassis hardware]}", 1)+
		"tests:\n  - {subject: noc, device: leaf-01, command: \"show chassis hardware\", expect: permit}\n")
	if d := Compare(before, acked); d.Unacknowledged() != 0 || len(d.Changes) == 0 {
		t.Fatalf("a test acknowledges it on every device: %+v", d.Changes)
	}
}

// Permit growth where no deny stood is a change, reported, and not gated; a
// permit taken away is a narrowing.
func TestGrowthIsReportedAndNotGated(t *testing.T) {
	before := mustParse(t, diffBase)
	after := mustParse(t, strings.Replace(diffBase, "permit: [show **]}", "permit: [show **, ping *]}", 1))
	d := Compare(before, after)
	if len(d.Changes) == 0 || d.Unacknowledged() != 0 {
		t.Fatalf("%+v", d.Changes)
	}
	for _, c := range d.Changes {
		if !strings.HasPrefix(c.Command, "ping ") || c.Gated || c.Old.Reason != decision.NoRuleMatched {
			t.Errorf("%+v", c)
		}
	}
	if back := Compare(after, before); len(back.Changes) != len(d.Changes) || back.Changes[0].New.Permit {
		t.Fatalf("the reverse is a narrowing: %+v", back.Changes)
	}
}

// A level or ceiling that moves is a privilege change (spec §6); a subject
// gaining a device outright is one line, not one per command; a rule carrying
// a regex is named rather than enumerated (spec §12); and a device the new
// version quarantines is listed.
func TestTheDiffReportsWhatItCannotEnumerate(t *testing.T) {
	before := mustParse(t, diffBase)
	after := mustParse(t, strings.Replace(strings.Replace(diffBase,
		"privilege: readonly, permit: [show **]}", "privilege: admin, permit: [show **, \"copy * /^scp:/\"]}", 1),
		"grants:\n", "  - {name: ops, identity: \"user:ops@example.com\", username: ops, token_ttl: 60s}\ngrants:\n"+
			"  - {subject: ops, scope: all_devices, roles: [read_only]}\n", 1))
	d := Compare(before, after)
	if len(d.Levels) == 0 || d.Levels[0].OldLevel != "readonly" || d.Levels[0].NewLevel != "admin" {
		t.Fatalf("levels %+v", d.Levels)
	}
	if len(d.Regex) == 0 || d.Regex[0].Rule.Rule != "copy * /^scp:/" || !d.Regex[0].Added {
		t.Fatalf("regex %+v", d.Regex)
	}
	gained := 0
	for _, a := range d.Access {
		if a.Subject == "ops" && a.Gained {
			gained += len(a.Devices)
		}
	}
	if gained != len(inventory()) {
		t.Fatalf("access %+v", d.Access)
	}
	quarantining := mustParse(t, strings.Replace(diffBase, "privilege: readonly", "privilege: operator", 1))
	if q := Compare(before, quarantining).Quarantined; len(q) != 2 || q[0].Device != "campus-sw-7" {
		t.Fatalf("newly quarantined %+v", q)
	}
}
