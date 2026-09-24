package policy

import (
	"slices"
	"strings"
	"testing"
	"time"

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
	d := Compare(before, after, time.Now())
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
	if d := Compare(before, acked, time.Now()); d.Unacknowledged() != 0 || len(d.Changes) == 0 {
		t.Fatalf("a test acknowledges it on every device: %+v", d.Changes)
	}
}

// Permit growth where no deny stood is a change, reported, and not gated; a
// permit taken away is a narrowing.
func TestGrowthIsReportedAndNotGated(t *testing.T) {
	before := mustParse(t, diffBase)
	after := mustParse(t, strings.Replace(diffBase, "permit: [show **]}", "permit: [show **, ping *]}", 1))
	d := Compare(before, after, time.Now())
	if len(d.Changes) == 0 || d.Unacknowledged() != 0 {
		t.Fatalf("%+v", d.Changes)
	}
	for _, c := range d.Changes {
		if !strings.HasPrefix(c.Command, "ping ") || c.Gated || c.Old.Reason != decision.NoRuleMatched {
			t.Errorf("%+v", c)
		}
	}
	if back := Compare(after, before, time.Now()); len(back.Changes) != len(d.Changes) || back.Changes[0].New.Permit {
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
	d := Compare(before, after, time.Now())
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
	if q := Compare(before, quarantining, time.Now()).Quarantined; len(q) != 2 || q[0].Device != "campus-sw-7" {
		t.Fatalf("newly quarantined %+v", q)
	}
}

const regexBase = `
scopes: [{name: all_devices, match: {}}]
roles:
  - {name: backup, privilege: readonly, permit: ["copy /^scp:/ *"]}
  - {name: guard, deny: [copy * startup-config]}
subjects:
  - {name: noc, identity: "user:noc@example.com", username: noc, token_ttl: 60s}
grants:
  - {subject: noc, scope: all_devices, roles: [backup, guard]}
`

// Narrowing a deny frees what an unchanged regex permit matches: the command
// is enumerated through an argument the regex matches, and gated, and the
// permit the changed deny meets is named as regex-constrained (spec §12).
func TestTheGateSeesARegexPermitAChangedDenyFrees(t *testing.T) {
	before := mustParse(t, regexBase)
	after := mustParse(t, strings.Replace(regexBase, "copy * startup-config", "copy * running-config", 1))
	d := Compare(before, after, time.Now())
	gated := 0
	for _, c := range d.Changes {
		if c.Gated && c.Old.Deny.Rule == "copy * startup-config" && c.New.Decided.Rule == "copy /^scp:/ *" {
			gated++
		}
	}
	if gated == 0 || d.Unacknowledged() == 0 {
		t.Fatalf("changes %+v", d.Changes)
	}
	exposed := false
	for _, r := range d.Regex {
		exposed = exposed || (r.Rule.Rule == "copy /^scp:/ *" && r.Deny.Rule == "copy * startup-config" && !r.Added)
	}
	if !exposed {
		t.Fatalf("regex %+v", d.Regex)
	}
}

const expiryBase = `
scopes: [{name: all_devices, match: {}}]
roles:
  - {name: read_only, privilege: readonly, permit: [show **]}
  - {name: cve, deny: [show chassis **]}
  - {name: ir, permit: [show chassis hardware]}
subjects:
  - {name: noc, identity: "user:noc@example.com", username: noc, token_ttl: 60s}
grants:
  - {subject: noc, scope: all_devices, roles: [read_only, cve]}
  - {subject: noc, scope: all_devices, roles: [ir], expires: 2026-01-01}
`

// The diff reads each version at now and at every later expiry: re-arming a
// lapsed grant is an expansion now, and removing an `expires:` is one at the
// instant the grant would have lapsed.
func TestTheGateSeesAGrantsExpiry(t *testing.T) {
	now := time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC)
	rearmed := func(before, after string, at time.Time) {
		t.Helper()
		d := Compare(mustParse(t, before), mustParse(t, after), now)
		for _, c := range d.Changes {
			if c.Command != "show chassis hardware" || !c.Gated || !c.At.Equal(at) {
				t.Errorf("%s %v %v", c.Command, c.Gated, c.At)
			}
		}
		if len(d.Changes) == 0 || d.Unacknowledged() != len(d.Changes) {
			t.Fatalf("changes %+v", d.Changes)
		}
	}
	rearmed(expiryBase, strings.Replace(expiryBase, "2026-01-01", "2030-01-01", 1), now)
	rearmed(strings.Replace(expiryBase, "2026-01-01", "2027-01-01", 1),
		strings.Replace(expiryBase, ", expires: 2026-01-01", "", 1), time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC))
}

// A widened pipe allowlist permits a pipeline stage the old one refused: a
// change from pipe_stage_denied, gated until a test exercises the entry.
func TestTheGateSeesAWidenedPipeAllowlist(t *testing.T) {
	base := strings.Replace(diffBase, "permit: [show **]}", "permit: [show **], pipe: {permit: [include **]}}", 1)
	widened := strings.Replace(base, "[include **]", "[include **, save **]", 1)
	d := Compare(mustParse(t, base), mustParse(t, widened), time.Now())
	if len(d.Changes) == 0 || d.Unacknowledged() != len(d.Changes) {
		t.Fatalf("changes %+v", d.Changes)
	}
	for _, c := range d.Changes {
		if c.Old.Reason != decision.PipeStageDenied || c.PipeEntry != "save **" || !strings.Contains(c.Command, "| save") {
			t.Errorf("%s %s %q", c.Command, c.Old.Reason, c.PipeEntry)
		}
	}
	acked := widened + "tests:\n  - {subject: noc, device: leaf-01, command: \"show version | save x\", expect: permit}\n"
	if d := Compare(mustParse(t, base), mustParse(t, acked), time.Now()); d.Unacknowledged() != 0 {
		t.Fatalf("a test acknowledges it: %+v", d.Changes)
	}
}

// A device the old version quarantines and the new releases refused
// everything before, so everything the new version permits there is gated;
// and a device quarantined in both for a new cause is newly quarantined.
func TestTheGateSeesAReleaseAndANewCause(t *testing.T) {
	quarantining := strings.Replace(diffBase, "privilege: readonly", "privilege: operator", 1)
	d := Compare(mustParse(t, quarantining), mustParse(t, diffBase), time.Now())
	if len(d.Released) != 2 || d.Released[0].Device != "campus-sw-7" || d.Unacknowledged() == 0 {
		t.Fatalf("released %+v, %d unacknowledged", d.Released, d.Unacknowledged())
	}
	for _, c := range d.Changes {
		if c.Old.Reason != decision.DeviceQuarantined || !c.Gated || !slices.Contains([]string{"leaf-01", "campus-sw-7"}, c.Devices[0]) {
			t.Errorf("%+v", c)
		}
	}
	acked := diffBase + "tests:\n  - {subject: noc, device: leaf-01, command: \"show version\", expect: permit}\n"
	if d := Compare(mustParse(t, quarantining), mustParse(t, acked), time.Now()); d.Unacknowledged() != 0 {
		t.Fatalf("a test acknowledges it: %+v", d.Changes)
	}
	second := strings.Replace(quarantining, "grants:\n", "  - {name: ops, identity: \"user:ops@example.com\", username: ops, token_ttl: 60s}\ngrants:\n"+
		"  - {subject: ops, scope: all_devices, roles: [read_only]}\n", 1)
	q := Compare(mustParse(t, quarantining), mustParse(t, second), time.Now()).Quarantined
	if len(q) != 2 || len(q[0].Entries) != 1 || !strings.Contains(q[0].Entries[0].Cause, `"ops"`) {
		t.Fatalf("newly quarantined %+v", q)
	}
}

// On IOS-XE a deny's `*` in the interface position also covers the name and
// index the device sends apart (spec §3 rule 5), so the diff finds adding
// `default interface *` a narrowing on `default interface <name> <index>`
// there and nowhere else, as the daemon would decide it.
func TestTheDiffSeesASplitAnyDeny(t *testing.T) {
	base := strings.Replace(diffBase, "permit: [show **]}", "permit: [show **, default **]}", 1)
	after := strings.Replace(base, "deny: [show chassis **]}", "deny: [show chassis **, default interface *]}", 1)
	d := Compare(mustParse(t, base), mustParse(t, after), time.Now())
	split := false
	for _, c := range d.Changes {
		if len(strings.Fields(c.Command)) == 4 && strings.HasPrefix(c.Command, "default interface ") {
			if !slices.Equal(c.Devices, []string{"xe-01"}) || !c.Old.Permit || c.New.Permit {
				t.Errorf("%+v", c)
			}
			split = true
		}
	}
	if !split {
		t.Fatalf("no split change: %+v", d.Changes)
	}
}
