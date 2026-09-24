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
	d := Compare(before, after, noon)
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
	if d := Compare(before, acked, noon); d.Unacknowledged() != 0 || len(d.Changes) == 0 {
		t.Fatalf("a test acknowledges it on every device: %+v", d.Changes)
	}
}

// Permit growth where no deny stood is a change, reported, and not gated; a
// permit taken away is a narrowing.
func TestGrowthIsReportedAndNotGated(t *testing.T) {
	before := mustParse(t, diffBase)
	after := mustParse(t, strings.Replace(diffBase, "permit: [show **]}", "permit: [show **, ping *]}", 1))
	d := Compare(before, after, noon)
	if len(d.Changes) == 0 || d.Unacknowledged() != 0 {
		t.Fatalf("%+v", d.Changes)
	}
	for _, c := range d.Changes {
		if !strings.HasPrefix(c.Command, "ping ") || c.Gated || c.Old.Reason != decision.NoRuleMatched {
			t.Errorf("%+v", c)
		}
	}
	if back := Compare(after, before, noon); len(back.Changes) != len(d.Changes) || back.Changes[0].New.Permit {
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
	d := Compare(before, after, noon)
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
	quarantining := mustParse(t, unmappedLevel+strings.Replace(diffBase, "privilege: readonly", "privilege: unmapped", 1))
	if q := Compare(before, quarantining, noon).Quarantined; len(q) != 2 || q[0].Device != "campus-sw-7" {
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
	d := Compare(before, after, noon)
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
	d := Compare(mustParse(t, base), mustParse(t, widened), noon)
	if len(d.Changes) == 0 || d.Unacknowledged() != len(d.Changes) {
		t.Fatalf("changes %+v", d.Changes)
	}
	for _, c := range d.Changes {
		if c.Old.Reason != decision.PipeStageDenied || c.PipeEntry != "save **" || !strings.Contains(c.Command, "| save") {
			t.Errorf("%s %s %q", c.Command, c.Old.Reason, c.PipeEntry)
		}
	}
	acked := widened + "tests:\n  - {subject: noc, device: leaf-01, command: \"show version | save x\", expect: permit}\n"
	if d := Compare(mustParse(t, base), mustParse(t, acked), noon); d.Unacknowledged() != 0 {
		t.Fatalf("a test acknowledges it: %+v", d.Changes)
	}
}

// A device the old version quarantines and the new releases refused
// everything before, so everything the new version permits there is gated;
// and a device quarantined in both for a new cause is newly quarantined.
func TestTheGateSeesAReleaseAndANewCause(t *testing.T) {
	quarantining := unmappedLevel + strings.Replace(diffBase, "privilege: readonly", "privilege: unmapped", 1)
	d := Compare(mustParse(t, quarantining), mustParse(t, diffBase), noon)
	if len(d.Released) != 2 || d.Released[0].Device != "campus-sw-7" || d.Unacknowledged() == 0 {
		t.Fatalf("released %+v, %d unacknowledged", d.Released, d.Unacknowledged())
	}
	for _, c := range d.Changes {
		if c.Old.Reason != decision.DeviceQuarantined || !c.Gated || !slices.Contains([]string{"leaf-01", "campus-sw-7"}, c.Devices[0]) {
			t.Errorf("%+v", c)
		}
	}
	acked := diffBase + "tests:\n  - {subject: noc, device: leaf-01, command: \"show version\", expect: permit}\n"
	if d := Compare(mustParse(t, quarantining), mustParse(t, acked), noon); d.Unacknowledged() != 0 {
		t.Fatalf("a test acknowledges it: %+v", d.Changes)
	}
	second := strings.Replace(quarantining, "grants:\n", "  - {name: ops, identity: \"user:ops@example.com\", username: ops, token_ttl: 60s}\ngrants:\n"+
		"  - {subject: ops, scope: all_devices, roles: [read_only]}\n", 1)
	q := Compare(mustParse(t, quarantining), mustParse(t, second), noon).Quarantined
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
	d := Compare(mustParse(t, base), mustParse(t, after), noon)
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

// The diff reads a version's mints as the broker would: a mint the new
// version refuses is reported and fails the gate, and one the old version
// refused makes everything the new one permits an expansion from refused.
func TestTheDiffSeesTheBrokersMintChecks(t *testing.T) {
	fits := strings.Replace(mintRefused, "a-username-long-enough-to-overflow", "s", 1)
	d := Compare(mustParse(t, fits), mustParse(t, mintRefused), noon)
	if len(d.Refused) == 0 || d.Refused[0].Code != "attribute_too_long" || d.Refused[0].Subject != "s" || len(d.Changes) != 0 {
		t.Fatalf("refused %+v, changes %+v", d.Refused, d.Changes)
	}
	d = Compare(mustParse(t, mintRefused), mustParse(t, fits), noon)
	if len(d.Refused) != 0 || len(d.Changes) == 0 || d.Unacknowledged() != len(d.Changes) {
		t.Fatalf("refused %+v, changes %+v", d.Refused, d.Changes)
	}
	for _, c := range d.Changes {
		if c.OldRefused != "attribute_too_long" || !c.Gated || !c.New.Permit {
			t.Errorf("%+v", c)
		}
	}
	acked := fits + "tests:\n  - {subject: s, device: leaf-01, command: \"show version\", expect: permit}\n"
	if d := Compare(mustParse(t, mintRefused), mustParse(t, acked), noon); d.Unacknowledged() != 0 {
		t.Fatalf("a test acknowledges it: %+v", d.Changes)
	}
}

// A level raise, or a ceiling raised or removed, fails the gate unless a
// session test in the new version asserts the new value for that subject on
// that device; a lowering is reported and does not (owner's ruling
// 2026-09-24; spec §12).
func TestTheGateFailsALevelOrCeilingRaise(t *testing.T) {
	ceilinged := strings.Replace(diffBase, "roles: [read_only, cve]}", "roles: [read_only, cve], max_privilege: readonly}", 1)
	raised := strings.Replace(diffBase, "privilege: readonly, permit", "privilege: admin, permit", 1)
	for _, tt := range []struct {
		name, before, after string
		raises              int
	}{
		// The inventory's four platforms are four groups of devices.
		{"a level raise", diffBase, raised, 1},
		{"a level lowering", raised, diffBase, 0},
		{"a ceiling removed", ceilinged, diffBase, 1},
		{"a ceiling added", diffBase, ceilinged, 0},
		{"a ceiling raised", ceilinged, strings.Replace(ceilinged, "max_privilege: readonly", "max_privilege: admin", 1), 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			d := Compare(mustParse(t, tt.before), mustParse(t, tt.after), noon)
			if len(d.Levels) == 0 {
				t.Fatal("the change is reported")
			}
			raises := 0
			for _, l := range d.Levels {
				if l.Raise {
					raises++
				}
			}
			if raises != tt.raises*4 || d.UnacknowledgedLevels() != tt.raises*4 {
				t.Fatalf("levels %+v: %d raises, %d unacknowledged", d.Levels, raises, d.UnacknowledgedLevels())
			}
		})
	}
	// A session test on one device of each group asserting the new value is
	// the acknowledgment; one asserting the old value, or on another subject,
	// is not.
	levelTest := func(assert string) string {
		out := "tests:\n"
		for _, device := range []string{"campus-sw-7", "nx-01", "xe-01", "srx-lab-01"} {
			out += "  - {subject: noc, device: " + device + ", " + assert + "}\n"
		}
		return out
	}
	// readonly to admin raises the level and the device privilege, 1 to 15:
	// the test asserts both.
	d := Compare(mustParse(t, diffBase), mustParse(t, raised+levelTest("level: admin, max_privilege: none, priv_lvl: 15")), noon)
	if d.UnacknowledgedLevels() != 0 {
		t.Fatalf("a session test acknowledges the raise: %+v", d.Levels)
	}
	d = Compare(mustParse(t, diffBase), mustParse(t, raised+levelTest("level: admin")), noon)
	if d.UnacknowledgedLevels() != 4 {
		t.Fatalf("the level alone does not acknowledge the device privilege's rise: %+v", d.Levels)
	}
	d = Compare(mustParse(t, diffBase), mustParse(t, raised+"tests:\n  - {subject: noc, device: leaf-01, level: admin, priv_lvl: 15}\n"), noon)
	if d.UnacknowledgedLevels() != 3 {
		t.Fatalf("a test on one group acknowledges that group alone: %+v", d.Levels)
	}
	d = Compare(mustParse(t, ceilinged), mustParse(t, diffBase+levelTest("level: readonly, max_privilege: none")), noon)
	if d.UnacknowledgedLevels() != 0 {
		t.Fatalf("a session test asserting no ceiling acknowledges its removal: %+v", d.Levels)
	}
	d = Compare(mustParse(t, ceilinged), mustParse(t, diffBase+"tests:\n  - {subject: noc, device: leaf-01, level: readonly}\n"+
		"  - {subject: noc, device: nx-01, level: readonly}\n"), noon)
	if d.UnacknowledgedLevels() != 4 {
		t.Fatalf("a level alone does not acknowledge a ceiling's removal: %+v", d.Levels)
	}
}

// A regex-constrained widening fails the gate unless a passing policy test in
// the new version exercises it; a narrowing is reported and does not (owner's
// ruling 2026-09-24; spec §12).
func TestTheGateFailsARegexConstrainedWidening(t *testing.T) {
	unacked := func(d Diff) (gated, open int) {
		for _, r := range d.Regex {
			if r.Gated {
				gated++
				if !r.Acknowledged {
					open++
				}
			}
		}
		return gated, open
	}
	// An acknowledgment holds on its own device group (review M1), so the
	// test runs on one device of each.
	test := func(command, expect string) string {
		out := "tests:\n"
		for _, device := range []string{"leaf-01", "nx-01", "xe-01", "srx-lab-01"} {
			out += "  - {subject: noc, device: " + device + ", command: \"" + command + "\", expect: " + expect + "}\n"
		}
		return out
	}
	// A permit carrying a regex, added.
	added := strings.Replace(regexBase, `permit: ["copy /^scp:/ *"]`, `permit: ["copy /^scp:/ *", "copy /^sftp:/ *"]`, 1)
	if g, o := unacked(Compare(mustParse(t, regexBase), mustParse(t, added), noon)); g == 0 || o != g {
		t.Fatalf("an added regex permit: %d gated, %d unacknowledged", g, o)
	}
	if _, o := unacked(Compare(mustParse(t, regexBase), mustParse(t, added+test("copy sftp://h/f flash:", "permit")), noon)); o != 0 {
		t.Fatal("a test the added permit decides acknowledges it")
	}
	if _, o := unacked(Compare(mustParse(t, regexBase), mustParse(t, added+test("copy scp://h/f flash:", "permit")), noon)); o == 0 {
		t.Fatal("a test another permit decides does not")
	}
	// Removed, it is a narrowing.
	if g, _ := unacked(Compare(mustParse(t, added), mustParse(t, regexBase), noon)); g != 0 {
		t.Fatalf("a removed regex permit is not gated: %d", g)
	}
	// A regex permit meeting a deny the change removed.
	freed := strings.Replace(regexBase, "copy * startup-config", "copy * running-config", 1)
	if g, o := unacked(Compare(mustParse(t, regexBase), mustParse(t, freed), noon)); g == 0 || o != g {
		t.Fatalf("a regex permit a removed deny frees: %d gated, %d unacknowledged", g, o)
	}
	if _, o := unacked(Compare(mustParse(t, regexBase), mustParse(t, freed+test("copy scp://h/f startup-config", "permit")), noon)); o != 0 {
		t.Fatal("a test of that permit over that deny acknowledges it")
	}
	// A deny carrying a regex, rewritten wider: no command flips, so a test it
	// still refuses acknowledges nothing (review I1), and an acknowledge:
	// entry naming the old rule with a reason does.
	regexDeny := strings.Replace(regexBase, "copy * startup-config", "copy * /^start/", 1)
	wider := strings.Replace(regexBase, "copy * startup-config", "copy * /^(start|run)/", 1)
	if g, o := unacked(Compare(mustParse(t, regexDeny), mustParse(t, wider), noon)); g == 0 || o != g {
		t.Fatalf("a rewritten regex deny: %d gated, %d unacknowledged", g, o)
	}
	if _, o := unacked(Compare(mustParse(t, regexDeny), mustParse(t, wider+test("copy scp://h/f startup-config", "deny")), noon)); o == 0 {
		t.Fatal("a test expecting deny never acknowledges a widening")
	}
	written := wider + "acknowledge:\n  - {role: guard, rule: \"copy * /^start/\", reason: \"rewritten wider as /^(start|run)/\"}\n"
	if d := Compare(mustParse(t, regexDeny), mustParse(t, written), noon); d.UnacknowledgedRegex() != 0 {
		t.Fatalf("an acknowledge: entry naming the old rule acknowledges it: %+v", d.Regex)
	} else {
		for _, r := range d.Regex {
			if r.Gated && r.AcknowledgedBy != "rewritten wider as /^(start|run)/" {
				t.Fatalf("the diff carries the entry's reason: %+v", r)
			}
		}
	}
	stale := wider + "acknowledge:\n  - {role: guard, rule: \"copy * /^stort/\", reason: \"typo\"}\n"
	if _, o := unacked(Compare(mustParse(t, regexDeny), mustParse(t, stale), noon)); o == 0 {
		t.Fatal("an entry naming another rule acknowledges nothing")
	}
	// Added, it is a narrowing: replacing the word deny with a regex one gates
	// only the word deny's removal where it meets the regex permit, once per
	// platform group.
	if g, _ := unacked(Compare(mustParse(t, regexBase), mustParse(t, regexDeny), noon)); g != 4 {
		t.Fatalf("replacing a word deny with a regex one gates only the removal's exposure: %d", g)
	}
}

// The privilege gate compares what the device gets, not level names (review
// C1; spec §12): each probe the review ran raised privilege with the gate
// silent, and each now fails it until a session test asserts the new value.
func TestTheGateFailsEveryKindOfPrivilegeRaise(t *testing.T) {
	custom := "privilege_levels: [{name: readonly}, {name: operator}, {name: admin}, {name: netops, parent: readonly}]\n" +
		strings.Replace(diffBase, "privilege: readonly", "privilege: netops", 1)
	ceilinged := strings.Replace(diffBase, "roles: [read_only, cve]}", "roles: [read_only, cve], max_privilege: admin}", 1)
	for _, tt := range []struct {
		name, before, after string
		groups              int
		dimension           string
		ack                 string
	}{
		{"a grant attribute priv-lvl=15", diffBase,
			strings.Replace(diffBase, "roles: [read_only, cve]}", "roles: [read_only, cve], attributes: {all: [priv-lvl=15]}}", 1),
			4, "priv_lvl", "priv_lvl: 15"},
		{"a role attribute priv-lvl=15 on one platform", diffBase,
			strings.Replace(diffBase, "{name: read_only, privilege: readonly, permit: [show **]}",
				"{name: read_only, privilege: readonly, permit: [show **], attributes: {arista_eos: [priv-lvl=15]}}", 1),
			1, "priv_lvl", "priv_lvl: 15"},
		{"a custom level's parent moved up", custom, strings.Replace(custom, "parent: readonly", "parent: admin", 1),
			4, "priv_lvl", "priv_lvl: 15"},
		{"enable switched on under a ceiling", ceilinged,
			strings.Replace(ceilinged, "token_ttl: 60s}", "token_ttl: 60s, enable: token}", 1), 4, "enable", "enable: token"},
		{"enable switched on with no ceiling", diffBase,
			strings.Replace(diffBase, "token_ttl: 60s}", "token_ttl: 60s, enable: token}", 1), 4, "enable", "enable: token"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			d := Compare(mustParse(t, tt.before), mustParse(t, tt.after), noon)
			if d.UnacknowledgedLevels() != tt.groups {
				t.Fatalf("levels %+v: %d unacknowledged, want %d", d.Levels, d.UnacknowledgedLevels(), tt.groups)
			}
			for _, l := range d.Levels {
				if l.Raise && !slices.Contains(l.Raised, tt.dimension) {
					t.Errorf("%+v does not name %s", l, tt.dimension)
				}
			}
			tests := "tests:\n"
			for _, device := range []string{"leaf-01", "nx-01", "xe-01", "srx-lab-01"} {
				tests += "  - {subject: noc, device: " + device + ", " + tt.ack + "}\n"
			}
			// A test on a group that did not rise may fail; it acknowledges
			// nothing there and nothing there needs it.
			d = Compare(mustParse(t, tt.before), mustParse(t, tt.after+tests), noon)
			if n := d.UnacknowledgedLevels(); n != 0 {
				t.Fatalf("session tests on every group: %d unacknowledged, %+v", n, d.Levels)
			}
		})
	}
}

// A session test acknowledges a raise only at the instant it passes: one that
// passes only after a grant expires does not acknowledge the raise before it
// (review M2). At noon the ceiling is admin, from the grant that expires;
// after it, none. The test asserts none.
func TestASessionAckHoldsOnlyAtItsInstant(t *testing.T) {
	after := strings.Replace(diffBase, "  - {name: cve, deny: [show chassis **]}\n",
		"  - {name: cve, deny: [show chassis **]}\n  - {name: adm, privilege: admin, permit: [show **]}\n", 1)
	after = strings.Replace(after, "  - {subject: noc, scope: all_devices, roles: [read_only, cve]}\n",
		"  - {subject: noc, scope: all_devices, roles: [read_only, cve, adm], max_privilege: admin, expires: 2026-10-01}\n"+
			"  - {subject: noc, scope: all_devices, roles: [read_only, adm]}\n", 1)
	later := "tests:\n"
	for _, device := range []string{"leaf-01", "nx-01", "xe-01", "srx-lab-01"} {
		later += "  - {subject: noc, device: " + device + ", level: admin, max_privilege: none, priv_lvl: 15}\n"
	}
	d := Compare(mustParse(t, diffBase), mustParse(t, after+later), noon)
	atNoon, afterwards := 0, 0
	for _, l := range d.Levels {
		switch {
		case l.At.Equal(noon) && l.Raise && !l.Acknowledged:
			atNoon++
		case !l.At.Equal(noon) && l.Raise && l.Acknowledged:
			afterwards++
		}
	}
	if atNoon != 4 || afterwards != 4 {
		t.Fatalf("levels %+v: %d unacknowledged at noon, %d acknowledged after the expiry", d.Levels, atNoon, afterwards)
	}
}

// The review's probe (I1): narrowing `/^(wri|rel)/` to `/^wri/` frees reload
// fleet-wide, and a test that `write erase` is still refused must not
// acknowledge it. A test that reload is now permitted does, on its own
// group; an acknowledge: entry does everywhere.
func TestNarrowingARegexDenyIsNotAcknowledgedByADenyTest(t *testing.T) {
	base := `
scopes: [{name: all_devices, match: {}}]
roles:
  - {name: ops, privilege: readonly, permit: ["**"]}
  - {name: guard, deny: ["/^(wri|rel)/ **"]}
subjects:
  - {name: noc, identity: "user:noc@example.com", username: noc, token_ttl: 60s}
grants:
  - {subject: noc, scope: all_devices, roles: [ops, guard]}
`
	narrowed := strings.Replace(base, "/^(wri|rel)/ **", "/^wri/ **", 1)
	gate := func(after string) int {
		d := Compare(mustParse(t, base), mustParse(t, after), noon)
		return d.Unacknowledged() + d.UnacknowledgedLevels() + d.UnacknowledgedRegex() + len(d.Quarantined) + len(d.Refused)
	}
	if n := gate(narrowed); n != 4 {
		t.Fatalf("no test: gate %d, want 4 groups", n)
	}
	if n := gate(narrowed + "tests:\n  - {subject: noc, device: leaf-01, command: \"write erase\", expect: deny}\n"); n != 4 {
		t.Fatalf("a deny test acknowledges nothing: gate %d", n)
	}
	if n := gate(narrowed + "tests:\n  - {subject: noc, device: leaf-01, command: \"reload now\", expect: permit}\n"); n != 3 {
		t.Fatalf("a permit flip acknowledges its own group alone (review M1): gate %d", n)
	}
	if n := gate(narrowed + "acknowledge:\n  - {role: guard, rule: \"/^(wri|rel)/ **\", reason: \"reload moves to the change window\"}\n"); n != 0 {
		t.Fatalf("an acknowledge: entry: gate %d", n)
	}
}
