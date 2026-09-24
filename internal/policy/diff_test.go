package policy

import (
	"crypto/sha256"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/platform"
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
	if q := Compare(before, quarantining, noon).Quarantined; len(q) != 4 || q[0].Device != "campus-sw-7" {
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
	if len(d.Released) != 4 || d.Released[0].Device != "campus-sw-7" || d.Unacknowledged() == 0 {
		t.Fatalf("released %+v, %d unacknowledged", d.Released, d.Unacknowledged())
	}
	for _, c := range d.Changes {
		if c.Old.Reason != decision.DeviceQuarantined || !c.Gated ||
			!slices.Contains([]string{"leaf-01", "campus-sw-7", "nx-01", "xe-01"}, c.Devices[0]) {
			t.Errorf("%+v", c)
		}
	}
	acked := diffBase + "tests:\n"
	for _, device := range []string{"leaf-01", "nx-01", "xe-01"} {
		acked += "  - {subject: noc, device: " + device + ", command: \"show version\", expect: permit}\n"
	}
	if d := Compare(mustParse(t, quarantining), mustParse(t, acked), noon); d.Unacknowledged() != 0 {
		t.Fatalf("a test acknowledges it: %+v", d.Changes)
	}
	second := strings.Replace(quarantining, "grants:\n", "  - {name: ops, identity: \"user:ops@example.com\", username: ops, token_ttl: 60s}\ngrants:\n"+
		"  - {subject: ops, scope: all_devices, roles: [read_only]}\n", 1)
	q := Compare(mustParse(t, quarantining), mustParse(t, second), noon).Quarantined
	if len(q) != 4 || len(q[0].Entries) != 1 || !strings.Contains(q[0].Entries[0].Cause, `"ops"`) {
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
	levelTest := func(assert string, replies map[string]string) string {
		out := "tests:\n"
		for _, device := range []string{"campus-sw-7", "nx-01", "xe-01", "srx-lab-01"} {
			out += "  - {subject: noc, device: " + device + ", " + assert + replies[device] + "}\n"
		}
		return out
	}
	// readonly to admin raises the level and the device privilege, 1 to 15,
	// and on EOS and NX-OS the role the reply names, which fences the session
	// when the device falls back to local: the test asserts all three.
	adminReply := map[string]string{
		"campus-sw-7": `, reply: ["priv-lvl=15", "roles=network-admin"]`,
		"nx-01":       `, reply: ["shell:roles*network-admin"]`,
	}
	d := Compare(mustParse(t, diffBase), mustParse(t, raised+levelTest("level: admin, max_privilege: none, priv_lvl: 15", adminReply)), noon)
	if d.UnacknowledgedLevels() != 0 {
		t.Fatalf("a session test acknowledges the raise: %+v", d.Levels)
	}
	d = Compare(mustParse(t, diffBase), mustParse(t, raised+levelTest("level: admin", nil)), noon)
	if d.UnacknowledgedLevels() != 4 {
		t.Fatalf("the level alone does not acknowledge the device privilege's rise: %+v", d.Levels)
	}
	d = Compare(mustParse(t, diffBase), mustParse(t, raised+levelTest("level: admin, max_privilege: none, priv_lvl: 15", nil)), noon)
	if d.UnacknowledgedLevels() != 2 {
		t.Fatalf("where the role rose, the level and priv_lvl do not acknowledge it: %+v", d.Levels)
	}
	d = Compare(mustParse(t, diffBase), mustParse(t, raised+"tests:\n  - {subject: noc, device: leaf-01, level: admin, priv_lvl: 15, "+
		`reply: ["priv-lvl=15", "roles=network-admin"]}`+"\n"), noon)
	if d.UnacknowledgedLevels() != 3 {
		t.Fatalf("a test on one group acknowledges that group alone: %+v", d.Levels)
	}
	d = Compare(mustParse(t, ceilinged), mustParse(t, diffBase+levelTest("level: readonly, max_privilege: none", nil)), noon)
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
		// replies is what a raise the role names also asserts, per device.
		replies map[string]string
	}{
		{"a grant attribute priv-lvl=15", diffBase,
			strings.Replace(diffBase, "roles: [read_only, cve]}", "roles: [read_only, cve], attributes: {all: [priv-lvl=15]}}", 1),
			4, "priv_lvl", "priv_lvl: 15", nil},
		{"a role attribute priv-lvl=15 on one platform", diffBase,
			strings.Replace(diffBase, "{name: read_only, privilege: readonly, permit: [show **]}",
				"{name: read_only, privilege: readonly, permit: [show **], attributes: {arista_eos: [priv-lvl=15]}}", 1),
			1, "priv_lvl", "priv_lvl: 15", nil},
		{"a custom level's parent moved up", custom, strings.Replace(custom, "parent: readonly", "parent: admin", 1),
			4, "priv_lvl", "priv_lvl: 15", map[string]string{
				"leaf-01": `, reply: ["priv-lvl=15", "roles=network-admin"]`,
				"nx-01":   `, reply: ["shell:roles*network-admin"]`,
			}},
		{"enable switched on under a ceiling", ceilinged,
			strings.Replace(ceilinged, "token_ttl: 60s}", "token_ttl: 60s, enable: token}", 1), 4, "enable", "enable: token", nil},
		{"enable switched on with no ceiling", diffBase,
			strings.Replace(diffBase, "token_ttl: 60s}", "token_ttl: 60s, enable: token}", 1), 4, "enable", "enable: token", nil},
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
				tests += "  - {subject: noc, device: " + device + ", " + tt.ack + tt.replies[device] + "}\n"
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

// A level's own rendering is exempt from the reply check only where the level
// it is rendered from went strictly down in both versions' orders (task 3
// review C1): on EOS operator and admin share priv-lvl 15, so a role raised
// from network-operator to network-admin is the one signal that the local
// fallback now hands the session configure (decision 25).
func TestTheGateFailsARoleRaiseAtTheSameLevel(t *testing.T) {
	custom := "privilege_levels: [{name: readonly}, {name: operator}, {name: admin}, {name: netops, parent: operator}]\n" +
		strings.Replace(diffBase, "privilege: readonly", "privilege: netops", 1)
	siblings := "privilege_levels: [{name: readonly}, {name: operator}, {name: admin}, {name: ops_plus, parent: admin}, " +
		"{name: ops, parent: operator}]\n"
	sideways := siblings + strings.Replace(diffBase, "privilege: readonly", "privilege: ops", 1)
	admin := strings.Replace(diffBase, "privilege: readonly", "privilege: admin", 1)
	eos := func(d Diff) LevelChange {
		for _, l := range d.Levels {
			if slices.Contains(l.Devices, "leaf-01") {
				return l
			}
		}
		t.Fatalf("no change on leaf-01: %+v", d.Levels)
		return LevelChange{}
	}
	for _, tt := range []struct {
		name, before, after string
		raise               bool
	}{
		{"a custom level's parent moved from operator to admin", custom,
			strings.Replace(custom, "parent: operator", "parent: admin", 1), true},
		{"a sibling custom level whose parent is admin", sideways,
			strings.Replace(sideways, "privilege: ops,", "privilege: ops_plus,", 1), true},
		{"admin to operator", admin, strings.Replace(diffBase, "privilege: readonly", "privilege: operator", 1), false},
		{"admin to readonly", admin, diffBase, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			d := Compare(mustParse(t, tt.before), mustParse(t, tt.after), noon)
			l := eos(d)
			if slices.Contains(l.Raised, "reply") != tt.raise || l.Raise != tt.raise {
				t.Fatalf("leaf-01: %+v, want a reply raise %v", l, tt.raise)
			}
			if !tt.raise {
				return
			}
			acked := tt.after + "tests:\n  - {subject: noc, device: leaf-01, reply: [\"priv-lvl=15\", \"roles=network-admin\"]}\n"
			if l := eos(Compare(mustParse(t, tt.before), mustParse(t, acked), noon)); !l.Acknowledged {
				t.Fatalf("a session test asserting the role acknowledges it: %+v", l)
			}
		})
	}
}

// The reply gate reads values, not the level order (task 7 review): a change
// to a level's rendering passes only where every value that bears privilege
// provably went down in role_order, under both versions' adapters. A custom level can
// sit above a level whose rendering is stronger, so "a lower level" proves
// nothing about what the device is told.
func TestTheGateReadsRoleValuesNotTheLevelOrder(t *testing.T) {
	on := func(t *testing.T, d Diff, device string) (LevelChange, bool) {
		for _, l := range d.Levels {
			if slices.Contains(l.Devices, device) {
				return l, true
			}
		}
		return LevelChange{}, false
	}
	above := "privilege_levels: [{name: readonly}, {name: operator}, {name: admin}, {name: netops, parent: operator}]\n"
	between := "privilege_levels: [{name: readonly}, {name: operator}, {name: viewer, parent: readonly}, {name: admin}]\n"
	admin := strings.Replace(diffBase, "privilege: readonly", "privilege: admin", 1)
	roleAttr := func(a string) string {
		return strings.Replace(diffBase, "permit: [show **]}", "permit: [show **], attributes: {arista_eos: ["+a+"]}}", 1)
	}
	for _, tt := range []struct {
		name, before, after, device string
		raised                      []string // nil: no change raises
	}{
		{"a custom level ordered above admin, rendered as operator, moved to admin",
			above + strings.Replace(diffBase, "privilege: readonly", "privilege: netops", 1), above + admin,
			"leaf-01", []string{"reply"}},
		{"a custom level rendered as readonly, ordered above operator, moved to operator",
			between + strings.Replace(diffBase, "privilege: readonly", "privilege: viewer", 1),
			between + strings.Replace(diffBase, "privilege: readonly", "privilege: operator", 1),
			"leaf-01", []string{"priv_lvl"}},
		{"admin to readonly on EOS", admin, diffBase, "leaf-01", nil},
		{"admin to readonly on NX-OS", admin, diffBase, "nx-01", nil},
		// Only a level's own rendering moves down role_order ungated: a role's
		// or grant's attribute is gated both ways (review C4), whatever it
		// ranks.
		{"a role attribute lowered", roleAttr("roles=network-admin"), diffBase, "leaf-01", []string{"reply"}},
		{"a role attribute raised", diffBase, roleAttr("roles=network-admin"), "leaf-01", []string{"reply"}},
		{"a role no adapter ranks", diffBase, roleAttr("roles=p49-noc"), "leaf-01", []string{"reply"}},
		{"from a role no adapter ranks", roleAttr("roles=p49-noc"), diffBase, "leaf-01", []string{"reply"}},
		{"the same role, mandatory to optional", roleAttr("roles=network-operator"), roleAttr("roles*network-operator"),
			"leaf-01", []string{"reply"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			l, changed := on(t, Compare(mustParse(t, tt.before), mustParse(t, tt.after), noon), tt.device)
			if !changed {
				t.Fatalf("no change on %s", tt.device)
			}
			if tt.raised == nil && l.Raise || tt.raised != nil && !slices.Equal(l.Raised, tt.raised) {
				t.Fatalf("%s: %+v, want raised %v", tt.device, l, tt.raised)
			}
		})
	}
	// The swap that would make "lower" a raise does not load: a block's
	// renderings rise in role_order, and it cannot reorder the set's.
	for _, block := range []string{
		"platforms:\n  arista_eos:\n    privilege:\n      readonly: [priv-lvl=1, roles=network-admin]\n" +
			"      admin: [priv-lvl=15, roles=network-operator]\n",
		"platforms:\n  arista_eos:\n    replace: true\n    role_order: {roles: [network-admin, network-operator]}\n" +
			"    privilege:\n      readonly: [priv-lvl=1, roles=network-admin]\n      admin: [priv-lvl=15, roles=network-operator]\n",
	} {
		if _, err := Parse([]byte(block+diffBase), env()); err == nil {
			t.Errorf("the swapped block loads:\n%s", block)
		}
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
	reply := map[string]string{
		"leaf-01": `, reply: ["priv-lvl=15", "roles=network-admin"]`,
		"nx-01":   `, reply: ["shell:roles*network-admin"]`,
	}
	later := "tests:\n"
	for _, device := range []string{"leaf-01", "nx-01", "xe-01", "srx-lab-01"} {
		later += "  - {subject: noc, device: " + device + ", level: admin, max_privilege: none, priv_lvl: 15" + reply[device] + "}\n"
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

// A permit test acknowledges an expansion past a deny only at the instant it
// passes (review M2): here it asserts the level the subject has only after a
// grant expires, so it does not acknowledge the expansion at noon.
func TestAnExpansionAckHoldsOnlyAtItsInstant(t *testing.T) {
	after := strings.Replace(diffBase, "  - {name: cve, deny: [show chassis **]}\n",
		"  - {name: cve, deny: [show chassis **]}\n  - {name: ir, permit: [show chassis hardware]}\n"+
			"  - {name: adm, privilege: admin}\n", 1)
	after = strings.Replace(after, "roles: [read_only, cve]}\n", "roles: [read_only, cve, ir]}\n"+
		"  - {subject: noc, scope: all_devices, roles: [adm], expires: 2026-10-01}\n", 1)
	test := after + "tests:\n  - {subject: noc, device: leaf-01, command: \"show chassis hardware\", expect: permit, level: readonly}\n"
	d := Compare(mustParse(t, diffBase), mustParse(t, test), noon)
	for _, c := range d.Changes {
		if c.Gated && c.Acknowledged && c.At.Equal(noon) {
			t.Fatalf("a test that fails at noon acknowledges noon's expansion: %+v", c)
		}
	}
	if d.Unacknowledged() == 0 {
		t.Fatalf("changes %+v", d.Changes)
	}
}

// A privilege-bearing attribute other than priv-lvl, added to the session
// reply, raises what the device lets the session do (review C2): each fails
// the gate on its platform's group until a session test asserts the new
// reply, and so does taking it away again.
func TestTheGateFailsAPrivilegeAttributeInTheReply(t *testing.T) {
	for _, tt := range []struct{ attrs, device, reply string }{
		{`{juniper_junos: [local-user-name=super-user]}`, "srx-lab-01", `["local-user-name=super-user"]`},
		{`{cisco_nxos: ["shell:roles=network-admin"]}`, "nx-01", `["shell:roles=network-admin"]`},
		{`{arista_eos: ["roles=network-admin"]}`, "leaf-01", `["priv-lvl=1", "roles=network-admin"]`},
		// idletime is inert on EOS, NX-OS and IOS-XE (tests/lab/results/L22-*.md)
		// and listed on no Junos adapter, so it bears privilege there.
		{`{all: ["idletime*30"]}`, "srx-lab-01", `["idletime*30"]`},
	} {
		after := strings.Replace(diffBase, "roles: [read_only, cve]}", "roles: [read_only, cve], attributes: "+tt.attrs+"}", 1)
		d := Compare(mustParse(t, diffBase), mustParse(t, after), noon)
		raised := 0
		for _, l := range d.Levels {
			if l.Raise && slices.Contains(l.Raised, "reply") && !l.Acknowledged {
				raised++
			}
		}
		if raised == 0 || d.UnacknowledgedLevels() != raised {
			t.Fatalf("%s: levels %+v", tt.attrs, d.Levels)
		}
		acked := after + "tests:\n  - {subject: noc, device: " + tt.device + ", reply: " + tt.reply + "}\n"
		d = Compare(mustParse(t, diffBase), mustParse(t, acked), noon)
		if d.UnacknowledgedLevels() != raised-1 {
			t.Fatalf("%s: a reply: test on %s acknowledges its group: %+v", tt.attrs, tt.device, d.Levels)
		}
		// Taking it away widens access too, whose direction the gate cannot
		// read (review C4): it fails until a reply: test asserts the reply
		// without it.
		back := Compare(mustParse(t, after), mustParse(t, diffBase), noon)
		if back.UnacknowledgedLevels() != raised {
			t.Fatalf("%s: removing it fails the gate: %+v", tt.attrs, back.Levels)
		}
		was := map[string]string{"leaf-01": `["priv-lvl=1", "roles=network-operator"]`,
			"nx-01": `["shell:roles*network-operator"]`, "xe-01": `["priv-lvl=1"]`}[tt.device]
		if was == "" {
			was = `[]`
		}
		back = Compare(mustParse(t, after), mustParse(t, diffBase+"tests:\n  - {subject: noc, device: "+tt.device+", reply: "+was+"}\n"), noon)
		if back.UnacknowledgedLevels() != raised-1 {
			t.Fatalf("%s: a reply: test acknowledges the removal: %+v", tt.attrs, back.Levels)
		}
	}
}

// What the lab measured inert passes the gate where it is listed inert, and
// only there: home-directory, idletime and timeout on EOS and NX-OS
// (tests/lab/results/L22-*.md, "Inert candidates"). IOS-XE lists nothing
// inert, since its refusals lock out SSH (L18-cisco_iosxe.md), so the same
// idletime and timeout there fail the gate on its group.
func TestTheGatePassesWhatTheLabMeasuredInert(t *testing.T) {
	reply := func(d Diff, device, attr string) (changed, gated bool) {
		for _, l := range d.Levels {
			if slices.Contains(l.Devices, device) && slices.Contains(l.NewReply, attr) &&
				!slices.Contains(l.OldReply, attr) {
				changed, gated = true, gated || (l.Raise && !l.Acknowledged)
			}
		}
		return changed, gated
	}
	attrs := `{arista_eos: ["idletime*30", "timeout*480", "home-directory*/home/noc"], ` +
		`cisco_nxos: ["idletime*30", "timeout*480", "home-directory*/home/noc"]}`
	after := strings.Replace(diffBase, "roles: [read_only, cve]}", "roles: [read_only, cve], attributes: "+attrs+"}", 1)
	d := Compare(mustParse(t, diffBase), mustParse(t, after), noon)
	for _, device := range []string{"leaf-01", "nx-01"} {
		if changed, _ := reply(d, device, "idletime*30"); !changed {
			t.Fatalf("%s's reply did not change: %+v", device, d.Levels)
		}
	}
	if d.UnacknowledgedLevels() != 0 || d.UnacknowledgedAdapters() != 0 {
		t.Fatalf("levels %+v adapters %+v", d.Levels, d.Adapters)
	}
	after = strings.Replace(diffBase, "roles: [read_only, cve]}",
		`roles: [read_only, cve], attributes: {cisco_iosxe: ["idletime*30"]}}`, 1)
	d = Compare(mustParse(t, diffBase), mustParse(t, after), noon)
	if changed, gated := reply(d, "xe-01", "idletime*30"); !changed || !gated {
		t.Fatalf("idletime on IOS-XE: levels %+v", d.Levels)
	}
}

// The gate compares principals, not only subjects (review C3): an identity
// moved to another person, identities swapped between subjects, and a
// username changed each hand access over with no subject's access changing.
// Each fails until a session test naming the principal asserts it; a
// principal taken away is reported and passes.
func TestTheGateComparesPrincipals(t *testing.T) {
	gated := func(d Diff) (n int) {
		for _, p := range d.Principals {
			if p.Gated && !p.Acknowledged {
				n++
			}
		}
		for _, s := range d.Subjects {
			if s.Gated && !s.Acknowledged {
				n++
			}
		}
		return n
	}
	mallory := strings.Replace(diffBase, "user:noc@example.com", "user:mallory@example.com", 1)
	d := Compare(mustParse(t, diffBase), mustParse(t, mallory), noon)
	if gated(d) != 1 || len(d.Principals) != 2 {
		t.Fatalf("mallory: %+v", d.Principals)
	}
	for _, p := range d.Principals {
		if (p.Principal == "user:mallory@example.com") != p.Gated {
			t.Errorf("only the principal who gained a subject is gated: %+v", p)
		}
	}
	acked := mallory + "tests:\n  - {principal: \"user:mallory@example.com\", device: leaf-01, level: readonly}\n"
	if n := gated(Compare(mustParse(t, diffBase), mustParse(t, acked), noon)); n != 0 {
		t.Fatalf("a session test naming the principal acknowledges it: %d", n)
	}
	subjectTest := mallory + "tests:\n  - {subject: noc, device: leaf-01, level: readonly}\n"
	if n := gated(Compare(mustParse(t, diffBase), mustParse(t, subjectTest), noon)); n != 1 {
		t.Fatalf("a subject test does not: %d", n)
	}

	two := diffBase + "  - {subject: adm, scope: all_devices, roles: [boss]}\n"
	two = strings.Replace(two, "subjects:\n", "subjects:\n  - {name: adm, identity: \"user:adm@example.com\", username: adm, token_ttl: 60s}\n", 1)
	two = strings.Replace(two, "roles:\n", "roles:\n  - {name: boss, privilege: admin, permit: [\"**\"]}\n", 1)
	swapped := strings.Replace(strings.Replace(two, "user:adm@example.com", "user:TMP", 1), "user:noc@example.com", "user:adm@example.com", 1)
	swapped = strings.Replace(swapped, "user:TMP", "user:noc@example.com", 1)
	if n := gated(Compare(mustParse(t, two), mustParse(t, swapped), noon)); n != 2 {
		t.Fatalf("swapped identities: %d gated", n)
	}

	renamed := strings.Replace(diffBase, "username: noc", "username: admin", 1)
	d = Compare(mustParse(t, diffBase), mustParse(t, renamed), noon)
	if gated(d) != 1 || len(d.Subjects) != 1 || d.Subjects[0].NewUsername != "admin" {
		t.Fatalf("username: %+v", d.Subjects)
	}
	if n := gated(Compare(mustParse(t, diffBase), mustParse(t, renamed+
		"tests:\n  - {principal: \"user:noc@example.com\", device: leaf-01, level: readonly}\n"), noon)); n != 0 {
		t.Fatalf("a principal session test acknowledges a username change: %d", n)
	}

	removed := strings.Replace(diffBase, "identity: \"user:noc@example.com\"", "identity: [\"user:noc@example.com\", \"user:old@example.com\"]", 1)
	if d := Compare(mustParse(t, removed), mustParse(t, diffBase), noon); gated(d) != 0 || len(d.Principals) != 1 {
		t.Fatalf("a removal is reported and passes: %+v", d.Principals)
	}
}

// A stale acknowledge: entry acknowledges nothing and is reported (review
// M5): one whose rule is still in the new policy removed nothing, and one no
// widening in the diff names is left over from an earlier change.
func TestAStaleAcknowledgmentAcknowledgesNothing(t *testing.T) {
	regexDeny := strings.Replace(regexBase, "copy * startup-config", "copy * /^start/", 1)
	wider := strings.Replace(regexBase, "copy * startup-config", "copy * /^(start|run)/", 1)
	// The old rule is kept under another role in the new policy: the entry
	// names a rule the new policy still has, so it removed nothing.
	kept := strings.Replace(wider, "  - {name: guard,", "  - {name: keep, deny: [\"copy * /^start/\"]}\n  - {name: guard,", 1) +
		"acknowledge:\n  - {role: keep, rule: \"copy * /^start/\", reason: \"still here\"}\n"
	p := mustParse(t, kept)
	if !slices.ContainsFunc(p.Lint(noon), func(f Finding) bool { return f.Kind == FindingAcknowledgeStale }) {
		t.Fatal("policy test reports an entry whose rule the policy still has")
	}
	leftover := wider + "acknowledge:\n  - {role: guard, rule: \"copy * /^start/\", reason: \"rewritten wider\"}\n" +
		"  - {role: guard, rule: \"reload **\", reason: \"from last quarter\"}\n"
	d := Compare(mustParse(t, regexDeny), mustParse(t, leftover), noon)
	if d.UnacknowledgedRegex() != 0 || len(d.StaleAcknowledgments) != 1 || d.StaleAcknowledgments[0].Rule != "reload **" {
		t.Fatalf("stale %+v, regex %+v", d.StaleAcknowledgments, d.Regex)
	}
	// An entry naming a rule the new policy still has, under the role it is
	// removed from elsewhere, acknowledges nothing.
	still := strings.Replace(wider, "  - {name: guard, deny: [copy * /^(start|run)/]}",
		"  - {name: guard, deny: [copy * /^(start|run)/]}\n  - {name: spare, deny: [\"copy * /^start/\"]}", 1)
	still += "acknowledge:\n  - {role: spare, rule: \"copy * /^start/\", reason: \"x\"}\n"
	if d := Compare(mustParse(t, regexDeny), mustParse(t, still), noon); d.UnacknowledgedRegex() == 0 {
		t.Fatalf("an entry for another role's rule acknowledges nothing: %+v", d.Regex)
	}
}

// The reviewer's C4 probes: removing Junos's deny-commands or its
// local-user-name widens a session-only device's access, and fails the gate.
func TestRemovingAJunosPrivilegeAttributeFailsTheGate(t *testing.T) {
	for _, attr := range []string{`"deny-commands=^(request|clear)"`, `"local-user-name=ro-class"`} {
		with := strings.Replace(diffBase, "roles: [read_only, cve]}", "roles: [read_only, cve], attributes: {juniper_junos: ["+attr+"]}}", 1)
		if d := Compare(mustParse(t, with), mustParse(t, diffBase), noon); d.UnacknowledgedLevels() != 1 {
			t.Fatalf("%s removed: %+v", attr, d.Levels)
		}
	}
}

// A broker API right gained fails the gate until a test asserts the
// subject's rights with api:, naming the subject or one of its principals;
// one lost is reported (review M6).
func TestTheGateComparesAPIRights(t *testing.T) {
	gated := func(d Diff) int { return d.UnacknowledgedPrincipals() }
	rights := strings.Replace(diffBase, "token_ttl: 60s}", "token_ttl: 60s, api: [explain_others, revoke_others, replay]}", 1)
	d := Compare(mustParse(t, diffBase), mustParse(t, rights), noon)
	if gated(d) != 1 || len(d.Subjects) != 1 || strings.Join(d.Subjects[0].APIGained, " ") != "explain_others replay revoke_others" {
		t.Fatalf("subjects %+v", d.Subjects)
	}
	for _, test := range []string{
		"  - {subject: noc, device: leaf-01, api: [revoke_others, replay, explain_others]}\n",
		"  - {principal: \"user:noc@example.com\", device: nx-01, api: [explain_others, replay, revoke_others]}\n",
	} {
		if n := gated(Compare(mustParse(t, diffBase), mustParse(t, rights+"tests:\n"+test), noon)); n != 0 {
			t.Fatalf("%s: %d", test, n)
		}
	}
	if n := gated(Compare(mustParse(t, diffBase), mustParse(t, rights+"tests:\n  - {subject: noc, device: leaf-01, api: [replay]}\n"), noon)); n != 1 {
		t.Fatalf("a test asserting another list fails and acknowledges nothing: %d", n)
	}
	if d := Compare(mustParse(t, rights), mustParse(t, diffBase), noon); gated(d) != 0 || len(d.Subjects) != 1 {
		t.Fatalf("a right lost is reported and passes: %+v", d.Subjects)
	}
	// A principal moved to a subject with rights its old one lacked needs the
	// rights asserted by a test naming it.
	two := rights + "  - {subject: ops, scope: all_devices, roles: [read_only]}\n"
	two = strings.Replace(two, "subjects:\n", "subjects:\n  - {name: ops, identity: \"user:ops@example.com\", username: ops, token_ttl: 60s}\n", 1)
	moved := strings.Replace(two, "identity: \"user:ops@example.com\"", "identity: [\"user:ops@example.com\", \"user:eve@example.com\"]", 1)
	moved = strings.Replace(moved, "identity: \"user:noc@example.com\"", "identity: [\"user:noc@example.com\"]", 1)
	eveToNoc := strings.Replace(strings.Replace(moved, ", \"user:eve@example.com\"", "", 1),
		"identity: [\"user:noc@example.com\"]", "identity: [\"user:noc@example.com\", \"user:eve@example.com\"]", 1)
	levelOnly := eveToNoc + "tests:\n  - {principal: \"user:eve@example.com\", device: leaf-01, level: readonly}\n"
	if n := gated(Compare(mustParse(t, moved), mustParse(t, levelOnly), noon)); n != 1 {
		t.Fatalf("a principal test without api: does not acknowledge the rights it gained: %d", n)
	}
	withAPI := eveToNoc + "tests:\n  - {principal: \"user:eve@example.com\", device: leaf-01, level: readonly, api: [explain_others, replay, revoke_others]}\n"
	if n := gated(Compare(mustParse(t, moved), mustParse(t, withAPI), noon)); n != 0 {
		t.Fatalf("one asserting them does: %d", n)
	}
}

// An api:-only principal test needs no mint, so it proves nothing about the
// access an identity move hands over, and does not acknowledge one (review
// M7).
func TestAnAPIOnlyTestDoesNotAcknowledgeAnIdentityMove(t *testing.T) {
	mallory := strings.Replace(diffBase, "user:noc@example.com", "user:mallory@example.com", 1) +
		"tests:\n  - {principal: \"user:mallory@example.com\", device: leaf-01, api: []}\n"
	if n := Compare(mustParse(t, diffBase), mustParse(t, mallory), noon).UnacknowledgedPrincipals(); n != 1 {
		t.Fatalf("an api:-only test acknowledged the move: %d unacknowledged", n)
	}
}

// Which attributes bear privilege is read from the adapters, so an edit that
// lists an attribute inert is judged under the stricter of the two versions:
// it cannot hide a change to that attribute in the same diff. The list edit is
// gated in its own right, and acknowledged only in writing (review M8). The
// platform is an operator's own: on a platform a set ships, a block may not
// list inert a name the set does not (final review M5), and listing a shipped
// privilege attribute inert is refused anywhere (task 7 review C1).
func TestAnInertListingCannotHideItsOwnEdit(t *testing.T) {
	e := env()
	e.Devices = append(e.Devices, admission.Device{Name: "acme-01", Platform: "acme_os",
		Addresses: []netip.Addr{netip.MustParseAddr("10.0.9.1")}})
	parse := func(body string) *Policy {
		t.Helper()
		p, err := Parse([]byte(body), e)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	before := "platforms:\n  acme_os:\n    supports: [session]\n" + diffBase
	after := "platforms:\n  acme_os:\n    supports: [session]\n    inert_attributes: [home-directory, x-label]\n" +
		strings.Replace(diffBase,
			"roles: [read_only, cve]}", `roles: [read_only, cve], attributes: {acme_os: ["x-label=network-admin"]}}`, 1)
	d := Compare(parse(before), parse(after), noon)
	raised := false
	for _, l := range d.Levels {
		if slices.Contains(l.Devices, "acme-01") && slices.Contains(l.Raised, "reply") && !l.Acknowledged {
			raised = true
		}
	}
	if !raised {
		t.Fatalf("x-label changed on acme_os, which the old adapter says bears privilege: %+v", d.Levels)
	}
	listed := `["home-directory","x-label"]`
	if len(d.Adapters) != 1 || d.Adapters[0] != (AdapterChange{Platform: "acme_os", Field: "inert_attributes",
		Old: `["home-directory"]`, New: listed, OldShown: `["home-directory"]`, NewShown: listed, Sha256: digest(listed),
		Gated: true}) || d.UnacknowledgedAdapters() != 1 {
		t.Fatalf("adapters %+v", d.Adapters)
	}
	acked := after + "acknowledge:\n  - {platform: acme_os, field: inert_attributes, sha256: " + d.Adapters[0].Sha256 +
		", reason: \"a label here\"}\n"
	d = Compare(parse(before), parse(acked), noon)
	if d.UnacknowledgedAdapters() != 0 || d.Adapters[0].AcknowledgedBy != "a label here" ||
		len(d.StaleAcknowledgments) != 0 {
		t.Fatalf("adapters %+v stale %+v", d.Adapters, d.StaleAcknowledgments)
	}
	if d.UnacknowledgedLevels() == 0 {
		t.Fatal("the entry acknowledges the list edit, not the reply the edit would have hidden")
	}
	// The same entry against a diff with no such edit acknowledges nothing.
	if d := Compare(parse(before), parse(before+"acknowledge:\n  - {platform: acme_os, "+
		"field: inert_attributes, sha256: "+digest("x")+", reason: x}\n"), noon); len(d.StaleAcknowledgments) != 1 {
		t.Fatalf("stale %+v", d.StaleAcknowledgments)
	}
}

// A name a shipped set lists as bearing privilege bears it under any adapter
// the gate is handed, even one both versions list it inert in: the load
// refuses such a block, and the gate does not rely on that alone.
func TestTheGateReadsAShippedPrivilegeNameAsBearing(t *testing.T) {
	d, _ := platform.DialectFor("cisco_nxos")
	d.InertAttributes = append(d.InertAttributes, "cisco-av-pair", "x-label")
	if !bearsPrivilege("cisco-av-pair", d, d) {
		t.Fatal("cisco-av-pair read as inert")
	}
	if bearsPrivilege("x-label", d, d) {
		t.Fatal("a name both versions list inert, and no set ships, read as bearing privilege")
	}
}

// An edit to any key of an adapter is gated, on every platform either version
// has an adapter for, a device or not (spec §8, §12). A block for a platform
// no device has yet is gated too: the inventory is not diffed, so the day a
// device of it arrives is not a review. A block on a verified adapter also
// clears verified, which is reported and not gated.
func TestAnAdapterEditIsGated(t *testing.T) {
	after := "platforms:\n  cisco_iosxe:\n    privilege: {operator: [\"priv-lvl=15\"]}\n  cisco_nxos:\n" +
		"    shows_server_msg: true\n  f5_bigip:\n    supports: [session]\n    privilege: {admin: [\"priv-lvl=15\"]}\n" +
		diffBase
	d := Compare(mustParse(t, diffBase), mustParse(t, after), noon)
	if len(d.Adapters) != 6 || d.UnacknowledgedAdapters() != 4 {
		t.Fatalf("adapters %+v", d.Adapters)
	}
	for _, i := range []int{1, 3} {
		if v := d.Adapters[i]; v.Field != "verified" || v.Gated || v.Old != `"containerlab"` || v.New != "null" {
			t.Fatalf("adapters %+v", d.Adapters)
		}
	}
	// f5_bigip's supports goes from no claim to [session] (adapterSpec).
	xe, nx, f5s, f5 := d.Adapters[0], d.Adapters[2], d.Adapters[4], d.Adapters[5]
	if f5s.Platform != "f5_bigip" || f5s.Field != "supports" || !f5s.Gated || f5s.Old != "null" {
		t.Fatalf("adapters %+v", d.Adapters)
	}
	if xe.Platform != "cisco_iosxe" || xe.Field != "privilege" || !xe.Gated ||
		!strings.Contains(xe.New, `"operator":["priv-lvl=15"]`) ||
		nx.Platform != "cisco_nxos" || nx.Field != "shows_server_msg" || !nx.Gated ||
		f5.Platform != "f5_bigip" || f5.Field != "privilege" || !f5.Gated || f5.Old != "null" {
		t.Fatalf("adapters %+v", d.Adapters)
	}
}

// A redaction pattern changes what the audit keeps, so a block that adds one
// is gated like a rendering: a pattern written wide enough removes what every
// command was typed with from the log and the spool (spec §5.8, §12).
func TestARedactionEditIsGated(t *testing.T) {
	after := "platforms:\n  arista_eos:\n    redact: [{match: ['**'], after: interface}]\n" + diffBase
	d := Compare(mustParse(t, diffBase), mustParse(t, after), noon)
	if len(d.Adapters) != 2 || d.Adapters[0].Field != "redact" || !d.Adapters[0].Gated ||
		d.Adapters[1].Field != "verified" || d.Adapters[1].Gated || d.UnacknowledgedAdapters() != 1 {
		t.Fatalf("adapters %+v", d.Adapters)
	}
}

// The gate fails closed on keys (task 1 review I3): only a key on the closed
// list of explain-only keys is reported, and every key an adapter has today,
// device_config included (task 7 review H6), and any a later plan adds is
// gated until it is listed. Four keys an adapter has are on the list:
// verified says how the set's adapter was checked, and no block may set it;
// unreachable, fallback and fallback_note feed only the dead-rule and
// fallback-exposure reports (spec §12).
func TestOnlyExplainKeysAreReported(t *testing.T) {
	for _, key := range platform.SpecKeys() {
		if !slices.Contains([]string{"verified", "unreachable", "fallback", "fallback_note"}, key) && !adapterKeyGated(key) {
			t.Errorf("%s is reported, not gated", key)
		}
	}
	for _, key := range []string{"port_pattern", "verified", "unreachable", "fallback", "fallback_note"} {
		if adapterKeyGated(key) {
			t.Errorf("%s is gated; it changes only what explain says", key)
		}
	}
	if !adapterKeyGated("a_key_no_plan_has_added") {
		t.Fatal("an unknown key is reported")
	}
}

// hbase is the base policy of task 7 review's hand-off cases H1–H7, verbatim.
const hbase = `
scopes: [{name: all_devices, match: {}}]
roles:
  - {name: rw, privilege: readonly, permit: ["**"], deny: [interface @management **, "configure **", "reload **"]}
subjects:
  - {name: noc, identity: "user:noc@example.com", username: noc, token_ttl: 60s}
grants:
  - {subject: noc, scope: all_devices, roles: [rw]}
`

// Each block task 7's review found passing `policy diff` with exit 0 fails
// the gate, or is refused at load, and an acknowledge: entry for exactly the
// key it names is what lets it through (task 7 review M1, hand-off H1–H7).
func TestTheHandOffBlocksFailTheGate(t *testing.T) {
	h1 := "platforms:\n  arista_eos:\n    role_order:\n      roles: [p49-x, network-operator, network-admin]\n"
	for _, tc := range []struct {
		name, before, after string
		platform, field     string // the gated key, or
		refused             string // the load error
	}{
		{"H1 a role_order value inserted", "", h1, "arista_eos", "role_order", ""},
		{"H2 a rendering moved onto it", h1, h1 + "    privilege:\n      readonly: [priv-lvl=1, roles=p49-x]\n",
			"arista_eos", "privilege", ""},
		{"H3 strip_cr turned off", "", "platforms:\n  cisco_iosxe:\n    strip_cr: false\n", "", "",
			"platforms.cisco_iosxe.strip_cr"},
		{"H4 expands_abbreviations claimed", "", "platforms:\n  juniper_junos:\n    expands_abbreviations: true\n",
			"", "", "platforms.juniper_junos.expands_abbreviations"},
		{"H5 a capability removed", "", "platforms:\n  arista_eos:\n    supports: [session]\n", "arista_eos",
			"supports", ""},
		{"H6 device_config ending in none", "", "platforms:\n  arista_eos:\n    device_config: [\"aaa authorization " +
			"exec default group port49 local\", \"aaa authorization commands all default group port49 none\"]\n",
			"arista_eos", "device_config", ""},
		{"H7 a platform no device has", "", "platforms:\n  f5_bigip:\n    privilege:\n      readonly: [priv-lvl=15]\n" +
			"      operator: [priv-lvl=15]\n      admin: [priv-lvl=15]\n", "f5_bigip", "privilege", ""},
		// Only the old version has the block: the platform is still compared.
		{"H7 removed", "platforms:\n  f5_bigip:\n    entity_classes: {management: ['^mgmt$']}\n", "\n", "f5_bigip",
			"entity_classes", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.refused != "" {
				if _, err := Parse([]byte(tc.after+hbase), env()); err == nil || !strings.Contains(err.Error(), tc.refused) {
					t.Fatalf("loaded: %v", err)
				}
				return
			}
			before := mustParse(t, tc.before+hbase)
			d := Compare(before, mustParse(t, tc.after+hbase), noon)
			// A block on a platform the set does not ship also changes its
			// supports, from no claim to a claim (adapterSpec), and one on a
			// verified adapter clears verified, which is reported: every
			// other change is gated, and the named key is one of them.
			target := slices.IndexFunc(d.Adapters, func(a AdapterChange) bool {
				return a.Platform == tc.platform && a.Field == tc.field
			})
			gated := 0
			for _, a := range d.Adapters {
				if a.Gated {
					gated++
				} else if a.Field != "verified" {
					t.Fatalf("%s is reported: %+v", a.Field, d.Adapters)
				}
			}
			if target < 0 || !d.Adapters[target].Gated || d.UnacknowledgedAdapters() != gated {
				t.Fatalf("adapters %+v", d.Adapters)
			}
			// acks acknowledges every change, the target by entry instead.
			acks := func(entry string) *Policy {
				body := tc.after + hbase + "acknowledge:\n"
				for i, a := range d.Adapters {
					if i == target {
						body += entry
						continue
					}
					if !a.Gated {
						continue
					}
					body += "  - {platform: " + a.Platform + ", field: " + a.Field + ", sha256: " + a.Sha256 +
						", reason: reviewed}\n"
				}
				return mustParse(t, body)
			}
			entry := func(platform, field, sha string) string {
				return "  - {platform: " + platform + ", field: " + field + ", sha256: " + sha + ", reason: reviewed}\n"
			}
			sha := d.Adapters[target].Sha256
			if d := Compare(before, acks(entry(tc.platform, tc.field, sha)), noon); d.UnacknowledgedAdapters() != 0 ||
				len(d.StaleAcknowledgments) != 0 {
				t.Fatalf("acknowledged: %+v stale %+v", d.Adapters, d.StaleAcknowledgments)
			}
			// An entry naming another platform, another key, or another value
			// acknowledges nothing, and is reported stale (task 9 review I1).
			other := "cisco_nxos"
			if tc.platform == other {
				other = "arista_eos"
			}
			otherField := "strip_cr"
			if tc.field == otherField {
				otherField = "supports"
			}
			for _, wrong := range []string{entry(other, tc.field, sha), entry(tc.platform, otherField, sha),
				entry(tc.platform, tc.field, digest("another value"))} {
				if d := Compare(before, acks(wrong), noon); d.UnacknowledgedAdapters() != 1 ||
					len(d.StaleAcknowledgments) != 1 || d.Adapters[target].Acknowledged {
					t.Fatalf("%s: adapters %+v stale %+v", wrong, d.Adapters, d.StaleAcknowledgments)
				}
			}
		})
	}
}

// digest is an acknowledge: entry's sha256 of a value.
func digest(v string) string { return fmt.Sprintf("%x", sha256.Sum256([]byte(v))) }

// An entry left in the file acknowledges the edit it was written for and no
// later one: its digest names the value that edit wrote. Task 9 review C1's
// probe: v1 adds a logging line and acknowledges it; v2 keeps the entry and
// ends the commands line in none (H6).
func TestALeftoverAdapterAcknowledgmentCoversNoLaterEdit(t *testing.T) {
	block := func(commands string) string {
		return "platforms:\n  arista_eos:\n    device_config: [\"aaa authorization exec default group port49 local\", " +
			"\"aaa authorization commands all default group port49 " + commands + "\", \"logging host 192.0.2.1\"]\n"
	}
	d := Compare(mustParse(t, diffBase), mustParse(t, block("local")+diffBase), noon)
	if len(d.Adapters) != 2 || d.Adapters[0].Field != "device_config" || d.UnacknowledgedAdapters() != 1 {
		t.Fatalf("adapters %+v", d.Adapters)
	}
	entry := "acknowledge:\n  - {platform: arista_eos, field: device_config, sha256: " + d.Adapters[0].Sha256 +
		", reason: add logging line}\n"
	v1 := mustParse(t, block("local")+diffBase+entry)
	if d := Compare(mustParse(t, diffBase), v1, noon); d.UnacknowledgedAdapters() != 0 {
		t.Fatalf("v1: %+v", d.Adapters)
	}
	d = Compare(v1, mustParse(t, block("none")+diffBase+entry), noon)
	if d.UnacknowledgedAdapters() != 1 || d.Adapters[0].Acknowledged || len(d.StaleAcknowledgments) != 1 {
		t.Fatalf("v2: adapters %+v stale %+v", d.Adapters, d.StaleAcknowledgments)
	}
}

// A block that says what the generic adapter already says still changes the
// platform: an adapted platform whose supports lacks commands is session-only,
// and abbreviation matching on its denies is off. The diff shows it as an edit
// to supports, gated (task 9 review I2).
func TestABlockEqualToGenericIsAnAdapterEdit(t *testing.T) {
	acme := admission.Device{Name: "acme-01", Platform: "acme_os", Addresses: []netip.Addr{netip.MustParseAddr("10.0.9.1")}}
	e := env()
	e.Devices = append(e.Devices, acme)
	base := `
scopes: [{name: all_devices, match: {}}]
roles:
  - {name: rw, privilege: readonly, permit: ["**"], deny: ["reload **", "configure **"]}
subjects:
  - {name: noc, identity: "user:noc@example.com", username: noc, token_ttl: 60s}
grants:
  - {subject: noc, scope: all_devices, roles: [rw]}
`
	parse := func(body string) *Policy {
		t.Helper()
		p, err := Parse([]byte(body), e)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	before, after := parse(base), parse("platforms: {acme_os: {}}\n"+base)
	for _, cmd := range []string{"rel", "conf t"} {
		_, was, err := before.Decide("noc", "", acme, cmd, noon)
		_, is, err2 := after.Decide("noc", "", acme, cmd, noon)
		if err != nil || err2 != nil || was.Permit || !is.Permit {
			t.Fatalf("%s: the probe no longer shows the flip: %v -> %v (%v, %v)", cmd, was.Permit, is.Permit, err, err2)
		}
	}
	d := Compare(before, after, noon)
	if len(d.Adapters) != 1 || d.Adapters[0] != (AdapterChange{Platform: "acme_os", Field: "supports", Old: "null",
		New: `["session"]`, OldShown: "null", NewShown: `["session"]`, Sha256: digest(`["session"]`), Gated: true}) || d.UnacknowledgedAdapters() != 1 {
		t.Fatalf("adapters %+v", d.Adapters)
	}
}
