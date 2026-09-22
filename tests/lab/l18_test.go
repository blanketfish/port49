//go:build lab

package lab

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// L18: how each platform treats a reply attribute it did not ask for.
//
// RFC 8907 §8.2 says a device SHOULD ignore an OPTIONAL argument it does not
// understand and MUST fail the authorization on a MANDATORY one it does not
// understand. This lab has already seen two platforms break the first half:
// IOS-XE 17.13.01a refuses an EXEC authorization carrying **any** attribute it
// does not recognise, invented ones included (results/L10-cisco_iosxe.md), and
// vEOS refuses one carrying `cisco-av-pair*` (results/L16-arista_eos.md).
//
// Why that is worth a register row of its own: operators write one server
// definition for a mixed fleet and use `*` for the other vendor's attributes,
// on exactly the reasoning RFC 8907 licenses. On two of these five images that
// reply does not degrade to "the other vendor ignores it" -- it ends the
// session. The docs owe a per-platform table saying which of three things a
// mistake in a reply does: applied, ignored, or session killed.
//
// The shape is one deploy per platform, one daemon restart and one token login
// per variant. Per variant the note records three things and derives a fourth:
//
//  1. the session outcome -- opened, or refused with the device's exact words;
//  2. the role or privilege the session ended up with, verbatim, from the
//     platform's own `show`;
//  3. whether the device then sent per-command authorization at all, with every
//     request's vector and port49's verdict;
//  4. the table cell, which is DERIVED from (1) and (2) against the variant's
//     own baseline and never written by hand -- see l18Cell and l18Variant's
//     `baseline` field, which is where the first draft of this file got it
//     wrong in a way that would have published the opposite answer.
//
// What this test does NOT measure, and it is a hole rather than an answer: the
// same question on a per-command authorization REPLY. The lab authorizer
// returns no attributes on that path (`internal/daemon/author/lab.go`,
// `Lab.Command`) and `lab:` in the daemon config has no key for them, so there
// is no reply to put a bad attribute in. The wire side is already shared --
// `author.Handler` copies `Decision.Attributes` onto the response for commands
// and sessions alike -- so this is a missing config key and not a protocol
// limit. Adding it is a daemon change, which this task was told not to make.
func TestL18OptionalAttributes(t *testing.T) {
	eachPlatform(t, func(t *testing.T, l *lab) {
		d, ok := l18Drivers[l.p.name]
		if !ok {
			t.Skipf("no L18 driver for %s", l.p.name)
		}
		stop := l.capture(t, "L18")
		defer stop()

		// Some platforms need something on the device before the question can
		// be asked at all -- on Junos a second login template, so that
		// `local-user-name` has somewhere to point that differs from the
		// default. It is removed again whatever happens below.
		if d.setup != nil {
			d.setup(t, l)
			defer d.teardown(t, l)
		}

		results := make([]l18Result, 0, len(d.variants))
		for _, v := range d.variants {
			results = append(results, l.l18Run(t, d, v))
		}

		// Put the daemon back on this platform's standing config, so nothing
		// that runs after this test is measuring the last variant's reply.
		l.l18RestoreDaemon(t)

		var b strings.Builder
		b.WriteString(l18Preamble(t, l, d))
		for _, r := range results {
			b.WriteString(r.render(d))
		}
		b.WriteString(l18Table(d, results))
		b.WriteString(l18Reading(t, l, d, results))
		l.result(t, "L18", l18Claim, b.String())

		l18Assert(t, d, results)
	})
}

const l18Claim = "How each platform treats a reply attribute it did not ask for -- one it does not " +
	"understand, one belonging to another vendor, one that does not exist, and a known attribute " +
	"carrying a value the device cannot use -- in both the OPTIONAL and the MANDATORY spelling. " +
	"For each: does the session open, what role or privilege does it end up with, and does the " +
	"device still send per-command authorization. RFC 8907 §8.2 says an optional argument a device " +
	"does not understand SHOULD be ignored; this row is the measurement of whether that holds, " +
	"because an operator writing one server definition for a mixed fleet is relying on it."

// l18Assert is the "a test that measured nothing must fail" gate.
//
// It is three separate checks rather than one, because they fail for different
// reasons and a reader of the failure needs to know which. A run where no
// session authorization reached port49 measured nothing at all. A run whose
// empty-attribute control never opened has transcripts but no baseline, so
// every "ignored" cell in it would be derived from a comparison that could not
// be made. And a refusal with no transcript is the L3-cisco_nxos defect: the
// note would assert the device refused something without showing what it said.
func l18Assert(t *testing.T, d l18Driver, rs []l18Result) {
	t.Helper()
	asked := 0
	for _, r := range rs {
		if r.sessionVerdict != "" {
			asked++
		}
	}
	if asked == 0 {
		t.Fatalf("not one of the %d variants produced an authorize_session record, so nothing about "+
			"reply attributes was measured on this platform", len(rs))
	}
	if c := l18ByName(rs, l18Empty); c.name() == "" {
		t.Fatalf("this platform has no %q variant, so there is no control to read the other cells "+
			"against and every `ignored` cell would be an assertion rather than a comparison", l18Empty)
	} else if !c.opened {
		t.Errorf("the empty-attribute control never opened a session, so no cell in this run can say "+
			"whether an attribute changed anything: %s", oneLine(c.loginErr))
	}
	// A refusal the device ANSWERED must carry its words: that is the
	// L3-cisco_nxos rule. A connection the device never ran AAA for is a
	// different outcome and is reported as one (see neverAsked), so it is not
	// held to the same test -- its evidence is the absence of any record for
	// that login in port49's own log, which the note states and the log backs.
	for _, r := range rs {
		if r.opened || r.neverAsked() || strings.TrimSpace(r.deviceSaid) != "" {
			continue
		}
		t.Errorf("the %q variant did not open a session, port49 DID answer its session authorization "+
			"(%s), and the device said nothing this run could quote -- so `refused` would be a claim "+
			"with no transcript behind it (the L3-cisco_nxos defect, see negativeFinding). The harness "+
			"reported: %s", r.v.name, r.sessionVerdict, oneLine(r.loginErr))
	}
	// The control for the whole row: the reply that carries only what this
	// platform is known to accept. If it cannot open a session, the platform is
	// in some state this run does not understand and every other cell is
	// suspect.
	if c := l18ByName(rs, l18Control); c.name() != "" && !c.opened {
		t.Errorf("the control variant %q -- the reply this platform is known to accept -- did not open "+
			"a session, so the device was not in a state where the other variants mean anything: %s",
			l18Control, oneLine(c.loginErr))
	}
}

// ---------------------------------------------------------------------------
// The variants
// ---------------------------------------------------------------------------

// The variant names the reading is built from. They are constants because the
// reading looks them up by name, and a typo in a lookup returns an empty result
// that renders as "not measured" rather than failing.
const (
	l18Control       = "1. mandatory KNOWN attribute (the control)"
	l18OptKnown      = "2. OPTIONAL known attribute"
	l18OptForeign    = "3. OPTIONAL foreign-vendor attribute"
	l18OptForeign2   = "3b. OPTIONAL foreign-vendor attribute, the other vendor's spelling"
	l18MandForeign   = "4. MANDATORY foreign-vendor attribute"
	l18MandForeign2  = "4b. MANDATORY foreign-vendor attribute, the other vendor's spelling"
	l18OptInvented   = "5. OPTIONAL invented attribute"
	l18MandInvented  = "6. MANDATORY invented attribute"
	l18BadValue      = "7. known attribute, a value the device cannot use"
	l18Empty         = "8. no attributes at all (the control for `ignored`)"
	l18JunosPermsM   = "9. Junos `user-permissions`, MANDATORY"
	l18JunosPermsO   = "10. Junos `user-permissions`, OPTIONAL"
	l18JunosBothMand = "11. Junos `local-user-name` and `user-permissions` together, MANDATORY"
)

// l18Variant is one reply-attribute set and the question it answers.
type l18Variant struct {
	name  string
	why   string
	attrs string // a YAML flow sequence, exactly as it goes into the config

	// baseline names the variant this one's cell is derived against, and
	// getting it right is the whole difference between a table that means
	// something and one that contradicts its own transcripts.
	//
	// Variants 3 to 6 send the platform's KNOWN attribute *and* the bad one, so
	// that the session has something to be given and the bad attribute is the
	// only variable. Read against the empty-attribute variant they would all
	// come out "applied" -- because `priv-lvl=15` was applied, which is not
	// what the row is asking. Their baseline is the control, which carries the
	// known attribute and nothing else, so the difference between them is
	// exactly the attribute under test.
	//
	// Variants that REPLACE the whole reply -- the bad value, the Junos
	// decision-22 attributes -- are read against the empty variant instead,
	// because there is no shared known attribute to hold constant.
	baseline string
}

// l18InventedAttr is the attribute no vendor has. It is spelled with the
// project's own prefix so that a device which happens to know it would be a
// finding about the device rather than a collision with a real VSA.
const l18InventedAttr = "p49-nonsense"

// l18CommonVariants are the variants every platform runs, given the spellings
// that platform's driver supplies. Order is the order the note reports them.
func l18CommonVariants(known, knownOpt, badValue string, foreign []l18Foreign) []l18Variant {
	vs := []l18Variant{
		{
			name: l18Control,
			why: "the control. One attribute, MANDATORY, that this platform is already measured to " +
				"understand, and nothing else. Variants 3 to 6 are read against this one, so its own " +
				"cell is read against the empty variant -- if the known attribute does not change the " +
				"session either, this platform's signal is not sensitive enough to say anything about " +
				"the others, and every cell below it says `not comparable` rather than `ignored`.",
			attrs:    `["` + known + `"]`,
			baseline: l18Empty,
		},
		{
			name: l18OptKnown,
			why: "the same attribute sent OPTIONAL. RFC 8907 §8.2's flag decides what a device MAY " +
				"ignore, not what it may apply, so a platform that drops a known attribute merely " +
				"because it is optional would be its own finding -- and would mean an adapter cannot " +
				"use the flag to be polite. It REPLACES the known attribute rather than sitting " +
				"beside it, so it is read against the empty reply -- `applied` here means the optional " +
				"form delivered something, which is the question. Whether the flag changed WHAT it " +
				"delivered is a comparison with the control, and finding 3 below makes it directly.",
			attrs:    `["` + knownOpt + `"]`,
			baseline: l18Empty,
		},
	}
	for i, f := range foreign {
		optName, mandName := l18OptForeign, l18MandForeign
		if i > 0 {
			optName, mandName = l18OptForeign2, l18MandForeign2
		}
		vs = append(vs,
			l18Variant{
				name: optName,
				why: "another vendor's attribute, OPTIONAL: `" + f.attr + "`. " + f.why + " This is the " +
					"reply an operator gets when one server definition serves a mixed fleet and the " +
					"other vendor's attributes are marked optional -- which is exactly what RFC 8907 " +
					"§8.2 invites them to do. The known attribute is in the reply too, so the foreign " +
					"one is the only thing separating this variant from the control.",
				attrs:    `["` + known + `", "` + f.attr + `*` + f.value + `"]`,
				baseline: l18Control,
			},
			l18Variant{
				name: mandName,
				why: "the same foreign attribute MANDATORY. Here the RFC is unambiguous: a device that " +
					"does not understand it must fail the authorization. A platform that opens the " +
					"session anyway is not following §8.2, and one that opens it AND applies nothing " +
					"is the worst case for an operator, who sees a working login and no privilege.",
				attrs:    `["` + known + `", "` + f.attr + `=` + f.value + `"]`,
				baseline: l18Control,
			})
	}
	return append(vs,
		l18Variant{
			name: l18OptInvented,
			why: "an attribute no vendor has, OPTIONAL. The foreign-vendor variants above cannot tell " +
				"\"this device dislikes that particular name\" from \"this device refuses anything it " +
				"does not recognise\"; this one can, and on IOS-XE it is the variant that settled it " +
				"in 2026-09-20's run (results/L10-cisco_iosxe.md).",
			attrs:    `["` + known + `", "` + l18InventedAttr + `*1"]`,
			baseline: l18Control,
		},
		l18Variant{
			name: l18MandInvented,
			why: "the invented attribute MANDATORY: the one cell in this table where every platform is " +
				"SUPPOSED to refuse the session. A platform that opens it here is ignoring a mandatory " +
				"argument, which means an adapter cannot use the mandatory flag to make a device tell " +
				"it that an attribute did not land.",
			attrs:    `["` + known + `", "` + l18InventedAttr + `=1"]`,
			baseline: l18Control,
		},
		l18Variant{
			name: l18BadValue,
			why: "a known attribute carrying a value the device cannot use: `" + badValue + "`. This is " +
				"the typo case rather than the mixed-fleet case, and it is a different question -- the " +
				"device parses the attribute and then has to decide what to do with the value. Does it " +
				"clamp, ignore the attribute, or refuse the session? It REPLACES the known attribute " +
				"rather than sitting beside it, so it is read against the empty variant.",
			attrs:    `["` + badValue + `"]`,
			baseline: l18Empty,
		},
		l18Variant{
			name: l18Empty,
			why: "no attributes at all on a permit. It is the floor of the table: what a session looks " +
				"like when port49 delivers nothing. The control is read against it, and so is every " +
				"variant that replaces the whole reply rather than adding to it. Without this row the " +
				"table could report \"ignored\" only as an opinion.",
			attrs: `[]`,
		})
}

// l18Foreign is one other-vendor attribute to send at this platform.
type l18Foreign struct {
	attr  string
	value string
	why   string
}

// The two foreign spellings this lab has measured being read by SOME platform,
// so that "foreign" means "a real attribute that a real device in this lab
// applies", not "a name I made up". `shell:roles` is what NX-OS reads
// (results/L16-cisco_nxos.md) and `roles` is what EOS reads
// (results/L16-arista_eos.md), so each is foreign to the other and both are
// foreign to IOS-XE and Junos.
var (
	l18ForeignShellRoles = l18Foreign{
		attr:  "shell:roles",
		value: "network-operator",
		why: "NX-OS reads this one and applies the role named in it (results/L16-cisco_nxos.md), and " +
			"vEOS does not (results/L16-arista_eos.md).",
	}
	l18ForeignBareRoles = l18Foreign{
		attr:  "roles",
		value: "network-operator",
		why: "vEOS reads this one and applies the role named in it (results/L16-arista_eos.md), and " +
			"NX-OS reads `shell:roles` instead.",
	}
)

// ---------------------------------------------------------------------------
// The drivers
// ---------------------------------------------------------------------------

// l18Driver is the per-platform half: how to open a token session, what to ask
// the device about the session it gave you, and how to read an answer out of
// that.
type l18Driver struct {
	platform string

	// prompts are every prompt shape a login on this platform may land at. All
	// of them, because WHICH one the session reached is part of the
	// measurement: on EOS `#` means the reply's `priv-lvl` arrived and `>`
	// means it did not.
	prompts func(l *lab) []string
	// pagingOff is the command that stops this platform paginating a `show`.
	pagingOff string

	// roleCmds are the commands whose verbatim output is what the session was
	// given. `%s` in one is replaced by the session's username.
	roleCmds []string
	// signal reduces those outputs to the one string the table compares
	// against the empty-attribute control. It returns "" when the session did
	// not say -- which is reported as "the device did not say", never as a
	// difference.
	signal func(r *l18Result) string
	// signalName is what the note calls that value.
	signalName string

	// probe is a command typed in every session that opens, to see whether the
	// device sends per-command authorization under this reply. It changes
	// nothing on the device and no platform's policy denies it.
	probe string

	// attempts and retryPause are how many times an SSH connection that never
	// reached the device's CLI is retried, and how long to wait between tries.
	//
	// They exist because of what the first IOS-XE run measured. After five
	// consecutive refused authorizations the Catalyst 8000V stopped answering
	// SSH at all -- three connections over 50 seconds, every one refused at the
	// authentication layer, and **not one TACACS+ packet for any of them** in
	// port49's decision log. The variant after them succeeded. That reads as the
	// vty pool being consumed by the refused sessions and recovering on its own,
	// and it is a finding rather than flakiness: on this platform a bad reply
	// attribute does not only cost one operator one session, it eventually stops
	// the device answering anyone. A patient retry is what makes the variant
	// measurable AND what measures the recovery, so the count is reported.
	attempts   int
	retryPause time.Duration

	// refusalMarkers are what this platform says when it refuses a session it
	// has already authenticated. They are waited for alongside the prompts, so
	// a refusal ends the wait the moment the device says it rather than after
	// the 90-second timeout -- which matters on IOS-XE, where most of this
	// table is expected to be a refusal and the timeouts alone would cost a
	// quarter of an hour. A platform with no marker is not penalised: it simply
	// waits out the timeout, and the transcript is the same either way.
	refusalMarkers []string

	// setup and teardown put whatever the variants need on the device. Only
	// Junos has any.
	setup    func(t *testing.T, l *lab)
	teardown func(t *testing.T, l *lab)

	variants []l18Variant
}

// l18JunosTemplate is the login template `local-user-name` points at, defined
// for this run and deleted after it. It exists because the device's own
// `user remote { class p49-readonly }` already catches every TACACS+ user with
// no local account, so `local-user-name=remote` would be indistinguishable from
// sending nothing -- the reply would read `ignored` whether the device applied
// it or not. A template with DIFFERENT permissions from the default is the only
// shape where "applied" and "ignored" look different.
const (
	l18JunosTemplate = "p49l18"
	l18JunosClass    = "p49-l18-ops"
)

var l18JunosDefine = []string{
	"set system login class " + l18JunosClass + " permissions [ view view-configuration configure ]",
	"set system login user " + l18JunosTemplate + " uid 2099 class " + l18JunosClass,
}

var l18JunosDelete = []string{
	"delete system login user " + l18JunosTemplate,
	"delete system login class " + l18JunosClass,
}

var l18Drivers = map[string]l18Driver{
	"arista_eos": {
		platform:  "arista_eos",
		prompts:   func(l *lab) []string { return []string{l.p.node + "#", l.p.node + ">"} },
		pagingOff: "terminal length 0",
		// Both, because EOS splits the answer across them: `show privilege` is
		// the level and `show users detail` is the role, and L16 measured a
		// reply that delivers one without the other.
		roleCmds:   []string{"show privilege", "show users detail"},
		signalName: "privilege level and role, as `show privilege` and `show users detail` report them",
		signal: func(r *l18Result) string {
			lvl := eosPrivLevel(r.show("show privilege"))
			role := eosRolesOf(r.show("show users detail"), r.user)
			if lvl == "" && role == "" {
				return ""
			}
			return "priv=" + l18Dash(lvl) + " role=" + l18Dash(role)
		},
		probe: "show version",
		// Measured on this image on 2026-09-21: a session EOS refuses after
		// authenticating it answers `Authorization denied:` and closes the
		// channel (results/L16-arista_eos.md).
		refusalMarkers: []string{"Authorization denied", "% Authorization"},
		variants: l18CommonVariants("priv-lvl=15", "priv-lvl*15", "priv-lvl=99",
			[]l18Foreign{l18ForeignShellRoles}),
	},
	"cisco_nxos": {
		platform:  "cisco_nxos",
		prompts:   func(l *lab) []string { return []string{l.p.node + "#", l.p.node + ">"} },
		pagingOff: "terminal length 0",
		// NX-OS assigns privilege by role and `priv-lvl` is inert beside one
		// (results/L16-cisco_nxos.md, the precedence section), so the role is
		// the whole signal here.
		roleCmds:   []string{"show user-account %s"},
		signalName: "role or roles, as `show user-account <user>` names them",
		signal: func(r *l18Result) string {
			return l16RoleOf(r.show("show user-account "+r.user), r.user)
		},
		probe:          "show version",
		refusalMarkers: []string{"Authorization denied", "AAA authorization failed", "Cmd exec error"},
		variants: l18CommonVariants("priv-lvl=15", "priv-lvl*15", "priv-lvl=99",
			[]l18Foreign{l18ForeignBareRoles}),
	},
	"cisco_iosxe": {
		platform:   "cisco_iosxe",
		prompts:    func(l *lab) []string { return []string{l.p.node + "#", l.p.node + ">"} },
		pagingOff:  "terminal length 0",
		roleCmds:   []string{"show privilege"},
		signalName: "privilege level, as `show privilege` reports it",
		signal: func(r *l18Result) string {
			return iosxePrivLevel(r.show("show privilege"))
		},
		probe: "show version",
		// Measured on this image on 2026-09-20: a session it refuses after
		// authenticating answers `% Authorization failed.` and the SSH session
		// is closed (results/L10-cisco_iosxe.md).
		refusalMarkers: []string{"% Authorization failed", "Authorization failed", "% Authorization"},
		// See the `attempts` comment: five refusals in a row take this device's
		// SSH server out for the best part of a minute. Four attempts 20s apart
		// clears what the first run measured, with room over it.
		attempts:   4,
		retryPause: l18IOSXEPause,
		// IOS-XE gets BOTH foreign spellings. It reads neither, so the pair
		// separates "this image dislikes that name" from "this image refuses
		// anything unfamiliar" without leaning on the invented variant alone.
		variants: l18CommonVariants("priv-lvl=15", "priv-lvl*15", "priv-lvl=99",
			[]l18Foreign{l18ForeignShellRoles, l18ForeignBareRoles}),
	},
	"juniper_vsrx":          l18JunosDriver("juniper_vsrx"),
	"juniper_vjunos-router": l18JunosDriver("juniper_vjunos-router"),
}

// l18JunosDriver is both Junos images. They have agreed cell for cell on every
// row measured so far (L17, the session-service run), and this builds one
// driver rather than copying it so that a change to the Junos question cannot
// land on one image and not the other.
//
// The known attribute here is `local-user-name`, not `priv-lvl`: Junos has no
// privilege level, and `local-user-name` is one of the two attributes decision
// 22 will use. The other, `user-permissions`, gets variants of its own below --
// the brief for this row asks specifically whether either takes effect over
// `junos-exec` and what `show cli authorization` then reports, because the
// projection in §8 rests on both and L12 is open.
func l18JunosDriver(name string) l18Driver {
	d := l18Driver{
		platform:  name,
		prompts:   func(*lab) []string { return []string{junosOpPrompt, "% "} },
		pagingOff: "set cli screen-length 0",
		// `show cli authorization` is Junos's own word for what the session may
		// do: the class it landed in and the permission bits that class carries.
		// It is what phase A of the session-service run read, so this row is
		// directly comparable with it.
		roleCmds:   []string{"show cli authorization"},
		signalName: "class and permissions, as `show cli authorization` reports them",
		signal: func(r *l18Result) string {
			return junosAuthSignal(r.show("show cli authorization"))
		},
		probe: "show version",
		setup: func(t *testing.T, l *lab) {
			t.Helper()
			l.junosL18Configure(t, l18JunosDefine)
		},
		teardown: func(t *testing.T, l *lab) {
			t.Helper()
			l.junosL18Configure(t, l18JunosDelete)
		},
		variants: l18CommonVariants(
			"local-user-name="+l18JunosTemplate,
			"local-user-name*"+l18JunosTemplate,
			"local-user-name=p49-nosuchtemplate",
			[]l18Foreign{l18ForeignShellRoles, l18ForeignBareRoles}),
	}
	// The decision-22 attributes, which are the half of this row that is about
	// Junos rather than about RFC 8907. `view` alone is NARROWER than the
	// default class `p49-readonly` (`view view-configuration`), so if it takes
	// effect the permissions list shrinks, and shrinking is something no
	// ignored attribute can do.
	d.variants = append(d.variants,
		l18Variant{
			name: l18JunosPermsM,
			why: "the second attribute decision 22 projects into, MANDATORY. `view` alone is narrower " +
				"than the default class `p49-readonly`, which carries `view view-configuration`, so a " +
				"permissions list that SHRINKS is proof the attribute was applied -- no ignored " +
				"attribute can take a permission away.",
			attrs:    `["user-permissions=view"]`,
			baseline: l18Empty,
		},
		l18Variant{
			name: l18JunosPermsO,
			why: "the same attribute OPTIONAL. If Junos applies it under both flags, decision 22 may " +
				"choose the flag for its own reasons; if only the mandatory form lands, the projection " +
				"has to send mandatory and accept what §8.2 says that costs on a device that does not " +
				"understand it.",
			attrs:    `["user-permissions*view"]`,
			baseline: l18Empty,
		},
		l18Variant{
			name: l18JunosBothMand,
			why: "both decision-22 attributes in one reply, which is the shape the projection would " +
				"actually send. `user-permissions` is documented to REPLACE the class's permissions " +
				"rather than merge with them (§15 L12); this is the variant that says whether the " +
				"template's class survives beside it. Read against the empty variant, and then by hand " +
				"against each attribute alone -- the three together are what say whether they compose.",
			attrs:    `["local-user-name=` + l18JunosTemplate + `", "user-permissions=view"]`,
			baseline: l18Empty,
		})
	// `local-user-name` OPTIONAL is variant 2 on this platform already -- the
	// common set's `knownOpt` is exactly that attribute -- so it is not repeated
	// here. A twelfth login that re-asks an eleventh's question costs a token
	// and answers nothing.
	return d
}

// junosL18Configure applies configuration lines over a break-glass CLI. On vSRX
// that is the console as root; junosCLI decides which, and withAdminCLI stops
// port49d first so the device takes the local password (L4 reading 3).
func (l *lab) junosL18Configure(t *testing.T, lines []string) {
	t.Helper()
	l.withAdminCLI(t, func(l *lab) (*cliConn, error) {
		return l.junosCLI(breakglassUser, breakglassPassword)
	}, func(c *cliConn) error {
		out, err := junosConfigure(c, lines...)
		if err != nil {
			return fmt.Errorf("applying %v: %w\n%s", lines, err, out)
		}
		t.Logf("%s: applied %v", l.p.name, lines)
		return nil
	})
}

// iosxePrivLevel pulls the number out of IOS-XE's `show privilege`, which
// answers `Current privilege level is 15`. Same shape as EOS's, and it is a
// separate function rather than a shared one because the two devices are free
// to change their wording independently and a silent fallback between them
// would report one platform's level for the other's session.
func iosxePrivLevel(out string) string { return eosPrivLevel(out) }

// junosAuthSignal reduces `show cli authorization` to the three things a
// reply attribute could change: the class, the permission bits, and the four
// individual-command regexes.
//
// All three, because decision 22 projects into all three and a signal that
// watched only one would report an attribute as ignored when it had moved
// something else. The regexes in particular: §8's projection sends
// `allow-commands` and `deny-commands`, and a session whose class and bits were
// untouched but whose regexes were set would otherwise look identical to one
// that got nothing.
//
// A permission is read as a line containing `--`, which is the separator Junos
// puts between the bit's name and its description:
//
//	view        -- Can view current values and statistics
//	view-configuration-- Can view all configuration (not including secrets)
//
// The first version of this function took any indented single-word line
// instead, and swept up the shell prompt that follows the output --
// `alice11@srx1>`. Every variant then carried its own username inside its
// signal, so every signal differed from every other, and the table reported
// **applied** for all thirteen rows on a run where ten of them had changed
// nothing at all. The `user-permissions` rows were the expensive ones: their
// transcripts are byte-identical to the empty control's and the cell said the
// attribute took effect. Requiring `--` is what keeps the prompt out.
func junosAuthSignal(out string) string {
	class, perms := "", []string{}
	regexes := []string{}
	inPerms, inRegex := false, false
	for _, ln := range strings.Split(out, "\n") {
		t := strings.TrimSpace(ln)
		if i := strings.Index(t, "class '"); i >= 0 {
			rest := t[i+len("class '"):]
			if j := strings.Index(rest, "'"); j >= 0 {
				class = rest[:j]
			}
		}
		switch {
		case strings.HasPrefix(t, "Permissions:"):
			inPerms, inRegex = true, false
			continue
		case strings.HasPrefix(t, "Individual command authorization:"):
			inPerms, inRegex = false, true
			continue
		case t == "":
			continue
		}
		if inPerms {
			i := strings.Index(t, "--")
			if i < 0 {
				// Not a permission line: the output has moved on, or this is
				// the prompt that follows it.
				inPerms = false
				continue
			}
			if name := strings.TrimSpace(t[:i]); name != "" {
				perms = append(perms, name)
			}
			continue
		}
		if inRegex {
			i := strings.Index(t, ":")
			if i < 0 {
				inRegex = false
				continue
			}
			name, val := strings.TrimSpace(t[:i]), strings.TrimSpace(t[i+1:])
			if name == "" || val == "" {
				continue
			}
			regexes = append(regexes, name+"="+val)
		}
	}
	if class == "" && len(perms) == 0 && len(regexes) == 0 {
		return ""
	}
	sig := "class=" + l18Dash(class) + " permissions=[" + strings.Join(perms, " ") + "]"
	// The four regexes are reported as one word while they are all `none`,
	// which they are under this lab's configuration, so the common case does
	// not bury the two values that do change. Anything else is spelled out.
	allNone := len(regexes) > 0
	for _, r := range regexes {
		if !strings.HasSuffix(r, "=none") {
			allNone = false
		}
	}
	switch {
	case len(regexes) == 0:
		sig += " regexes=(not reported)"
	case allNone:
		sig += " regexes=all none"
	default:
		sig += " regexes=[" + strings.Join(regexes, "; ") + "]"
	}
	return sig
}

func l18Dash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "—"
	}
	return s
}

// ---------------------------------------------------------------------------
// Running a variant
// ---------------------------------------------------------------------------

// l18Result is one variant's evidence.
type l18Result struct {
	v     l18Variant
	attrs string
	user  string

	opened bool
	// loginErr is the harness's own error when no session opened, and
	// deviceSaid is what the DEVICE said on the channel before it went away.
	// They are separate because only the second is a measurement: "i/o timeout"
	// is this test failing to read a device, and `% Authorization failed.` is
	// the device answering.
	loginErr   string
	deviceSaid string

	// sessionVerdict is port49's own answer to the session authorization, and
	// sessionAttrs is what port49 sent. Both are on the page for the same
	// reason: every refusal below is the DEVICE refusing a session port49
	// permitted, and a reader should not have to take that on trust.
	sessionVerdict string

	shows []l18Show

	// attempts is how many SSH connections this variant took, and attemptErrs
	// is what each one that failed said. More than one is reported in the note:
	// a device that refused three connections and answered the fourth is saying
	// something about itself that a bare "opened" cell would hide.
	attempts    int
	attemptErrs []string

	// probeCmd is the command typed to see whether per-command authorization
	// happens; probeOut is the device's exact reply.
	probeCmd string
	probeOut string
	// cmdReqs is every authorize_command that reached port49 in this variant's
	// window, as `vector -> verdict reason`.
	cmdReqs []string
}

type l18Show struct {
	cmd string
	out string
}

func (r l18Result) name() string { return r.v.name }

// neverAsked reports that this variant produced no session AND no TACACS+
// exchange at all: the device refused the SSH connection without consulting
// port49.
//
// It is a different outcome from a refusal and has to be kept apart from one.
// A refusal is the device answering a reply port49 sent; this is the device
// not asking, so the reply under test never reached it and the variant
// measures nothing about that reply. The evidence for it is positive rather
// than absent -- port49's decision log holds no record for this login, and the
// note says so and shows what the SSH layer returned.
func (r l18Result) neverAsked() bool {
	return !r.opened && r.sessionVerdict == "" && strings.TrimSpace(r.deviceSaid) == ""
}

// show returns the verbatim output of one of this variant's role commands.
func (r *l18Result) show(cmd string) string {
	for _, s := range r.shows {
		if s.cmd == cmd {
			return s.out
		}
	}
	return ""
}

// l18Run measures one variant: restart the daemon with these reply attributes,
// spend a token on one login, ask the device what the session got, and type one
// command to see whether per-command authorization follows.
func (l *lab) l18Run(t *testing.T, d l18Driver, v l18Variant) l18Result {
	t.Helper()
	cfg, err := l.derivedConfig("l18-"+l16Slug(v.name), l18Attrs(v.attrs), "")
	if err != nil {
		t.Fatalf("derive the config for %q: %v", v.name, err)
	}
	if err := l.stopDaemon(); err != nil {
		t.Fatalf("%q: stopping the daemon: %v", v.name, err)
	}
	if err := l.startDaemonWith(cfg, true); err != nil {
		t.Fatalf("%q: starting the daemon: %v", v.name, err)
	}

	off := l.mark()
	r := l18Result{v: v, attrs: v.attrs, probeCmd: d.probe}
	user, secret := l.nextLogin(t)
	r.user = user

	c, said, attempts, attemptErrs, err := l.l18CLI(d, user, secret)
	r.deviceSaid, r.attempts, r.attemptErrs = said, attempts, attemptErrs
	if err != nil {
		r.loginErr = err.Error()
		l.collectL18(&r, l.drainRecords(off, 10*time.Second))
		return r
	}
	r.opened = true
	for _, cmd := range d.roleCmds {
		cmd = strings.ReplaceAll(cmd, "%s", user)
		out, _ := l.l18Show(d, c, cmd)
		r.shows = append(r.shows, l18Show{cmd: cmd, out: precReply(l16TrimEcho(out, cmd))})
	}
	out, _ := l.l18Show(d, c, d.probe)
	r.probeOut = precReply(l16TrimEcho(out, d.probe))
	c.Close()

	l.collectL18(&r, l.drainRecords(off, 10*time.Second))
	return r
}

// l18Attrs maps the variant's attribute list onto derivedConfig's contract.
//
// derivedConfig treats an empty string as "do not substitute, use the
// checked-in file", which is not the same thing as "send no attributes" -- and
// the empty-attribute control is a variant of this test, so the two must not
// collide. YAML's `[]` is a list with nothing in it and is passed through as
// itself; the guard is here so a future variant written as `""` fails loudly
// rather than quietly measuring `port49d-lab.yaml`'s standing reply.
func l18Attrs(attrs string) string {
	if strings.TrimSpace(attrs) == "" {
		panic("an L18 variant with no attrs string would silently measure the checked-in " +
			"session_attributes; the empty-attribute control must be spelled `[]`")
	}
	return attrs
}

// l18CLI opens a token session and returns what the device said on the way,
// whether or not a prompt was reached.
//
// The second return value is the whole point. On IOS-XE a reply carrying an
// attribute the image does not recognise produces `% Authorization failed.` and
// a closed SSH session (results/L10-cisco_iosxe.md); on vEOS a mandatory
// `cisco-av-pair=` produces `Authorization denied:` (results/L16-arista_eos.md).
// In both the SSH authentication SUCCEEDED -- port49 answered it -- and the
// device then refused the session. sshCLI closes the connection on a failed
// expect and the transcript would go with it, so this keeps it: a `refused`
// cell in the table has the device's own words under it, which is what
// negativeFinding exists to insist on.
//
// The retry is IOS-XE's alone and is not about this measurement: that image
// intermittently refuses one of two near-simultaneous SSH connections with no
// TACACS+ packet for the refused one anywhere in the capture (see
// iosxeTokenCLI). A retry at the SSH layer only -- never after the device has
// said something -- stops that flake from being written down as a refusal.
func (l *lab) l18CLI(d l18Driver, user, password string) (c *cliConn, said string, attempts int, errs []string, err error) {
	tries := d.attempts
	if tries < 1 {
		tries = 1
	}
	for attempts = 1; attempts <= tries; attempts++ {
		c, err = l.sshCLI(user, password)
		if err != nil {
			// The device never ran a shell for this login, so it said nothing
			// this test can quote. Whether it even ASKED port49 is the thing
			// that tells this apart from a refusal, and the caller reads that
			// off the decision log rather than guessing here.
			errs = append(errs, err.Error())
			if attempts < tries {
				time.Sleep(d.retryPause)
			}
			continue
		}
		// The refusal markers are waited for beside the prompts, so a device
		// that has decided to refuse is not waited out in full. Whichever
		// appeared is then checked: a prompt means the session opened, and
		// anything else means the device answered and did not give one.
		out, werr := c.expect(90*time.Second, append(d.prompts(l), d.refusalMarkers...)...)
		if werr != nil {
			said = c.transcript()
			c.Close()
			return nil, said, attempts, errs, werr
		}
		if !containsAny(out, d.prompts(l)) {
			said = c.transcript()
			c.Close()
			return nil, said, attempts, errs, fmt.Errorf("the device refused the session after "+
				"authenticating it; it said: %s", oneLine(said))
		}
		// Only where `<node>#` is really this platform's prompt. On Junos it is
		// the CONFIGURATION prompt, and a cliConn carrying it would send any
		// later helper that trusts c.prompt waiting for a mode this session
		// never enters. Nothing in this test reads it; it is set for the
		// platforms where it is true and left empty where it is not.
		if l.p.name != "juniper_vsrx" && l.p.name != "juniper_vjunos-router" {
			c.prompt = l.p.node + "#"
		}
		if _, perr := c.sendExpect(d.pagingOff, 45*time.Second, d.prompts(l)...); perr != nil {
			said = c.transcript()
			c.Close()
			return nil, said, attempts, errs, fmt.Errorf("turning paging off with %q: %w", d.pagingOff, perr)
		}
		return c, c.transcript(), attempts, errs, nil
	}
	return nil, "", tries, errs, err
}

// containsAny reports whether s holds any of want.
func containsAny(s string, want []string) bool {
	for _, w := range want {
		if strings.Contains(s, w) {
			return true
		}
	}
	return false
}

// l18Show runs one command and waits for any of this platform's prompt shapes.
// All of them, because a session that landed at `>` rather than `#` is a
// finding: waiting only for `#` would turn it into a timeout that says nothing.
func (l *lab) l18Show(d l18Driver, c *cliConn, cmd string) (string, error) {
	return c.sendExpect(cmd, 60*time.Second, d.prompts(l)...)
}

// collectL18 reads this variant's records out of the decision log.
func (l *lab) collectL18(r *l18Result, recs []map[string]any) {
	for _, rec := range recs {
		switch str(rec, "event") {
		case "authorize_session":
			if r.sessionVerdict == "" {
				r.sessionVerdict = strings.TrimSpace(str(rec, "verdict") + " " + str(rec, "reason"))
			}
		case "authorize_command":
			r.cmdReqs = append(r.cmdReqs, fmt.Sprintf("%s -> %s",
				strings.Join(strs(sub(rec, "request"), "vector"), " "),
				strings.TrimSpace(str(rec, "verdict")+" "+str(rec, "reason"))))
		}
	}
}

// l18RestoreDaemon puts port49d back on this platform's standing config.
func (l *lab) l18RestoreDaemon(t *testing.T) {
	t.Helper()
	base, err := l.configPath()
	if err != nil {
		t.Fatalf("recover this platform's standing config: %v", err)
	}
	if err := l.stopDaemon(); err != nil {
		t.Fatalf("stopping the daemon to restore it: %v", err)
	}
	if err := l.startDaemonWith(base, true); err != nil {
		t.Fatalf("restoring the daemon on the standing config: %v", err)
	}
}

func l18ByName(rs []l18Result, name string) l18Result {
	for _, r := range rs {
		if r.v.name == name {
			return r
		}
	}
	return l18Result{}
}

// ---------------------------------------------------------------------------
// The note
// ---------------------------------------------------------------------------

func l18Preamble(t *testing.T, l *lab, d l18Driver) string {
	t.Helper()
	var b strings.Builder
	fmt.Fprintf(&b, "- **Date measured:** %s\n- **Image version:** %s (`%s`)\n- **Capture:** %s\n\n",
		time.Now().UTC().Format("2006-01-02"), l.p.version, l.p.image, l.captureLine(t))
	fmt.Fprintf(&b, "Each variant below is one set of reply attributes on the session authorization, one "+
		"daemon restart and one token login. Per variant: whether the session opened and what the device "+
		"said if it did not; `%s` for what the session was given; and one `%s`, typed only to see whether "+
		"the device sends per-command authorization under this reply at all.\n\n",
		strings.Join(d.roleCmds, "`, `"), d.probe)
	fmt.Fprintf(&b, "**How the summary table's cell is derived.** It is not written by hand and it is not "+
		"a reading of the attribute's name. A variant whose session never opened is `session refused`. "+
		"Otherwise the variant is compared with the one named in its `read against` column, on a single "+
		"value: %s. Identical is `ignored`, different is `applied`. So `ignored` means the session came out "+
		"indistinguishable from the one that differs only by the attribute under test, which is the "+
		"only thing a lab can observe about an attribute a device chose to drop.\n\n"+
		"**Which baseline, and why it is not one fixed row.** Variants 3 to 6 send the known attribute "+
		"AND the attribute under test, so that the session has something to be given and the bad "+
		"attribute is the only variable; they are read against the control, which is the known "+
		"attribute alone. Variants that REPLACE the whole reply -- the bad value, and on Junos the "+
		"decision-22 attributes -- are read against variant %s. Reading everything against that "+
		"instead would mark every row carrying the known attribute `applied`, because the known "+
		"attribute was applied, and the table would then contradict the transcripts printed above "+
		"it.\n\n", d.signalName, l18Empty)
	if d.setup != nil {
		fmt.Fprintf(&b, "The device carries one login template for the length of this run, removed "+
			"afterwards:\n\n```\n%s\n```\n\nIt exists because this image already maps every TACACS+ user "+
			"with no local account onto `user remote { class p49-readonly }`, so an attribute pointing at "+
			"`remote` would leave the session identical to one carrying no attribute -- and the table "+
			"could not tell `applied` from `ignored`. This template's class is deliberately different "+
			"from the default's.\n\n", strings.Join(l18JunosDefine, "\n"))
	}
	b.WriteString("**What is not measured here.** The same question asked on a per-command authorization " +
		"REPLY. The lab authorizer returns no attributes on that path (`Lab.Command` in " +
		"`internal/daemon/author/lab.go`) and the `lab:` config block has no key for them, so there is " +
		"no reply to put a bad attribute in. The wire side is not the obstacle -- `author.Handler` " +
		"copies a decision's attributes onto the response for commands and sessions alike -- so this is " +
		"a missing configuration key, and adding one is a daemon change this measurement was not " +
		"scoped to make. Every variant below still records whether per-command authorization happened, " +
		"which answers the neighbouring question of whether a device under this reply reaches that " +
		"path at all.\n")
	return b.String()
}

func (r l18Result) render(d l18Driver) string {
	var b strings.Builder
	fmt.Fprintf(&b, "\n### %s\n\n%s\n\nReply attributes: `%s`\n\n", r.v.name, r.v.why, r.attrs)
	if r.sessionVerdict != "" {
		fmt.Fprintf(&b, "port49 answered the session authorization **%s**, so everything below is the "+
			"DEVICE's answer to a session port49 permitted.\n\n", r.sessionVerdict)
	} else {
		b.WriteString("**No `authorize_session` record reached port49's decision log for this variant**, " +
			"so nothing here is attributable to the reply it would have carried.\n\n")
	}
	if r.neverAsked() {
		fmt.Fprintf(&b, "**No session, and the device never asked port49.** %d SSH connection(s) were "+
			"refused at the authentication layer, and port49's decision log holds no record at all for "+
			"this login -- no redeem, no session authorization. So the reply under test never reached "+
			"the device, and this variant measures nothing about that reply. It measures the device: "+
			"something about its SSH server, not its authorization, refused the connection. What each "+
			"attempt returned:\n\n```\n%s\n```\n\n", r.attempts, strings.Join(r.attemptErrs, "\n"))
		return b.String()
	}
	if !r.opened {
		if r.attempts > 1 {
			fmt.Fprintf(&b, "This variant took %d SSH connection(s); the earlier ones were refused before "+
				"the device ran AAA:\n\n```\n%s\n```\n\n",
				r.attempts, strings.Join(r.attemptErrs, "\n"))
		}
		fmt.Fprintf(&b, "**The session did not open.** What the device said on the channel, verbatim:\n\n"+
			"```\n%s\n```\n\nWhat the harness reported:\n\n```\n%s\n```\n\n",
			strings.TrimRight(precReply(r.deviceSaid), "\n"), strings.TrimRight(r.loginErr, "\n"))
		if len(r.cmdReqs) > 0 {
			fmt.Fprintf(&b, "Per-command authorization still reached port49 in this variant:\n\n```\n%s\n```\n\n",
				strings.Join(r.cmdReqs, "\n"))
		}
		return b.String()
	}
	if r.attempts > 1 {
		fmt.Fprintf(&b, "**The session opened on attempt %d.** The earlier attempts were refused at the "+
			"SSH authentication layer, before the device ran AAA:\n\n```\n%s\n```\n\n",
			r.attempts, strings.Join(r.attemptErrs, "\n"))
	} else {
		b.WriteString("**The session opened.**\n\n")
	}
	for _, s := range r.shows {
		fmt.Fprintf(&b, "`%s`:\n\n```\n%s\n```\n\n", s.cmd, strings.TrimRight(s.out, "\n"))
	}
	fmt.Fprintf(&b, "`%s` — typed to see whether per-command authorization follows. The device said:\n\n"+
		"```\n%s\n```\n\n", r.probeCmd, strings.TrimRight(r.probeOut, "\n"))
	if len(r.cmdReqs) > 0 {
		fmt.Fprintf(&b, "Every command authorization port49 answered in this session, as it arrived:\n\n"+
			"```\n%s\n```\n\n", strings.Join(r.cmdReqs, "\n"))
	} else {
		b.WriteString("**No command authorization reached port49 in this session at all.**\n\n")
	}
	return b.String()
}

// l18Cell is the table cell, derived and never written.
//
// Three outcomes and two non-answers. `session refused` needs no baseline. The
// others are a comparison against THIS variant's baseline (v.baseline), not
// against one fixed row: a variant that adds an attribute beside the known one
// is read against the control, and a variant that replaces the whole reply is
// read against the empty one. Reading everything against the empty variant --
// which is what the first draft of this file did -- reports `applied` for every
// row that carries `priv-lvl=15` beside the attribute under test, because the
// privilege level was applied. That is a true statement about the reply and the
// wrong answer to the question, and it would have contradicted the transcripts
// printed directly above it.
//
// When the baseline produced no signal there is nothing to compare with and the
// cell says so rather than guessing: a table that reported `ignored` because the
// baseline was unreadable would be asserting the strongest claim in the row from
// the weakest evidence.
func l18Cell(d l18Driver, r l18Result, rs []l18Result) string {
	if r.neverAsked() {
		return "**no session, and port49 was never asked**"
	}
	if !r.opened {
		return "**session refused**"
	}
	if r.v.baseline == "" {
		return "opened (this is the baseline)"
	}
	base := l18ByName(rs, r.v.baseline)
	sig, bsig := d.signal(&r), d.signal(&base)
	switch {
	case base.v.name == "" || !base.opened || bsig == "":
		return "opened; **not comparable** (its baseline produced no signal)"
	case sig == "":
		return "opened; **the device did not say** what the session got"
	case sig == bsig:
		return "ignored"
	default:
		return "**applied**"
	}
}

// l18BaselineNote is the short "read against" cell, so a reader can see which
// comparison produced the verdict beside it without going back to the code.
func l18BaselineNote(v l18Variant) string {
	switch v.baseline {
	case "":
		return "—"
	case l18Control:
		return "the control (same reply, minus this attribute)"
	case l18Empty:
		return "no attributes at all"
	default:
		return v.baseline
	}
}

func l18Table(d l18Driver, rs []l18Result) string {
	var b strings.Builder
	b.WriteString("\n## Every variant side by side\n\n")
	b.WriteString("| variant | reply attributes | outcome | what the session got | read against | " +
		"per-command authorization |\n")
	b.WriteString("|---|---|---|---|---|---|\n")
	for _, r := range rs {
		got := "—"
		if r.opened {
			got = l18Dash(d.signal(&r))
		}
		cmds := fmt.Sprintf("%d request(s)", len(r.cmdReqs))
		if len(r.cmdReqs) == 0 {
			cmds = "**none**"
		}
		fmt.Fprintf(&b, "| %s | `%s` | %s | %s | %s | %s |\n",
			r.v.name, r.attrs, l18Cell(d, r, rs), got, l18BaselineNote(r.v), cmds)
	}
	b.WriteString("\nThe `what the session got` column is the verbatim `show` output above reduced to " +
		"the one value the cell is derived from, and `read against` names the row it was compared " +
		"with. The transcripts both come from are in each variant's section, and a cell that " +
		"disagrees with the transcript above it is a defect in this generator rather than a finding " +
		"about the device.\n")
	return b.String()
}

// l18Reading answers the row's question from the results. Every negative goes
// through negativeFinding, so a claim that a platform refuses something cannot
// be written without the exact reply sent and the device's exact words back.
func l18Reading(t *testing.T, l *lab, d l18Driver, rs []l18Result) string {
	t.Helper()
	control := l18ByName(rs, l18Empty)
	var b strings.Builder
	b.WriteString("\n## What this answers\n\n")

	// 0. Whether this platform's signal can see an attribute land at all. Every
	// `ignored` below is "the session came out the same", and that sentence is
	// worth nothing if the signal would have come out the same whatever the
	// reply carried. The control against the empty variant is the one pair that
	// settles it, and it is stated first because it bounds everything after it.
	b.WriteString(l18SensitivityReading(d, rs))

	// 1. The §8.2 question itself: what does an OPTIONAL attribute the device
	// does not understand do?
	opt := []l18Result{
		l18ByName(rs, l18OptForeign), l18ByName(rs, l18OptForeign2), l18ByName(rs, l18OptInvented),
	}
	refused, ignored, applied := l18Partition(d, opt, rs)
	switch {
	case len(refused) > 0:
		r := refused[0]
		b.WriteString("**1. This platform does NOT ignore an optional attribute it does not understand: " +
			"it refuses the session.** " + negativeFinding{
			Claim: fmt.Sprintf("RFC 8907 §8.2 says a device SHOULD ignore an OPTIONAL argument it does "+
				"not understand. On %s it does not: %d of the %d optional unknown attributes tried here "+
				"produced no session at all, on a session authorization port49 answered `%s`.",
				l.p.version, len(refused), l18Count(opt), orNone(r.sessionVerdict)),
			Sent: "reply attributes " + r.attrs + "\n(then one SSH login as a token operator)",
			Got:  strings.TrimRight(precReply(r.deviceSaid), "\n"),
		}.render(t) + "\n")
		fmt.Fprintf(&b, "The variants that did this: %s. An operator whose server definition carries "+
			"another vendor's attributes for a mixed fleet is locked out of this platform, and port49's "+
			"own log says `permit`.\n\n", l18Names(refused))
		// A platform that refuses some and not others is the interesting case,
		// and a paragraph that named only the refusals would read as though it
		// refused them all. The rest are named here or nowhere.
		if rest := append(append([]l18Result{}, ignored...), applied...); len(rest) > 0 {
			fmt.Fprintf(&b, "It is not every optional attribute, which is what makes this a rule about "+
				"particular names rather than about the flag: %s opened a session. So this platform "+
				"cannot be described as \"refuses anything it does not recognise\" on this run's "+
				"evidence, and an adapter cannot predict which names are safe from the flag alone.\n\n",
				l18Names(rest))
		}
	case len(applied) > 0:
		fmt.Fprintf(&b, "**1. An optional attribute this platform does not read is not inert here -- it "+
			"changed the session.** %s changed what the session got -- %s -- against the control, "+
			"which is the same reply without that attribute. Read the table before drawing a rule: "+
			"an attribute that changes "+
			"something without being the attribute that was meant is worse than one that is "+
			"ignored.\n\n", l18Names(applied), d.signalName)
	case len(ignored) == l18Count(opt) && l18Count(opt) > 0:
		fmt.Fprintf(&b, "**1. This platform does what RFC 8907 §8.2 says: an optional attribute it does "+
			"not understand is ignored.** All %d of them -- %s -- opened a session that matched the "+
			"control's on %s. The control carries the same reply without the extra attribute, so the "+
			"attribute is what changed, and nothing changed. An adapter may send another vendor's "+
			"attributes here marked optional without ending anyone's session.\n\n",
			l18Count(opt), l18Names(opt), d.signalName)
	default:
		b.WriteString("**1. Not answered by this run.** None of the optional-unknown variants produced " +
			"a comparable result; the table says what each one did.\n\n")
	}

	// 2. The mandatory half, which is the one §8.2 makes a MUST.
	mand := []l18Result{
		l18ByName(rs, l18MandForeign), l18ByName(rs, l18MandForeign2), l18ByName(rs, l18MandInvented),
	}
	mRefused, mIgnored, mApplied := l18Partition(d, mand, rs)
	switch {
	case len(mRefused) == l18Count(mand) && l18Count(mand) > 0:
		fmt.Fprintf(&b, "**2. And it does what §8.2 makes a MUST: every MANDATORY attribute it does not "+
			"understand ended the session.** All %d of them -- %s. So on this platform the argument "+
			"flag is a working switch: an adapter that wants to be told when an attribute did not land "+
			"can send it mandatory and find out by losing the session.\n\n",
			len(mRefused), l18Names(mRefused))
	case len(mRefused) > 0:
		fmt.Fprintf(&b, "**2. The MANDATORY half is not uniform.** %s ended the session, and %s did "+
			"not. §8.2 says a device MUST fail an authorization carrying a mandatory argument it does "+
			"not understand, so the ones that opened are the exception -- and they are the dangerous "+
			"ones for an adapter, which cannot tell from the wire that its attribute was dropped.\n\n",
			l18Names(mRefused), l18Names(append(append([]l18Result{}, mIgnored...), mApplied...)))
	case len(mIgnored) > 0 && len(mApplied) == 0:
		b.WriteString("**2. It does NOT do what §8.2 makes a MUST.** " + negativeFinding{
			Claim: fmt.Sprintf("a MANDATORY argument this device does not understand does NOT fail the "+
				"authorization on %s: the session opened and came out indistinguishable from the "+
				"control, which is the same reply with the mandatory argument taken out. So the "+
				"mandatory flag buys an adapter nothing here -- there is no way to make this device "+
				"say that an attribute did not land.", l.p.version),
			Sent: "reply attributes " + l18ByName(rs, l18MandInvented).attrs +
				"\nthen, in the session:\n" + strings.Join(l18ByName(rs, l18MandInvented).showCmds(), "\n"),
			Got: strings.TrimRight(l18ByName(rs, l18MandInvented).showAll(), "\n"),
		}.render(t) + "\n")
	default:
		b.WriteString("**2. The mandatory half is in the table**, and the variants did not form one " +
			"answer; read the rows rather than a rule.\n\n")
	}

	// 3. The known attribute under both flags: can an adapter be polite?
	ctrlR, optKnown := l18ByName(rs, l18Control), l18ByName(rs, l18OptKnown)
	if ctrlR.opened && optKnown.opened {
		cs, os := d.signal(&ctrlR), d.signal(&optKnown)
		if cs != "" && cs == os {
			fmt.Fprintf(&b, "**3. A KNOWN attribute is applied under either flag.** `%s` and `%s` both "+
				"left the session on `%s`, so an adapter may mark this platform's own attributes "+
				"optional -- the politeness §8.2 invites -- without losing what they deliver.\n\n",
				ctrlR.attrs, optKnown.attrs, cs)
		} else {
			fmt.Fprintf(&b, "**3. The argument flag CHANGES what a known attribute delivers.** Mandatory "+
				"gives `%s`; optional gives `%s`. An adapter has to choose the flag deliberately on "+
				"this platform, and an operator who copies a reply from another vendor's server "+
				"definition may copy the flag with it.\n\n", l18Dash(cs), l18Dash(os))
		}
	} else if !optKnown.opened {
		b.WriteString("**3. The OPTIONAL spelling of a known attribute ended the session**, which is " +
			"the opposite of what §8.2 is about; the variant's own section has the device's words.\n\n")
	}

	// 4. The bad value, which is the typo rather than the mixed fleet.
	bad := l18ByName(rs, l18BadValue)
	switch {
	case !bad.opened:
		b.WriteString("**4. A known attribute with a value the device cannot use ends the session.** " +
			negativeFinding{
				Claim: "`" + bad.attrs + "` is an attribute this platform reads, carrying a value it " +
					"cannot use. It does not clamp the value and it does not ignore the attribute: " +
					"there is no session.",
				Sent: "reply attributes " + bad.attrs + "\n(then one SSH login as a token operator)",
				Got:  strings.TrimRight(precReply(bad.deviceSaid), "\n"),
			}.render(t) + "\n")
	case d.signal(&bad) != "" && control.opened && d.signal(&bad) == d.signal(&control):
		fmt.Fprintf(&b, "**4. A known attribute with an unusable value is dropped, not clamped.** `%s` "+
			"left the session on `%s` -- the same as sending nothing. The operator gets a working "+
			"login with none of the privilege the policy named, and port49's log records the attribute "+
			"as sent.\n\n", bad.attrs, l18Dash(d.signal(&bad)))
	default:
		fmt.Fprintf(&b, "**4. A known attribute with an unusable value is taken somehow.** `%s` left the "+
			"session on `%s`, against `%s` for the empty control. What the device did with the value is "+
			"in the transcript above; this run does not name a rule for it.\n\n",
			bad.attrs, l18Dash(d.signal(&bad)), l18Dash(d.signal(&control)))
	}

	// 5. Per-command authorization: does a session that survived a bad
	// attribute still reach the command path?
	b.WriteString(l18CommandReading(rs))

	// 6. What a run of refusals does to the device's SSH server, which is the
	// question an operator actually meets: not "is my session refused" but "is
	// the device still answering".
	b.WriteString(l18SSHReading(t, l, rs))

	// 7. Junos only: the two attributes decision 22 will use.
	b.WriteString(l18JunosReading(t, d, rs, control))
	return b.String()
}

// showCmds and showAll render a variant's role commands and their output, for a
// negativeFinding that has to show what was asked as well as what came back.
func (r l18Result) showCmds() []string {
	out := make([]string, 0, len(r.shows))
	for _, s := range r.shows {
		out = append(out, s.cmd)
	}
	return out
}

func (r l18Result) showAll() string {
	var b strings.Builder
	for _, s := range r.shows {
		fmt.Fprintf(&b, "%s\n%s\n", s.cmd, strings.TrimRight(s.out, "\n"))
	}
	if b.Len() == 0 {
		return emptyDeviceReply
	}
	return b.String()
}

// l18Partition splits variants into refused, ignored and applied, each against
// ITS OWN baseline rather than one shared row -- the same correction l18Cell
// carries, so the prose below the table cannot reach a different verdict from
// the cell above it. Variants that are not present on this platform (an empty
// name) are dropped rather than counted, so a three-way count on a platform
// that runs two of them is two.
func l18Partition(d l18Driver, rs, all []l18Result) (refused, ignored, applied []l18Result) {
	for _, r := range rs {
		if r.v.name == "" {
			continue
		}
		base := l18ByName(all, r.v.baseline)
		switch {
		case r.neverAsked():
			// The reply never reached the device, so this variant says nothing
			// about the attribute. It is reported on its own, not as a refusal.
		case !r.opened:
			refused = append(refused, r)
		case base.v.name == "" || !base.opened || d.signal(&base) == "" || d.signal(&r) == "":
			// Not comparable; it belongs in no bucket, and the table says so.
		case d.signal(&r) == d.signal(&base):
			ignored = append(ignored, r)
		default:
			applied = append(applied, r)
		}
	}
	return refused, ignored, applied
}

func l18Count(rs []l18Result) int {
	n := 0
	for _, r := range rs {
		if r.v.name != "" {
			n++
		}
	}
	return n
}

func l18Names(rs []l18Result) string {
	names := make([]string, 0, len(rs))
	for _, r := range rs {
		if r.v.name != "" {
			names = append(names, "`"+r.attrs+"`")
		}
	}
	if len(names) == 0 {
		return "(none)"
	}
	return strings.Join(names, ", ")
}

// l18CommandReading says whether the sessions that opened went on to send
// per-command authorization, which is the neighbouring question to the one the
// lab authorizer cannot ask.
func l18CommandReading(rs []l18Result) string {
	opened, withCmds := 0, 0
	for _, r := range rs {
		if !r.opened {
			continue
		}
		opened++
		if len(r.cmdReqs) > 0 {
			withCmds++
		}
	}
	if opened == 0 {
		return "**5. Per-command authorization is unmeasured here**: no variant opened a session.\n\n"
	}
	if withCmds == 0 {
		return fmt.Sprintf("**5. This platform sends no per-command authorization at all.** All %d "+
			"sessions that opened ran the probe command and not one produced an `authorize_command` "+
			"record. So the per-command reply is not a place this platform could be handed a bad "+
			"attribute even if port49 had one to send -- which is the shape decision 21 already "+
			"records for Junos.\n\n", opened)
	}
	if withCmds == opened {
		return fmt.Sprintf("**5. Every session that opened went on to per-command authorization**, %d of "+
			"%d, whatever the reply carried. So a bad attribute on this platform either ends the "+
			"session outright or leaves the command path exactly as it was: there is no middle state "+
			"where the session survives and the device stops asking.\n\n", withCmds, opened)
	}
	return fmt.Sprintf("**5. Per-command authorization did not follow every session.** %d of the %d "+
		"sessions that opened produced `authorize_command` records and the rest produced none, so on "+
		"this platform a reply attribute can leave a session alive and outside the command path. The "+
		"table says which.\n\n", withCmds, opened)
}

// l18JunosReading is the decision-22 half, and renders nothing on the platforms
// that have no such variants.
func l18JunosReading(t *testing.T, d l18Driver, rs []l18Result, control l18Result) string {
	user := l18ByName(rs, l18Control)
	permsM := l18ByName(rs, l18JunosPermsM)
	permsO := l18ByName(rs, l18JunosPermsO)
	both := l18ByName(rs, l18JunosBothMand)
	if permsM.v.name == "" {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n## The two attributes decision 22 will use\n\n")
	fmt.Fprintf(&b, "Spec §8's session-only projection sends `local-user-name` and `user-permissions` "+
		"over `junos-exec`, and §15 L12 records both as unmeasured over TACACS+. This run asks each of "+
		"them the same way the variants above ask about foreign attributes: does the session change, "+
		"and what does `show cli authorization` say.\n\n")

	// local-user-name.
	if !user.opened {
		fmt.Fprintf(&b, "**`local-user-name` ended the session.** The device said:\n\n```\n%s\n```\n\n",
			strings.TrimRight(precReply(user.deviceSaid), "\n"))
	} else if control.opened && d.signal(&user) != "" && d.signal(&user) != d.signal(&control) {
		b.WriteString("**`local-user-name` takes effect over `junos-exec`.** " + negativeFinding{
			Claim: "the session does NOT stay on the device's own `user remote` template when the reply " +
				"names another one. With `" + user.attrs + "` the session came out `" +
				d.signal(&user) + "`, against `" + d.signal(&control) + "` for a reply carrying no " +
				"attributes at all, minutes apart on the same device.",
			Sent: "reply attributes " + user.attrs + "\nthen, in the session:\nshow cli authorization",
			Got:  strings.TrimRight(user.show("show cli authorization"), "\n"),
		}.render(t) + "\n")
	} else {
		fmt.Fprintf(&b, "**`local-user-name` did not change the session.** It came out `%s`, the same as "+
			"a reply carrying nothing. The template it names is defined on the device for this run, so "+
			"this is the device declining to move the session rather than the template being absent.\n\n",
			l18Dash(d.signal(&user)))
	}

	// `local-user-name` OPTIONAL is variant 2 on this platform, and the
	// projection's choice of flag rests on it: §8.2 lets a device drop an
	// optional argument, and if Junos does, decision 22 has to send mandatory
	// and wear what that costs on a device that does not understand it.
	if optUser := l18ByName(rs, l18OptKnown); optUser.v.name != "" {
		switch {
		case !optUser.opened:
			fmt.Fprintf(&b, "**`local-user-name` sent OPTIONAL ended the session.** The device "+
				"said:\n\n```\n%s\n```\n\n", strings.TrimRight(precReply(optUser.deviceSaid), "\n"))
		case user.opened && d.signal(&optUser) == d.signal(&user) && d.signal(&user) != "":
			fmt.Fprintf(&b, "**The flag does not change `local-user-name`.** Sent optional (`%s`) it "+
				"left the session `%s`, the same as the mandatory form, so decision 22 may mark it "+
				"optional -- which on a device that does not understand it is the difference between "+
				"a degraded session and no session.\n\n", optUser.attrs, l18Dash(d.signal(&optUser)))
		default:
			fmt.Fprintf(&b, "**The flag DOES change `local-user-name`.** Optional (`%s`) left the "+
				"session `%s` against `%s` mandatory, so the projection has to choose the flag "+
				"deliberately.\n\n", optUser.attrs, l18Dash(d.signal(&optUser)), l18Dash(d.signal(&user)))
		}
	}

	// user-permissions, both flags.
	for _, r := range []l18Result{permsM, permsO} {
		if r.v.name == "" {
			continue
		}
		flag := "MANDATORY"
		if r.v.name == l18JunosPermsO {
			flag = "OPTIONAL"
		}
		switch {
		case !r.opened:
			fmt.Fprintf(&b, "**`user-permissions` %s ended the session.** The device said:\n\n```\n%s\n```\n\n",
				flag, strings.TrimRight(precReply(r.deviceSaid), "\n"))
		case control.opened && d.signal(&r) != "" && d.signal(&r) != d.signal(&control):
			fmt.Fprintf(&b, "**`user-permissions` %s takes effect.** `%s` left the session `%s`, against "+
				"`%s` for the empty control. `show cli authorization` in full:\n\n```\n%s\n```\n\n",
				flag, r.attrs, l18Dash(d.signal(&r)), l18Dash(d.signal(&control)),
				strings.TrimRight(r.show("show cli authorization"), "\n"))
		default:
			fmt.Fprintf(&b, "**`user-permissions` %s did not change the session**: `%s` came out `%s`, "+
				"the same as the empty control. `show cli authorization` in full:\n\n```\n%s\n```\n\n",
				flag, r.attrs, l18Dash(d.signal(&r)),
				strings.TrimRight(r.show("show cli authorization"), "\n"))
		}
	}

	// Both together, which is the shape the projection would send.
	if both.v.name != "" {
		if !both.opened {
			fmt.Fprintf(&b, "**Both together ended the session.** The device said:\n\n```\n%s\n```\n\n",
				strings.TrimRight(precReply(both.deviceSaid), "\n"))
		} else {
			bs, us, ps := d.signal(&both), d.signal(&user), d.signal(&permsM)
			fmt.Fprintf(&b, "**Both together** -- the shape the projection would actually send -- left "+
				"the session `%s`, against `%s` for `local-user-name` alone and `%s` for "+
				"`user-permissions` alone. %s `show cli authorization` in full:\n\n```\n%s\n```\n\n",
				l18Dash(bs), l18Dash(us), l18Dash(ps), junosPairReading(bs, us, ps, d.signal(&control)),
				strings.TrimRight(both.show("show cli authorization"), "\n"))
		}
	}
	b.WriteString("None of this closes §15 L12. That row asks four more questions this run does not " +
		"touch -- whether `user-permissions` replaces or merges across a bitless template, what each " +
		"bit reaches, the wire `deny-commands` precedence, and whether numbered attribute names are " +
		"distinct -- and a row closes on all of its clauses or none.\n")
	return b.String()
}

// l18SensitivityReading says whether this run could have seen an attribute
// land, and it is the first paragraph of every note for that reason.
//
// `ignored` is a negative in disguise: it says the device did something
// invisible with the attribute. The only thing that makes it evidence rather
// than an assumption is that the SAME measurement, on the same device minutes
// apart, showed a visible difference when an attribute the device does read was
// sent. That is the control against the empty variant. If those two come out
// identical, every `ignored` cell in the table is unfalsifiable and the note
// has to say so rather than let a reader take the column at face value.
func l18SensitivityReading(d l18Driver, rs []l18Result) string {
	ctrl, empty := l18ByName(rs, l18Control), l18ByName(rs, l18Empty)
	if !ctrl.opened || !empty.opened {
		return "**0. This run cannot tell `ignored` from `not applied`.** One of the two rows that " +
			"calibrate the measurement -- the control and the empty reply -- did not open a session, " +
			"so nothing below is a comparison against a known-good delivery. Read the transcripts.\n\n"
	}
	cs, es := d.signal(&ctrl), d.signal(&empty)
	if cs == "" || es == "" {
		return "**0. This run cannot tell `ignored` from `not applied`.** The device did not report " +
			"what one of the two calibrating sessions was given, so there is no visible difference to " +
			"measure the other rows against.\n\n"
	}
	if cs == es {
		return fmt.Sprintf("**0. Read every `ignored` below as unproven.** The control (`%s`) and the "+
			"empty reply (`%s`) produced the SAME %s -- `%s` -- so on this platform this measurement "+
			"cannot see an attribute land at all. A row that looks `ignored` here may equally have "+
			"been applied invisibly. What the table still says with confidence is which replies "+
			"ended the session.\n\n", ctrl.attrs, empty.attrs, d.signalName, cs)
	}
	return fmt.Sprintf("**0. The measurement can see an attribute land.** The control (`%s`) left the "+
		"session `%s` and the empty reply (`%s`) left it `%s`, on the same device minutes apart. So "+
		"when a row below reads `ignored` it means the device produced the same session as the "+
		"control despite being sent something extra -- a comparison, not an assumption.\n\n",
		ctrl.attrs, cs, empty.attrs, es)
}

// l18SSHReading reports what a run of refused authorizations did to the
// device's SSH server, and says nothing on a platform where nothing happened.
//
// This exists because the first IOS-XE run found it by failing. Five variants
// in a row were refused, and the sixth could not get an SSH connection at all:
// three attempts over 50 seconds, every one refused at the authentication
// layer, with **no TACACS+ packet for any of them** in port49's decision log.
// The variant after it connected normally. So the device recovered on its own,
// and for that window it was refusing everyone -- break-glass included, since
// break-glass reaches the same SSH server.
//
// That is the operational half of this row. "A bad attribute costs one operator
// one session" is the polite version; what a fleet meets is a device that stops
// answering after a handful of them, with nothing in the TACACS+ log to say so,
// because the refusals never reach the TACACS+ server.
func l18SSHReading(t *testing.T, l *lab, rs []l18Result) string {
	t.Helper()
	var never, retried []l18Result
	for _, r := range rs {
		switch {
		case r.neverAsked():
			never = append(never, r)
		case r.attempts > 1:
			retried = append(retried, r)
		}
	}
	if len(never) == 0 && len(retried) == 0 {
		return "**6. Every login in this run reached the device's AAA.** No SSH connection was refused " +
			"before the device asked port49, so nothing here says a run of refused authorizations " +
			"costs anything beyond the sessions refused.\n\n"
	}
	var b strings.Builder

	// The heading is the strongest thing this run's own evidence supports and
	// no stronger. A variant the device never answered at all is an outage; a
	// variant that needed a second or third connection and then got one is the
	// same mechanism caught recovering, and calling that an outage would be a
	// paragraph contradicting the table above it.
	if len(never) > 0 {
		r := never[0]
		b.WriteString("**6. A run of refused authorizations stops the device answering SSH at all.** " +
			negativeFinding{
				Claim: fmt.Sprintf("on %s, after the refusals above, %d variant(s) could not get an SSH "+
					"connection at all -- and port49 was never asked. Its decision log holds no redeem "+
					"and no session authorization for those logins, so the device refused them without "+
					"consulting the TACACS+ server. The reply under test never reached it.",
					l.p.version, len(never)),
				Sent: "reply attributes " + r.attrs + "\n(then " + fmt.Sprint(r.attempts) +
					" SSH connections as a token operator, " + fmt.Sprint(int(l18IOSXEPause.Seconds())) +
					"s apart)",
				Got:      strings.Join(r.attemptErrs, "\n"),
				Inferred: true,
				Why: "the device said nothing: it refused the SSH authentication before any banner. " +
					"What is measured is the ABSENCE of any record for these logins in port49's own " +
					"decision log, beside records for the logins either side of them, which is what " +
					"says the device did not ask rather than that port49 did not answer.",
			}.render(t) + "\n")
	} else {
		r := retried[0]
		fmt.Fprintf(&b, "**6. A refused authorization costs the NEXT connection too, and the device "+
			"recovers on its own.** %s took %d SSH connections: the first %d were refused at the "+
			"authentication layer, before the device ran AAA at all, and the last one got through to "+
			"the device's own answer. What the refused connections returned:\n\n```\n%s\n```\n\n"+
			"Nothing was lost to it here -- every variant was measured -- so this run does not show an "+
			"outage, it shows the mechanism that produces one. An earlier run of this same test on this "+
			"same image did lose one: three connections over 50 seconds, every one refused this way, "+
			"with no TACACS+ packet for any of them, and the variant after them connected normally.\n\n",
			l18Names([]l18Result{r}), r.attempts, r.attempts-1, strings.Join(r.attemptErrs, "\n"))
		if len(retried) > 1 {
			fmt.Fprintf(&b, "%d variants in this run needed more than one connection; each one's "+
				"section says how many it took.\n\n", len(retried))
		}
	}

	b.WriteString("**What that means at 3am, and it is the operational half of this row.** These " +
		"refusals do not reach port49, so its log says nothing about them: the last thing in it is a " +
		"`permit`. The operator sees an SSH server refusing their password, which looks like a " +
		"credential problem and is not one. Break-glass reaches the same SSH server, so for as long " +
		"as the condition lasts it is refused too. The trigger is a reply attribute -- one line in a " +
		"server definition -- and the blast radius is the device rather than the session.\n\n")
	return b.String()
}

// l18IOSXEPause is the gap between retried SSH connections on IOS-XE. It is a
// package-level constant so the note can quote the number it actually used
// rather than a number written beside it.
const l18IOSXEPause = 20 * time.Second

// junosPairReading says what the pair of decision-22 attributes did together,
// from the three signals rather than from an expectation.
//
// It is a sentence and not a table cell because it is the question the
// projection turns on: §8 sends both, and whether the second one adds anything
// decides whether the projection is one mechanism or two. The three outcomes
// are distinguishable from the signals alone -- the pair equal to
// `local-user-name` alone means the second attribute is inert, the pair equal
// to `user-permissions` alone means it wins, and anything else means they
// compose -- so this never states more than the run measured.
func junosPairReading(both, user, perms, empty string) string {
	switch {
	case both == "" || user == "" || perms == "":
		return "One of the three produced no signal, so this run does not say whether they compose."
	case both == user && perms == empty:
		return "**So `user-permissions` contributes nothing, beside `local-user-name` or on its own.** " +
			"The pair is indistinguishable from `local-user-name` alone, and `user-permissions` alone " +
			"is indistinguishable from an empty reply. On this image the projection's second attribute " +
			"is inert: whatever decision 22 puts in it, the operator gets the template's class and " +
			"nothing else, and port49's log records an attribute that did nothing."
	case both == user:
		return "**So `local-user-name` decides it and `user-permissions` does not change the result " +
			"when both are sent**, even though `user-permissions` alone does something."
	case both == perms:
		return "**So `user-permissions` wins when both are sent**: the pair matches it and not " +
			"`local-user-name` alone, which is the documented replace-rather-than-merge behaviour " +
			"(§15 L12) showing up between the two attributes rather than inside one."
	default:
		return "**So the two compose into something neither produces alone.** Read the three signals " +
			"above before the projection sends both."
	}
}
