package policy

import (
	"slices"
	"strings"
	"testing"

	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/engine"
	"github.com/rhwendt/port49/internal/platform"
	"github.com/rhwendt/port49/internal/projection"
)

// projectedKeywords is the test set's keyword tree: every word these tests
// deny or allow on juniper_junos, as the lab's capture writes it. `show
// interfaces` and `show route` take an argument, as on Junos, and nothing
// under `show configuration` is a keyword: a hierarchy is not proven one to
// deny-commands, so the capture proves none there (Task 3b ruling;
// tests/lab/results/L26-juniper_*.md).
const projectedKeywords = `platform: juniper_junos
nodes:
  "": {words: ["clear", "configure", "help", "monitor", "ping", "quit", "request", "set", "show", "traceroute"], argument: false}
  "show": {words: ["alpha", "bravo", "charlie", "configuration", "delta", "echo", "foxtrot", "golf", "hotel", "india", "interfaces", "juliett", "kilo", "lima", "log", "mike", "november", "oscar", "papa", "route", "system", "version"], argument: false}
  "show configuration": {words: [], argument: true}
  "show interfaces": {words: ["terse"], argument: true}
  "show route": {words: [], argument: true}
  "show system": {words: ["users"], argument: false}
  "show version": {words: [], argument: false}
  "clear": {words: ["bgp", "counters"], argument: false}
  "clear counters": {words: [], argument: false}
  "request": {words: ["system"], argument: false}
  "request system": {words: ["reboot"], argument: false}
`

func init() {
	_, k, err := platform.ParseKeywords([]byte(projectedKeywords))
	if err != nil {
		panic(err)
	}
	shipped := setKeywords
	setKeywords = func(version, name string) *platform.Keywords {
		if version == projectedSet && name == "juniper_junos" {
			return k
		}
		return shipped(version, name)
	}
}

// A deny that names an argument and meets a permit gets its subject the
// fail-closed reply, and lint, policy test and explain tell the operator the
// word Junos can't deny by and the whole command to deny instead, naming only
// the rule they wrote (decision 27; spec §12 projection_refused). Each is a
// command the lab did not prove a keyword: a hierarchy under `show
// configuration`, `summary` after `show route`, and `show cli`.
func TestAnArgumentDenyTellsTheOperatorWhatToDenyInstead(t *testing.T) {
	for _, c := range []struct{ deny, word, instead string }{
		{"show configuration system", "`system` in `deny show configuration system`", "deny the whole command (`show configuration`) or drop the rule"},
		{"show route summary", "`summary` in `deny show route summary`", "deny the whole command (`show route`) or drop the rule"},
		{"show cli", "`cli` in `deny show cli`", "deny the whole command (`show`) or drop the rule"},
	} {
		p := parseProjected(t, platform.BitDeliveryUserPermissions, scopeOK+`roles:
  - {name: r, privilege: readonly, permit: ["show **"], deny: ["`+c.deny+`"]}
`+subjOK+grantOK+`tests:
  - {subject: s, device: srx-fw-04, command: "show version", expect: permit}
`)
		says := func(text string) bool {
			return strings.Contains(text, "gets the fail-closed reply (argument_deny)") ||
				strings.Contains(text, "faithfully (argument_deny)")
		}
		told := func(text string) bool {
			return says(text) && strings.Contains(text, "Junos can't deny by argument: "+c.word) &&
				strings.Contains(text, c.instead) && !strings.Contains(text, "baseline")
		}
		var refused []string
		for _, f := range p.Lint(noon) {
			if f.Kind == FindingProjectionRefused {
				refused = append(refused, f.Message)
			}
		}
		if len(refused) != 1 || !told(refused[0]) {
			t.Errorf("%s: lint %q", c.deny, refused)
		}
		// It binds that subject only: the device is not quarantined
		// (decision 26), and the test says why the device refuses it.
		r := p.RunTests(noon)[0]
		if r.Reason == decision.DeviceQuarantined || !slices.ContainsFunc(r.Caveats, told) {
			t.Errorf("%s: policy test %s %q", c.deny, r.Reason, r.Caveats)
		}
	}
}

// A refusal quotes a deny only where no value in it is one redaction hides:
// one that carries a secret is refused as secret_rule first, naming the role,
// and no report prints the value (spec §5.8).
func TestAnArgumentDenyNeverPrintsASecret(t *testing.T) {
	p := parseProjected(t, platform.BitDeliveryUserPermissions, scopeOK+`roles:
  - {name: r, privilege: readonly, permit: ["show **"], deny: ["show system radius-server 10.0.0.1 secret HUNTER2"]}
`+subjOK+grantOK+`tests:
  - {subject: s, device: srx-fw-04, command: "show version", expect: permit}
`)
	var shown []string
	for _, f := range p.Lint(noon) {
		shown = append(shown, f.Message)
		if f.Kind == FindingProjectionRefused && !strings.Contains(f.Message, "(secret_rule)") {
			t.Errorf("not refused as secret_rule: %s", f.Message)
		}
	}
	for _, r := range p.RunTests(noon) {
		shown = append(shown, r.Caveats...)
	}
	if text := strings.Join(shown, "\n"); strings.Contains(text, "HUNTER2") || !strings.Contains(text, "secret_rule") {
		t.Fatalf("%s", text)
	}
}

// An allow Junos would not match as port49 does is left off the reply, and
// policy test warns, naming the rule and why, without failing (decision 27).
func TestAnArgumentAllowIsAWarning(t *testing.T) {
	p := parseProjected(t, platform.BitDeliveryUserPermissions, scopeOK+`roles:
  - {name: r, privilege: readonly, permit: ["show version", "show interfaces fxp0 **", "show interfaces terse"]}
`+subjOK+grantOK)
	var got []string
	for _, f := range p.Lint(noon) {
		if f.Kind == FindingProjectionArgumentAllow {
			got = append(got, f.Message)
		}
	}
	if len(got) != 2 || got[0] != `subject "s" on juniper_junos: allow "show interfaces fxp0 **" (role "r") is not sent: `+
		`"fxp0" is not a keyword the lab measured after "show interfaces", so an allow of it never matches on the `+
		"device; the device refuses what port49 permits there. Permit the whole command with `**` after its "+
		"keywords, or drop the rule (spec §13 decision 27)" ||
		!strings.Contains(got[1], `would also run "show interfaces <argument> terse"`) || ProjectionRefusals(p.Lint(noon)) != 0 {
		t.Fatalf("%q", got)
	}
	// It fails neither policy test nor policy diff: the device refuses what
	// port49 permits there, which fails closed.
	if d := Compare(p, p, noon); len(d.ProjectionRefusals) != 0 {
		t.Fatalf("policy diff: %+v", d.ProjectionRefusals)
	}
}

// The warning says when it holds and names its devices where it is on fewer
// than all of the subject's, as a projection finding does (task 11).
func TestAnArgumentAllowWarningSaysWhenAndWhere(t *testing.T) {
	p := parseProjected(t, platform.BitDeliveryUserPermissions, scopeOK+
		"  - {name: few, match: {os_version: 21.4R3-S4}}\n"+`roles:
  - {name: ok, privilege: readonly, permit: ["show version"]}
  - {name: r, privilege: readonly, permit: ["show interfaces fxp0 **"]}
`+subjOK+`grants:
  - {subject: s, scope: all_devices, roles: [ok]}
  - {subject: s, scope: few, roles: [r], expires: 2099-01-01}
`)
	var got []string
	for _, f := range p.Lint(noon) {
		if f.Kind == FindingProjectionArgumentAllow {
			got = append(got, f.Message)
		}
	}
	if len(got) != 1 || !strings.HasPrefix(got[0], `subject "s" on juniper_junos, until 2099-01-01T00:00:00.000Z, `+
		`when grant few [r] expires: allow "show interfaces fxp0 **" (role "r") is not sent: `) ||
		!strings.HasSuffix(got[0], "(spec §13 decision 27); on 1 device: srx-fw-04") {
		t.Fatalf("%q", got)
	}
}

// The warning prints no value redaction hides (spec §5.8). A rule that
// carries one never reaches Unsent: its composition is refused as
// secret_rule first, naming only the role. A value another rule hides,
// written in a rule that is sent nowhere, the writer redacts in any letter
// case, since the reason quotes the rule's own words unchanged.
func TestAnArgumentAllowWarningNeverPrintsASecret(t *testing.T) {
	const secret = "show system radius-server 10.0.0.1 secret HUNTER2"
	p := parseProjected(t, platform.BitDeliveryUserPermissions, scopeOK+`roles:
  - {name: r, privilege: readonly, permit: ["show version", "`+secret+`"]}
`+subjOK+grantOK)
	var all []string
	secretRule := false
	for _, f := range p.Lint(noon) {
		if f.Kind == FindingProjectionArgumentAllow {
			t.Errorf("a secret rule reached Unsent: %s", f.Message)
		}
		all = append(all, f.Message)
		secretRule = secretRule || strings.Contains(f.Message, `(secret_rule): role "r" has a rule`)
	}
	if !secretRule || strings.Contains(strings.Join(all, "\n"), "HUNTER2") {
		t.Fatalf("%s", strings.Join(all, "\n"))
	}
	for _, d := range p.env.Devices {
		if res, err := p.ResolveSubject("s", d, noon); err == nil && res.Projection != nil && len(res.Projection.Unsent) != 0 {
			t.Errorf("%s: %+v", d.Name, res.Projection.Unsent)
		}
	}

	p = parseProjected(t, platform.BitDeliveryUserPermissions, scopeOK+`roles:
  - {name: r, privilege: readonly, permit: ["show version", "show interfaces hunter2 **"]}
  - {name: sec, privilege: readonly, permit: ["`+secret+`"]}
`+subjOK+grantOK)
	writer := func(line string) string {
		return platform.RedactValues(p.HiddenValues(), platform.RedactQuoted(p.Redactions(), line))
	}
	var warned []string
	for _, f := range p.Lint(noon) {
		if f.Kind == FindingProjectionArgumentAllow {
			warned = append(warned, writer(f.Message))
		}
	}
	if len(warned) != 1 || strings.Contains(strings.ToUpper(warned[0]), "HUNTER") ||
		!strings.Contains(warned[0], `is not a keyword the lab measured after "show interfaces"`) {
		t.Fatalf("%q", warned)
	}

	// The message redacts the rule it quotes itself, whatever reached it.
	patterns := p.Redactions()
	msg := unsentMessage(projection.Unsent{Rule: engine.Rule{Verdict: engine.Permit, Rule: secret, Role: "r"},
		Why: "w"}, patterns)
	if strings.Contains(msg, "HUNTER2") || !strings.Contains(msg, platform.Redacted) {
		t.Errorf("%s", msg)
	}
}
