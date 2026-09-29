//go:build lab

package lab

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/tests/lab/labcreds"
)

// L16, the precedence half: what an NX-OS session holds when the reply carries
// BOTH `priv-lvl=N` and `shell:roles`.
//
// L16 measured the two paths separately and each one works: `priv-lvl=15`
// alone lands the session on `network-admin`, `shell:roles*<name>` alone
// delivers the named role. It never sent both at once, which is the only shape
// that decides the adapter rule for this platform -- and the shape the owner's
// production Nexus 9000 has been running for years. Its read-only server
// definition sent `priv-lvl=15` together with an attribute misnamed `roles`;
// the misnamed one was rejected outright and everybody came in as
// `network-admin`. Correct the name and the two attributes disagree, and
// nothing in this lab or in the spec says which the device believes.
//
// The question, exactly: with `priv-lvl=15` and `shell:roles*network-operator`
// both in the reply, is the session an administrator or a read-only operator?
// If `priv-lvl` wins, an adapter that names a restrictive role and also sends
// the privilege level it computed hands out administrative access while its
// log records the restriction. If `shell:roles` wins, the rule is one line:
// send the role and never the privilege level.
//
// Three probes per variant. `show user-account <user>` is the device's own word
// for the role; `configure terminal` asks whether the session reaches
// configuration mode; `hostname <node>` asks whether it can change anything
// once there. The last two are separate because on Nexus 9300v 10.4(2)F they
// answer differently -- a `network-operator` session is admitted to
// configuration mode and refused the command inside it, `% Permission denied
// for the role` -- so reaching `(config)#` is not evidence of privilege on this
// platform, and configRefused() reads the pair rather than the prompt.
func TestL16PrivLvlRolePrecedence(t *testing.T) {
	eachPlatform(t, func(t *testing.T, l *lab) {
		if l.p.name != "cisco_nxos" {
			t.Skipf("the priv-lvl/roles precedence question is NX-OS's: it is the platform that reads "+
				"`shell:roles`, and L16 measured that %s does not (results/L16-arista_eos.md)", l.p.name)
		}
		d := l16Drivers[l.p.name]
		stop := l.capture(t, "L16-prec")
		defer stop()

		// Variant 7 names the custom role from L16, so it has to exist for the
		// length of this run and not afterwards.
		l16DefineRole(t, l, d)
		defer l16DeleteRole(t, l, d)

		results := make([]precResult, 0, len(precVariants))
		for _, v := range precVariants {
			results = append(results, l.precRun(t, d, v))
		}

		// Phase B. Everything above runs with `aaa authorization commands`
		// pointed at port49, which is the state this lab configures and the
		// state an operator is in AFTER port49 is deployed. In it, port49
		// answers every command `permit` and the role's own rules never get a
		// say -- so the configuration probe above cannot separate
		// `network-operator` from `network-admin`, and reading it as though it
		// could is how this note would claim a precedence the device never
		// showed it. Phase B takes port49 out of the command path and asks the
		// same two variants again, which is the only way to see what the
		// delivered role is worth by itself.
		phaseB := l.precPhaseB(t, d)

		var b strings.Builder
		b.WriteString(precPreamble(t, l, d))
		for _, r := range results {
			b.WriteString(r.render())
		}
		b.WriteString(precTable(results))
		b.WriteString(phaseB.render(results))
		b.WriteString(precReading(t, l, results, phaseB))
		l.appendResultSection(t, "L16", precHeading, b.String())

		// A variant whose session never opened measured nothing about
		// precedence. One is a finding; all of them is a test that measured
		// nothing, and must fail.
		reached := 0
		for _, r := range results {
			if r.loginErr == "" {
				reached++
			}
		}
		if reached == 0 {
			t.Fatalf("not one of the %d variants reached a prompt, so nothing about priv-lvl/roles "+
				"precedence was measured", len(results))
		}
		// The role the device names is the measurement; the configuration
		// probe is port49's answer, not the device's word about privilege. A
		// run where `show user-account` named a role for nobody has a note full
		// of transcripts and no answer in it.
		named := 0
		for _, r := range results {
			if r.role != "" {
				named++
			}
		}
		if named == 0 {
			t.Fatalf("`%s <user>` named a role in none of the %d variants, so which attribute the device "+
				"honours was not measured", d.whoami, len(results))
		}
		// These three decide the question: the two conflicting variants and the
		// `priv-lvl=15` baseline they are read against. Without all three there
		// is a note, but no answer in it.
		for _, name := range []string{precConflictOptional, precConflictMandatory, precBaselinePriv} {
			if r := precByName(results, name); r.loginErr != "" {
				t.Errorf("the %s variant never opened a session, so the precedence question is not answered "+
					"by this run: %s", name, r.loginErr)
			}
		}
	})
}

// precHeading is the section this test owns in results/L16-cisco_nxos.md. It is
// matched literally on rewrite, so a re-run replaces its own section rather
// than appending a second copy.
const precHeading = "Precedence: `priv-lvl` and `shell:roles` in the same reply"

// The names of the three variants the reading is built from.
const (
	precConflictOptional  = "`priv-lvl=15` + `shell:roles*network-operator`"
	precConflictMandatory = "`priv-lvl=15` + `shell:roles=network-operator`"
	precBaselinePriv      = "`priv-lvl=15` alone"
	precBaselineRole      = "`shell:roles=network-operator` alone"
	precInverseOptional   = "`priv-lvl=1` + `shell:roles*network-admin`"
	precInverseMandatory  = "`priv-lvl=0` + `shell:roles=network-admin`"
	precUnknownRole       = "`shell:roles=nonexistent-role` + `priv-lvl=15`"
	precSixAlone          = "`priv-lvl=6` alone"
)

// precVariant is one reply-attribute set and the question it answers.
type precVariant struct {
	name  string
	why   string
	attrs func(d l16Driver) string // a YAML flow sequence
}

// The variants, in the order the note reports them. The first two are the
// question; 3 and 4 ask it in the other direction, so an answer cannot be an
// artefact of `network-operator` being the weaker role; 5 and 6 are the
// controls each half is read against.
var precVariants = []precVariant{
	{
		name: precConflictOptional,
		why: "the question. The privilege level says administrator and the role says read-only, in the " +
			"OPTIONAL spelling an adapter would use. Whichever the session turns out to hold is the one " +
			"the device believes.",
		attrs: func(l16Driver) string { return `["priv-lvl=15", "shell:roles*network-operator"]` },
	},
	{
		name: precConflictMandatory,
		why: "the same conflict with the role sent MANDATORY. If a device resolves a conflict by argument " +
			"flag rather than by attribute, this is where it shows: the mandatory one is the one RFC 8907 " +
			"§8.2 says the device must honour or fail.",
		attrs: func(l16Driver) string { return `["priv-lvl=15", "shell:roles=network-operator"]` },
	},
	{
		name: precInverseOptional,
		why: "the conflict inverted: the privilege level says near-nothing and the role says administrator. " +
			"Without this, an answer of \"the restrictive one wins\" cannot be told apart from \"the role " +
			"wins\", and they imply opposite adapter rules.",
		attrs: func(l16Driver) string { return `["priv-lvl=1", "shell:roles*network-admin"]` },
	},
	{
		name: precInverseMandatory,
		why: "the inverted conflict with the role mandatory, and `priv-lvl=0` rather than 1 -- the lowest " +
			"privilege the protocol can express, against the highest role the device has.",
		attrs: func(l16Driver) string { return `["priv-lvl=0", "shell:roles=network-admin"]` },
	},
	{
		name: precBaselineRole,
		why: "the control for the role half: the role with NO privilege level in the reply at all. This is " +
			"the reply an adapter would send under the rule \"roles only\", so it is also the variant that " +
			"says whether that rule is safe to ship.",
		attrs: func(l16Driver) string { return `["shell:roles=network-operator"]` },
	},
	{
		name: precBaselinePriv,
		why: "the control for the privilege half, and the reply `tests/lab/port49d-lab.yaml` sends today " +
			"once its `shell:roles*network-admin` is taken out. L16 measured this as `network-admin`; it " +
			"is repeated here so both halves of every conflict are measured on the same deploy.",
		attrs: func(l16Driver) string { return `["priv-lvl=15"]` },
	},
	{
		name: "`shell:roles=p49-noc` + `priv-lvl=15`",
		why: "a CUSTOM role against the administrative privilege level. A built-in role might be resolved " +
			"by a table the custom ones are not in, and the custom role is what plan 5 would actually " +
			"deliver.",
		attrs: func(d l16Driver) string { return `["priv-lvl=15", "shell:roles=` + d.roleName + `"]` },
	},
	{
		name: precUnknownRole,
		why: "the 3am case crossed with the question. L16 measured that an unknown role name alone degrades " +
			"the session to `network-operator`. With `priv-lvl=15` beside it, does the degradation still " +
			"happen, or does the privilege level fill the gap and make the operator an administrator?",
		attrs: func(l16Driver) string { return `["priv-lvl=15", "shell:roles=nonexistent-role"]` },
	},
	{
		name: precSixAlone,
		why: "the owner saw `priv-lvl=6` map to `vdc-operator` on a production Nexus 9000 running NX-OS " +
			"10.3(5). This asks whether 10.4(2)F on the N9Kv agrees, which is the only part of the " +
			"production reading this lab can check.",
		attrs: func(l16Driver) string { return `["priv-lvl=6"]` },
	},
}

// precProbe is one command typed in a variant's session.
type precProbe struct {
	cmd       string
	expect    string // what this probe is for
	attempted bool
	skipped   string // why it was not typed, when it was not
	out       string // the device's exact reply
	refused   bool
	verdict   string // port49's verdict and reason, or "" when it never asked
	requests  int
	privs     string // the privilege the device asserted on those requests
}

// precResult is one variant's evidence.
type precResult struct {
	v        precVariant
	attrs    string
	user     string
	loginErr string
	whoami   string
	role     string
	// sessionVerdict and sessionPriv are port49's answer to this variant's
	// session authorization and the privilege the DEVICE asserted on it. The
	// second is the device's own notion of the session before any reply
	// attribute is applied, so it is the same on every variant -- which is
	// worth having on the page, because it is what makes the differences below
	// attributable to the reply and to nothing else.
	sessionVerdict string
	sessionPriv    string
	entered        bool // the session reached configuration mode
	probes         []precProbe
	// allCmds is every command authorization that reached port49 during this
	// variant, in order, as `vector -> verdict reason`. The probes above match
	// a record by its exact vector, and a device that spells a command
	// differently on the wire than it is typed would leave a probe reading "0
	// authorization requests" -- which is a finding, and a false one. This list
	// is what a reader checks that against without trusting the matcher.
	allCmds []string
}

// precPhase is the second half of this measurement: the same conflict asked
// with port49 out of the command path.
type precPhase struct {
	applied  bool
	applyErr string
	lines    []string
	rows     []precResult
}

// The method lists phase B swaps in and puts back. `local` rather than `none`
// on purpose: `none` authorizes everything and would answer the question with
// "the device stopped checking", where `local` is the device consulting the
// role it was handed -- which is what the role is for, and the configuration an
// operator has BEFORE port49 is deployed (spec §15 L16, "Unmeasured").
var (
	precLocalAuthz = []string{
		"aaa authorization commands default local",
		"aaa authorization config-commands default local",
	}
	precPort49Authz = []string{
		"aaa authorization commands default group port49 local",
		"aaa authorization config-commands default group port49 local",
	}
)

// precPhaseB points the device's command authorization at its own role
// database, re-asks the two variants that decide the question, and puts the
// method lists back.
//
// Why it has to exist: with `aaa authorization commands` pointed at port49 and
// a lab authorizer that permits everything, EVERY session configures the
// device whatever role it holds. That is a true measurement of this lab's
// configuration and a useless one for the question "what is the delivered role
// worth", because the role never gets asked. Here it is the only thing asked.
func (l *lab) precPhaseB(t *testing.T, d l16Driver) precPhase {
	t.Helper()
	p := precPhase{lines: precLocalAuthz}

	l.withAdminCLI(t, d.adminCLI, func(c *cliConn) error {
		out, err := l16Configure(l, c, d, precLocalAuthz)
		if err != nil {
			// Not fatal: phase A is already measured and written, and a note
			// that reports phase B as "not applied, here is why" is worth more
			// than a run thrown away. The claim itself is never written from a
			// phase that did not apply.
			p.applyErr = fmt.Sprintf("%v\n%s", err, out)
			return nil
		}
		p.applied = true
		return nil
	})
	if !p.applied {
		return p
	}
	// Put the lists back whatever happens below, so no later test on this
	// deploy measures a device whose command authorization this one moved.
	defer l.withAdminCLI(t, d.adminCLI, func(c *cliConn) error {
		if out, err := l16Configure(l, c, d, precPort49Authz); err != nil {
			return fmt.Errorf("restoring the port49 command-authorization method lists: %w\n%s", err, out)
		}
		return nil
	})

	for _, v := range []precVariant{
		{
			name: precPhaseBConflict,
			why: "the conflict again, with the device authorizing commands against the role it was handed " +
				"instead of asking port49. If `network-operator` is refused configuration mode here and " +
				"was allowed it above, the role is real privilege and port49's permit was what made it " +
				"look like a label.",
			attrs: func(l16Driver) string { return `["priv-lvl=15", "shell:roles*network-operator"]` },
		},
		{
			name: precPhaseBBaseline,
			why: "the same control as above, under the same changed method lists: the reply that carries " +
				"no role at all. It is what the `network-operator` row has to be read against, because a " +
				"refusal that happens to every session under local authorization says nothing about roles.",
			attrs: func(l16Driver) string { return `["priv-lvl=15"]` },
		},
	} {
		p.rows = append(p.rows, l.precRun(t, d, v))
	}
	return p
}

const (
	precPhaseBConflict = "`priv-lvl=15` + `shell:roles*network-operator`, command authorization LOCAL"
	precPhaseBBaseline = "`priv-lvl=15` alone, command authorization LOCAL"
)

// render writes phase B. aRows is phase A's results, so the paragraph that
// says why phase B exists counts what phase A did instead of asserting it.
func (p precPhase) render(aRows []precResult) string {
	opened, configured := 0, 0
	for _, r := range aRows {
		if r.loginErr != "" {
			continue
		}
		opened++
		if refused, _ := r.configRefused(); !refused {
			configured++
		}
	}
	var b strings.Builder
	b.WriteString("\n#### Phase B — the same question with port49 out of the command path\n\n")
	fmt.Fprintf(&b, "%d of the %d sessions above configured the device, whatever role the device named "+
		"for them. That is not the role failing to arrive -- `show user-account` names it in every row -- "+
		"it is `aaa authorization commands default group port49 local` sending each command to a lab "+
		"authorizer that permits everything, so the role is never consulted. Phase B points both "+
		"command-authorization method lists at the device's own role database and asks the two decisive "+
		"variants again:\n\n```\n%s\n```\n\nand puts them back afterwards.\n\n",
		configured, opened, strings.Join(precLocalAuthz, "\n"))
	if !p.applied {
		fmt.Fprintf(&b, "**Phase B did not run.** The method lists could not be changed, so nothing here "+
			"is measured:\n\n```\n%s\n```\n\n", strings.TrimRight(p.applyErr, "\n"))
		return b.String()
	}
	for _, r := range p.rows {
		b.WriteString(r.render())
	}
	b.WriteString(precTable(p.rows))
	return b.String()
}

// precRun measures one variant: restart the daemon with these reply
// attributes, log a token operator in, ask the device which role it thinks the
// session holds, and try to configure it.
func (l *lab) precRun(t *testing.T, d l16Driver, v precVariant) precResult {
	t.Helper()
	attrs := v.attrs(d)
	cfg, err := l.derivedConfig("l16prec-"+l16Slug(v.name), attrs, "")
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
	r := precResult{v: v, attrs: attrs}
	user, secret := l.nextLogin(t)
	r.user = user

	c, err := d.cli(l, user, secret)
	if err != nil {
		r.loginErr = err.Error()
		l.collectPrec(&r, l.drainRecords(off, 5*time.Second))
		return r
	}

	whoami := d.whoami + " " + user
	if out, err := d.show(l, c, whoami); err == nil {
		r.whoami = l16TrimEcho(out, whoami)
		r.role = l16RoleOf(r.whoami, user)
	}
	r.probes, r.entered = l.precConfigProbes(c, d)
	c.Close()

	l.collectPrec(&r, l.drainRecords(off, 10*time.Second))
	return r
}

// precConfigProbes types the two configuration commands and returns what the
// device said to each, verbatim.
//
// `configure terminal` is the privilege itself on this platform: `network-admin`
// enters configuration mode and `network-operator` does not, so the prompt that
// comes back is the measurement and no interpretation of a role name is needed
// to read it. `hostname <node>` is then a configuration command whose effect is
// to set the hostname to the value it already has -- a real write through the
// parser, `aaa authorization config-commands` and all, that changes nothing.
//
// A device that never reached configuration mode is not asked the second
// question, and the note says it was not asked rather than showing an empty
// reply that would read as a refusal.
func (l *lab) precConfigProbes(c *cliConn, d l16Driver) ([]precProbe, bool) {
	exec := l.p.node + "#"
	cfg := l.p.node + "(config)#"

	enter := precProbe{cmd: d.enterConfig, expect: "does the session reach configuration mode at all",
		attempted: true}
	out, _ := c.sendExpect(d.enterConfig, 60*time.Second, cfg, exec)
	enter.out = precReply(l16TrimEcho(out, d.enterConfig))
	entered := strings.Contains(out, cfg)
	enter.refused = !entered || precRefused(enter.out, d)

	set := precProbe{cmd: "hostname " + l.p.node, expect: "the configuration command itself, writing the " +
		"value the device already holds -- this is where NX-OS enforces a role, not at the mode change"}
	if entered {
		set.attempted = true
		out, _ := c.sendExpect(set.cmd, 60*time.Second, cfg)
		set.out = precReply(l16TrimEcho(out, set.cmd))
		set.refused = precRefused(set.out, d)
		// Back to exec mode, so the next thing typed on this session is not
		// typed into configuration mode.
		_, _ = c.sendExpect("end", 45*time.Second, exec)
	} else {
		set.skipped = "the session never reached configuration mode, so this command was not typed"
	}
	return []precProbe{enter, set}, entered
}

// precRefused reports whether a reply is this platform's way of saying no. The
// driver's markers cover an authorization refusal; a role that hides a command
// from the parser answers with an `^` marker instead, which is a refusal by
// another route and would otherwise be counted as the command running.
func precRefused(out string, d l16Driver) bool {
	if l16Refused(out, d.refusalMarkers) {
		return true
	}
	return l16Refused(out, []string{"% Invalid command", "Invalid command", "% Incomplete", "% Permission"})
}

func precReply(out string) string {
	if strings.TrimSpace(out) == "" {
		return emptyDeviceReply
	}
	return out
}

// collectPrec reads this variant's records out of the decision log: what port49
// answered for the session and for each probe, how many requests arrived, and
// what privilege the device asserted on them.
func (l *lab) collectPrec(r *precResult, recs []map[string]any) {
	for _, rec := range recs {
		if str(rec, "event") != "authorize_session" {
			continue
		}
		r.sessionVerdict = strings.TrimSpace(str(rec, "verdict") + " " + str(rec, "reason"))
		r.sessionPriv = fmt.Sprintf("%v", sub(rec, "session")["privilege"])
		break
	}
	for _, rec := range recs {
		if str(rec, "event") != "authorize_command" {
			continue
		}
		r.allCmds = append(r.allCmds, fmt.Sprintf("%s -> %s",
			strings.Join(strs(sub(rec, "request"), "vector"), " "),
			strings.TrimSpace(str(rec, "verdict")+" "+str(rec, "reason"))))
	}
	for i, p := range r.probes {
		var privs []string
		for _, rec := range recs {
			if str(rec, "event") != "authorize_command" {
				continue
			}
			if strings.Join(strs(sub(rec, "request"), "vector"), " ") != p.cmd {
				continue
			}
			r.probes[i].requests++
			r.probes[i].verdict = strings.TrimSpace(str(rec, "verdict") + " " + str(rec, "reason"))
			privs = append(privs, fmt.Sprintf("%v", sub(rec, "session")["privilege"]))
		}
		r.probes[i].privs = strings.Join(privs, ", ")
	}
}

func precByName(rs []precResult, name string) precResult {
	for _, r := range rs {
		if r.v.name == name {
			return r
		}
	}
	return precResult{}
}

// configRefused reports whether this session was stopped from configuring the
// device, and which probe stopped it.
//
// It is two steps and not one, and that is a measurement rather than a
// nicety: on Nexus 9300v 10.4(2)F a `network-operator` session **enters
// configuration mode** and is refused the configuration command inside it --
//
//	% Permission denied for the role
//
// so a reading keyed on reaching `nx1(config)#` concludes the role did not
// bind, on a run whose own table shows the command refused two lines above. The
// first version of this file did exactly that. What matters is whether the
// session could change the device, which is the last step, not the first.
func (r precResult) configRefused() (bool, precProbe) {
	enter := precProbeOf(r, "configure terminal")
	if !r.entered {
		return true, enter
	}
	set := precProbeOf(r, "hostname "+precNode(r))
	return set.refused, set
}

func precProbeOf(r precResult, cmd string) precProbe {
	for _, p := range r.probes {
		if p.cmd == cmd {
			return p
		}
	}
	return precProbe{cmd: cmd}
}

func (r precResult) render() string {
	var b strings.Builder
	fmt.Fprintf(&b, "\n### %s\n\n%s\n\nReply attributes: `%s`\n\n", r.v.name, r.v.why, r.attrs)
	if r.loginErr != "" {
		fmt.Fprintf(&b, "**The session never opened.**\n\n```\n%s\n```\n\n", r.loginErr)
		return b.String()
	}
	if r.sessionVerdict != "" {
		fmt.Fprintf(&b, "port49 answered the session authorization **%s**; the device asserted "+
			"`session.privilege=%s` on the request.\n\n", r.sessionVerdict, r.sessionPriv)
	}
	if strings.TrimSpace(r.whoami) != "" {
		fmt.Fprintf(&b, "`show user-account %s` — the device's own word for the role this session holds:\n\n"+
			"```\n%s\n```\n\n", r.user, strings.TrimRight(r.whoami, "\n"))
	} else {
		fmt.Fprintf(&b, "`show user-account %s` returned nothing, so this variant does not say which role "+
			"the device believes the session holds.\n\n", r.user)
	}
	for _, p := range r.probes {
		if !p.attempted {
			fmt.Fprintf(&b, "`%s` (%s) — **not typed**: %s.\n\n", p.cmd, p.expect, p.skipped)
			continue
		}
		state := "the device accepted it"
		if p.refused {
			state = "the device **refused** it"
		}
		fmt.Fprintf(&b, "`%s` (%s) — %s; port49 answered **%s** over %d authorization request(s)%s. "+
			"Verbatim:\n\n```\n%s\n```\n\n",
			p.cmd, p.expect, state, orNone(p.verdict), p.requests, precPrivNote(p),
			strings.TrimRight(p.out, "\n"))
	}
	if len(r.allCmds) > 0 {
		fmt.Fprintf(&b, "Every command authorization port49 answered in this session, as it arrived:\n\n"+
			"```\n%s\n```\n\n", strings.Join(r.allCmds, "\n"))
	} else {
		b.WriteString("**No command authorization reached port49 in this session at all.**\n\n")
	}
	return b.String()
}

func precPrivNote(p precProbe) string {
	if p.privs == "" {
		return ""
	}
	return ", asserting `privilege=" + p.privs + "`"
}

func precPreamble(t *testing.T, l *lab, d l16Driver) string {
	t.Helper()
	return fmt.Sprintf("- **Date measured:** %s\n- **Image version:** %s (`%s`)\n- **Capture:** %s\n\n"+
		"L16 above sent `priv-lvl` and `shell:roles` one at a time. Each works: `priv-lvl=15` alone lands "+
		"the session on `network-admin`, and a named role alone is delivered. **This section sends both at "+
		"once**, which is the only shape that decides what an NX-OS adapter may put in a reply -- and the "+
		"shape a read-only server definition on a production Nexus 9000 has been sending for years, with "+
		"the roles attribute misnamed so that only the privilege level took effect.\n\n"+
		"Each variant below is one set of reply attributes, one daemon restart and one token login. Three "+
		"probes per session: `%s <user>` for the role the device says it holds, `%s` for whether the "+
		"session reaches configuration mode, and `hostname %s` -- a configuration command that writes "+
		"the value the device already has -- for whether it can actually change anything. The last two "+
		"are separate because on this image they answer differently: a `network-operator` session is "+
		"admitted to configuration mode and refused the command inside it, so reaching `(config)#` is "+
		"not evidence of privilege here. The custom role from the section above is defined for the run "+
		"and removed after it:\n\n```\n%s\n```\n",
		time.Now().UTC().Format("2006-01-02"), l.p.version, l.p.image, l.captureLine(t),
		d.whoami, d.enterConfig, l.p.node, strings.Join(d.defineRole, "\n"))
}

// precTable is the summary, built from the results, so no cell can say more
// than the run measured.
func precTable(rs []precResult) string {
	var b strings.Builder
	b.WriteString("\n#### Every variant side by side\n\n")
	b.WriteString("| reply attributes | session | role the device reports | config mode | " +
		"`hostname` accepted | port49 asked about |\n")
	b.WriteString("|---|---|---|---|---|---|\n")
	for _, r := range rs {
		if r.loginErr != "" {
			fmt.Fprintf(&b, "| %s | **no session** | — | — | — | — |\n", r.v.name)
			continue
		}
		enter, set := precProbeOf(r, "configure terminal"), precProbeOf(r, "hostname "+precNode(r))
		cfgCell := "**refused**"
		if r.entered {
			cfgCell = "entered"
		}
		setCell := "—"
		if set.attempted {
			setCell = "yes"
			if set.refused {
				setCell = "**refused**"
			}
		}
		asked := fmt.Sprintf("`configure terminal` %d req (%s)", enter.requests, orNone(enter.verdict))
		if set.attempted {
			asked += fmt.Sprintf("; `hostname` %d req (%s)", set.requests, orNone(set.verdict))
		}
		fmt.Fprintf(&b, "| %s | opened | %s | %s | %s | %s |\n",
			r.v.name, precRoleCell(r), cfgCell, setCell, asked)
	}
	return b.String()
}

// precNode recovers the node name from the probe this test typed, so the table
// looks the probe up by the same string precConfigProbes built.
func precNode(r precResult) string {
	for _, p := range r.probes {
		if rest, ok := strings.CutPrefix(p.cmd, "hostname "); ok {
			return rest
		}
	}
	return ""
}

func precRoleCell(r precResult) string {
	if r.role != "" {
		return "`" + r.role + "`"
	}
	if strings.TrimSpace(r.whoami) == "" {
		return "(nothing returned)"
	}
	return "**no entry for this user**"
}

// precReading answers the question from the variants. Every negative goes
// through negativeFinding, which fails the test rather than writing a claim
// with no transcript behind it.
//
// It reads the ROLE the device names, not the configuration probe, and that is
// the correction this file exists to carry. The first version of this reading
// asked "did the session reach configuration mode" and would have published
// "`priv-lvl` wins" from a run where every session reached it -- including the
// ones holding `network-operator` and `vdc-operator` -- because port49 was
// answering every command `permit` and the role was never consulted. The
// device's answer to "which role is this" is the measurement; what the session
// may then DO is port49's answer in phase A and the role's in phase B.
func precReading(t *testing.T, l *lab, rs []precResult, ph precPhase) string {
	t.Helper()
	opt := precByName(rs, precConflictOptional)
	mand := precByName(rs, precConflictMandatory)
	priv := precByName(rs, precBaselinePriv)
	roleOnly := precByName(rs, precBaselineRole)
	inv := precByName(rs, precInverseOptional)
	invM := precByName(rs, precInverseMandatory)
	unknown := precByName(rs, precUnknownRole)
	six := precByName(rs, precSixAlone)

	var b strings.Builder
	b.WriteString("\n#### What this answers\n\n")

	// 1. The question itself, read off the role the device names.
	switch {
	case opt.loginErr != "" || priv.loginErr != "":
		b.WriteString("**1. Not answered by this run.** The conflicting variant or its `priv-lvl=15` " +
			"baseline never opened a session, and a precedence claim needs both.\n\n")
	case opt.role == "" || priv.role == "":
		b.WriteString("**1. Not answered by this run.** The device named no role for one of the two " +
			"sessions, so there is nothing to compare.\n\n")
	case opt.role != priv.role:
		b.WriteString("**1. `shell:roles` wins. The privilege level beside it changes nothing.** " +
			negativeFinding{
				Claim: "`priv-lvl=15` does NOT put the session on `" + priv.role + "` when " +
					"`shell:roles*network-operator` is in the same reply. The device names the session `" +
					opt.role + "`, against `" + priv.role + "` for `priv-lvl=15` alone on this same " +
					"deploy and the same image.",
				Sent: "reply attributes " + opt.attrs + "\nthen, in the session:\n" +
					"show user-account " + opt.user,
				Got: strings.TrimRight(opt.whoami, "\n"),
			}.render(t) + "\n")
		fmt.Fprintf(&b, "The same question with the role taken out of the reply, minutes later on the same "+
			"device:\n\n```\n%s\n```\n\nOne attribute separates them.\n\n", strings.TrimRight(priv.whoami, "\n"))
	default:
		fmt.Fprintf(&b, "**1. `priv-lvl` survives beside the role.** The conflicting reply and "+
			"`priv-lvl=15` alone both put the session on `%s`, so naming `network-operator` did not "+
			"change what the device believes. An adapter that names a restrictive role and also sends a "+
			"privilege level is not delivering the role it logged.\n\n", opt.role)
	}

	// 1b. What the role is WORTH in phase A, which is the question the
	// configuration probe actually answers there.
	optRefused, optProbe := opt.configRefused()
	privRefused, _ := priv.configRefused()
	if opt.loginErr == "" && priv.loginErr == "" && !optRefused && !privRefused && opt.role != priv.role {
		b.WriteString("**1b. And in this lab's configuration the role is a label and nothing more.** " +
			negativeFinding{
				Claim: "Holding `" + opt.role + "` did NOT stop the session configuring the device. It " +
					"entered configuration mode and `" + optProbe.cmd + "` was accepted, because `aaa " +
					"authorization commands default group port49 local` sends every command to port49, " +
					"which permitted it. The role the device named is not consulted while port49 is in " +
					"the command path -- the same shape L16 found with `p49-noc` and `show version`.",
				Sent: "reply attributes " + opt.attrs + "\nthen, in the session:\n" + optProbe.cmd,
				Got:  strings.TrimRight(optProbe.out, "\n"),
			}.render(t) + "\n")
		b.WriteString("So the configuration probe does not separate the roles in phase A, and a reading " +
			"that took it for a privilege measurement would have reported the opposite of question 1. " +
			"Phase B is where the role gets asked.\n\n")
	}

	// 2. The mandatory spelling, which is the same question by another flag.
	if mand.loginErr == "" && opt.loginErr == "" {
		if mand.role == opt.role {
			fmt.Fprintf(&b, "**2. The argument flag does not change it.** `shell:roles=network-operator` "+
				"sent MANDATORY names the same role as the optional spelling, `%s`, and the session "+
				"opened either way. RFC 8907 §8.2's mandatory/optional distinction decides whether a "+
				"device may ignore an attribute; this device ignores it under neither flag.\n\n",
				orNone2(mand.role))
		} else {
			fmt.Fprintf(&b, "**2. The argument flag DOES change it.** Optional gives role `%s`; mandatory "+
				"gives `%s`. An adapter has to choose the flag deliberately on this platform.\n\n",
				orNone2(opt.role), orNone2(mand.role))
		}
	} else if mand.loginErr != "" {
		fmt.Fprintf(&b, "**2. The MANDATORY spelling ended the session.** `shell:roles=network-operator` "+
			"beside `priv-lvl=15` produced no session at all:\n\n```\n%s\n```\n\n",
			strings.TrimRight(mand.loginErr, "\n"))
	}

	// 3. The inverted conflict: the direction that separates "the role wins"
	// from "the restrictive one wins".
	if inv.loginErr == "" && invM.loginErr == "" {
		fmt.Fprintf(&b, "**3. Inverted, the answer is the same one.** `priv-lvl=1` with "+
			"`shell:roles*network-admin` names `%s`, and `priv-lvl=0` with the same role mandatory names "+
			"`%s`. %s\n\n", orNone2(inv.role), orNone2(invM.role), precInverseReading(inv, invM))
	}

	// 4. The role-only control, which is the reply the adapter rule proposes.
	if roleOnly.loginErr == "" {
		fmt.Fprintf(&b, "**4. The role alone is enough, and that is what makes the rule shippable.** With "+
			"NO `priv-lvl` in the reply at all, port49 answered the session authorization `%s`, the "+
			"session opened, and the device named it `%s` -- the same role as when `priv-lvl=15` was "+
			"sent beside it. Dropping `priv-lvl` from an NX-OS reply costs nothing this run can see.\n\n",
			orNone(roleOnly.sessionVerdict), orNone2(roleOnly.role))
	} else {
		fmt.Fprintf(&b, "**4. The role alone did NOT open a session.** A reply carrying only "+
			"`shell:roles=network-operator` produced:\n\n```\n%s\n```\n\nSo `priv-lvl` cannot simply be "+
			"dropped on this platform.\n\n", strings.TrimRight(roleOnly.loginErr, "\n"))
	}

	// 5. The unknown role beside priv-lvl=15: the 3am case for the rule.
	if unknown.loginErr == "" {
		fmt.Fprintf(&b, "**5. An unknown role name still degrades the session, with `priv-lvl=15` beside "+
			"it.** `shell:roles=nonexistent-role` names `%s`. The privilege level does not fill the gap, "+
			"so a policy naming a role this device does not have leaves the operator where L16 found them "+
			"-- and port49 cannot tell: the reply it sent and the record it wrote are byte-identical to "+
			"the case where the role exists.\n\n", orNone2(unknown.role))
	}

	// 6. priv-lvl=6, the one production reading this lab can check.
	if six.loginErr == "" {
		fmt.Fprintf(&b, "**6. `priv-lvl=6` alone gives `%s`** on Nexus 9300v 10.4(2)F. The owner's "+
			"production Nexus 9000 on NX-OS 10.3(5) maps 0 and 6 to `vdc-operator` and 15 to "+
			"`network-admin`; this image %s on 6. Read with question 1, that is the whole danger of "+
			"`priv-lvl` here: with no role in the reply the device picks a role nobody named, and which "+
			"one it picks is a per-release mapping.\n\n",
			orNone2(six.role), precAgreeWord(six.role, "vdc-operator"))
	}

	// 7. Phase B: what the delivered role is worth when the device is the one
	// authorizing commands.
	b.WriteString(precPhaseBReading(t, ph))

	fmt.Fprintf(&b, "%s\n\nEvery other cell -- the custom role beside `priv-lvl=15`, the `privilege` the "+
		"device asserted on each request, how many authorization requests each command cost -- is in the "+
		"tables above, and each one is what that variant's session did on %s.\n",
		precAdapterRule(rs, ph), l.p.version)
	return b.String()
}

// precPhaseBReading says what phase B measured, and says nothing when phase B
// did not run.
func precPhaseBReading(t *testing.T, ph precPhase) string {
	t.Helper()
	if !ph.applied {
		return "**7. Phase B did not run**, so what the delivered role is worth when the device authorizes " +
			"its own commands is unmeasured here; the block above says why.\n\n"
	}
	conflict := precByName(ph.rows, precPhaseBConflict)
	baseline := precByName(ph.rows, precPhaseBBaseline)
	if conflict.loginErr != "" || baseline.loginErr != "" {
		return "**7. Phase B measured nothing:** one of its two sessions never opened, and a claim about " +
			"local command authorization needs both.\n\n"
	}
	cRefused, cProbe := conflict.configRefused()
	bRefused, bProbe := baseline.configRefused()

	var b strings.Builder
	switch {
	case cRefused && !bRefused:
		b.WriteString("**7. With port49 out of the command path, the delivered role is real privilege.** " +
			negativeFinding{
				Claim: "Under `aaa authorization commands default local`, a session delivered " +
					"`shell:roles*network-operator` beside `priv-lvl=15` CANNOT change the device: `" +
					cProbe.cmd + "` is refused. The same reply with `priv-lvl=15` and no role runs it. So " +
					"the role the reply names is what the device enforces once the device is the one " +
					"enforcing, and `priv-lvl=15` does not override it.",
				Sent: "reply attributes " + conflict.attrs + "\nthen, in the session:\n" + cProbe.cmd,
				Got:  strings.TrimRight(cProbe.out, "\n"),
			}.render(t) + "\n")
		fmt.Fprintf(&b, "The control, same method lists, same minute, no role in the reply, the same "+
			"command:\n\n```\n%s\n```\n\nThat is the pair phase A could not produce: same device, same "+
			"port49, one attribute apart, opposite outcomes.\n\n", strings.TrimRight(bProbe.out, "\n"))
		if conflict.entered {
			fmt.Fprintf(&b, "**Where the device enforces it is worth knowing for its own sake.** The "+
				"`network-operator` session was allowed INTO configuration mode and refused the command "+
				"inside it. `%s` answered:\n\n```\n%s\n```\n\nso a probe that only checked for the "+
				"`(config)#` prompt would have concluded the role does not bind. Reaching configuration "+
				"mode is not evidence of privilege on this platform.\n\n",
				precProbeOf(conflict, "configure terminal").cmd,
				strings.TrimRight(precProbeOf(conflict, "configure terminal").out, "\n"))
		}
	case cRefused && bRefused:
		fmt.Fprintf(&b, "**7. Phase B's control failed with it.** Neither session could configure the "+
			"device under `aaa authorization commands default local`, so the refusal is not attributable "+
			"to the role -- a remote account may simply not be authorized locally on this image. The "+
			"control said:\n\n```\n%s\n```\n\n", strings.TrimRight(bProbe.out, "\n"))
	default:
		fmt.Fprintf(&b, "**7. Even with port49 out of the command path, the role did not bind.** A session "+
			"holding `%s` configured the device under `aaa authorization commands default local`: `%s` "+
			"was accepted.\n\n```\n%s\n```\n\nSo on this image the role this reply delivers is a label in "+
			"both configurations, and nothing port49 can send constrains an NX-OS session by itself.\n\n",
			orNone2(conflict.role), cProbe.cmd, strings.TrimRight(cProbe.out, "\n"))
	}
	return b.String()
}

func precAgreeWord(got, want string) string {
	if got == want {
		return "agrees"
	}
	return "does NOT agree: it gives `" + orNone2(got) + "`"
}

// precInverseReading reads the inverted pair, which is the only thing that
// tells "the role wins" apart from "the more restrictive attribute wins".
func precInverseReading(inv, invM precResult) string {
	if inv.role == "network-admin" && invM.role == "network-admin" {
		return "A reply whose privilege level says 0 or 1 still puts the session on the administrative " +
			"role, so this is not \"the more restrictive of the two wins\": it is the role, in both " +
			"directions, whatever the privilege level says."
	}
	return "Neither direction put the session on the role that was named, so the device is not simply " +
		"taking the role attribute; read this beside question 1 before drawing a rule from either."
}

// precAdapterRule states the rule the data supports, and says so only when the
// data supports it.
//
// It is built from the ROLE the device names in each variant. The earlier
// version of this function read the configuration probe instead and would have
// concluded the opposite on this run, because port49 permitted every command
// and so every session configured the device whatever role it held.
func precAdapterRule(rs []precResult, ph precPhase) string {
	opt := precByName(rs, precConflictOptional)
	mand := precByName(rs, precConflictMandatory)
	priv := precByName(rs, precBaselinePriv)
	roleOnly := precByName(rs, precBaselineRole)
	inv := precByName(rs, precInverseOptional)
	invM := precByName(rs, precInverseMandatory)

	for _, r := range []precResult{opt, mand, priv, roleOnly, inv, invM} {
		if r.loginErr != "" || r.role == "" {
			return "**No adapter rule is stated here**: one of the variants that decides it produced no " +
				"session or no role, so this section records what was measured and nothing further."
		}
	}
	// The role named in the reply is the role the device reports, in both
	// directions, whatever priv-lvl says; and the role alone is enough.
	rolesDecide := opt.role == "network-operator" && mand.role == "network-operator" &&
		inv.role == "network-admin" && invM.role == "network-admin" &&
		roleOnly.role == "network-operator" && priv.role == "network-admin"

	if !rolesDecide {
		return fmt.Sprintf("**No adapter rule is stated here**: the roles the device named do not form a "+
			"consistent answer (`%s` / `%s` for the conflict, `%s` / `%s` inverted, `%s` for the role "+
			"alone, `%s` for `priv-lvl=15` alone). Read the table, not a rule.",
			orNone2(opt.role), orNone2(mand.role), orNone2(inv.role), orNone2(invM.role),
			orNone2(roleOnly.role), orNone2(priv.role))
	}

	rule := "**The adapter rule this supports: on NX-OS send `shell:roles` and never `priv-lvl`.** " +
		"Whenever both are in the reply the device takes the role and ignores the privilege level, in " +
		"both directions -- `priv-lvl=15` with `network-operator` is a read-only account, `priv-lvl=0` " +
		"with `network-admin` is an administrator. The role alone opens a session and is delivered, so " +
		"nothing is lost by leaving `priv-lvl` out. Leaving it IN costs something real: it is inert here " +
		"and it is the attribute that governs the session on every other platform in this lab, so an " +
		"adapter that computes one and sends it to NX-OS is writing a privilege into the log that the " +
		"device did not apply -- and `priv-lvl` with no role is how a reply silently picks a role nobody " +
		"named (`15` to `network-admin`, `6` to `vdc-operator`, per-release)."
	if ph.applied {
		conflict := precByName(ph.rows, precPhaseBConflict)
		baseline := precByName(ph.rows, precPhaseBBaseline)
		cRefused, cProbe := conflict.configRefused()
		bRefused, _ := baseline.configRefused()
		if conflict.loginErr == "" && baseline.loginErr == "" && cRefused && !bRefused {
			rule += " **Phase B is what makes this a privilege claim rather than a labelling one:** with " +
				"the device authorizing its own commands, the same reply that names `network-operator` " +
				"is refused `" + cProbe.cmd + "` and the one carrying `priv-lvl=15` alone runs it. The " +
				"role port49 sends is the operator's real privilege on a device that enforces it, which " +
				"is the state a fleet is in before port49 owns command authorization."
		}
	}
	return rule
}

// appendResultSection adds one section to an existing results note, keeping
// everything already in it (spec §15 rule 3: a note is the record of a
// measurement, and an earlier measurement is not invalidated by a later one).
//
// A re-run replaces its own section rather than appending a second copy, so the
// note says what the last run measured instead of accumulating near-identical
// transcripts. The file must already exist: this test measures one clause of a
// row another test wrote, and a bare file here would be a results note with no
// platform, image or capture line at the top of it.
func (l *lab) appendResultSection(t *testing.T, entry, heading, body string) {
	t.Helper()
	path := filepath.Join(root, "tests", "lab", "results", fmt.Sprintf("%s-%s.md", entry, l.p.name))
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%s does not exist, and this section belongs inside it rather than in a note of its "+
			"own: %v", path, err)
	}
	marker := "\n## " + heading + "\n"
	old := string(raw)
	if i := strings.Index(old, marker); i >= 0 {
		old = old[:i]
	}
	out := strings.TrimRight(old, "\n") + "\n" + marker + body
	if err := os.WriteFile(path, []byte(labcreds.RedactNote(out)), 0o644); err != nil { // as result()
		t.Fatalf("write %s: %v", path, err)
	}
	t.Logf("wrote the %q section of %s", heading, path)
}
