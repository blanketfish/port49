//go:build lab

package lab

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// L16 on EOS, re-asked with the attribute the first run never sent.
//
// The 2026-09-21 run concluded that vEOS "does not apply a role": with
// `shell:roles*p49-noc` in the reply the device reported the session's role as
// `<unknown>`, and `shell:roles=` sent mandatory ended the session. Both
// observations stand. The conclusion drawn from them does not, and the reason
// is the attribute NAME: every variant of that run spelled it `shell:roles`,
// which is NX-OS's spelling. The owner runs EOS in production against the BARE
// attribute
//
//	roles=network-operator
//
// sent MANDATORY, and reports two things this lab has never tried: that the
// bare name is what Arista reads, and that EOS needs `priv-lvl` sent MANDATORY
// as well, because an OPTIONAL `priv-lvl*N` is ignored and the session is left
// at level 1. So "vEOS does not apply roles" may be an artefact of asking in
// NX-OS's words, and nothing in the earlier note separates the two.
//
// This test asks in Arista's words. Eight reply-attribute sets, plus the
// control the whole thing has to be read against -- `priv-lvl=15` alone, which
// is what this lab sends to EOS today -- each one daemon restart and one token
// login. Per session: the role the device names (`show users detail`), the
// privilege level it reports (`show privilege`), whether a configuration
// command is accepted, whether port49's per-command deny still binds, and every
// command authorization that reached port49.
//
// Phase B then points `aaa authorization commands` at the device's own role
// database and asks `network-admin` against `network-operator`. It has to
// exist for the reason the NX-OS precedence run found the hard way: with
// command authorization pointed at a lab authorizer that permits everything,
// EVERY session configures the device whatever role it holds, so phase A's
// configuration probe measures port49's answer and not the device's privilege.
// Phase B is the only place the delivered role is asked for anything.
func TestL16EOSBareRoles(t *testing.T) {
	eachPlatform(t, func(t *testing.T, l *lab) {
		if l.p.name != "arista_eos" {
			t.Skipf("the bare `roles` attribute is Arista's spelling; %s is measured by TestL16Roles "+
				"and TestL16PrivLvlRolePrecedence", l.p.name)
		}
		d := l16Drivers[l.p.name]
		stop := l.capture(t, "L16-eos-roles")
		defer stop()

		// Variants 6 and 7 name the custom role from L16, so it has to exist
		// for the length of this run and not afterwards.
		l16DefineRole(t, l, d)
		defer l16DeleteRole(t, l, d)

		results := make([]eosRoleResult, 0, len(eosRoleVariants))
		for _, v := range eosRoleVariants {
			results = append(results, l.eosRoleRun(t, d, v))
		}
		phaseB := l.eosRolePhaseB(t, d)

		var b strings.Builder
		b.WriteString(eosRolePreamble(t, l, d))
		for _, r := range results {
			b.WriteString(r.render())
		}
		b.WriteString(eosRoleTable(results))
		b.WriteString(phaseB.render(results))
		b.WriteString(eosRoleReading(t, l, results, phaseB))
		l.appendResultSection(t, "L16", eosRoleHeading, b.String())

		// A variant whose session never opened measured nothing. One is a
		// finding; all of them is a test that measured nothing, and must fail.
		opened := 0
		for _, r := range results {
			if r.loginErr == "" {
				opened++
			}
		}
		if opened == 0 {
			t.Fatalf("not one of the %d variants reached a prompt, so nothing about the bare `roles` "+
				"attribute was measured", len(results))
		}
		// The role the device names is the measurement this section exists for.
		// A run where `show users detail` named a role for nobody has a note
		// full of transcripts and no answer in it.
		named := 0
		for _, r := range results {
			if r.role != "" {
				named++
			}
		}
		if named == 0 {
			t.Fatalf("`%s` named a role for the session's own user in none of the %d variants, so whether "+
				"EOS applies the bare `roles` attribute was not measured", d.whoami, len(results))
		}
		// These three decide the question: the bare attribute mandatory, the
		// same attribute optional, and the no-role control they are read
		// against. Without all three there is a note, but no answer in it.
		for _, name := range []string{eosRoleMandatory, eosRoleOptional, eosRoleControl} {
			if r := eosRoleByName(results, name); r.loginErr != "" {
				t.Errorf("the %s variant never opened a session, so whether EOS reads the bare `roles` "+
					"attribute is not answered by this run: %s", name, r.loginErr)
			}
		}
	})
}

// eosRoleHeading is the section this test owns in results/L16-arista_eos.md. It
// is matched literally on rewrite, so a re-run replaces its own section rather
// than appending a second copy.
const eosRoleHeading = "The bare `roles` attribute, and `priv-lvl` mandatory against optional"

// The names of the variants the reading is built from.
const (
	eosRoleControl   = "`priv-lvl=15` alone — the control"
	eosRoleMandatory = "`priv-lvl=15` + `roles=network-operator` — MANDATORY"
	eosRoleOptional  = "`priv-lvl=15` + `roles*network-operator` — OPTIONAL"
	eosRoleAlone     = "`roles=network-operator` alone, no `priv-lvl`"
	eosPrivOptAlone  = "`priv-lvl*2` alone — OPTIONAL"
	eosPrivMandAlone = "`priv-lvl=2` alone — MANDATORY"
	eosRoleCustom    = "`priv-lvl=15` + `roles=p49-noc`"
	eosRoleTwo       = "`priv-lvl=15` + `roles=\"p49-noc network-operator\"` — quoted"
	eosRoleTwoSpace  = "`priv-lvl=15` + `roles=p49-noc network-operator` — unquoted"
	eosRoleTwoComma  = "`priv-lvl=15` + `roles=p49-noc,network-operator` — comma"
	eosRoleUnknown   = "`priv-lvl=15` + `roles=p49-nosuchrole`"
)

// eosRoleVariant is one reply-attribute set and the question it answers.
type eosRoleVariant struct {
	name  string
	why   string
	attrs func(d l16Driver) string // a YAML flow sequence
}

// The variants, in the order the note reports them. The control is first
// because every other row is read against it.
var eosRoleVariants = []eosRoleVariant{
	{
		name: eosRoleControl,
		why: "what `tests/lab/port49d-lab.yaml` sends to this platform today, minus the `shell:roles*` " +
			"the 2026-09-21 run showed does nothing here. Whatever role and privilege level this " +
			"produces is the baseline every row below has to differ from before anything can be " +
			"claimed about the `roles` attribute.",
		attrs: func(l16Driver) string { return `["priv-lvl=15"]` },
	},
	{
		name: eosRoleMandatory,
		why: "**the question.** The bare attribute name the owner runs in production, sent MANDATORY " +
			"as they send it, with a read-only role against an administrative privilege level. If " +
			"the device names `network-operator` here and `network-admin` in the control, the " +
			"2026-09-21 reading was an artefact of the `shell:` prefix and nothing else.",
		attrs: func(l16Driver) string { return `["priv-lvl=15", "roles=network-operator"]` },
	},
	{
		name: eosRoleOptional,
		why: "the same attribute sent OPTIONAL -- the case the owner could not remember. RFC 8907 " +
			"§8.2 lets a device ignore an optional argument it does not understand, and this " +
			"platform has already been seen ending a session over one (`cisco-av-pair*`), so the " +
			"flag is not a formality here.",
		attrs: func(l16Driver) string { return `["priv-lvl=15", "roles*network-operator"]` },
	},
	{
		name: eosRoleAlone,
		why: "the role with no privilege level in the reply at all. This is the shape an adapter " +
			"would send under a \"roles only\" rule, so it is also the variant that says whether " +
			"that rule is safe to ship on EOS -- and what privilege level a session lands on when " +
			"nothing names one.",
		attrs: func(l16Driver) string { return `["roles=network-operator"]` },
	},
	{
		name: eosPrivOptAlone,
		why: "the owner's second production reading: an OPTIONAL `priv-lvl*` is ignored on EOS and " +
			"the session is left at level 1. Nothing in this lab has ever sent `priv-lvl` optional " +
			"to any platform, so this is the first time it is asked.",
		attrs: func(l16Driver) string { return `["priv-lvl*2"]` },
	},
	{
		name: eosPrivMandAlone,
		why: "the same level sent MANDATORY, which is the half that makes the row above a " +
			"measurement rather than a curiosity: two replies one argument flag apart, on the same " +
			"device in the same minute.",
		attrs: func(l16Driver) string { return `["priv-lvl=2"]` },
	},
	{
		name: eosRoleCustom,
		why: "a CUSTOM role rather than a built-in one. A built-in name might be resolved by a table " +
			"the custom ones are not in, and a custom role is what plan 5 would actually deliver.",
		attrs: func(d l16Driver) string { return `["priv-lvl=15", "roles=` + d.roleName + `"]` },
	},
	{
		name: eosRoleTwo,
		why: "two roles in one value, in the quoted form NX-OS takes. NX-OS delivers these as a union " +
			"with permit winning, which would make a restrictive role delivered beside a permissive " +
			"one no restriction at all. Whether EOS does the same, takes one of them, or takes " +
			"neither is unmeasured -- and so is whether it strips the quotes, which the two rows " +
			"after this one are here to separate.",
		attrs: func(d l16Driver) string {
			return `["priv-lvl=15", "roles=\"` + d.roleName + ` ` + d.secondRole + `\""]`
		},
	},
	{
		name: eosRoleTwoSpace,
		why: "the same two roles with no quotes around them. A TACACS+ argument is one string to its " +
			"end, so the space needs no quoting on the wire; if the quoted row above comes back with " +
			"a quote character inside the role name, this row is the one that says what the device " +
			"does with the pair itself.",
		attrs: func(d l16Driver) string {
			return `["priv-lvl=15", "roles=` + d.roleName + ` ` + d.secondRole + `"]`
		},
	},
	{
		name: eosRoleTwoComma,
		why: "the same two roles comma-separated, the third spelling a fleet might have in its server " +
			"definition. Three spellings of one intention, one deploy: whichever the device takes is " +
			"the one an adapter may send, and \"none of them\" is an answer too.",
		attrs: func(d l16Driver) string {
			return `["priv-lvl=15", "roles=` + d.roleName + `,` + d.secondRole + `"]`
		},
	},
	{
		name: eosRoleUnknown,
		why: "the 3am case: a policy names a role that was renamed or never created on this device. " +
			"Does the operator get no privileges, all of them, or no session? On NX-OS the answer " +
			"is a silent degradation to `network-operator`, which is the safe direction and " +
			"invisible to port49.",
		attrs: func(l16Driver) string { return `["priv-lvl=15", "roles=p49-nosuchrole"]` },
	},
}

// eosRoleResult is one variant's evidence.
type eosRoleResult struct {
	v        eosRoleVariant
	attrs    string
	user     string
	loginErr string

	// prompt is the prompt shape the login itself produced, before anything was
	// typed. On EOS `leaf1#` means the session came up privileged and `leaf1>`
	// means it did not, and that is a measurement no `show` command can replace:
	// a session at `>` refuses `show users detail` outright, so the row where
	// the privilege question matters most is the row with no `show privilege`
	// output in it.
	prompt string

	users string // `show users detail`, verbatim
	role  string // the role read out of it, for THIS session's user
	priv  string // `show privilege`, verbatim
	level string // the level parsed out of it, or ""

	// usersRefused records that the device refused `show users detail` rather
	// than answering it with no row for this user. The two look identical in a
	// role column and mean opposite things: a refusal measures nothing about the
	// role, and reporting it as "no role" would assert that the attribute did
	// not arrive on the strength of a command that was never run. EOS refuses
	// this command outright at privilege 1 -- `% Invalid input (privileged mode
	// required)` -- which is exactly the variant where no `priv-lvl` was sent,
	// so this is the row where the distinction decides the reading.
	usersRefused bool

	// sessionVerdict and sessionPriv are port49's answer to this variant's
	// session authorization and the privilege the DEVICE asserted on the
	// request. The second is the device's own notion of the session before any
	// reply attribute is applied, which is what makes every difference below
	// attributable to the reply and to nothing else.
	sessionVerdict string
	sessionPriv    string

	entered bool // the session reached configuration mode
	probes  []precProbe
	// allCmds is every command authorization that reached port49 during this
	// variant, in order, as `vector -> verdict reason`. A probe whose command
	// the device spells differently on the wire would otherwise read as "0
	// authorization requests", which is a finding and a false one.
	allCmds []string
}

// The probe commands, named so the table and the reading look each one up by
// the same string the session typed.
func eosRoleSetCmd(l *lab) string { return "hostname " + l.p.node }

// eosRolePhase is phase B: the same attributes with port49 out of the command
// path, so the delivered role is the only thing left to authorize a command.
type eosRolePhase struct {
	applied  bool
	applyErr string
	lines    []string
	rows     []eosRoleResult
}

// The method list phase B swaps in and puts back. `local` rather than `none` on
// purpose: `none` authorizes everything and would answer the question with "the
// device stopped checking", where `local` is the device consulting the role it
// was handed -- which is what a role is for, and the configuration a fleet is in
// BEFORE port49 is deployed.
//
// Only `aaa authorization commands` is moved. `aaa authorization exec` stays
// pointed at port49, because a token operator has no local account: moving it
// would refuse every login and phase B would measure nothing at all.
var (
	eosLocalAuthz  = []string{"aaa authorization commands all default local"}
	eosPort49Authz = []string{"aaa authorization commands all default group port49 local"}
)

const (
	eosPhaseBAdmin    = "`priv-lvl=15` + `roles=network-admin`, command authorization LOCAL"
	eosPhaseBOperator = "`priv-lvl=15` + `roles=network-operator`, command authorization LOCAL"
	eosPhaseBNoRole   = "`priv-lvl=15` alone, command authorization LOCAL"
	eosPhaseBUnknown  = "`priv-lvl=15` + `roles=p49-nosuchrole`, command authorization LOCAL"
	eosPhaseBTwo      = "`priv-lvl=15` + `roles=p49-noc network-operator`, command authorization LOCAL"
)

// eosRolePhaseB points the device's command authorization at its own role
// database, asks the administrative role against the read-only one, and puts the
// method list back.
func (l *lab) eosRolePhaseB(t *testing.T, d l16Driver) eosRolePhase {
	t.Helper()
	p := eosRolePhase{lines: eosLocalAuthz}

	l.withAdminCLI(t, d.adminCLI, func(c *cliConn) error {
		out, err := l16Configure(l, c, d, eosLocalAuthz)
		if err != nil {
			// Not fatal: phase A is already measured and written, and a note
			// that reports phase B as "not applied, here is why" is worth more
			// than a run thrown away. No claim is ever written from a phase
			// that did not apply.
			p.applyErr = fmt.Sprintf("%v\n%s", err, out)
			return nil
		}
		p.applied = true
		return nil
	})
	if !p.applied {
		return p
	}
	// Put the method list back whatever happens below, so nothing later on this
	// deploy measures a device whose command authorization this test moved.
	defer l.withAdminCLI(t, d.adminCLI, func(c *cliConn) error {
		if out, err := l16Configure(l, c, d, eosPort49Authz); err != nil {
			return fmt.Errorf("restoring the port49 command-authorization method list: %w\n%s", err, out)
		}
		return nil
	})

	for _, v := range []eosRoleVariant{
		{
			name: eosPhaseBAdmin,
			why: "the administrative role delivered by the bare attribute, with the device " +
				"authorizing its own commands. If this session configures the device and the one " +
				"below does not, the role port49 sends is real privilege on a device that enforces " +
				"it -- not a label.",
			attrs: func(l16Driver) string { return `["priv-lvl=15", "roles=network-admin"]` },
		},
		{
			name: eosPhaseBOperator,
			why: "the read-only role, same method list, same minute, one attribute value apart from " +
				"the row above.",
			attrs: func(l16Driver) string { return `["priv-lvl=15", "roles=network-operator"]` },
		},
		{
			name: eosPhaseBNoRole,
			why: "the control: no role in the reply at all. `configs/eos-startup.cfg` already records " +
				"that an EOS account with `privilege 15` and NO role falls to the default role, " +
				"which refuses `configure`, so this row is expected to be refused -- and it is what " +
				"stops a refusal in the row above from being read as the role binding when it is " +
				"really every remote session being refused.",
			attrs: func(l16Driver) string { return `["priv-lvl=15"]` },
		},
		{
			name: eosPhaseBUnknown,
			why: "the 3am case, asked where it means something. Phase A's unknown-role session ran " +
				"every command, but port49 was answering all of them, so that row says nothing about " +
				"what the operator can do. Here the device is the one deciding, and a policy that " +
				"names a role this device does not have is a policy an operator is holding at 3am.",
			attrs: func(l16Driver) string { return `["priv-lvl=15", "roles=p49-nosuchrole"]` },
		},
		{
			name: eosPhaseBTwo,
			why: "the two-role question asked where it has an answer. Phase A measured which names the " +
				"device REPORTS; only here does it matter which rules apply. `p49-noc` permits every " +
				"command and `network-operator` is read-only, so if this session configures the " +
				"device the union takes the permit -- and a restrictive role delivered beside a " +
				"permissive one is no restriction at all, which is the whole point of delivering one.",
			attrs: func(d l16Driver) string {
				return `["priv-lvl=15", "roles=` + d.roleName + ` ` + d.secondRole + `"]`
			},
		},
	} {
		p.rows = append(p.rows, l.eosRoleRun(t, d, v))
	}
	return p
}

// eosRoleRun measures one variant: restart the daemon with these reply
// attributes, log a token operator in, ask the device which role and which
// privilege level the session holds, and try to configure it.
func (l *lab) eosRoleRun(t *testing.T, d l16Driver, v eosRoleVariant) eosRoleResult {
	t.Helper()
	attrs := v.attrs(d)
	cfg, err := l.derivedConfig("l16eos-"+l16Slug(v.name), attrs, "")
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
	r := eosRoleResult{v: v, attrs: attrs}
	user, secret := l.nextLogin(t)
	r.user = user

	c, err := d.cli(l, user, secret)
	if err != nil {
		r.loginErr = err.Error()
		l.collectEOSRole(&r, l.drainRecords(off, 5*time.Second))
		return r
	}
	r.prompt = eosPromptShape(l, c)

	if out, err := d.show(l, c, d.whoami); err == nil {
		r.users = l16TrimEcho(out, d.whoami)
		r.role = eosRolesOf(r.users, user)
		r.usersRefused = r.role == "" && precRefused(r.users, d)
	}
	if out, err := d.show(l, c, eosPrivCmd); err == nil {
		r.priv = precReply(l16TrimEcho(out, eosPrivCmd))
		r.level = eosPrivLevel(r.priv)
	}
	r.probes, r.entered = l.eosRoleProbes(c, d)
	c.Close()

	l.collectEOSRole(&r, l.drainRecords(off, 10*time.Second))
	return r
}

// eosPrivCmd is EOS's own word for the privilege level this session holds.
const eosPrivCmd = "show privilege"

// eosPromptShape reports which prompt the login produced, by which of the two
// appeared last in what the device has said so far. Testing the final characters
// instead would be defeated by a trailing newline or by any notice EOS prints
// after a login.
func eosPromptShape(l *lab, c *cliConn) string {
	t := c.transcript()
	if strings.LastIndex(t, l.p.node+"#") > strings.LastIndex(t, l.p.node+">") {
		return l.p.node + "#"
	}
	if strings.Contains(t, l.p.node+">") {
		return l.p.node + ">"
	}
	return ""
}

// eosPrivLevel pulls the number out of `show privilege`. EOS answers
// `Current privilege level is 15`; a session that is refused the command
// answers something else entirely, and then there is no level to report and the
// prompt shape is what the note has.
func eosPrivLevel(out string) string {
	const anchor = "privilege level is "
	i := strings.Index(out, anchor)
	if i < 0 {
		return ""
	}
	rest := strings.TrimSpace(out[i+len(anchor):])
	end := 0
	for end < len(rest) && rest[end] >= '0' && rest[end] <= '9' {
		end++
	}
	return rest[:end]
}

// eosRoleProbes types the configuration probes and the deny probe, and returns
// what the device said to each, verbatim.
//
// `configure` asks whether the session reaches configuration mode; `hostname
// <node>` is a configuration command whose effect is to set the hostname to the
// value it already has -- a real write through the parser with nothing changed
// by it -- and the two are separate because NX-OS answered them differently and
// nothing says EOS will not. `show clock` is the last entry of
// `lab.deny_prefixes`, so it asks whether port49's per-command deny still binds
// under whatever the reply delivered.
//
// A session that never reached configuration mode is not asked the second
// question, and the note says it was not asked rather than showing an empty
// reply that would read as a refusal.
func (l *lab) eosRoleProbes(c *cliConn, d l16Driver) ([]precProbe, bool) {
	exec, unpriv := l.p.node+"#", l.p.node+">"
	cfg := l.p.node + "(config)#"

	enter := precProbe{cmd: d.enterConfig, expect: "does the session reach configuration mode at all",
		attempted: true}
	out, _ := c.sendExpect(d.enterConfig, 60*time.Second, cfg, exec, unpriv)
	enter.out = precReply(l16TrimEcho(out, d.enterConfig))
	entered := strings.Contains(out, cfg)
	enter.refused = !entered || precRefused(enter.out, d)

	set := precProbe{cmd: eosRoleSetCmd(l), expect: "the configuration command itself, writing the value " +
		"the device already holds"}
	if entered {
		set.attempted = true
		out, _ := c.sendExpect(set.cmd, 60*time.Second, cfg)
		set.out = precReply(l16TrimEcho(out, set.cmd))
		set.refused = precRefused(set.out, d)
		// Back to exec mode, so the deny probe below is not typed into
		// configuration mode.
		_, _ = c.sendExpect("end", 45*time.Second, exec, unpriv)
	} else {
		set.skipped = "the session never reached configuration mode, so this command was not typed"
	}

	deny := precProbe{cmd: l16Port49Denied, expect: "port49 denies this by prefix; whether the device " +
		"still refuses it says whether a per-command deny binds under this reply", attempted: true}
	out, _ = c.sendExpect(deny.cmd, 60*time.Second, exec, unpriv)
	deny.out = precReply(l16TrimEcho(out, deny.cmd))
	deny.refused = precRefused(deny.out, d)

	return []precProbe{enter, set, deny}, entered
}

// collectEOSRole reads this variant's records out of the decision log: what
// port49 answered for the session and for each probe, how many requests
// arrived, and what privilege the device asserted on them.
func (l *lab) collectEOSRole(r *eosRoleResult, recs []map[string]any) {
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

// eosRolesOf reads the whole `Roles` column for one user out of
// `show users detail`, by the column widths the device itself prints.
//
// It exists because the shared l16RoleOf splits the row on whitespace and takes
// the field after the username, and **a role column can hold a space**. On the
// 2026-09-22 run the reply `roles=p49-noc network-operator` produced
//
//	13  alice09  p49-noc network-operator  vty4  E  ...
//
// and l16RoleOf returned `p49-noc`. The transcript in the note said one thing
// and the table cell two lines below it said another, and the paragraph built
// from the cells then reached its conclusion about two-role delivery from a
// value the device never reported. That is the defect this whole section was
// re-run to avoid, arriving through the parser instead of through the prose.
//
// EOS prints a dashed rule under the header whose groups are exactly the column
// widths, so the column is read by position and a space inside it survives. A
// table this cannot parse falls back to l16RoleOf rather than reporting nothing:
// one wrong-shaped output should not silently erase a role that is on the page.
func eosRolesOf(users, user string) string {
	lines := strings.Split(users, "\n")
	rule, spans := -1, [][2]int{}
	for i, ln := range lines {
		if s := eosColumnSpans(ln); len(s) >= 3 {
			rule, spans = i, s
			break
		}
	}
	if rule < 1 {
		return l16RoleOf(users, user)
	}
	// The header is the line above the rule, and it names which span is which.
	head := lines[rule-1]
	userCol, roleCol := -1, -1
	for i, s := range spans {
		switch strings.TrimSpace(eosSlice(head, s)) {
		case "Username":
			userCol = i
		case "Roles":
			roleCol = i
		}
	}
	if userCol < 0 || roleCol < 0 {
		return l16RoleOf(users, user)
	}
	for _, ln := range lines[rule+1:] {
		if strings.TrimSpace(eosSlice(ln, spans[userCol])) == user {
			return strings.TrimSpace(eosSlice(ln, spans[roleCol]))
		}
	}
	return ""
}

// eosColumnSpans reports the [start, end) of each run of `-` on a line that is
// nothing but dashes and spaces, and nothing at all for any other line.
func eosColumnSpans(line string) [][2]int {
	var spans [][2]int
	start := -1
	for i, r := range line {
		switch r {
		case '-':
			if start < 0 {
				start = i
			}
		case ' ', '\r', '\t':
			if start >= 0 {
				spans = append(spans, [2]int{start, i})
				start = -1
			}
		default:
			return nil
		}
	}
	if start >= 0 {
		spans = append(spans, [2]int{start, len(line)})
	}
	return spans
}

// eosSlice takes a column out of a row, tolerating a row shorter than the rule
// above it -- the last column of a line with a trailing empty field.
func eosSlice(line string, span [2]int) string {
	if span[0] >= len(line) {
		return ""
	}
	end := span[1]
	if end > len(line) {
		end = len(line)
	}
	return line[span[0]:end]
}

func eosRoleByName(rs []eosRoleResult, name string) eosRoleResult {
	for _, r := range rs {
		if r.v.name == name {
			return r
		}
	}
	return eosRoleResult{}
}

func eosRoleProbeOf(r eosRoleResult, cmd string) precProbe {
	for _, p := range r.probes {
		if p.cmd == cmd {
			return p
		}
	}
	return precProbe{cmd: cmd}
}

// eosConfigRefused reports whether this session was stopped from changing the
// device, and which probe stopped it. It is the last step that counts, not the
// first: a device that admits a session to configuration mode and refuses the
// command inside it has refused it, and a reading keyed on the prompt would say
// the opposite. That is not hypothetical -- it is what NX-OS does.
func (r eosRoleResult) configRefused() (bool, precProbe) {
	enter := eosRoleProbeOf(r, "configure")
	if !r.entered {
		return true, enter
	}
	set := eosRoleProbeOf(r, eosRoleSetName(r))
	return set.refused, set
}

// eosRoleSetName recovers the configuration probe's command from the probes the
// session typed, so the lookup uses the same string that built it.
func eosRoleSetName(r eosRoleResult) string {
	for _, p := range r.probes {
		if strings.HasPrefix(p.cmd, "hostname ") {
			return p.cmd
		}
	}
	return "hostname"
}

func (r eosRoleResult) render() string {
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
	if r.prompt != "" {
		fmt.Fprintf(&b, "The login itself landed on `%s`.\n\n", r.prompt)
	}
	if r.usersRefused {
		fmt.Fprintf(&b, "`show users detail` — **the device refused it**, so this variant measures no role "+
			"at all. What it said, verbatim:\n\n```\n%s\n```\n\n", strings.TrimRight(r.users, "\n"))
	} else if strings.TrimSpace(r.users) != "" {
		fmt.Fprintf(&b, "`%s` — the `Roles` column names the role EOS believes this session holds:\n\n"+
			"```\n%s\n```\n\n", "show users detail", strings.TrimRight(r.users, "\n"))
	} else {
		fmt.Fprintf(&b, "`show users detail` returned nothing, so this variant does not say which role the "+
			"device believes the session holds.\n\n")
	}
	if strings.TrimSpace(r.priv) != "" {
		fmt.Fprintf(&b, "`%s` — the device's own word for the privilege level:\n\n```\n%s\n```\n\n",
			eosPrivCmd, strings.TrimRight(r.priv, "\n"))
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

func eosRolePreamble(t *testing.T, l *lab, d l16Driver) string {
	t.Helper()
	return fmt.Sprintf("- **Date measured:** %s\n- **Image version:** %s (`%s`)\n- **Capture:** %s\n\n"+
		"Every variant of the 2026-09-21 run above spelled the attribute `shell:roles`, which is NX-OS's "+
		"name for it. **This section sends the BARE name, `roles`**, which is what Arista reads and what "+
		"the owner runs in production, and it asks `priv-lvl` MANDATORY against OPTIONAL as well -- the "+
		"owner reports that an optional `priv-lvl*` is ignored here and the session is left at level 1. "+
		"Neither had ever been sent to this device.\n\n"+
		"Each variant below is one set of reply attributes, one daemon restart and one token login. Per "+
		"session: the prompt the login produced, `%s` for the role the device names for this user, `%s` "+
		"for the level it reports, `%s` and `hostname %s` for whether the session can change the device, "+
		"and `%s` -- the last entry of `lab.deny_prefixes` -- for whether port49's per-command deny still "+
		"binds. The custom role from the section above is defined for the run and removed after it:\n\n"+
		"```\n%s\n```\n",
		time.Now().UTC().Format("2006-01-02"), l.p.version, l.p.image, l.captureLine(t),
		d.whoami, eosPrivCmd, d.enterConfig, l.p.node, l16Port49Denied, strings.Join(d.defineRole, "\n"))
}

// eosRoleTable is the summary, built from the results, so no cell can say more
// than the run measured.
func eosRoleTable(rs []eosRoleResult) string {
	var b strings.Builder
	b.WriteString("\n#### Every variant side by side\n\n")
	b.WriteString("| reply attributes | session | role the device reports | privilege | config mode | " +
		"`hostname` accepted | `show clock` | port49 asked |\n")
	b.WriteString("|---|---|---|---|---|---|---|---|\n")
	for _, r := range rs {
		if r.loginErr != "" {
			fmt.Fprintf(&b, "| %s | **no session** | — | — | — | — | — | — |\n", r.v.name)
			continue
		}
		enter := eosRoleProbeOf(r, "configure")
		set := eosRoleProbeOf(r, eosRoleSetName(r))
		deny := eosRoleProbeOf(r, l16Port49Denied)

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
		denyCell := "**ran**"
		if deny.refused {
			denyCell = "refused"
		}
		total := enter.requests + set.requests + deny.requests
		fmt.Fprintf(&b, "| %s | opened (`%s`) | %s | %s | %s | %s | %s | %d req |\n",
			r.v.name, orDash(r.prompt), eosRoleCell(r), eosPrivCell(r), cfgCell, setCell, denyCell, total)
	}
	return b.String()
}

func orDash(s string) string {
	if s == "" {
		return "no prompt seen"
	}
	return s
}

func eosRoleCell(r eosRoleResult) string {
	if r.role != "" {
		return "`" + r.role + "`"
	}
	if r.usersRefused {
		return "**not measured** (the device refused the command)"
	}
	if strings.TrimSpace(r.users) == "" {
		return "(nothing returned)"
	}
	return "**no entry for this user**"
}

// eosRoleWord renders the role for a sentence, keeping "refused" and "absent"
// apart for the same reason eosRoleCell does.
func eosRoleWord(r eosRoleResult) string {
	if r.role != "" {
		return "`" + r.role + "`"
	}
	if r.usersRefused {
		return "nothing this run can read: the device refused `show users detail`"
	}
	return "no role entry for this user at all"
}

func eosPrivCell(r eosRoleResult) string {
	if r.level != "" {
		return "`" + r.level + "`"
	}
	return "(not reported)"
}

// render writes phase B. aRows is phase A's results, so the paragraph that says
// why phase B exists counts what phase A did instead of asserting it.
func (p eosRolePhase) render(aRows []eosRoleResult) string {
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
	fmt.Fprintf(&b, "%d of the %d sessions above configured the device, whatever role it named for them. "+
		"That is `aaa authorization commands all default group port49 local` sending every command to a "+
		"lab authorizer that permits everything, so the role is never consulted -- not the role failing "+
		"to arrive. Phase B points the command-authorization method list at the device's own role "+
		"database:\n\n```\n%s\n```\n\nand puts it back afterwards. `aaa authorization exec` is left "+
		"pointed at port49 throughout, because a token operator has no local account and moving it would "+
		"refuse every login.\n\n", configured, opened, strings.Join(eosLocalAuthz, "\n"))
	if !p.applied {
		fmt.Fprintf(&b, "**Phase B did not run.** The method list could not be changed, so nothing here "+
			"is measured:\n\n```\n%s\n```\n\n", strings.TrimRight(p.applyErr, "\n"))
		return b.String()
	}
	for _, r := range p.rows {
		b.WriteString(r.render())
	}
	b.WriteString(eosRoleTable(p.rows))
	return b.String()
}

// eosRoleReading answers the questions from the variants. Every negative goes
// through negativeFinding, which fails the test rather than writing a claim with
// no transcript behind it.
func eosRoleReading(t *testing.T, l *lab, rs []eosRoleResult, ph eosRolePhase) string {
	t.Helper()
	ctrl := eosRoleByName(rs, eosRoleControl)
	mand := eosRoleByName(rs, eosRoleMandatory)
	opt := eosRoleByName(rs, eosRoleOptional)
	alone := eosRoleByName(rs, eosRoleAlone)
	privOpt := eosRoleByName(rs, eosPrivOptAlone)
	privMand := eosRoleByName(rs, eosPrivMandAlone)
	custom := eosRoleByName(rs, eosRoleCustom)
	unknown := eosRoleByName(rs, eosRoleUnknown)

	var b strings.Builder
	b.WriteString("\n#### What this answers\n\n")

	// 1. The question itself, read off the role the device names.
	switch {
	case mand.loginErr != "":
		fmt.Fprintf(&b, "**1. Not answered by this run.** The MANDATORY `roles=` variant produced no "+
			"session:\n\n```\n%s\n```\n\n", strings.TrimRight(mand.loginErr, "\n"))
	case ctrl.loginErr != "":
		b.WriteString("**1. Not answered by this run.** The control never opened a session, and a " +
			"delivery claim needs something to compare against.\n\n")
	case mand.role != "" && mand.role != ctrl.role:
		fmt.Fprintf(&b, "**1. The bare `roles` attribute IS applied, and the 2026-09-21 reading was an "+
			"artefact of the attribute name.** `roles=network-operator` sent mandatory puts the session "+
			"on `%s`; the same reply with the attribute removed puts it on `%s`, on the same device "+
			"minutes apart. The device's own words:\n\n```\n%s\n```\n\nand the control:\n\n```\n%s\n```\n\n"+
			"Everything the earlier section measured stands -- `shell:roles` really does nothing here -- "+
			"but \"vEOS does not apply a role\" was a statement about the spelling `shell:roles`, not "+
			"about EOS.\n\n",
			mand.role, orNone2(ctrl.role), strings.TrimRight(mand.users, "\n"),
			strings.TrimRight(ctrl.users, "\n"))
	default:
		b.WriteString("**1.** " + negativeFinding{
			Claim: "The bare attribute `roles=network-operator`, sent MANDATORY, does NOT deliver a role " +
				"on this platform either. The device names the session `" + orNone2(mand.role) + "`, " +
				"against `" + orNone2(ctrl.role) + "` for the same reply with no `roles` attribute in " +
				"it at all. The role exists -- this test defined `p49-noc` and the device accepted the " +
				"definition, and `network-operator` is built in -- and the session does not hold it.",
			Sent: "reply attributes " + mand.attrs + "\nthen, in the session:\nshow users detail",
			Got:  strings.TrimRight(mand.users, "\n"),
		}.render(t) + "\n")
	}

	// 2. The argument flag on `roles`.
	switch {
	case opt.loginErr != "" && mand.loginErr == "":
		fmt.Fprintf(&b, "**2. The OPTIONAL spelling ended the session.** `roles*network-operator` "+
			"produced no session at all, where the mandatory spelling opened one. An adapter on this "+
			"platform has no choice of flag:\n\n```\n%s\n```\n\n", strings.TrimRight(opt.loginErr, "\n"))
	case opt.loginErr == "" && mand.loginErr == "" && opt.role == mand.role:
		fmt.Fprintf(&b, "**2. The argument flag does not change it.** Optional and mandatory both name "+
			"`%s`, and the session opened either way. RFC 8907 §8.2's distinction decides whether a "+
			"device may ignore an attribute; this device ignores `roles` under neither flag.\n\n",
			orNone2(mand.role))
	case opt.loginErr == "" && mand.loginErr == "":
		fmt.Fprintf(&b, "**2. The argument flag DOES change it.** Optional gives `%s`; mandatory gives "+
			"`%s`. An adapter has to choose the flag deliberately on this platform.\n\n",
			orNone2(opt.role), orNone2(mand.role))
	}

	// 3. The role with no privilege level beside it.
	if alone.loginErr == "" {
		fmt.Fprintf(&b, "**3. The role alone, with no `priv-lvl` in the reply, lands the session at "+
			"privilege `%s`.** port49 answered the session authorization `%s`, the session opened on "+
			"`%s`, and the role it holds is %s. %s\n\n",
			orNone3(alone.level), orNone(alone.sessionVerdict), orDash(alone.prompt),
			eosRoleWord(alone), eosAloneReading(alone, mand))
	} else {
		fmt.Fprintf(&b, "**3. The role alone did NOT open a session.** A reply carrying only "+
			"`roles=network-operator` produced:\n\n```\n%s\n```\n\nSo `priv-lvl` cannot simply be "+
			"dropped on this platform.\n\n", strings.TrimRight(alone.loginErr, "\n"))
	}

	// 4. The owner's second production reading: optional priv-lvl is ignored.
	b.WriteString(eosPrivFlagReading(t, privOpt, privMand))

	// 5. A custom role, two roles, an unknown role.
	if custom.loginErr == "" {
		fmt.Fprintf(&b, "**5. A custom role behaves like a built-in one here:** `roles=p49-noc` names "+
			"`%s` and reports privilege `%s`. That is the shape plan 5 would deliver.\n\n",
			orNone2(custom.role), orNone3(custom.level))
	}
	b.WriteString(eosTwoRolesReading(rs))
	if unknown.loginErr == "" {
		fmt.Fprintf(&b, "**7. A role the device does not have** is reported back as %s, with privilege "+
			"`%s`, and the session still opened. The device does not degrade the name to anything: it "+
			"repeats what it was sent. port49 cannot tell it happened either -- the reply it sent and "+
			"the record it wrote are identical to the case where the role exists. What that costs the "+
			"operator is phase B's question, not this one's, because here port49 answered every "+
			"command.\n\n", eosRoleWord(unknown), orNone3(unknown.level))
	}

	// 8. port49's per-command deny, across every variant that opened.
	b.WriteString(eosDenyReading(t, rs))

	// 9. Phase B: what the delivered role is worth when the device authorizes.
	b.WriteString(eosPhaseBReading(t, ph))

	fmt.Fprintf(&b, "%s\n\nEvery other cell -- the privilege the device asserted on each request, how "+
		"many authorization requests each command cost, what each session was told -- is in the tables "+
		"above, and each one is what that variant's session did on %s.\n",
		eosAdapterRule(rs, ph), l.p.version)
	return b.String()
}

// orNone3 renders an unreported privilege level as a phrase rather than as an
// empty pair of backticks.
func orNone3(level string) string {
	if level == "" {
		return "not reported"
	}
	return level
}

// eosAloneReading says what the role-only variant means, by comparing it with
// the variant that had `priv-lvl=15` beside the same role.
func eosAloneReading(alone, mand eosRoleResult) string {
	if alone.usersRefused {
		return fmt.Sprintf("**Which is the finding: at privilege `%s` the device refuses `show users "+
			"detail` outright, so a reply that names a role and no privilege level produces a session "+
			"whose role cannot be read -- by this test or by the operator holding it.** Whether the "+
			"role arrived and is simply unreadable, or never arrived, is NOT separated by this row; "+
			"what is measured is that dropping `priv-lvl` costs the session its privilege level. An "+
			"adapter for EOS therefore sends both attributes, which is the opposite of the NX-OS rule.",
			orNone3(alone.level))
	}
	if mand.loginErr != "" || alone.role == "" || mand.role == "" {
		return "There is no `priv-lvl=15` row with the same role to compare it against in this run, so " +
			"this row stands on its own."
	}
	if alone.role == mand.role && alone.level == mand.level {
		return "That is the same role and the same level as the reply that carried `priv-lvl=15` beside " +
			"it, so on this evidence the privilege level adds nothing once a role is named."
	}
	if alone.role == mand.role {
		return fmt.Sprintf("The role is the same as with `priv-lvl=15` beside it, but the level is not "+
			"(`%s` here against `%s` there), so the two attributes are not interchangeable and a reply "+
			"that drops `priv-lvl` is not the same reply.", orNone3(alone.level), orNone3(mand.level))
	}
	return fmt.Sprintf("That is a different role from the one the same name delivered with `priv-lvl=15` "+
		"beside it (`%s`), so the two attributes interact and neither row can be read alone.",
		orNone2(mand.role))
}

// eosTwoRolesReading reads the three spellings of "two roles in one value"
// against each other. One of them may be taken, all three may be taken, or none
// may be: the paragraph is built from the role the device named in each, so it
// cannot claim a union the run did not see.
func eosTwoRolesReading(rs []eosRoleResult) string {
	quoted := eosRoleByName(rs, eosRoleTwo)
	spaced := eosRoleByName(rs, eosRoleTwoSpace)
	comma := eosRoleByName(rs, eosRoleTwoComma)

	var b strings.Builder
	b.WriteString("**6. Two roles in one value, three spellings.** ")
	for _, r := range []eosRoleResult{quoted, spaced, comma} {
		if r.loginErr != "" {
			fmt.Fprintf(&b, "%s produced **no session**. ", r.v.name)
			continue
		}
		fmt.Fprintf(&b, "%s names %s. ", r.v.name, eosRoleWord(r))
	}
	// What the device REPORTS is a string, and a string is not a privilege. This
	// paragraph goes no further than the string; the union claim is phase B's,
	// where the pair is asked to authorize something.
	twoNames := func(r eosRoleResult) bool {
		return strings.Contains(r.role, "p49-noc ") && strings.Contains(r.role, "network-operator")
	}
	if quoted.role != "" && strings.Contains(quoted.role, `"`) {
		b.WriteString("**The quoted spelling is a trap:** the device kept the quote character as part " +
			"of the role name rather than stripping it, so a reply copied from an NX-OS server " +
			"definition names a role no device has. ")
	}
	if twoNames(spaced) {
		b.WriteString("The unquoted spelling is the one that arrives as two names separated by a " +
			"space, which is what the device's own column shows. **Whether that is a union or only a " +
			"label with a space in it is not decided here** -- port49 answered every command in these " +
			"sessions -- and finding 11 below asks it where the device is the one authorizing.\n\n")
	} else if twoNames(comma) {
		b.WriteString("Only the comma spelling holds both names, and it holds them as one token, so " +
			"nothing here says the device parsed it as two roles rather than as one role with a comma " +
			"in its name. Finding 11 asks the question where it has an answer.\n\n")
	} else {
		b.WriteString("No spelling arrived as two names, so on this image a reply carrying two roles " +
			"is not delivered as a pair at all; read the role column above for what each produced.\n\n")
	}
	return b.String()
}

// eosPrivFlagReading is the owner's production claim, measured: an OPTIONAL
// `priv-lvl*` is ignored and the session is left at level 1.
func eosPrivFlagReading(t *testing.T, opt, mand eosRoleResult) string {
	t.Helper()
	switch {
	case opt.loginErr != "":
		return fmt.Sprintf("**4. `priv-lvl*2` sent OPTIONAL produced no session at all**, so whether it "+
			"is ignored could not be measured; what it did produce is:\n\n```\n%s\n```\n\n",
			strings.TrimRight(opt.loginErr, "\n"))
	case mand.loginErr != "":
		return fmt.Sprintf("**4. `priv-lvl=2` sent MANDATORY produced no session**, so the optional row "+
			"has nothing to be read against:\n\n```\n%s\n```\n\n", strings.TrimRight(mand.loginErr, "\n"))
	case opt.level != "" && mand.level != "" && opt.level != mand.level:
		return "**4. The owner is right: an OPTIONAL `priv-lvl*` is not applied.** " + negativeFinding{
			Claim: "`priv-lvl*2` sent OPTIONAL does NOT put the session at level 2. The device reports " +
				"level `" + opt.level + "` and the login lands on `" + orDash(opt.prompt) + "`, where " +
				"the identical level sent MANDATORY as `priv-lvl=2` reports `" + mand.level + "` on `" +
				orDash(mand.prompt) + "`. One argument flag apart, same device, same minute.",
			Sent: "reply attributes " + opt.attrs + "\nthen, in the session:\n" + eosPrivCmd,
			Got:  strings.TrimRight(opt.priv, "\n"),
		}.render(t) + "\n" + fmt.Sprintf("The mandatory reply, for comparison:\n\n```\n%s\n```\n\n",
			strings.TrimRight(mand.priv, "\n"))
	case opt.level != "" && opt.level == mand.level:
		return fmt.Sprintf("**4. The argument flag on `priv-lvl` makes no difference here.** Optional and "+
			"mandatory both leave the session at level `%s`, on `%s` and `%s`. The owner's production "+
			"reading -- that an optional `priv-lvl*` is ignored and level 1 assumed -- does **not** "+
			"reproduce on %s.\n\n", opt.level, orDash(opt.prompt), orDash(mand.prompt),
			"this image")
	default:
		return fmt.Sprintf("**4. Not settled by this run.** `priv-lvl*2` reported level `%s` on prompt "+
			"`%s` and `priv-lvl=2` reported `%s` on `%s`; at least one of the two did not report a "+
			"level, so the flag comparison rests on the prompt alone and is not stated as a "+
			"measurement here.\n\n", orNone3(opt.level), orDash(opt.prompt), orNone3(mand.level),
			orDash(mand.prompt))
	}
}

// eosDenyReading reports whether port49's per-command deny bound in every
// session that opened. It counts rather than asserting, so the sentence cannot
// disagree with the table above it.
func eosDenyReading(t *testing.T, rs []eosRoleResult) string {
	t.Helper()
	opened, refused := 0, 0
	var ran eosRoleResult
	for _, r := range rs {
		if r.loginErr != "" {
			continue
		}
		opened++
		if eosRoleProbeOf(r, l16Port49Denied).refused {
			refused++
		} else if ran.v.name == "" {
			ran = r
		}
	}
	if opened == 0 {
		return ""
	}
	if refused == opened {
		return fmt.Sprintf("**8. port49's per-command deny binds under every one of these replies.** "+
			"`%s` was refused in all %d sessions that opened, whatever role the device named and "+
			"whatever privilege level it reported. A per-command deny is real on this platform "+
			"however the session was delivered.\n\n", l16Port49Denied, opened)
	}
	p := eosRoleProbeOf(ran, l16Port49Denied)
	return "**8.** " + negativeFinding{
		Claim: fmt.Sprintf("port49's per-command DENY did not bind in %d of the %d sessions that "+
			"opened. Under the reply %s the command port49 denies ran anyway, which makes port49's "+
			"command authorization advisory under that reply.", opened-refused, opened, ran.attrs),
		Sent: p.cmd + "\n(port49 answered " + orNone(p.verdict) + " for it, over " +
			fmt.Sprintf("%d", p.requests) + " request(s))",
		Got: strings.TrimRight(p.out, "\n"),
	}.render(t) + "\n"
}

// eosPhaseBReading says what phase B measured, and says nothing when phase B did
// not run.
func eosPhaseBReading(t *testing.T, ph eosRolePhase) string {
	t.Helper()
	if !ph.applied {
		return "**9. Phase B did not run**, so what the delivered role is worth when the device " +
			"authorizes its own commands is unmeasured here; the block above says why.\n\n"
	}
	admin := eosRoleByName(ph.rows, eosPhaseBAdmin)
	oper := eosRoleByName(ph.rows, eosPhaseBOperator)
	none := eosRoleByName(ph.rows, eosPhaseBNoRole)
	if admin.loginErr != "" || oper.loginErr != "" {
		return "**9. Phase B measured nothing:** one of its two decisive sessions never opened, and a " +
			"claim about local command authorization needs both.\n\n"
	}
	aRefused, aProbe := admin.configRefused()
	oRefused, oProbe := oper.configRefused()
	nRefused, nProbe := none.configRefused()

	var b strings.Builder
	switch {
	case oRefused && !aRefused:
		b.WriteString("**9. With port49 out of the command path, the delivered role is real privilege.** " +
			negativeFinding{
				Claim: "Under `aaa authorization commands all default local`, a session delivered " +
					"`roles=network-operator` CANNOT change the device: `" + oProbe.cmd + "` is " +
					"refused. The same reply naming `network-admin` runs it. So the role the bare " +
					"attribute delivers is what the device enforces once the device is the one " +
					"enforcing.",
				Sent: "reply attributes " + oper.attrs + "\nthen, in the session:\n" + oProbe.cmd,
				Got:  strings.TrimRight(oProbe.out, "\n"),
			}.render(t) + "\n")
		fmt.Fprintf(&b, "The administrative role, same method list, same minute, the same command:\n\n"+
			"```\n%s\n```\n\n", strings.TrimRight(aProbe.out, "\n"))
		if none.loginErr == "" {
			fmt.Fprintf(&b, "And the no-role control, which `configs/eos-startup.cfg` predicts falls to "+
				"the default role: `%s` was %s.\n\n```\n%s\n```\n\n", nProbe.cmd,
				eosAcceptedWord(nRefused), strings.TrimRight(nProbe.out, "\n"))
		}
		b.WriteString(eosUnknownRoleReading(t, ph))
		b.WriteString(eosTwoRolesPhaseBReading(ph))
	case oRefused && aRefused:
		fmt.Fprintf(&b, "**9. Phase B's administrative row failed with the read-only one.** Neither "+
			"session could configure the device under `aaa authorization commands all default local`, "+
			"so the refusal is not attributable to the role -- a remote account may simply not be "+
			"authorized locally on this image whatever role it holds. The `network-admin` session "+
			"said:\n\n```\n%s\n```\n\n", strings.TrimRight(aProbe.out, "\n"))
	default:
		fmt.Fprintf(&b, "**9. Even with port49 out of the command path, the role did not constrain the "+
			"session.** A session holding `%s` configured the device under `aaa authorization commands "+
			"all default local`: `%s` was accepted.\n\n```\n%s\n```\n\nSo on this image the role this "+
			"reply delivers does not bind in either configuration.\n\n",
			orNone2(oper.role), oProbe.cmd, strings.TrimRight(oProbe.out, "\n"))
	}
	return b.String()
}

func eosAcceptedWord(refused bool) string {
	if refused {
		return "**refused**"
	}
	return "accepted"
}

// eosUnknownRoleReading is the 3am case with the device deciding: a policy names
// a role this device does not have, and port49 is not in the command path to
// cover for it. Phase A cannot answer this, because there port49 permits
// everything; here nothing does.
func eosUnknownRoleReading(t *testing.T, ph eosRolePhase) string {
	t.Helper()
	unknown := eosRoleByName(ph.rows, eosPhaseBUnknown)
	if unknown.loginErr != "" {
		return fmt.Sprintf("**10. The unknown role under local command authorization: no session.** The "+
			"reply naming a role this device does not have produced:\n\n```\n%s\n```\n\n",
			strings.TrimRight(unknown.loginErr, "\n"))
	}
	refused, probe := unknown.configRefused()
	deny := eosRoleProbeOf(unknown, l16Port49Denied)
	if refused {
		return "**10. The 3am case: an unknown role name is a session that can do nothing.** " +
			negativeFinding{
				Claim: "Under `aaa authorization commands all default local`, a session delivered " +
					"`roles=p49-nosuchrole` CANNOT change the device. The session opens, the device " +
					"reports the role by the name it was sent, and the commands are refused. So on " +
					"EOS a policy naming a role that was renamed or never created leaves the " +
					"operator with a session and no privileges -- the safe direction, and invisible " +
					"to port49, which sent a reply identical to the working case.",
				Sent: "reply attributes " + unknown.attrs + "\nthen, in the session:\n" + probe.cmd,
				Got:  strings.TrimRight(probe.out, "\n"),
			}.render(t) + "\n" + fmt.Sprintf("Even `%s`, which needs no privilege, was %s:\n\n"+
			"```\n%s\n```\n\n", deny.cmd, eosAcceptedWord(deny.refused),
			strings.TrimRight(deny.out, "\n"))
	}
	return fmt.Sprintf("**10. An unknown role name is not a restriction here.** Under `aaa authorization "+
		"commands all default local` a session delivered `roles=p49-nosuchrole` still ran `%s`:\n\n"+
		"```\n%s\n```\n\nSo the name the device does not have did not cost the operator this "+
		"command.\n\n", probe.cmd, strings.TrimRight(probe.out, "\n"))
}

// eosTwoRolesPhaseBReading says whether the two delivered roles behave as a
// union, read from what the session could do rather than from the name the
// device echoed back. It is the only place in this note where "two roles" means
// anything beyond a string in a column.
func eosTwoRolesPhaseBReading(ph eosRolePhase) string {
	two := eosRoleByName(ph.rows, eosPhaseBTwo)
	oper := eosRoleByName(ph.rows, eosPhaseBOperator)
	if two.loginErr != "" {
		return fmt.Sprintf("**11. The two-role session did not open under local command "+
			"authorization:**\n\n```\n%s\n```\n\n", strings.TrimRight(two.loginErr, "\n"))
	}
	refused, probe := two.configRefused()
	operRefused, _ := oper.configRefused()
	if !refused && operRefused {
		return fmt.Sprintf("**11. Two roles are a union, and the permit wins.** The device reports this "+
			"session as `%s`, and under `aaa authorization commands all default local` it ran `%s` -- "+
			"which the read-only role alone is refused, two rows above. `p49-noc` permits everything, "+
			"and its permit carried the pair. **So delivering a restrictive role alongside a "+
			"permissive one restricts nobody**, which is the same shape NX-OS documents and the thing "+
			"plan 5 must not do by accident.\n\n", orNone2(two.role), probe.cmd)
	}
	if refused && operRefused {
		return fmt.Sprintf("**11. Two roles do not take the permit here.** The device reports this "+
			"session as `%s` and refused `%s` under local command authorization, exactly as the "+
			"read-only role alone was refused:\n\n```\n%s\n```\n\nSo the permissive half of the pair "+
			"did not carry it, and a union with permit winning is NOT what this image does.\n\n",
			orNone2(two.role), probe.cmd, strings.TrimRight(probe.out, "\n"))
	}
	return fmt.Sprintf("**11. The two-role row cannot be read against its control**: the single "+
		"read-only role was %s the same command, so there is no contrast to draw a union claim from. "+
		"This session reports `%s` and `%s` was %s.\n\n",
		eosAcceptedWord(operRefused), orNone2(two.role), probe.cmd, eosAcceptedWord(refused))
}

// eosAdapterRule states the rule the data supports, and states one only when the
// data supports it. It is built from the role the device NAMES and the level it
// REPORTS, never from the configuration probe: in phase A port49 permits every
// command, so that probe measures port49's answer and not the device's
// privilege. Reading it as a privilege measurement is the defect the NX-OS
// precedence run published twice before it was caught.
func eosAdapterRule(rs []eosRoleResult, ph eosRolePhase) string {
	ctrl := eosRoleByName(rs, eosRoleControl)
	mand := eosRoleByName(rs, eosRoleMandatory)
	opt := eosRoleByName(rs, eosRoleOptional)
	alone := eosRoleByName(rs, eosRoleAlone)
	privOpt := eosRoleByName(rs, eosPrivOptAlone)
	privMand := eosRoleByName(rs, eosPrivMandAlone)

	if mand.loginErr != "" || ctrl.loginErr != "" || mand.role == "" {
		return "**No adapter rule is stated here**: the variant that decides it produced no session or " +
			"no role, so this section records what was measured and nothing further."
	}
	if mand.role == ctrl.role {
		return fmt.Sprintf("**No adapter rule is stated here beyond the negative**: the bare `roles` "+
			"attribute named the same role as the reply without it (`%s` both times), so this run "+
			"gives an adapter nothing to send. Read the tables, not a rule.", orNone2(mand.role))
	}

	rule := fmt.Sprintf("**The adapter rule this supports: on EOS send the BARE attribute `roles=<name>`, "+
		"not `shell:roles`.** The bare name puts the session on `%s` where the same reply without it "+
		"gives `%s`; the `shell:` spelling the earlier section measured does nothing here and its "+
		"mandatory form ends the session outright. ", mand.role, orNone2(ctrl.role))
	if opt.loginErr == "" && opt.role == mand.role {
		rule += "Either argument flag delivers it, so the mandatory form the owner runs is a choice and " +
			"not a requirement. "
	} else if opt.loginErr != "" {
		rule += "It must be sent MANDATORY: the optional spelling ended the session. "
	} else {
		rule += fmt.Sprintf("The flag matters: optional gives `%s` against `%s` mandatory, so an adapter "+
			"has to pick one deliberately. ", orNone2(opt.role), mand.role)
	}
	if privOpt.loginErr == "" && privMand.loginErr == "" && privOpt.level != "" && privMand.level != "" {
		if privOpt.level != privMand.level {
			rule += fmt.Sprintf("**And `priv-lvl` must be sent MANDATORY here**: `priv-lvl*2` leaves the "+
				"session at level `%s` while `priv-lvl=2` reaches level `%s`, so an adapter that sends "+
				"the level optional writes a privilege into the decision log the device did not apply.",
				privOpt.level, privMand.level)
		} else {
			rule += fmt.Sprintf("The flag on `priv-lvl` makes no difference on this image -- optional and "+
				"mandatory both reach level `%s` -- so the owner's production reading about an ignored "+
				"`priv-lvl*` is not reproduced here and an adapter rule should not rest on it.",
				privOpt.level)
		}
	} else {
		rule += "The `priv-lvl` flag question is not settled by this run; see finding 4."
	}
	// The role alone is the shape the NX-OS rule would suggest, and on EOS it is
	// the one an adapter must not send.
	if alone.loginErr == "" && mand.loginErr == "" && alone.level != "" && alone.level != mand.level {
		rule += fmt.Sprintf(" **Both attributes go in the reply, which is the opposite of the NX-OS "+
			"rule:** the role with no `priv-lvl` beside it opens a session at level `%s` on `%s`, "+
			"against level `%s` on `%s` when the level is sent too. On NX-OS `priv-lvl` is inert "+
			"beside a role and an adapter drops it; on EOS dropping it costs the operator their "+
			"privilege level. One reply cannot serve both platforms.",
			alone.level, orDash(alone.prompt), mand.level, orDash(mand.prompt))
	}
	if ph.applied {
		admin := eosRoleByName(ph.rows, eosPhaseBAdmin)
		oper := eosRoleByName(ph.rows, eosPhaseBOperator)
		if admin.loginErr == "" && oper.loginErr == "" {
			aRefused, _ := admin.configRefused()
			oRefused, oProbe := oper.configRefused()
			if oRefused && !aRefused {
				rule += " **Phase B is what makes this a privilege claim rather than a labelling one:** " +
					"with the device authorizing its own commands, the reply naming `network-operator` " +
					"is refused `" + oProbe.cmd + "` and the one naming `network-admin` runs it. The " +
					"role port49 sends is the operator's real privilege on a device that enforces it, " +
					"which is the state a fleet is in before port49 owns command authorization."
			}
		}
	}
	return rule
}
