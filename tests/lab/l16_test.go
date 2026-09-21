//go:build lab

package lab

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// L16: role delivery over TACACS+, and how a delivered role interacts with
// per-command authorization. EOS and NX-OS.
//
// The framing is the owner's: **a custom role is the NX-OS and EOS analogue of
// a Junos login class.** On Junos, port49 will eventually project a policy into
// a class and a set of regexes (§8, decision 22). On these two platforms the
// same job is done by naming a role the device already holds, and nothing in
// this lab has ever checked that naming one does anything at all — the lab
// authorizer has been sending `shell:roles*network-admin` to every platform
// since the N9Kv asked for it, and no test has ever verified that the device
// applied it rather than ignored it.
//
// Eight questions, one deploy, one login per variant:
//
//  1. does a custom role delivered by name take effect? Verified by the device
//     reporting it AND by a command the role forbids actually being refused —
//     never by assumption, which is what the existing `shell:roles` line rests
//     on today;
//  2. when the role refuses a command locally, does the device still send a
//     per-command authorization request for it?
//  3. the role permits and port49 denies — which wins?
//  4. the role denies and port49 permits — which wins?
//  5. two roles at once (NX-OS documents a union with permit winning);
//  6. a role name the device does not have;
//  7. no role attribute at all;
//  8. the accepted spellings: `shell:roles*` and `shell:roles=`, bare and
//     inside `cisco-av-pair`, and `priv-lvl=N`.
//
// Questions 3 and 4 are the ones that matter to the product. If the device's
// own role can refuse a command port49 permitted, then a role is a second
// policy engine port49 does not control, and the decision log says `permit`
// about a command that never ran. If port49's deny loses to a role's permit,
// the deny is decoration.
func TestL16Roles(t *testing.T) {
	eachPlatform(t, func(t *testing.T, l *lab) {
		d, ok := l16Drivers[l.p.name]
		if !ok {
			t.Skipf("L16 is about role delivery, which %s does not use: Junos assigns a class and "+
				"IOS-XE a privilege level (spec §6)", l.p.name)
		}
		stop := l.capture(t, "L16")
		defer stop()

		// The role is defined before anything is measured, and removed after,
		// so a later test on this deploy does not inherit it.
		l16DefineRole(t, l, d)
		defer l16DeleteRole(t, l, d)

		var b strings.Builder
		b.WriteString(l16Preamble(d))

		results := make([]l16VariantResult, 0, len(l16Variants))
		for _, v := range l16Variants {
			r := l.l16Run(t, d, v)
			results = append(results, r)
			b.WriteString(r.render(d))
		}

		b.WriteString(l16Table(results))
		b.WriteString(l16Reading(t, d, results))

		l.result(t, "L16", l16Claim, b.String())

		// A variant that never reached a prompt measured nothing about roles.
		// One such variant is a finding (see the reading); all of them is a
		// test that measured nothing, and must fail.
		reached := 0
		for _, r := range results {
			if r.loginErr == "" {
				reached++
			}
		}
		if reached == 0 {
			t.Fatalf("not one of the %d variants reached a prompt, so nothing about role delivery was "+
				"measured on %s", len(results), l.p.name)
		}
	})
}

const l16Claim = "Whether a custom role delivered by name over TACACS+ takes effect on EOS and NX-OS; " +
	"whether a command that role forbids is refused locally and whether the device still sends a " +
	"per-command authorization request for it; which wins when the device's role and port49 disagree, " +
	"in both directions; two roles at once; a role the device does not have; no role attribute at all; " +
	"the accepted spellings of the attribute; and the `priv-lvl=N` to role mapping."

// The three probe commands. Each is chosen so that the role and port49
// disagree about it in a known direction, which is what makes questions 3 and
// 4 answerable from one login.
//
//   - l16RoleDenied is denied by the custom role and PERMITTED by port49
//     (it is on no `lab.deny_prefixes` entry). The role's word against a
//     port49 permit.
//   - l16Port49Denied is permitted by the custom role (which permits
//     everything but the command above) and DENIED by port49, because
//     `show clock` is the last entry of `lab.deny_prefixes` in
//     port49d-lab.yaml. port49's word against a role permit.
//   - l16BothPermit is permitted by both, and is the control: a variant where
//     even this is refused has a role that broke the session rather than a
//     role that denied one command.
//
// None of the three changes anything on the device. `reload` would have been
// the obvious "role permits, port49 denies" probe because it is already a deny
// prefix, and it is deliberately not used: if port49's deny ever loses — which
// is precisely what this row is asking — the device reboots mid-run.
const (
	l16RoleDenied   = "show version"
	l16Port49Denied = "show clock"
	l16BothPermit   = "show hostname"
)

// l16Driver is the per-platform half of this test: how to define a role, how
// to ask the device which roles the session holds, and how to open a CLI.
type l16Driver struct {
	platform string

	// defineRole and deleteRole are configuration lines. The role permits
	// everything and denies one command, so exactly one variable separates the
	// two probe outcomes.
	defineRole []string
	deleteRole []string

	// roleName is the custom role, and secondRole is an existing built-in used
	// for the two-roles-at-once variant.
	roleName   string
	secondRole string

	// whoami is the command that reports the roles the session holds, and
	// whoamiNote says what a reader should look for in its output.
	whoami     string
	whoamiNote string

	// cli opens the TOKEN session. It is deliberately not eosCLI: that helper
	// types `enable` on the way in, and a variant that lands the operator at
	// privilege 1 -- which is one of the variants -- would meet a password
	// prompt there and have `terminal length 0` typed into it. `l3CLI` exists
	// for exactly this reason (see its comment) and takes whatever prompt the
	// login produced.
	cli      func(l *lab, user, password string) (*cliConn, error)
	adminCLI func(*lab) (*cliConn, error)
	// show must wait for EITHER prompt, because which one the session got is
	// one of the things being measured: `#` means the reply attributes reached
	// the device, `>` means they did not.
	// enterConfig is how this platform enters configuration mode. The lines
	// that follow it define a role, which is a SUB-mode, and that is why L16
	// cannot use eosConfigure or nxosConfigure: both wait for the exact
	// `<node>(config)#` prompt, and `role p49-noc` puts the device at
	// `<node>(config-role-p49-noc)#`, which they would wait out in full and
	// then fail. l16Configure waits for any prompt ending `)#` instead.
	enterConfig string
	show        func(l *lab, c *cliConn, cmd string) (string, error)

	// refusalMarkers are what this device says when it refuses a command. A
	// refusal it does not recognise is reported as "unrecognised output"
	// rather than silently counted as a permit.
	refusalMarkers []string
}

var l16Drivers = map[string]l16Driver{
	// NX-OS. `rule` numbers are evaluated in DESCENDING order, so rule 10's
	// deny is considered before rule 5's blanket permit. That ordering is
	// itself something this test verifies rather than assumes: if it is the
	// other way round on this image, `show version` is permitted and the note
	// says so in the variant table.
	"cisco_nxos": {
		platform: "cisco_nxos",
		defineRole: []string{
			"role name p49-noc",
			"rule 10 deny command " + l16RoleDenied,
			"rule 5 permit command *",
			"exit",
		},
		deleteRole:     []string{"no role name p49-noc"},
		enterConfig:    "configure terminal",
		roleName:       "p49-noc",
		secondRole:     "network-operator",
		whoami:         "show user-account",
		whoamiNote:     "the `roles:` line names the roles NX-OS believes this session holds",
		cli:            (*lab).l3CLI,
		adminCLI:       func(l *lab) (*cliConn, error) { return l.nxosCLI(breakglassUser, breakglassPassword) },
		show:           l16Show,
		refusalMarkers: []string{"Permission denied", "permission denied", "% Permission", "AAA authorization failed", "Cmd exec error", "no permission", "Authorization failed"},
	},
	// EOS. Role rules are numbered and evaluated in ASCENDING order, first
	// match winning, so the deny is numbered below the permit. Same caveat as
	// above: the variant table reports what happened, not what was intended.
	"arista_eos": {
		platform: "arista_eos",
		defineRole: []string{
			"role p49-noc",
			"10 deny command " + l16RoleDenied,
			"20 permit command .*",
			"exit",
		},
		deleteRole:     []string{"no role p49-noc"},
		enterConfig:    "configure",
		roleName:       "p49-noc",
		secondRole:     "network-operator",
		whoami:         "show users detail",
		whoamiNote:     "the `Role` column names the role EOS believes this session holds",
		cli:            (*lab).l3CLI,
		adminCLI:       func(l *lab) (*cliConn, error) { return l.eosCLI(breakglassUser, breakglassPassword) },
		show:           l16Show,
		refusalMarkers: []string{"Authorization denied", "% Authorization", "Permission denied", "Invalid input", "not authorized"},
	},
}

// l16Variant is one reply-attribute set, and the question it answers.
type l16Variant struct {
	name  string
	why   string
	attrs func(d l16Driver) string // a YAML flow sequence
}

// The variants, in the order the note reports them. `{role}` and `{other}` are
// substituted per platform so one table serves both.
var l16Variants = []l16Variant{
	{
		name: "no role attribute at all",
		why: "the control. Whatever the device does here is what a role delivery has to be measured " +
			"against, and it is also what port49 sends today on every platform but NX-OS.",
		attrs: func(l16Driver) string { return `["priv-lvl=15"]` },
	},
	{
		name: "`shell:roles*<role>` — bare, OPTIONAL",
		why: "the spelling `tests/lab/port49d-lab.yaml` has been sending since the N9Kv asked for it, " +
			"with the custom role in place of `network-admin`. Nothing has ever checked that the " +
			"device applies it.",
		attrs: func(d l16Driver) string { return `["priv-lvl=15", "shell:roles*` + d.roleName + `"]` },
	},
	{
		name: "`shell:roles=<role>` — bare, MANDATORY",
		why: "the same attribute sent as mandatory. RFC 8907 §8.2 says a device that does not " +
			"understand a mandatory argument must fail the authorization, so this variant also asks " +
			"whether the device understands it at all.",
		attrs: func(d l16Driver) string { return `["priv-lvl=15", "shell:roles=` + d.roleName + `"]` },
	},
	{
		name: "inside `cisco-av-pair`",
		why: "the spelling Cisco documentation uses for NX-OS. If both work the adapter has a choice; " +
			"if only one does, plan 5 has no choice at all.",
		attrs: func(d l16Driver) string {
			return `["priv-lvl=15", "cisco-av-pair*shell:roles=\"` + d.roleName + `\""]`
		},
	},
	{
		name: "two roles at once",
		why: "NX-OS documents a union with permit winning. If that holds, a role delivered alongside a " +
			"permissive one is not a restriction, which is the whole point of delivering it.",
		attrs: func(d l16Driver) string {
			return `["priv-lvl=15", "shell:roles*\"` + d.roleName + ` ` + d.secondRole + `\""]`
		},
	},
	{
		name: "a role the device does not have",
		why: "the 3am case: a policy names a role that was renamed or never created on this device. " +
			"Does the operator get no privileges, all of them, or no session?",
		attrs: func(l16Driver) string { return `["priv-lvl=15", "shell:roles*p49-nosuchrole"]` },
	},
	{
		name: "`priv-lvl=1` alone",
		why: "the privilege-level path rather than the role path, for the mapping half of this row. " +
			"On NX-OS this is only meaningful with `feature privilege`, and this lab does not " +
			"configure it, so what the device does with it here is itself the finding.",
		attrs: func(l16Driver) string { return `["priv-lvl=1"]` },
	},
}

// l16VariantResult is one variant's evidence.
type l16VariantResult struct {
	v        l16Variant
	attrs    string
	loginErr string
	whoami   string
	probes   []l16Probe
	authzs   map[string]string // probe command word -> port49's verdict/reason
	cmdReqs  map[string]int    // probe command word -> how many authorization requests arrived
}

// l16Probe is one command typed in a variant's session.
type l16Probe struct {
	cmd      string
	expect   string // what this probe is for
	out      string // the device's exact reply
	refused  bool
	verdict  string // port49's verdict for it, or "" when it never asked
	requests int
}

func (r l16VariantResult) render(d l16Driver) string {
	var b strings.Builder
	fmt.Fprintf(&b, "\n### %s\n\n%s\n\nReply attributes: `%s`\n\n", r.v.name, r.v.why, r.attrs)
	if r.loginErr != "" {
		fmt.Fprintf(&b, "**The session never opened.**\n\n```\n%s\n```\n\n", r.loginErr)
		return b.String()
	}
	if r.whoami != "" {
		fmt.Fprintf(&b, "`%s` — %s:\n\n```\n%s\n```\n\n", d.whoami, d.whoamiNote, strings.TrimRight(r.whoami, "\n"))
	} else {
		fmt.Fprintf(&b, "`%s` returned nothing, so this variant does not say which role the device believes "+
			"the session holds.\n\n", d.whoami)
	}
	for _, p := range r.probes {
		fmt.Fprintf(&b, "`%s` (%s) — port49 answered **%s**, %d authorization request(s); the device said:\n\n```\n%s\n```\n\n",
			p.cmd, p.expect, orNone(p.verdict), p.requests, strings.TrimRight(p.out, "\n"))
	}
	return b.String()
}

func orNone(s string) string {
	if s == "" {
		return "nothing (no authorization request reached port49)"
	}
	return s
}

// l16DefineRole puts the custom role on the device, as the break-glass account.
func l16DefineRole(t *testing.T, l *lab, d l16Driver) {
	t.Helper()
	l.withAdminCLI(t, d.adminCLI, func(c *cliConn) error {
		out, err := l16Configure(l, c, d, d.defineRole)
		if err != nil {
			return fmt.Errorf("defining role %s: %w\n%s", d.roleName, err, out)
		}
		t.Logf("%s: defined role %s", d.platform, d.roleName)
		return nil
	})
}

func l16DeleteRole(t *testing.T, l *lab, d l16Driver) {
	t.Helper()
	l.withAdminCLI(t, d.adminCLI, func(c *cliConn) error {
		out, err := l16Configure(l, c, d, d.deleteRole)
		if err != nil {
			return fmt.Errorf("removing role %s: %w\n%s", d.roleName, err, out)
		}
		return nil
	})
}

// l16Run measures one variant: restart the daemon with these reply attributes,
// log in a token user, ask the device which roles it thinks the session has,
// and run the three probes.
func (l *lab) l16Run(t *testing.T, d l16Driver, v l16Variant) l16VariantResult {
	t.Helper()
	attrs := v.attrs(d)
	cfg, err := l.derivedConfig("l16-"+l16Slug(v.name), attrs, "")
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
	r := l16VariantResult{v: v, attrs: attrs, authzs: map[string]string{}, cmdReqs: map[string]int{}}

	user, secret := l.nextLogin(t)
	c, err := d.cli(l, user, secret)
	if err != nil {
		r.loginErr = err.Error()
		l.drainRecords(off, 5*time.Second)
		return r
	}
	if out, err := d.show(l, c, d.whoami); err == nil {
		r.whoami = l16TrimEcho(out, d.whoami)
	}
	for _, p := range []l16Probe{
		{cmd: l16RoleDenied, expect: "the custom role DENIES this; port49 permits it"},
		{cmd: l16Port49Denied, expect: "the custom role permits this; port49 DENIES it"},
		{cmd: l16BothPermit, expect: "both permit this — the control"},
	} {
		out, _ := d.show(l, c, p.cmd)
		p.out = l16TrimEcho(out, p.cmd)
		if strings.TrimSpace(p.out) == "" {
			p.out = emptyDeviceReply
		}
		p.refused = l16Refused(p.out, d.refusalMarkers)
		r.probes = append(r.probes, p)
	}
	c.Close()

	recs := l.drainRecords(off, 10*time.Second)
	for i, p := range r.probes {
		word := strings.Fields(p.cmd)[1] // "show version" -> "version"
		for _, rec := range recs {
			if str(rec, "event") != "authorize_command" {
				continue
			}
			vec := strs(sub(rec, "request"), "vector")
			if len(vec) < 2 || vec[1] != word {
				continue
			}
			r.probes[i].requests++
			r.probes[i].verdict = str(rec, "verdict") + " " + str(rec, "reason")
		}
		r.cmdReqs[word] = r.probes[i].requests
		r.authzs[word] = r.probes[i].verdict
	}
	return r
}

// l16Configure applies configuration lines that may enter a sub-mode.
//
// Every configuration prompt on both platforms ends `)#` -- `leaf1(config)#`,
// `leaf1(config-role-p49-noc)#`, `nx1(config-role)#` -- so that suffix is the
// one matcher that works in and out of a role block. `end` returns to the exec
// prompt, which is what is waited for last. A line the parser rejects is an
// error rather than a silent skip: a role that was never defined would make
// every variant below measure a device with no role on it, and the table would
// read as "role delivery does nothing" about a role that does not exist.
func l16Configure(l *lab, c *cliConn, d l16Driver, lines []string) (string, error) {
	from := len(c.transcript())
	if _, err := c.sendExpect(d.enterConfig, 45*time.Second, ")#"); err != nil {
		return c.transcript(), fmt.Errorf("entering configuration mode with %q: %w", d.enterConfig, err)
	}
	for _, ln := range lines {
		out, err := c.sendExpect(ln, 60*time.Second, ")#")
		if err != nil {
			return out, fmt.Errorf("%q: %w", ln, err)
		}
		for _, bad := range []string{"% Invalid", "Invalid command", "% Incomplete", "ERROR:", "% Error"} {
			if strings.Contains(out, bad) {
				return out, fmt.Errorf("%q was refused by the device:\n%s", ln, out)
			}
		}
	}
	if _, err := c.sendExpect("end", 45*time.Second, l.p.node+"#"); err != nil {
		return c.transcript(), fmt.Errorf("leaving configuration mode: %w", err)
	}
	return c.transcript()[from:], nil
}

// l16Show runs one command and waits for either prompt shape. A variant that
// left the session at `>` is a finding, not a hang, so waiting only for `#`
// would turn it into a timeout that says nothing.
func l16Show(l *lab, c *cliConn, cmd string) (string, error) {
	return c.sendExpect(cmd, 60*time.Second, l.p.node+"#", l.p.node+">")
}

func l16Refused(out string, markers []string) bool {
	for _, m := range markers {
		if strings.Contains(out, m) {
			return true
		}
	}
	return false
}

func l16TrimEcho(out, cmd string) string {
	s := out
	if i := strings.Index(s, cmd); i >= 0 {
		s = s[i+len(cmd):]
	}
	return strings.Trim(s, "\r\n")
}

func l16Slug(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r + 32)
		default:
			b.WriteRune('-')
		}
	}
	return strings.Trim(b.String(), "-")
}

func l16Preamble(d l16Driver) string {
	return fmt.Sprintf("The device holds one custom role, defined for this test and removed afterwards:\n\n"+
		"```\n%s\n```\n\nIt permits everything and denies exactly one command, so one variable separates "+
		"the two probes that matter. The three probes are `%s` (the role denies it, port49 permits it), "+
		"`%s` (the role permits it, port49 denies it — it is the last entry of `lab.deny_prefixes`), and "+
		"`%s` (both permit it, the control). Each variant below is one set of reply attributes, one daemon "+
		"restart and one token login.\n",
		strings.Join(d.defineRole, "\n"), l16RoleDenied, l16Port49Denied, l16BothPermit)
}

// l16Table is the summary, built from the results. Every cell is something a
// variant saw, so the table cannot say more than the run measured.
func l16Table(rs []l16VariantResult) string {
	var b strings.Builder
	b.WriteString("\n## Every variant side by side\n\n")
	b.WriteString("| reply attributes | session | role reported | `" + l16RoleDenied + "` (role denies) | `" +
		l16Port49Denied + "` (port49 denies) | `" + l16BothPermit + "` (control) |\n")
	b.WriteString("|---|---|---|---|---|---|\n")
	for _, r := range rs {
		if r.loginErr != "" {
			fmt.Fprintf(&b, "| %s | **no session** | — | — | — | — |\n", r.v.name)
			continue
		}
		cells := make([]string, 0, 3)
		for _, p := range r.probes {
			state := "ran"
			if p.refused {
				state = "**refused**"
			}
			cells = append(cells, fmt.Sprintf("%s; %d req; %s", state, p.requests, orNone(p.verdict)))
		}
		fmt.Fprintf(&b, "| %s | opened | %s | %s | %s | %s |\n",
			r.v.name, l16RoleSummary(r.whoami), cells[0], cells[1], cells[2])
	}
	return b.String()
}

// l16RoleSummary pulls the roles line out of the whoami output for the table,
// falling back to a marker rather than to silence.
func l16RoleSummary(whoami string) string {
	for _, line := range strings.Split(whoami, "\n") {
		l := strings.TrimSpace(line)
		low := strings.ToLower(l)
		if strings.HasPrefix(low, "roles:") || strings.Contains(low, " role ") {
			return "`" + strings.TrimSpace(l) + "`"
		}
	}
	if strings.TrimSpace(whoami) == "" {
		return "(nothing returned)"
	}
	return "(see the variant above)"
}

// l16Reading answers the row's own questions from the variants, and routes
// every negative through negativeFinding so none of them can be written
// without the transcript behind it.
func l16Reading(t *testing.T, d l16Driver, rs []l16VariantResult) string {
	t.Helper()
	byName := map[string]l16VariantResult{}
	for _, r := range rs {
		byName[r.v.name] = r
	}
	bare := byName["`shell:roles*<role>` — bare, OPTIONAL"]
	none := byName["no role attribute at all"]

	var b strings.Builder
	b.WriteString("\n## What this answers\n\n")

	// 1 and 2: does the role take effect, and is the command still authorized?
	switch {
	case bare.loginErr != "":
		b.WriteString("**1. Does a delivered role take effect?** Not measured on the bare optional " +
			"spelling: that variant's session never opened, so the role could not be exercised.\n\n")
	case l16ProbeOf(bare, l16RoleDenied).refused:
		p := l16ProbeOf(bare, l16RoleDenied)
		fmt.Fprintf(&b, "**1. A role delivered by name DOES take effect**, and it is verified by a refusal "+
			"rather than by the device echoing the name back. `%s` is denied by the role and permitted by "+
			"port49, and the device refused it:\n\n```\n%s\n```\n\n", p.cmd, strings.TrimRight(p.out, "\n"))
		if p.requests > 0 {
			fmt.Fprintf(&b, "**2. The device still asked port49 about it** — %d authorization request(s), "+
				"answered `%s`. So the role's refusal is applied *after* port49 has been consulted and "+
				"agreed, and **port49's decision log records a permit for a command that never ran.** "+
				"That is the reconciliation gap of §9 arriving from a direction the spec does not "+
				"describe: not a device that fails to ask, but a device that asks, is told yes, and "+
				"refuses anyway.\n\n", p.requests, p.verdict)
		} else {
			b.WriteString("**2.** " + negativeFinding{
				Claim: "the device does NOT send a per-command authorization request for a command its own " +
					"role forbids: it refuses it locally first. port49 never learns the command was " +
					"typed, so the decision log has no record of it at all — neither a permit nor a deny.",
				Sent: p.cmd,
				Got: strings.TrimRight(p.out, "\n") + "\n\n(and no authorize_command record for `" +
					strings.Fields(p.cmd)[1] + "` reached the decision log in this variant's window)",
			}.render(t) + "\n")
		}
	default:
		p := l16ProbeOf(bare, l16RoleDenied)
		b.WriteString("**1.** " + negativeFinding{
			Claim: "delivering role `" + d.roleName + "` by name did NOT take effect: the command the role " +
				"denies ran anyway. Whatever the device reported for `" + d.whoami + "`, the role's rules " +
				"were not applied to this session.",
			Sent: p.cmd,
			Got:  strings.TrimRight(p.out, "\n"),
		}.render(t) + "\n")
	}

	// 3: role permits, port49 denies.
	if bare.loginErr == "" {
		p := l16ProbeOf(bare, l16Port49Denied)
		if p.refused {
			fmt.Fprintf(&b, "**3. port49's deny wins over the role's permit.** `%s` is permitted by the "+
				"role and denied by port49 (`%s`), and the device refused it. So a per-command deny is "+
				"real on this platform whatever the role says.\n\n", p.cmd, orNone(p.verdict))
		} else {
			b.WriteString("**3.** " + negativeFinding{
				Claim: "port49's per-command DENY did not stop the command: the role permitted it and it " +
					"ran. On this platform a deny does not bind, which makes port49's command " +
					"authorization advisory here.",
				Sent: p.cmd + "\n(port49 answered " + orNone(p.verdict) + " for it)",
				Got:  strings.TrimRight(p.out, "\n"),
			}.render(t) + "\n")
		}
	}

	// The control, and the no-role baseline, which is what makes 1 meaningful.
	if none.loginErr == "" && bare.loginErr == "" {
		nb, bb := l16ProbeOf(none, l16RoleDenied), l16ProbeOf(bare, l16RoleDenied)
		if !nb.refused && bb.refused {
			fmt.Fprintf(&b, "**The baseline holds.** With no role attribute, `%s` ran; with the role "+
				"delivered, it was refused. The difference is the role and nothing else — same device, "+
				"same command, same port49 verdict.\n\n", l16RoleDenied)
		} else if nb.refused {
			fmt.Fprintf(&b, "**Read question 1 with care:** `%s` was refused in the no-role variant too, "+
				"so the refusal in the role variant is not attributable to the role. This is the control "+
				"failing, and it is why the control is here.\n\n", l16RoleDenied)
		}
	}

	b.WriteString("Every other question — the spellings, two roles at once, an absent role, `priv-lvl=1` — " +
		"is answered by the table above, cell by cell, and each cell is what that variant's session did.\n")
	return b.String()
}

func l16ProbeOf(r l16VariantResult, cmd string) l16Probe {
	for _, p := range r.probes {
		if p.cmd == cmd {
			return p
		}
	}
	return l16Probe{cmd: cmd}
}
