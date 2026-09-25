//go:build lab

package lab

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

// The Junos wire facts decision 22's generator rests on (spec §8, §13; §15
// L9 and L12): what a reply's `user-permissions` does over a bitless
// template, whether a wire `deny-commands .*` plus one allow alternation
// yields exactly the permits, how a deny regex is anchored, whether it reads
// a command in the case, the abbreviation and the pipe typed, what a
// malformed one does, whether it reaches a statement typed in configuration
// mode, the `-regexps` family's precedence, whether numbered names are
// distinct attributes, and whether a template user can be logged into
// locally. Each is a variant of the lab authorizer's session reply
// (`lab.session_attributes`) and one token login; the control is a template
// holding every bit and no regex, so a command the control does not run says
// nothing about a variant.
//
// Every command typed has a deadline, junosPer: a prompt that does not come
// back within it is "not observed", never a refusal, and fails the test.

// junosPer is the deadline on every command a Junos lab test types.
const junosPer = 45 * time.Second

// junosHost is the host name both Junos images carry
// (tests/lab/configs/vjunos-startup.conf), whatever the lab node is named.
const junosHost = "srx1"

// junosRefusal are the words a Junos CLI answers a command it will not run
// with. A cell is `refused` only where the control ran the command and the
// variant's output holds one of these; every cell's output is in the note
// verbatim, so a marker this list lacks shows up as `ran` beside the text
// that says otherwise, and the reader sees it. `missing argument` is how
// vJunos 23.4 refuses `show version` under a deny naming it: the deny hides
// `version`, and `show` alone wants an argument
// (results/L12-juniper_vjunos-router.md).
var junosRefusal = []string{"permission denied", "unknown command", "syntax error", "not allowed", "error:",
	"missing argument"}

// junosProbe is one command a variant types, or with complete, whose last
// word it asks `?` completion for and never runs: `request system reboot` is
// probed by whether `reboot` completes after `request system`. A complete
// probe ending in `?` is a listing, `show ?`, kept whole. A probe with
// evidence ran only where its output holds it: `show configuration` that
// prints nothing has not shown the configuration.
type junosProbe struct {
	cmd      string
	complete bool
	evidence string
}

// junosRun is one variant's session.
type junosRun struct {
	name, attrs, user string
	loginErr          string
	auth              string            // `show cli authorization`
	outs              map[string]string // probe → the device's reply
	unobserved        []string          // probes whose prompt never came back
	privilege         string            // the authorize_session record's session.privilege
}

// runs reports whether the session ran the probe: observed, and its output
// holds the probe's evidence, or no refusal where it has none.
func (r junosRun) runs(p junosProbe) bool {
	out, ok := r.outs[p.cmd]
	if !ok || slices.Contains(r.unobserved, p.cmd) {
		return false
	}
	if p.evidence != "" {
		return strings.Contains(out, p.evidence)
	}
	return !containsAny(strings.ToLower(out), junosRefusal)
}

// ran is runs for a probe with no evidence.
func (r junosRun) ran(cmd string) bool { return r.runs(junosProbe{cmd: cmd}) }

func (r junosRun) completes(p junosProbe) bool {
	words := strings.Fields(p.cmd)
	out := r.outs[p.cmd]
	return strings.Contains(out, "\n  "+words[len(words)-1]+" ") || strings.Contains(out, "\n"+words[len(words)-1]+" ")
}

// cell is a probe's outcome in a variant, read against the control.
func (r junosRun) cell(p junosProbe, control junosRun) string {
	switch {
	case r.loginErr != "":
		return "no session"
	case slices.Contains(r.unobserved, p.cmd):
		return "not observed"
	case p.complete && r.completes(p):
		return "completes"
	case p.complete:
		return "absent"
	case !control.runs(p):
		return "not comparable (the control did not run it)"
	case r.runs(p):
		return "ran"
	}
	return "refused"
}

// junosConfigureAdmin applies configuration lines over a break-glass CLI,
// port49d stopped so the device takes the local password (L4 reading 3).
func (l *lab) junosConfigureAdmin(t *testing.T, lines []string) string {
	t.Helper()
	var out string
	l.withAdminCLI(t, func(l *lab) (*cliConn, error) {
		return l.junosCLI(breakglassUser, breakglassPassword)
	}, func(c *cliConn) error {
		o, err := junosConfigure(c, lines...)
		out = o
		if err != nil {
			return fmt.Errorf("applying %v: %w\n%s", lines, err, o)
		}
		return nil
	})
	return out
}

// junosLogin restarts port49d with attrs as the session reply and logs in
// with the next seeded token, paging off. A session that did not open is a
// run with loginErr set and no connection.
func (l *lab) junosLogin(t *testing.T, name, attrs string) (*cliConn, junosRun, int64) {
	t.Helper()
	r := junosRun{name: name, attrs: attrs, outs: map[string]string{}}
	cfg, err := l.derivedConfigCmd("junos-"+l16Slug(name), attrs, "", "")
	if err == nil {
		err = l.restart(cfg)
	}
	if err != nil {
		t.Fatalf("%s: port49d with %s: %v", name, attrs, err)
	}
	off := l.mark()
	user, secret := l.nextLogin(t)
	r.user = user
	c, err := l.sshCLI(user, secret)
	if err == nil {
		if _, err = c.expect(90*time.Second, junosOpPrompt); err != nil {
			c.Close()
		}
	}
	if err != nil {
		r.loginErr = oneLine(err.Error())
		return nil, r, off
	}
	if err := junosPrepare(c); err != nil {
		r.unobserved = append(r.unobserved, "set cli screen-length 0")
		t.Errorf("%s: `set cli screen-length 0` not observed within its deadline: %v", name, err)
	}
	if out, err := c.sendExpect("show cli authorization", junosPer, junosOpPrompt); err != nil {
		r.unobserved = append(r.unobserved, "show cli authorization")
		t.Errorf("%s: `show cli authorization` not observed within %s: %v", name, junosPer, err)
	} else {
		r.auth = precReply(l16TrimEcho(out, "show cli authorization"))
	}
	return c, r, off
}

// junosSession is junosLogin, then each probe with its deadline, then the
// priv_lvl the device put on the session authorization. A probe sequence that
// enters configuration mode ends with `exit configuration-mode` itself
// (configurationProbes).
func (l *lab) junosSession(t *testing.T, name, attrs string, probes []junosProbe) junosRun {
	t.Helper()
	c, r, off := l.junosLogin(t, name, attrs)
	if c == nil {
		return r
	}
	defer c.Close()
	for _, p := range probes {
		out, err := l.junosProbe(c, p)
		r.outs[p.cmd] = out
		if err != nil {
			r.unobserved = append(r.unobserved, p.cmd)
			t.Errorf("%s: %q not observed within %s: %v", name, p.cmd, junosPer, err)
			break // the session's state is unknown past a missed prompt
		}
	}
	for _, rec := range l.drainRecords(off, 10*time.Second) {
		if str(rec, "event") == "authorize_session" && str(sub(rec, "session"), "username") == r.user {
			r.privilege = fmt.Sprint(sub(rec, "session")["privilege"])
		}
	}
	return r
}

// junosProbe types one probe. A completion probe writes the words and `?`
// with no newline, waits for the prompt to be redrawn with them, and clears
// the line with ^U, so the command is never run.
func (l *lab) junosProbe(c *cliConn, p junosProbe) (string, error) {
	if !p.complete {
		out, err := c.sendExpect(p.cmd, junosPer, junosOpPrompt, junosCfgPrompt, "(yes)")
		if err == nil && strings.Contains(out, "(yes)") {
			var more string
			more, err = c.sendExpect("yes", junosPer, junosOpPrompt)
			out += more
		}
		return precReply(l16TrimEcho(out, p.cmd)), err
	}
	send := p.cmd
	prefix := strings.TrimSuffix(p.cmd, "?")
	if !strings.HasSuffix(p.cmd, "?") {
		words := strings.Fields(p.cmd)
		prefix = strings.Join(words[:len(words)-1], " ") + " "
		send = prefix + "?"
	}
	from := len(c.out.String())
	if _, err := fmt.Fprint(c.in, send); err != nil {
		return "", err
	}
	// A word the session may not type is refused as it is typed, so the line
	// is never redrawn with the prefix; the device's answer is then `No valid
	// completions` and a prompt after it, and the probe's cell reads absent.
	const none = "No valid completions"
	out, err := c.expectFrom(from, junosPer, junosOpPrompt+prefix, none)
	if i := strings.Index(out, none); err == nil && i >= 0 && !strings.Contains(out, junosOpPrompt+prefix) {
		out, err = c.expectFrom(from+i+len(none), junosPer, junosOpPrompt)
		out = c.out.String()[from:]
	}
	fmt.Fprint(c.in, "\x15")
	return out, err
}

// junosWireClasses are the templates the wire variants name: one with no
// bits, one with `view`, one that configures, one with every bit. None has a
// uid, which is itself a measurement: a template the reference configuration
// renders has none (platform export --classes).
var junosWireClasses = []string{
	"set system login class p49-l12-none idle-timeout 60",
	"set system login user p49-l12-none class p49-l12-none",
	"set system login class p49-l12-view permissions view",
	"set system login user p49-l12-view class p49-l12-view",
	"set system login class p49-l12-cfg permissions [ configure view view-configuration ]",
	"set system login user p49-l12-cfg class p49-l12-cfg",
	"set system login class p49-l12-all permissions all",
	"set system login user p49-l12-all class p49-l12-all",
}

var junosWireDelete = []string{
	"delete system login user p49-l12-none", "delete system login class p49-l12-none",
	"delete system login user p49-l12-view", "delete system login class p49-l12-view",
	"delete system login user p49-l12-cfg", "delete system login class p49-l12-cfg",
	"delete system login user p49-l12-all", "delete system login class p49-l12-all",
}

// junosWireProbes are typed in every variant. None changes the device: a
// clear of one interface's counters, a ping of the loopback, and the two
// disruptive commands by completion only.
var junosWireProbes = []junosProbe{
	{cmd: "show version"}, {cmd: "show version | no-more"}, {cmd: "show system uptime"},
	{cmd: "show interfaces terse"}, {cmd: "show interfaces fxp0 terse"},
	{cmd: "show configuration system host-name", evidence: "host-name " + junosHost},
	{cmd: "clear interfaces statistics fxp0"}, {cmd: "ping 127.0.0.1 count 1 rapid"},
	{cmd: "SHOW VERSION"}, {cmd: "show interfaces FXP0 terse"}, {cmd: "sh ver"}, {cmd: "sh int fxp0 terse"},
	{cmd: "set cli screen-width 200"}, {cmd: "file list /var/tmp"},
	{cmd: "request system reboot", complete: true}, {cmd: "restart routing", complete: true},
}

type junosVariant struct{ name, attrs, why string }

// junosWireVariants are fourteen logins; the per-session check spends two
// more, the harness's pool of sixteen.
var junosWireVariants = []junosVariant{
	{"control", `["local-user-name=p49-l12-all"]`, "every bit and no regex: what the device runs at all"},
	{"bitless", `["local-user-name=p49-l12-none"]`, "a template with no bits: the baseline every session has"},
	{"bitless + user-permissions", `["local-user-name=p49-l12-none", "user-permissions=view"]`,
		"L12: is user-permissions applied over a bitless template"},
	{"bitless + two bits", `["local-user-name=p49-l12-none", "user-permissions=view clear"]`,
		"L12: two bits in one value, space-separated, as the generator writes them"},
	{"remote + user-permissions", `["user-permissions=view"]`,
		"L12: over remote's view view-configuration, does it replace (view alone) or merge"},
	{"narrow", `["local-user-name=p49-l12-view", "deny-commands=^.*$", "allow-commands=^(show version|show interfaces( .*)?)$"]`,
		"L12: deny .* and one allow alternation yield exactly the permits, and what .* does to the baseline"},
	{"deny unanchored word", `["local-user-name=p49-l12-all", "deny-commands=version"]`,
		"L9: is a deny regex matched anywhere in the line"},
	{"deny prefix", `["local-user-name=p49-l12-all", "deny-commands=show ver"]`, "L9: is it matched as a prefix"},
	{"deny anchored", `["local-user-name=p49-l12-all", "deny-commands=^show version( *\\|.*)?$"]`,
		"L9: explicit anchors with the pipe tail the generator writes; and the case and abbreviation of `show version`"},
	{"deny argument", `["local-user-name=p49-l12-all", "deny-commands=^show interfaces fxp0( .*)?$"]`,
		"L9: an argument's case and an abbreviated command against a deny"},
	{"deny malformed", `["local-user-name=p49-l12-all", "deny-commands=^(show$"]`,
		"L9: a regex the dialect rejects: refused session, ignored, or applied"},
	{"configuration mode", `["local-user-name=p49-l12-cfg", "deny-commands=^(set system host-name.*|show version)$"]`,
		"L12: does deny-commands reach a statement typed in configuration mode, and `run`"},
	{"regexps family", `["local-user-name=p49-l12-view", "deny-commands-regexps=^show version$", "allow-commands-regexps=^show version$"]`,
		"L12: does the -regexps family's deny beat its allow over the wire"},
	{"numbered name", `["local-user-name=p49-l12-view", "deny-commands=^.*$", "allow-commands=^show version$", "allow-commands2=^show system uptime$"]`,
		"L12: is allow-commands2 an attribute of its own"},
}

// configurationProbes are typed in the configuration-mode variant after its
// probes: the statement sets the host name the device already has, so
// nothing changes whether it is refused or not.
var configurationProbes = []junosProbe{{cmd: "configure"}, {cmd: "set system host-name " + junosHost},
	{cmd: "run show version"}, {cmd: "run show system uptime"}, {cmd: "exit configuration-mode"}}

func TestL12JunosWire(t *testing.T) {
	eachPlatform(t, func(t *testing.T, l *lab) {
		if l.p.name != "juniper_vjunos-router" && l.p.name != "juniper_vsrx" {
			t.Skip("Junos only")
		}
		stop := l.capture(t, "L12")
		defer stop()
		commit := l.junosConfigureAdmin(t, junosWireClasses)
		defer l.junosConfigureAdmin(t, junosWireDelete)
		defer func() {
			if std, err := l.configPath(); err == nil {
				if err := l.restart(std); err != nil {
					t.Errorf("could not put port49d back on the lab config: %v", err)
				}
			}
		}()
		runs := map[string]junosRun{}
		for _, v := range junosWireVariants {
			probes := junosWireProbes
			// The control types them too, or no configuration-mode cell compares.
			if v.name == "configuration mode" || v.name == "control" {
				probes = append(slices.Clone(probes), configurationProbes...)
			}
			runs[v.name] = l.junosSession(t, v.name, v.attrs, probes)
			if runs[v.name].loginErr != "" && v.name != "deny malformed" {
				t.Errorf("%s: the session did not open, so nothing was measured: %s", v.name, runs[v.name].loginErr)
			}
			// The control is checked before a token more is spent: without it
			// no cell compares.
			if c := runs["control"]; v.name == "control" && (!c.ran("show version") || !c.ran("show interfaces terse") ||
				!c.runs(junosWireProbes[5])) {
				t.Fatalf("the control did not run `show version`, `show interfaces terse` and show the configuration, "+
					"so no cell compares: %+v", c)
			}
		}
		perSession := l.junosPerSession(t)
		locks := l.junosTemplateLogins(t)
		control := runs["control"]
		facts := junosFacts(runs)
		var b strings.Builder
		fmt.Fprintf(&b, "The templates were committed without a uid (%s).\n\n", commitWord(commit))
		fmt.Fprintf(&b, "| variant | reply | why | priv_lvl on the request |\n|---|---|---|---|\n")
		for _, v := range junosWireVariants {
			fmt.Fprintf(&b, "| %s | `%s` | %s | %s |\n", v.name, tableCell(v.attrs), v.why, runs[v.name].privilege)
		}
		fmt.Fprintf(&b, "\n| probe |")
		for _, v := range junosWireVariants {
			fmt.Fprintf(&b, " %s |", v.name)
		}
		fmt.Fprintf(&b, "\n|---|%s\n", strings.Repeat("---|", len(junosWireVariants)))
		for _, p := range append(slices.Clone(junosWireProbes), configurationProbes...) {
			fmt.Fprintf(&b, "| `%s` |", tableCell(p.cmd))
			for _, v := range junosWireVariants {
				r := runs[v.name]
				cell := "—"
				if _, ok := r.outs[p.cmd]; ok || r.loginErr != "" {
					cell = r.cell(p, control)
				}
				fmt.Fprintf(&b, " %s |", cell)
			}
			b.WriteString("\n")
		}
		fmt.Fprintf(&b, "\n### Read off the table\n\n%s%s\n%s\n", facts, perSession, locks)
		for _, v := range junosWireVariants {
			r := runs[v.name]
			fmt.Fprintf(&b, "\n### %s\n\nReply `%s`.", v.name, v.attrs)
			if r.loginErr != "" {
				fmt.Fprintf(&b, " The session did not open: `%s`.\n", r.loginErr)
				continue
			}
			fmt.Fprintf(&b, " `show cli authorization`:\n\n```\n%s\n```\n", r.auth)
			for _, p := range append(slices.Clone(junosWireProbes), configurationProbes...) {
				if out, ok := r.outs[p.cmd]; ok {
					fmt.Fprintf(&b, "\n`%s`:\n\n```\n%s\n```\n", p.cmd, orEmpty([]string{out}, 0))
				}
			}
		}
		// One run, two rows: each note carries the whole table, so either
		// reads on its own; the capture is the run's (L12-*.pcap).
		l.result(t, "L12", "Over TACACS+ on `junos-exec`: whether `user-permissions` is applied over a bitless "+
			"template, replacing or merging, per session, and two bits in one value; whether a wire "+
			"`deny-commands .*` plus one allow alternation yields exactly the permits, and what it does to the "+
			"commands a class with no bits runs; whether deny-commands reaches a statement typed in configuration "+
			"mode, and `run`; whether `deny-commands-regexps` beats `allow-commands-regexps`; whether "+
			"`allow-commands2` is an attribute of its own; whether a template user commits with no uid, and "+
			"whether it can be logged into locally (spec §8, §13 decision 22, §15 L12).", b.String())
		l.result(t, "L9", "Over TACACS+ on `junos-exec`: whether a `deny-commands` regex is matched anywhere in "+
			"the line, as a prefix, or only as anchored; whether explicit `^` and `$` are taken with the pipe tail "+
			"`( *\\|.*)?`; whether it reads a command in the case typed (`SHOW VERSION`, an argument `FXP0`), the "+
			"abbreviation typed (`sh ver`) and the pipe typed (`| no-more`), or as the CLI expands it; what a "+
			"malformed regex does; and whether a value with spaces is taken raw (spec §8, §15 L9). The "+
			"`JunosFacts` lines below are what internal/projection reads.", b.String())
	})
}

// junosFacts reads the facts the generator's JunosFacts, bit_delivery and
// the set's fallbacks take off the table, each with the rule it was read by.
func junosFacts(runs map[string]junosRun) string {
	c := runs["control"]
	var b strings.Builder
	say := func(format string, args ...any) { fmt.Fprintf(&b, "- "+format+"\n", args...) }
	anchored := runs["deny anchored"]
	anchors := !anchored.ran("show version") && !anchored.ran("show version | no-more") &&
		anchored.ran("show system uptime")
	say("explicit anchors with the pipe tail: %v: `^show version( *\\|.*)?$` refused `show version` (%v) and "+
		"`show version | no-more` (%v), and ran `show system uptime` (%v)", anchors, !anchored.ran("show version"),
		!anchored.ran("show version | no-more"), anchored.ran("show system uptime"))
	say("unanchored: `version` refused `show version` (%v); `show ver` refused `show version` (%v)",
		!runs["deny unanchored word"].ran("show version"), !runs["deny prefix"].ran("show version"))
	caseSafe := func(cmd string, deny junosRun) bool { return !c.ran(cmd) || !deny.ran(cmd) }
	caseSensitive := !(caseSafe("SHOW VERSION", anchored) && caseSafe("show interfaces FXP0 terse", runs["deny argument"]))
	say("JunosFacts.CaseSensitive = %v: false only where every other-case spelling was refused by the CLI in "+
		"the control or by the deny", caseSensitive)
	expanded := c.ran("sh ver") && !anchored.ran("sh ver") && c.ran("sh int fxp0 terse") &&
		!runs["deny argument"].ran("sh int fxp0 terse")
	say("JunosFacts.DenyMatchesExpanded = %v: true only where the control ran both abbreviations and each "+
		"deny refused them", expanded)
	m := runs["deny malformed"]
	say("a malformed deny `^(show$`: the session opened %v (%s); `show version` ran %v", m.loginErr == "",
		orErr(m.loginErr), m.ran("show version"))
	n := runs["narrow"]
	exact := n.ran("show version") && n.ran("show interfaces terse") && !n.ran("show system uptime") &&
		!n.ran("clear interfaces statistics fxp0") && !n.ran("ping 127.0.0.1 count 1 rapid") &&
		!n.runs(junosWireProbes[5]) && n.loginErr == ""
	say("narrow shape exact: %v: ran `show version` %v and `show interfaces terse` %v; refused `show system "+
		"uptime` %v, `clear interfaces statistics fxp0` %v, `ping` %v, the configuration %v", exact,
		n.ran("show version"), n.ran("show interfaces terse"), !n.ran("show system uptime"),
		!n.ran("clear interfaces statistics fxp0"), !n.ran("ping 127.0.0.1 count 1 rapid"), !n.runs(junosWireProbes[5]))
	bl := runs["bitless"]
	say("under deny .*, the commands a class with no bits runs: `set cli screen-width 200` bitless %v, narrow %v; "+
		"`file list /var/tmp` bitless %v, narrow %v", bl.ran("set cli screen-width 200"), n.ran("set cli screen-width 200"),
		bl.ran("file list /var/tmp"), n.ran("file list /var/tmp"))
	up := strings.Contains(runs["bitless + user-permissions"].auth, "view") &&
		!strings.Contains(runs["bitless"].auth, "view")
	two := runs["bitless + two bits"].auth
	say("user-permissions over a bitless template applied: %v; both bits of a two-bit value applied: %v "+
		"(bit_delivery: user_permissions only if both are true, and per session below)", up,
		strings.Contains(two, "view") && strings.Contains(two, "clear"))
	say("user-permissions over remote: `show cli authorization` lists view-configuration: %v (true: merged or "+
		"ignored; false: replaced)", strings.Contains(runs["remote + user-permissions"].auth, "view-configuration"))
	cfg := runs["configuration mode"]
	say("a statement typed in configuration mode under a deny-commands naming it: %s; `run show version` "+
		"under a deny naming `show version`: %s", cfg.cell(configurationProbes[1], c), cfg.cell(configurationProbes[2], c))
	say("-regexps: `show version` refused with both deny and allow naming it: %v", !runs["regexps family"].ran("show version"))
	say("allow-commands2 an attribute of its own: `show system uptime` ran: %v", runs["numbered name"].ran("show system uptime"))
	return b.String()
}

// tableCell escapes the pipes in a table cell: `show version | no-more` and a
// reply's alternation would otherwise split the row, and every cell after
// them would read under the wrong variant.
func tableCell(s string) string { return strings.ReplaceAll(s, "|", `\|`) }

func orErr(s string) string {
	if s == "" {
		return "no error"
	}
	return s
}

// junosPerSession asks whether user-permissions is per session: session A
// opens under `view`, port49d restarts under `clear`, session B opens, and A
// is asked again. It spends two tokens. Anything not observed fails the test.
func (l *lab) junosPerSession(t *testing.T) string {
	t.Helper()
	cfgA, err := l.derivedConfigCmd("junos-per-a", `["local-user-name=p49-l12-none", "user-permissions=view"]`, "", "")
	if err == nil {
		err = l.restart(cfgA)
	}
	if err != nil {
		t.Fatal(err)
	}
	user, secret := l.nextLogin(t)
	a, err := l.sshCLI(user, secret)
	if err == nil {
		_, err = a.expect(90*time.Second, junosOpPrompt)
	}
	if err != nil {
		t.Errorf("per session: session A did not open: %v", err)
		return "- per session: not observed (session A did not open)\n"
	}
	defer a.Close()
	before, errA := a.sendExpect("show cli authorization", junosPer, junosOpPrompt)
	cfgB, err := l.derivedConfigCmd("junos-per-b", `["local-user-name=p49-l12-none", "user-permissions=clear"]`, "", "")
	if err == nil {
		err = l.restart(cfgB)
	}
	if err != nil {
		t.Fatal(err)
	}
	userB, secretB := l.nextLogin(t)
	bConn, err := l.sshCLI(userB, secretB)
	var bAuth string
	if err == nil {
		if _, err = bConn.expect(90*time.Second, junosOpPrompt); err == nil {
			bAuth, err = bConn.sendExpect("show cli authorization", junosPer, junosOpPrompt)
		}
		bConn.Close()
	}
	after, errA2 := a.sendExpect("show cli authorization", junosPer, junosOpPrompt)
	if errA != nil || errA2 != nil || err != nil {
		t.Errorf("per session: not observed (%v %v %v)", errA, errA2, err)
		return "- per session: not observed\n"
	}
	return fmt.Sprintf("- per session: A before `%s`, B `%s`, A after B `%s`\n", oneLine(before), oneLine(bAuth),
		oneLine(after))
}

// junosTemplateLogins asks whether a template user can be logged into on
// its own, with port49d stopped so the device takes the local password (L4):
// the reference configuration's templates carry no authentication, and one
// with class `all` that took an empty password would be a way in for anyone.
// Then whether `authentication encrypted-password "*"` commits, and whether it
// locks the account. Each dial has a 30 s deadline; a dial that neither
// failed nor opened is not observed and fails the test.
func (l *lab) junosTemplateLogins(t *testing.T) string {
	t.Helper()
	if err := l.stopDaemon(); err != nil {
		t.Fatalf("could not stop port49d for the local logins: %v", err)
	}
	defer func() {
		if std, err := l.configPath(); err == nil {
			if err := l.restart(std); err != nil {
				t.Errorf("could not put port49d back on the lab config: %v", err)
			}
		}
	}()
	var b strings.Builder
	dial := func(user, password string) string {
		c, err := l.dial(user, password, 30*time.Second)
		if err == nil {
			c.Close()
			return "**logged in**"
		}
		if !isAuthRejection(err) {
			t.Errorf("a local login as %s was not observed: %v", user, err)
			return "not observed: " + oneLine(err.Error())
		}
		return "refused"
	}
	fmt.Fprintf(&b, "- a template user with no authentication, locally: empty password %s, `x` %s\n",
		dial("p49-l12-none", ""), dial("p49-l12-none", "x"))
	lock := []string{"set system login user p49-l12-lock class p49-l12-none",
		`set system login user p49-l12-lock authentication encrypted-password "*"`}
	c, err := l.junosCLI(breakglassUser, breakglassPassword)
	if err != nil {
		t.Fatalf("no admin CLI for the lock measurement: %v", err)
	}
	out, cerr := junosConfigure(c, lock...)
	c.Close()
	fmt.Fprintf(&b, "- `authentication encrypted-password \"*\"` commits: %v (%s)\n", cerr == nil, commitWord(out))
	if cerr == nil {
		fmt.Fprintf(&b, "- that template, locally: empty password %s, `*` %s\n", dial("p49-l12-lock", ""),
			dial("p49-l12-lock", "*"))
		if c, err := l.junosCLI(breakglassUser, breakglassPassword); err == nil {
			if _, err := junosConfigure(c, "delete system login user p49-l12-lock"); err != nil {
				t.Errorf("removing p49-l12-lock: %v", err)
			}
			c.Close()
		}
	}
	return b.String()
}

func commitWord(out string) string {
	if strings.Contains(out, "commit complete") {
		return "commit complete"
	}
	return "the commit output did not say complete: " + oneLine(out)
}
