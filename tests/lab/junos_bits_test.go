//go:build lab

package lab

import (
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// junosBitReach is each permission bit's reach in rule form, the candidate
// this test verifies as an upper bound and platforms/1.1.0/juniper_junos.yaml
// ships under `bits:` (spec §8, §15 L12). `baseline` is what a class with no
// bits runs, held by every session. A bit that reaches a command no rule here
// holds fails the test: widen the rule, here and in the adapter. Reach is a
// union, so a wider reach only makes the projection send the bit for fewer
// grants.
//
// Every rule past the plan's candidate was added from the first runs on
// vJunos-router 23.4R2-S2.1 and vSRX 21.4R3.15, the union of the two
// (tests/lab/results/L12-bits-juniper_*.md). A top-level word the survey lists
// is held whole (`request **`, `set **`), never per word under it: `?` does not
// list Junos's hidden commands, so a per-word reach could under-report what the
// device runs (the lead's ruling, 2026-09-25).
var junosBitReach = map[string][]string{
	"baseline": {"help **", "quit **", "exit **", "set cli **", "show cli **",
		"file **", "load **", "op **", "request **", "save **", "scp **", "set **", "start **", "test **"},
	"view": {"show **", "request flight-recorder **", "request pppoe **", "request snmp **",
		"request validation **", "test interface **", "test msdp **", "test policy **", "test rib-sharding **",
		"test services **"},
	"view-configuration": {"show configuration **", "monitor **", "request mpls **",
		"request path-computation-client **", "request security **", "request unified-edge **",
		"request virtual-chassis **", "load dhcp-security-snoop **", "save dhcp-security-snoop **"},
	"clear":   {"clear **", "request mpls **", "set chassis **"},
	"network": {"ping **", "traceroute **", "ssh **", "telnet **", "mtrace **", "probe **", "request routing-engine **"},
	"trace":   {"monitor **"},
}

// junosCarveOuts are the commands a bit alone makes available, whatever other
// bit reaches them: the adapter's `carve_outs:`. The one candidate is the one
// the projection's realistic readonly rests on, and this test asserts it:
// under `view` alone the configuration is not shown.
var junosCarveOuts = map[string][]string{"view-configuration": {"show configuration **"}}

// junosHostProbe shows the configuration only where it prints the host name.
var junosHostProbe = junosProbe{cmd: "show configuration system host-name", evidence: "host-name " + junosHost}

// junosCarveProbes show the configuration of three hierarchies, each only
// where it prints what the lab's configuration holds there (pre-flight R-M5:
// the carve-out on more than one hierarchy). `mgmt_junos` is the routing
// instance both images' /init.conf define (tests/lab/configs/vjunos-startup.conf).
var junosCarveProbes = []junosProbe{junosHostProbe,
	{cmd: "show configuration routing-instances", evidence: "mgmt_junos"},
	{cmd: "show configuration interfaces", evidence: "fxp0"},
}

// junosBaselineProbes are the candidate baseline's commands that can be typed
// and leave the session open (pre-flight R-M1); `quit` and `exit` are typed
// last, by junosCloser.
var junosBaselineProbes = []junosProbe{{cmd: "help tip cli"}, {cmd: "show cli"},
	{cmd: "set cli screen-width 200"}, {cmd: "file list /var/tmp"}}

// junosBitProbes are typed under each single-bit template after the survey,
// read against the `all` control.
var junosBitProbes = append(append([]junosProbe{
	{cmd: "show version"}, {cmd: "show system uptime"},
	{cmd: "clear interfaces statistics fxp0"}, {cmd: "ping 127.0.0.1 count 1 rapid"},
	{cmd: "traceroute 127.0.0.1 ttl 1 wait 1"},
	{cmd: "monitor interface", complete: true}, {cmd: "request system reboot", complete: true},
	{cmd: "restart routing", complete: true}}, junosCarveProbes...), append(slices.Clone(junosBaselineProbes),
	junosProbe{cmd: "configure"}, junosProbe{cmd: "exit configuration-mode"})...)

// junosPairClass is the carve-out's isolating control: `view` and
// `view-configuration`, so a configuration `view` alone does not show and
// this class does is withheld by view-configuration and nothing else.
const junosPairClass = "view+view-configuration"

// junosBitsClass is the login class, and template user, of a column.
func junosBitsClass(b string) string { return "p49-l12-b-" + strings.ReplaceAll(b, "+", "-") }

// junosCloser types word, a command that ends the session where the class
// runs it, and reports what the device did: `closed the session` where no
// prompt came back within junosPer and the channel then refused a write, the
// refusal where a prompt came back. Anything else is not observed.
func junosCloser(c *cliConn, word string) (string, error) {
	if err := junosSettle(c); err != nil {
		return "", fmt.Errorf("%q: %w", word, err)
	}
	out, err := c.sendExpect(word, junosPer, junosOpPrompt)
	if err == nil {
		return "prompt back: " + oneLine(precReply(l16TrimEcho(out, word))), nil
	}
	if _, werr := fmt.Fprint(c.in, "\n"); werr != nil {
		return "closed the session", nil
	}
	return "", fmt.Errorf("%q: neither a prompt nor a closed channel within %s: %w", word, junosPer, err)
}

// junosSettle waits, within junosPer, until the device has said nothing for a
// second. A completion probe's ^U makes the device redraw its prompt after the
// probe has returned; a command typed before that redraw lands would read the
// stale prompt as its own answer, as the first run's `exit` did (the session
// "none, exit" read `prompt back` with no output at all).
func junosSettle(c *cliConn) error {
	deadline := time.Now().Add(junosPer)
	last, since := len(c.out.String()), time.Now()
	for time.Now().Before(deadline) {
		time.Sleep(250 * time.Millisecond)
		if n := len(c.out.String()); n != last {
			last, since = n, time.Now()
		} else if time.Since(since) >= time.Second {
			return nil
		}
	}
	return fmt.Errorf("the device did not fall quiet within %s", junosPer)
}

// completionWord is a word a `?` listing offers, one per line, the
// description after it dropped.
var completionWord = regexp.MustCompile(`(?m)^  ?([a-z][a-z0-9-]*)\s`)

func completionWords(out string) []string {
	var words []string
	for _, m := range completionWord.FindAllStringSubmatch(out, -1) {
		if !slices.Contains(words, m[1]) {
			words = append(words, m[1])
		}
	}
	return words
}

// junosSurvey is one class's reach as its completion offers it: every word
// at the top level, and every word one level under each (`show ?`,
// `request ?`), keyed "word" and "word sub". Each listing has junosPer; a
// listing not observed fails the test and ends the survey.
func (l *lab) junosSurvey(t *testing.T, name string, c *cliConn, r *junosRun) []string {
	t.Helper()
	top, err := l.junosProbe(c, junosProbe{cmd: "?", complete: true})
	if err != nil {
		t.Errorf("%s: the top-level listing not observed within %s: %v", name, junosPer, err)
		r.unobserved = append(r.unobserved, "?")
		return nil
	}
	var reach []string
	for _, w := range completionWords(top) {
		reach = append(reach, w)
		out, err := l.junosProbe(c, junosProbe{cmd: w + " ?", complete: true})
		if err != nil {
			t.Errorf("%s: `%s ?` not observed within %s: %v", name, w, junosPer, err)
			r.unobserved = append(r.unobserved, w+" ?")
			return reach
		}
		for _, x := range completionWords(out) {
			reach = append(reach, w+" "+x)
		}
	}
	return reach
}

func TestL12JunosBits(t *testing.T) {
	eachPlatform(t, func(t *testing.T, l *lab) {
		if l.p.name != "juniper_vjunos-router" && l.p.name != "juniper_vsrx" {
			t.Skip("Junos only")
		}
		stop := l.capture(t, "L12-bits")
		defer stop()
		var bits []string
		for b := range junosBitReach {
			if b != "baseline" {
				bits = append(bits, b)
			}
		}
		slices.Sort(bits)
		classes := append(append([]string{"none", "all"}, bits...), junosPairClass)
		var define, remove []string
		for _, b := range classes {
			class := junosBitsClass(b)
			switch {
			case b == "none":
				define = append(define, "set system login class "+class+" idle-timeout 60")
			case b == junosPairClass:
				define = append(define, "set system login class "+class+" permissions [ "+
					strings.ReplaceAll(b, "+", " ")+" ]")
			default:
				define = append(define, "set system login class "+class+" permissions "+b)
			}
			define = append(define, "set system login user "+class+" class "+class)
			remove = append(remove, "delete system login user "+class, "delete system login class "+class)
		}
		l.junosConfigureAdmin(t, define)
		defer l.junosConfigureAdmin(t, remove)
		defer func() {
			if std, err := l.configPath(); err == nil {
				if err := l.restart(std); err != nil {
					t.Errorf("could not put port49d back on the lab config: %v", err)
				}
			}
		}()
		runs, reach := map[string]junosRun{}, map[string][]string{}
		// closers[session][word] is what `quit` or `exit` did (pre-flight R-M1).
		closers := map[string]map[string]string{}
		closeWith := func(name string, c *cliConn, r *junosRun, words ...string) {
			closers[name] = map[string]string{}
			for _, w := range words {
				said, err := junosCloser(c, w)
				if err != nil {
					r.unobserved = append(r.unobserved, w)
					t.Errorf("%s: %v", name, err)
					return
				}
				closers[name][w] = said
				if said == "closed the session" {
					return
				}
			}
		}
		session := func(name, attrs string, probes []junosProbe, closing ...string) {
			c, r, _ := l.junosLogin(t, "bit "+name, attrs)
			if c == nil {
				t.Errorf("bit %s: the session did not open: %s", name, r.loginErr)
				runs[name] = r
				return
			}
			defer c.Close()
			reach[name] = l.junosSurvey(t, name, c, &r)
			if err := junosSettle(c); err != nil {
				t.Errorf("bit %s: after the survey: %v", name, err)
				runs[name] = r
				return
			}
			for _, p := range probes {
				out, err := l.junosProbe(c, p)
				r.outs[p.cmd] = out
				if err != nil {
					r.unobserved = append(r.unobserved, p.cmd)
					t.Errorf("bit %s: %q not observed within %s: %v", name, p.cmd, junosPer, err)
					runs[name] = r
					return
				}
			}
			closeWith(name, c, &r, closing...)
			runs[name] = r
		}
		for _, b := range classes {
			if b == "none" {
				session(b, `["local-user-name=`+junosBitsClass(b)+`"]`, junosBitProbes, "quit")
				continue
			}
			session(b, `["local-user-name=`+junosBitsClass(b)+`"]`, junosBitProbes)
		}
		all := runs["all"]
		if !all.runs(junosHostProbe) || !all.ran("show version") {
			t.Fatalf("the `all` control neither showed the configuration nor ran `show version`, so nothing "+
				"compares: %+v", all)
		}
		// Pre-flight R-M1: every candidate baseline command, typed under the
		// class with no bits and under that class with the fail-closed reply's
		// `deny-commands=^.*$`. `exit` under none needs a session of its own,
		// since `quit` ended the first; under the deny both are typed, and
		// `exit` gets its own session if `quit` ended the session there.
		const noneDeny = "none + deny .*"
		denyAttrs := `["local-user-name=` + junosBitsClass("none") + `", "deny-commands=^.*$"]`
		session("none, exit", `["local-user-name=`+junosBitsClass("none")+`"]`, nil, "exit")
		session(noneDeny, denyAttrs, junosBaselineProbes, "quit", "exit")
		if closers[noneDeny]["quit"] == "closed the session" {
			session(noneDeny+", exit", denyAttrs, nil, "exit")
		}
		var b strings.Builder
		fmt.Fprintf(&b, "Each row is a session whose template's class holds one bit and nothing else; `none` "+
			"holds none and `all` every bit. A command word, or a word and the word under it, is the bit's where "+
			"its completion offers it and `none`'s does not; `none`'s own are the baseline.\n\n"+
			"| bit | words beyond none | candidate reach | held |\n|---|---|---|---|\n")
		check := func(bit string, words []string) {
			var unheld []string
			for _, w := range words {
				if !heldBy(junosBitReach[bit], w+" **") {
					unheld = append(unheld, w+" **")
				}
			}
			fmt.Fprintf(&b, "| %s | %s | `%s` | %s |\n", bit, strings.Join(words, ", "),
				strings.Join(junosBitReach[bit], "`, `"), heldCell(unheld))
			if len(unheld) > 0 {
				t.Errorf("%s reaches %v, which its candidate reach does not hold: add each to junosBitReach[%q] "+
					"and to platforms/1.1.0/juniper_junos.yaml's bits.%s", bit, unheld, bit, bit)
			}
		}
		check("baseline", reach["none"])
		for _, bit := range bits {
			check(bit, beyond(reach[bit], reach["none"]))
		}
		fmt.Fprintf(&b, "\nA top-level word is held whole (`request **`, `set **`), not word by word under it: "+
			"`?` does not list Junos's hidden commands, so a per-word reach could under-report what the device "+
			"runs. A per-word reach is a possible later refinement, and needs proof, not measured here, that no "+
			"hidden command sits under each word.\n")
		// The carve-out the projection reads: under `view` alone the
		// configuration is not shown, observed, against a control that shows it,
		// on every hierarchy the `all` control shows, and at least two of them
		// (pre-flight R-M5). The cell is isolated only where `view` and
		// `view-configuration` together show it, so view-configuration is the
		// one bit that withholds it.
		view, pair := runs["view"], runs[junosPairClass]
		fmt.Fprintf(&b, "\n| hierarchy probe | `all` shows it | `view` alone: observed | `view` alone shows it | "+
			"`view-configuration` alone shows it | `view view-configuration` shows it | isolated |\n"+
			"|---|---|---|---|---|---|---|\n")
		hierarchies := 0
		for _, p := range junosCarveProbes {
			shown := view.runs(p)
			_, typed := view.outs[p.cmd]
			observed := typed && !slices.Contains(view.unobserved, p.cmd)
			isolated := "no: the `all` control did not show it, so the row says nothing"
			if all.runs(p) {
				hierarchies++
				isolated = "yes"
				if !pair.runs(p) {
					isolated = "**not isolated**: `view view-configuration` did not show it either, so a bit " +
						"beyond view-configuration withholds it"
				}
				if !observed || shown {
					t.Errorf("the carve-out is not measured on `%s`: under view alone the probe was observed %v and "+
						"showed the configuration %v; remove it from junosCarveOuts and from the adapter's carve_outs, "+
						"and add \"show configuration **\" to view's reach", p.cmd, observed, shown)
				}
			}
			fmt.Fprintf(&b, "| `%s` | %v | %v | %v | %v | %v | %s |\n", p.cmd, all.runs(p), observed, shown,
				runs["view-configuration"].runs(p), pair.runs(p), isolated)
		}
		fmt.Fprintf(&b, "\nThe adapter's carve-out `view-configuration: [show configuration **]` holds only if `view` "+
			"alone shows none of them; it was measured on %d hierarchies the `all` control shows.\n", hierarchies)
		if hierarchies < 2 {
			t.Errorf("the carve-out was measured on %d hierarchies; pre-flight R-M5 needs two the `all` control shows",
				hierarchies)
		}
		fmt.Fprintf(&b, "\n| probe |")
		for _, c := range classes {
			fmt.Fprintf(&b, " %s |", c)
		}
		fmt.Fprintf(&b, "\n|---|%s\n", strings.Repeat("---|", len(classes)))
		for _, p := range junosBitProbes {
			fmt.Fprintf(&b, "| `%s` |", tableCell(p.cmd))
			for _, c := range classes {
				fmt.Fprintf(&b, " %s |", runs[c].cell(p, all))
			}
			b.WriteString("\n")
		}
		// Pre-flight R-M2: a bit other than `all` that enters configuration
		// mode, or a baseline that does, is a finding Task 14 fails closed on.
		var enters []string
		for _, c := range classes {
			if c != "all" && runs[c].cell(junosProbe{cmd: "configure"}, all) == "ran" {
				enters = append(enters, c)
			}
		}
		if len(enters) == 0 {
			enters = []string{"none"}
		}
		fmt.Fprintf(&b, "\nClasses other than `all` that entered configuration mode (`configure` ran): %s.\n",
			strings.Join(enters, ", "))
		// Pre-flight R-M1: the baseline's commands under no bits, and under the
		// fail-closed reply's deny. Each that runs under none must be refused
		// under the deny, and `quit` and `exit` must leave the session open.
		fmt.Fprintf(&b, "\n| baseline command | none | %s |\n|---|---|---|\n", noneDeny)
		deny := runs[noneDeny]
		for _, p := range junosBaselineProbes {
			fmt.Fprintf(&b, "| `%s` | %s | %s |\n", p.cmd, runs["none"].cell(p, all), deny.cell(p, runs["none"]))
			if runs["none"].runs(p) && deny.cell(p, runs["none"]) != "refused" {
				t.Errorf("baseline: `%s` ran under none and was not refused under `deny-commands=^.*$` (%s): "+
					"Task 14 branch A", p.cmd, deny.cell(p, runs["none"]))
			}
		}
		for _, w := range []string{"quit", "exit"} {
			under := closers["none"][w]
			if w == "exit" {
				under = closers["none, exit"][w]
			}
			denied, ok := closers[noneDeny][w]
			if !ok {
				denied = closers[noneDeny+", exit"][w]
			}
			fmt.Fprintf(&b, "| `%s` | %s | %s |\n", w, tableCell(orNotTyped(under)), tableCell(orNotTyped(denied)))
			if denied == "" || denied == "closed the session" {
				t.Errorf("baseline: `%s` under `deny-commands=^.*$`: %q, not a prompt back: Task 14 branch A", w, denied)
			}
		}
		fmt.Fprintf(&b, "\nThe reach as measured, ready for `bits:` and `carve_outs:`:\n\n```yaml\n    bits:\n")
		for _, bit := range sortedKeysOf(junosBitReach) {
			fmt.Fprintf(&b, "      %s: [%s]\n", bit, quotedList(junosBitReach[bit]))
		}
		b.WriteString("      all: [\"**\"]\n    carve_outs:\n")
		for _, bit := range sortedKeysOf(junosCarveOuts) {
			fmt.Fprintf(&b, "      %s: [%s]\n", bit, quotedList(junosCarveOuts[bit]))
		}
		b.WriteString("```\n")
		for _, c := range append(slices.Clone(classes), "none, exit", noneDeny, noneDeny+", exit") {
			r, ok := runs[c]
			if !ok {
				continue
			}
			fmt.Fprintf(&b, "\n### %s\n\nReply `%s`.", c, r.attrs)
			if r.loginErr != "" {
				fmt.Fprintf(&b, " The session did not open: `%s`.\n", r.loginErr)
				continue
			}
			fmt.Fprintf(&b, " `show cli authorization`:\n\n```\n%s\n```\n\nCompletion: %s\n", r.auth,
				strings.Join(reach[c], ", "))
			for _, p := range junosBitProbes {
				if out, ok := r.outs[p.cmd]; ok {
					fmt.Fprintf(&b, "\n`%s`:\n\n```\n%s\n```\n", p.cmd, orEmpty([]string{out}, 0))
				}
			}
			for _, w := range []string{"quit", "exit"} {
				if said, ok := closers[c][w]; ok {
					fmt.Fprintf(&b, "\n`%s`: %s\n", w, said)
				}
			}
		}
		l.result(t, "L12-bits", "What each permission bit a built-in level's ceiling names reaches, alone in a "+
			"template's class, over TACACS+ `local-user-name`: every command word, and every word one level under "+
			"it, its completion offers that a class with no bits does not, held by the adapter's `bits:` reach as "+
			"an upper bound; what a class with no bits runs (`baseline`); and that `view` alone does not show the "+
			"configuration, the one carve-out the adapter declares (spec §8, §15 L12).", b.String())
	})
}

func orNotTyped(s string) string {
	if s == "" {
		return "not typed"
	}
	return s
}

func sortedKeysOf(m map[string][]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

func beyond(words, base []string) []string {
	var out []string
	for _, w := range words {
		if !slices.Contains(base, w) {
			out = append(out, w)
		}
	}
	return out
}

// heldBy reports whether some reach rule holds rule, both words then `**`:
// the reach rule's words are a prefix of the rule's.
func heldBy(reach []string, rule string) bool {
	want := strings.Fields(rule)
	return slices.ContainsFunc(reach, func(r string) bool {
		f := strings.Fields(r)
		if len(f) == 0 || f[len(f)-1] != "**" || len(f)-1 > len(want)-1 {
			return false
		}
		return slices.Equal(f[:len(f)-1], want[:len(f)-1])
	})
}

func heldCell(unheld []string) string {
	if len(unheld) == 0 {
		return "yes"
	}
	return "**no**: " + strings.Join(unheld, ", ")
}

func quotedList(rules []string) string {
	q := make([]string, len(rules))
	for i, r := range rules {
		q[i] = fmt.Sprintf("%q", r)
	}
	return strings.Join(q, ", ")
}

// TestL24JunosIdleTimeout measures decision 21's approximation: a login
// class's idle-timeout ends an idle session a TACACS+ reply landed in that
// class, through `local-user-name` and through the `remote` template. The
// clock starts at the prompt; a session closed in under 50 s did not idle out
// (idle-timeout is 1 minute) and fails, and one still open after four minutes
// is not observed, and fails.
func TestL24JunosIdleTimeout(t *testing.T) {
	eachPlatform(t, func(t *testing.T, l *lab) {
		if l.p.name != "juniper_vjunos-router" && l.p.name != "juniper_vsrx" {
			t.Skip("Junos only")
		}
		stop := l.capture(t, "L24")
		defer stop()
		l.junosConfigureAdmin(t, []string{"set system login class p49-l24-idle permissions view",
			"set system login class p49-l24-idle idle-timeout 1",
			"set system login user p49-l24-idle class p49-l24-idle",
			"set system login class p49-readonly idle-timeout 1"})
		defer l.junosConfigureAdmin(t, []string{"delete system login user p49-l24-idle",
			"delete system login class p49-l24-idle", "delete system login class p49-readonly idle-timeout"})
		defer func() {
			if std, err := l.configPath(); err == nil {
				if err := l.restart(std); err != nil {
					t.Errorf("could not put port49d back on the lab config: %v", err)
				}
			}
		}()
		var b strings.Builder
		fmt.Fprintf(&b, "| path | reply | closed after the prompt | what the device said |\n|---|---|---|---|\n")
		for _, v := range []struct{ name, attrs string }{
			{"local-user-name", `["local-user-name=p49-l24-idle"]`},
			{"remote template", `[]`},
		} {
			cfg, err := l.derivedConfigCmd("l24-"+l16Slug(v.name), v.attrs, "", "")
			if err == nil {
				err = l.restart(cfg)
			}
			if err != nil {
				t.Fatal(err)
			}
			user, secret := l.nextLogin(t)
			elapsed, said, err := l.holdUntilClosed(user, secret, 4*time.Minute)
			cell := elapsed.Round(time.Second).String()
			switch {
			case err != nil:
				cell = "not observed: " + oneLine(err.Error())
				t.Errorf("%s: %v", v.name, err)
			case elapsed < 50*time.Second:
				t.Errorf("%s: closed %s after the prompt, before a 1-minute idle-timeout could: not the timer", v.name,
					elapsed)
			}
			fmt.Fprintf(&b, "| %s | `%s` | %s | `%s` |\n", v.name, v.attrs, cell, oneLine(said))
		}
		l.result(t, "L24", "A login class's `idle-timeout` ends an idle session a TACACS+ reply landed in "+
			"that class, through `local-user-name` and through the `remote` template (spec §5.6; §13 decision 21).",
			b.String())
	})
}

// holdUntilClosed opens an interactive session, waits for its prompt (90 s),
// and types nothing until the device closes it, within the deadline. An error
// is a session that did not reach a prompt, or one still open at the
// deadline: not observed.
func (l *lab) holdUntilClosed(user, password string, within time.Duration) (time.Duration, string, error) {
	c, err := l.dial(user, password, 45*time.Second)
	if err != nil {
		return 0, "", err
	}
	defer c.Close()
	s, err := c.NewSession()
	if err != nil {
		return 0, "", err
	}
	defer s.Close()
	if err := s.RequestPty("vt100", 40, 120, ssh.TerminalModes{ssh.ECHO: 0}); err != nil {
		return 0, "", err
	}
	var buf syncBuf
	s.Stdout, s.Stderr = &buf, &buf
	stdin, err := s.StdinPipe()
	if err != nil {
		return 0, "", err
	}
	defer stdin.Close()
	if err := s.Shell(); err != nil {
		return 0, "", err
	}
	done := make(chan error, 1)
	go func() { done <- s.Wait() }()
	prompt := time.Now().Add(90 * time.Second)
	for !strings.Contains(buf.String(), junosOpPrompt) {
		select {
		case <-done:
			return 0, tail(buf.String()), fmt.Errorf("closed before a prompt")
		case <-time.After(250 * time.Millisecond):
		}
		if time.Now().After(prompt) {
			return 0, tail(buf.String()), fmt.Errorf("no prompt within 90s")
		}
	}
	start := time.Now()
	select {
	case <-done:
		return time.Since(start), tail(buf.String()), nil
	case <-time.After(within):
		io.WriteString(stdin, "exit\n")
		return 0, tail(buf.String()), fmt.Errorf("still open after %s", within)
	}
}

func tail(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > 3 {
		lines = lines[len(lines)-3:]
	}
	return strings.Join(lines, " / ")
}
