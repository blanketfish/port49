//go:build lab

package lab

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	adapter "github.com/rhwendt/port49/internal/platform"
)

// TestL68ViewConfigurationCLI, TestL68ViewConfigurationNetconf and
// TestL68ViewConfigurationNetconfOperator measure spec §15 L68 (plan 9g Task
// 1, gates G1 and G1-operator). The question: does a reply sending
// view-configuration, with deny-commands covering the grant's deny and the
// rest of view-configuration's reach, let the session read the configuration
// and nothing the denies leave open? Each row is user-permissions over the
// reference configuration's bitless p49-remote, the shape production sends:
//   - P: set 1.2.0's render of a readonly granted `show **` less `show
//     security **` and `monitor **` (l68Projected), which set 1.3.0 sends
//     without the `monitor **` deny;
//   - H: the same bits, and a deny of exactly `show security`,
//     view-configuration's other reach, and the entry denies (l68Hand);
//   - O: `clear view view-configuration` and P's deny, the operator reply;
//   - V: `view` alone under P's deny: what the bit adds;
//   - Vc: `view` alone and no deny: the completion baseline;
//   - C: `view view-configuration` and no deny: the control.
// A refused probe that runs in P or H is a STOP: no reply change ships (plan
// 9g ruling R1). One that runs in O stops the operator reply alone
// (G1-operator).

// l68Projected is set 1.2.0's deny-commands for a readonly granted `show **`
// less `show security **` and `monitor **`, and for an operator also granted
// `clear **`: 173 bytes (TestL68ProjectedIsSet120sRender pins both).
const l68Projected = `deny-commands=^( *show +security( .*)? *(\|.*)?| *(monitor|help|quit|exit|file|load|op|request|save|scp|set|start|test|junoscript)( .*)? *(\|.*)?| *set +cli( .*)? *(\|.*)?)$`

// l68Hand denies `show security`, view-configuration's other reach (set
// 1.2.0's `bits:`) and the entry denies, nothing else: 235 bytes. The
// `request` words share one group after `request`, the L26b shape
// (l26bDeny); written one rule to an alternative it is 373 bytes, past RFC
// 8907.
const l68Hand = `deny-commands=^( *show +security( .*)? *(\|.*)?| *(monitor|junoscript|op)( .*)? *(\|.*)?| *request +(mpls|path-computation-client|security|unified-edge|virtual-chassis)( .*)? *(\|.*)?| *(load|save) +dhcp-security-snoop( .*)? *(\|.*)?)$`

func l68Attrs(bits, deny string) string {
	out := `["user-permissions=` + bits + `"`
	if deny != "" {
		out += `, "` + jsonEscape(deny) + `"`
	}
	return out + "]"
}

var junosL68Variants = []junosVariant{
	{"P", l68Attrs("view view-configuration", l68Projected),
		"set 1.2.0's render of a readonly granted show ** less show security ** and monitor **: set 1.3.0's reply"},
	{"H", l68Attrs("view view-configuration", l68Hand),
		"show security, view-configuration's other reach and the entry denies, nothing else"},
	{"O", l68Attrs("clear view view-configuration", l68Projected),
		"the operator granted show ** and clear ** less the same: set 1.3.0's operator reply"},
	{"V", l68Attrs("view", l68Projected), "view alone under P's deny: what the bit adds"},
	{"Vc", l68Attrs("view", ""), "view alone, no deny: the completion baseline"},
	{"C", l68Attrs("view view-configuration", ""), "the control"},
}

func l68Variant(name string) junosVariant {
	i := slices.IndexFunc(junosL68Variants, func(v junosVariant) bool { return v.name == name })
	return junosL68Variants[i]
}

// l68DenyRows are the rows whose deny is gated: P and H under G1, O under
// G1-operator.
var l68DenyRows = []string{"P", "H", "O"}

// l68Bits is what `show cli authorization` must list for each row: the reply
// landed as sent, and no configuration group adds a bit to p49-remote (L57).
var l68Bits = map[string][]string{
	"P": {"view", "view-configuration"}, "H": {"view", "view-configuration"},
	"O": {"clear", "view", "view-configuration"}, "V": {"view"}, "Vc": {"view"},
	"C": {"view", "view-configuration"},
}

// l68ConfigMode is what the CLI prints entering configuration mode.
const l68ConfigMode = "Entering configuration mode"

// l68Probe is one command a row types. prefix is how many of its leading
// typed words name the reach (or the grant's deny) it probes: the cell reads
// whether the CLI refused it there. A `p49-none` after the prefix is never a
// command: the control's CLI takes the prefix and stops at it, so nothing
// runs, and a deny refuses at the prefix (L58's reading of `save`). evidence
// is what a run prints. canonical: the control must take it, or the run is
// INVALID. reading: recorded, gated by nothing. entry: it enters
// configuration mode, which no row may. exec: typed over the SSH exec
// channel, not the CLI.
type l68Probe struct {
	cmd       string
	prefix    int
	evidence  string
	canonical bool
	reading   bool
	entry     bool
	exec      bool
}

// key is the probe's cell key: an exec probe's is prefixed, since the same
// command is typed at the CLI too.
func (p l68Probe) key() string {
	if p.exec {
		return "exec: " + p.cmd
	}
	return p.cmd
}

var l68Probes = []l68Probe{
	// What the bit is sent for: it runs in P, H, O and C, and not in V.
	{cmd: "show configuration system host-name", evidence: hostEvidence, canonical: true},
	{cmd: "sh conf sys host-name", evidence: hostEvidence},
	{cmd: "show configuration system host-name | display set", evidence: hostEvidence},
	// The grant's deny.
	{cmd: "show security p49-none", prefix: 2, canonical: true},
	{cmd: "sh sec p49-none", prefix: 2},
	// view-configuration's other reach, in full (as a hidden command must be
	// typed: it does not abbreviate, L26c-junoscript), abbreviated, spaced and
	// piped (L9's forms). Case is the CLI's own refusal (L9), recorded.
	{cmd: "monitor p49-none", prefix: 1, canonical: true},
	{cmd: "mon p49-none", prefix: 1},
	{cmd: "monitor list", prefix: 1},
	{cmd: "monitor list | no-more", prefix: 1},
	{cmd: "   monitor   list", prefix: 1},
	{cmd: "MONITOR LIST", prefix: 1, reading: true},
	{cmd: "request mpls p49-none", prefix: 2, canonical: true},
	{cmd: "req mpls p49-none", prefix: 2},
	{cmd: "request mp p49-none", prefix: 2},
	{cmd: "request path-computation-client p49-none", prefix: 2},
	{cmd: "req path-computation-client p49-none", prefix: 2},
	{cmd: "request security p49-none", prefix: 2, canonical: true},
	{cmd: "req sec p49-none", prefix: 2},
	{cmd: "request unified-edge p49-none", prefix: 2},
	{cmd: "request virtual-chassis p49-none", prefix: 2},
	{cmd: "req vir p49-none", prefix: 2},
	{cmd: "load dhcp-security-snoop /var/tmp/p49-l68-none", prefix: 2},
	{cmd: "save dhcp-security-snoop | count", prefix: 2},
	// The entry denies: `op url` runs the staged script in the control.
	{cmd: opURLCmd, prefix: 1, evidence: opURLEvidence, canonical: true},
	{cmd: opAbbrevCmd, prefix: 1, evidence: opURLEvidence},
	// Configuration mode's entries, none of them in P's deny: view-configuration
	// must not enter it, in any row (pre-flight I5).
	{cmd: "configure", prefix: 1, evidence: l68ConfigMode, entry: true},
	{cmd: "edit", prefix: 1, evidence: l68ConfigMode, entry: true},
	{cmd: "configure private", prefix: 1, evidence: l68ConfigMode, entry: true},
	// Readings: the carve-outs, the configuration file, (L59).
	{cmd: "show log messages | count", evidence: "Count: ", reading: true},
	{cmd: "show firewall | no-more", reading: true},
	{cmd: "show policer | no-more", reading: true},
	{cmd: "file list /config", reading: true},
	{cmd: "file show /config/juniper.conf.gz | count", evidence: "Count: ", reading: true},
}

// l68ExecProbes run over the SSH exec channel in P, H, O and C: a reply's
// deny must bind a command sent there as at the CLI (pre-flight I5).
var l68ExecProbes = []l68Probe{
	{cmd: "show configuration system host-name", evidence: hostEvidence, canonical: true, exec: true},
	{cmd: "monitor list", prefix: 1, canonical: true, exec: true},
	{cmd: "show security zones", prefix: 2, exec: true},
}

// l68Gated are the probes the gate reads: every CLI probe but the readings,
// then the exec probes.
func l68Gated() []l68Probe {
	var out []l68Probe
	for _, p := range slices.Concat(l68Probes, l68ExecProbes) {
		if !p.reading {
			out = append(out, p)
		}
	}
	return out
}

var l68UnknownCommand = regexp.MustCompile(`unknown command: ([a-z][a-z-]*)`)

// l68Cell reads one CLI probe's window:
//   - "ran": its evidence, and no refusal;
//   - "refused": a caret on one of its first prefix words, `permission
//     denied`, or `unknown command` naming one;
//   - "platform refused": the platform's "command is not valid on the" refusal
//     of the whole command;
//   - "past": a caret after the prefix, or, for a probe with no evidence, no
//     refusal at all;
//   - else "not observed".
func l68Cell(p l68Probe, out string, promptLen int) string {
	lower := strings.ToLower(out)
	refusal := containsAny(lower, junosL26bRefusal)
	if p.evidence != "" && strings.Contains(out, p.evidence) && !refusal {
		return "ran"
	}
	words := strings.Fields(p.cmd)
	n := p.prefix
	if n == 0 || n > len(words) {
		n = len(words)
	}
	if at := caretAt(out, promptLen); at != "" {
		for _, w := range words[:n] {
			if caretOn(at, w) {
				return "refused"
			}
		}
		return "past"
	}
	if strings.Contains(lower, "permission denied") {
		return "refused"
	}
	if m := l68UnknownCommand.FindStringSubmatch(lower); m != nil && slices.Contains(words[:n], m[1]) {
		return "refused"
	}
	if strings.Contains(lower, "command is not valid on the") {
		return "platform refused"
	}
	if !refusal && p.evidence == "" {
		return "past"
	}
	return "not observed"
}

// l68ExecCell reads an exec-channel command: "ran" (its evidence), "refused"
// (a refusal word), "past" (it exited and said neither, for a probe with no
// evidence), else "not observed" (a hang, or no evidence where one is due).
func l68ExecCell(p l68Probe, out string, err error) string {
	refused := containsAny(strings.ToLower(out), junosL26bRefusal)
	switch {
	case p.evidence != "" && strings.Contains(out, p.evidence) && !refused:
		return "ran"
	case refused:
		return "refused"
	case err != nil && strings.Contains(err.Error(), "no exit"):
		return "not observed"
	case p.evidence == "":
		return "past"
	}
	return "not observed"
}

// l68AuthBits are the bits `show cli authorization` lists under
// "Permissions:", sorted.
func l68AuthBits(out string) []string {
	var bits []string
	in := false
	for _, line := range strings.Split(strings.ReplaceAll(out, "\r", ""), "\n") {
		switch {
		case strings.HasPrefix(strings.TrimSpace(line), "Permissions:"):
			in = true
		case in && (line == "" || line[0] != ' '):
			in = false
		case in:
			if f := strings.Fields(line); len(f) > 0 {
				bits = append(bits, strings.SplitN(f[0], "--", 2)[0])
			}
		}
	}
	slices.Sort(bits)
	return bits
}

// l68Verdict is a gated probe's reading in a deny row against the control:
// "runs nowhere" where both met the platform's refusal, or both refused it
// (the image lacks the word); "reached" where the row ran it or took it;
// "deny" where the row refused it and the control took it.
func l68Verdict(row, control string) string {
	took := func(c string) bool { return c == "ran" || c == "past" || c == "platform refused" }
	switch {
	case row == "platform refused" && control == "platform refused":
		return "runs nowhere"
	case took(row):
		return "reached"
	case row == "refused" && took(control):
		return "deny"
	case row == "refused" && control == "refused":
		return "runs nowhere"
	}
	return "not observed"
}

// l68Gate reads the CLI run. It returns:
//   - invalid: the control did not take a canonical probe or run the configuration;
//   - stop: a G1 STOP, which is one of these:
//   - P or H took what it denies;
//   - P or H did not run the configuration, or V did;
//   - a row other than O entered configuration mode;
//   - the bit's completion over `view` offers a word reach does not hold;
//   - operator: the same STOPs for row O, G1-operator's;
//   - the verdicts the note prints, keyed "row key".
func l68Gate(runs map[string]l26cRun, surveyC, surveyVc, reach []string) (invalid, stop, operator []string,
	verdicts map[string]string) {
	verdicts = map[string]string{}
	add := func(row, s string) {
		if row == "O" {
			operator = append(operator, s)
		} else {
			stop = append(stop, s)
		}
	}
	c := runs["C"]
	for _, p := range l68Gated() {
		k := p.key()
		cc := c.cells[k]
		switch {
		case p.entry:
			for _, row := range []string{"P", "H", "O", "V", "C"} {
				if runs[row].cells[k] == "ran" {
					add(row, fmt.Sprintf("%s: %s entered configuration mode", k, row))
				}
			}
			continue
		case p.evidence == hostEvidence:
			if p.canonical && cc != "ran" {
				invalid = append(invalid, k+": the control "+cellOr(c, k))
			}
			for _, row := range l68DenyRows {
				if got := runs[row].cells[k]; got != "ran" {
					add(row, fmt.Sprintf("%s: %s %s, so the bit does not deliver the configuration", k, row,
						cellOr(runs[row], k)))
				}
			}
			if !p.exec && runs["V"].cells[k] == "ran" {
				stop = append(stop, k+": V ran it under `view` alone, which L12-bits measured refused")
			}
			continue
		}
		if p.canonical && cc != "ran" && cc != "past" && cc != "platform refused" {
			invalid = append(invalid, k+": the control "+cellOr(c, k))
		}
		for _, row := range l68DenyRows {
			v := l68Verdict(runs[row].cells[k], cc)
			verdicts[row+" "+k] = v
			if v == "reached" {
				add(row, fmt.Sprintf("%s: %s took it past its deny", k, row))
			}
		}
	}
	for _, w := range beyond(surveyC, surveyVc) {
		if !heldBy(reach, w+" **") {
			stop = append(stop, fmt.Sprintf("completion: view-configuration offers %q over `view`, which its "+
				"declared reach does not hold, so no deny covers it", w))
		}
	}
	return invalid, stop, operator, verdicts
}

// l68Guard is the lab's rules before each row: the STOP sentinel and the
// disk floor.
func l68Guard(t *testing.T) {
	t.Helper()
	if err := labGuardAt(l66StopSentinel, "/", l66DiskFloorMB); err != nil {
		t.Fatalf("%v", err)
	}
}

// l68Reference is set 1.2.0's reference configuration for juniper_junos:
// remote in the bitless p49-remote, as the projection differential applies it.
func l68Reference(t *testing.T) []string {
	t.Helper()
	set, _ := adapter.Set("1.2.0")
	ref, err := adapter.ReferenceClasses(set["juniper_junos"], 12*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return ref
}

func (l *lab) l68RestoreDaemon(t *testing.T) {
	t.Helper()
	if std, err := l.configPath(); err == nil {
		if err := l.restart(std); err != nil {
			t.Errorf("could not put port49d back on the lab config: %v", err)
		}
	}
}

// l68Exec runs l68ExecProbes over the SSH exec channel, one session each on
// one connection with the next token, while port49d sends the row's reply.
func (l *lab) l68Exec(t *testing.T, r l26cRun) {
	t.Helper()
	user, secret := l.nextLogin(t)
	conn, err := l.dialHostPort(user, secret, l.p.addr+":22", 60*time.Second)
	if err != nil {
		for _, p := range l68ExecProbes {
			r.cells[p.key()], r.outs[p.key()] = dialCell(err), oneLine(err.Error())
		}
		return
	}
	defer conn.Close()
	for _, p := range l68ExecProbes {
		k := p.key()
		s, err := conn.NewSession()
		if err != nil {
			r.cells[k], r.outs[k] = "not observed", oneLine(err.Error())
			continue
		}
		var out xnmOut
		s.Stdout, s.Stderr = &out, &out
		done := make(chan error, 1)
		go func() { done <- s.Run(p.cmd) }()
		select {
		case err = <-done:
		case <-time.After(junosPer):
			err = fmt.Errorf("no exit within %s", junosPer)
		}
		s.Close()
		r.outs[k] = firstLines(out.String(), 12)
		r.cells[k] = l68ExecCell(p, out.String(), err)
	}
}

// l68PagerSave pages `show configuration` and answers the pager's `s` with
// path, then quits the pager and turns paging off again. It records what the
// pager said; whether the file was written is read over the admin CLI
// afterwards (l68Files). A reading only (L59).
func l68PagerSave(c *cliConn, path string) (string, string) {
	from := len(c.out.String())
	if _, err := c.sendExpect("set cli screen-length 5", junosPer, junosOpPrompt); err != nil {
		return "not observed", oneLine(err.Error())
	}
	if err := c.send("show configuration"); err != nil {
		return "not observed", oneLine(err.Error())
	}
	if _, err := c.expectFrom(from, junosPer, junosPagerMark, junosOpPrompt); err != nil ||
		!junosPaged(c.out.String()[from:]) {
		junosSettle(c)
		c.sendExpect("set cli screen-length 0", junosPer, junosOpPrompt)
		return "no pager", c.out.String()[from:]
	}
	at := len(c.out.String())
	fmt.Fprint(c.in, "s")
	_, err := c.expectFrom(at, junosPer, "ile", junosPagerMark, junosOpPrompt)
	cell := "prompted for a file"
	if err != nil || !strings.Contains(c.out.String()[at:], "ile") {
		cell = "no save prompt"
	} else {
		c.send(path)
		c.expectFrom(at, junosPer, junosPagerMark, junosOpPrompt)
	}
	fmt.Fprint(c.in, "q")
	c.expectFrom(at, junosPer, junosOpPrompt)
	junosSettle(c)
	c.sendExpect("set cli screen-length 0", junosPer, junosOpPrompt)
	return cell, c.out.String()[from:]
}

// l68Files lists what the rows' `| save` and pager `s` wrote under /var/tmp,
// over the break-glass CLI, and deletes each.
func (l *lab) l68Files(t *testing.T) string {
	t.Helper()
	var out string
	l.withAdminCLI(t, func(l *lab) (*cliConn, error) {
		return l.junosCLI(breakglassUser, breakglassPassword)
	}, func(c *cliConn) error {
		o, err := l26cSend(c, "file list /var/tmp/ | match p49-l68")
		out = o
		if err != nil {
			return err
		}
		for _, v := range junosL68Variants {
			for _, f := range []string{"p49-l68-pipe-", "p49-l68-pager-"} {
				l26cSend(c, "file delete /var/tmp/"+f+v.name)
			}
		}
		return nil
	})
	return out
}

func TestL68ViewConfigurationCLI(t *testing.T) {
	eachPlatform(t, func(t *testing.T, l *lab) {
		if l.p.name != "juniper_vjunos-router" && l.p.name != "juniper_vsrx" {
			t.Skip("Junos only")
		}
		l68Guard(t)
		stop := l.capture(t, "L68")
		defer stop()
		reference := l68Reference(t)
		commit := l.junosConfigureAdmin(t, reference)
		defer l.junosConfigureAdmin(t, projectionRestore(reference))
		defer l.l68RestoreDaemon(t)
		l.stageOpScript(t)
		runs := map[string]l26cRun{}
		surveys := map[string][]string{}
		var invalid []string
		for _, v := range junosL68Variants {
			l68Guard(t)
			r := newL26cRun()
			runs[v.name] = r
			c, run, _ := l.junosLogin(t, "L68 "+v.name, v.attrs)
			if c == nil {
				t.Fatalf("INVALID: %s: the session did not open, so nothing was measured: %s", v.name, run.loginErr)
			}
			r.outs["show cli authorization"] = run.auth
			if got := l68AuthBits(run.auth); !slices.Equal(got, l68Bits[v.name]) {
				invalid = append(invalid, fmt.Sprintf("%s: show cli authorization lists %v, want %v: the reply did "+
					"not land as sent, or a configuration group adds a bit to p49-remote", v.name, got, l68Bits[v.name]))
			}
			promptLen := len(run.user + "@" + junosHost + "> ")
			// l26cSend keeps the echo, which caretAt reads the caret against;
			// junosProbe trims it. Paging is off (junosLogin's junosPrepare).
			for _, p := range l68Probes {
				out, err := l26cSend(c, p.cmd)
				r.outs[p.cmd], r.cells[p.cmd] = out, l68Cell(p, out, promptLen)
				if err == nil && p.entry && r.cells[p.cmd] == "ran" {
					_, err = l26cSend(c, "exit configuration-mode")
				}
				if err != nil {
					r.cells[p.cmd] = "not observed"
					break // the session's state is unknown past a missed prompt
				}
			}
			if v.name == "C" || v.name == "Vc" {
				surveys[v.name] = l.junosSurvey(t, "L68 "+v.name, c, &run)
			}
			pipe := "show configuration system host-name | save /var/tmp/p49-l68-pipe-" + v.name
			r.outs["| save"], _ = l26cSend(c, pipe)
			r.cells["pager s"], r.outs["pager s"] = l68PagerSave(c, "/var/tmp/p49-l68-pager-"+v.name)
			if len(run.unobserved) > 0 {
				invalid = append(invalid, fmt.Sprintf("%s: not observed: %s", v.name, strings.Join(run.unobserved, ", ")))
			}
			c.Close()
			// port49d still sends this row's reply: the exec channel and scp
			// log in under it.
			if slices.Contains([]string{"P", "H", "O", "C"}, v.name) {
				l.l68Exec(t, r)
			}
			if slices.Contains([]string{"P", "V", "C"}, v.name) {
				l.entryScp(t, r, "/config/juniper.conf.gz") // a reading (L59)
			}
		}
		files := l.l68Files(t)
		set, _ := adapter.Set("1.2.0")
		gi, stopped, operator, verdicts := l68Gate(runs, surveys["C"], surveys["Vc"],
			set["juniper_junos"].Bits["view-configuration"])
		invalid = append(invalid, gi...)
		// A gated cell not observed (or never typed, past a missed prompt) says
		// nothing: the run is INVALID before any STOP is read.
		for _, p := range l68Gated() {
			rows := []string{"P", "H", "O", "V", "C"}
			if p.exec {
				rows = []string{"P", "H", "O", "C"}
			}
			for _, n := range rows {
				if cell, ok := runs[n].cells[p.key()]; !ok || cell == "not observed" || cell == "login refused" {
					invalid = append(invalid, fmt.Sprintf("%s in %s: %s", p.key(), n, cellOr(runs[n], p.key())))
					t.Logf("raw %s in %s: %q", p.key(), n, firstLines(runs[n].outs[p.key()], 12))
				}
			}
		}
		if len(invalid) > 0 {
			t.Fatalf("INVALID: %s; no note is written", strings.Join(invalid, "; "))
		}
		// Anything that failed before the STOPs are read makes a STOP note
		// INVALID too (pre-flight I3).
		failedBefore := t.Failed()
		var b strings.Builder
		fmt.Fprintf(&b, "**Gate:** %s; %s\n\nThe reference configuration was committed: %s.\n\n",
			l68GateLine("G1", stopped), l68GateLine("G1-operator", operator), commitWord(commit))
		l68Tables(&b, runs, verdicts, surveys, files)
		for _, s := range stopped {
			t.Errorf("STOP: %s: no reply change ships; report to the controller (plan 9g R1)", s)
		}
		for _, s := range operator {
			t.Errorf("STOP (G1-operator): %s: the operator reply does not ship; report to the controller", s)
		}
		l.l68Note(t, "L68", "Whether `user-permissions` holding view-configuration, with deny-commands covering `show "+
			"security` and view-configuration's other reach, lets the session read the configuration and nothing the "+
			"denies leave open, at the CLI and over the exec channel, for a readonly's reply and an operator's, "+
			"against `view` alone and a control with the same bits and no deny (spec §15 L68; plan 9g Task 1, gates "+
			"G1 and G1-operator).", b.String(), len(stopped)+len(operator) > 0, failedBefore)
	})
}

// l68GateLine is a gate's line in a note: pass, or STOP and why.
func l68GateLine(gate string, stops []string) string {
	if len(stops) == 0 {
		return gate + ": pass"
	}
	return gate + ": STOP — " + strings.Join(stops, "; ")
}

func TestL68ViewConfigurationNetconf(t *testing.T) {
	eachPlatform(t, func(t *testing.T, l *lab) {
		l.l68Netconf(t, "L68-netconf", "G1", []string{"P", "H"})
	})
}

func TestL68ViewConfigurationNetconfOperator(t *testing.T) {
	eachPlatform(t, func(t *testing.T, l *lab) {
		l.l68Netconf(t, "L68-netconf-operator", "G1-operator", []string{"O"})
	})
}

// l68Netconf probes NETCONF (`xml-mode` from the CLI, port 830, the port-22
// subsystem, the exec channel) in the deny rows and the control C, and gates
// them under gate. Each row takes four tokens, so the readonly rows and the
// operator row run in two invocations within the pool of 16.
func (l *lab) l68Netconf(t *testing.T, entry, gate string, deny []string) {
	t.Helper()
	if l.p.name != "juniper_vjunos-router" && l.p.name != "juniper_vsrx" {
		t.Skip("Junos only")
	}
	l68Guard(t)
	stop := l.capture(t, entry)
	defer stop()
	reference := l68Reference(t)
	commit := l.junosConfigureAdmin(t, append(slices.Clone(reference), "set system services netconf ssh"))
	defer l.junosConfigureAdmin(t, projectionRestore(reference))
	defer l.l68RestoreDaemon(t)
	probes, canonical := entryProbes[1:], entryCanonical[1:] // the CLI test reads the configuration
	names := append(slices.Clone(deny), "C")
	runs := map[string]l26cRun{}
	for _, n := range names {
		l68Guard(t)
		v := l68Variant(n)
		r := newL26cRun()
		runs[n] = r
		c, run, _ := l.junosLogin(t, "L68 netconf "+n, v.attrs)
		if c == nil {
			t.Fatalf("INVALID: %s: the session did not open, so nothing was measured: %s", n, run.loginErr)
		}
		r.outs["show cli authorization"] = run.auth
		entryXMLMode(c, r)
		c.Close()
		l.entryNetconf(t, r, "port 830", "830")
		l.entryNetconf(t, r, "port 22 subsystem", "22")
		l.entryExec(t, r)
	}
	var unobserved []string
	for _, p := range probes {
		for _, n := range names {
			if runs[n].cells[p] == "not observed" || runs[n].cells[p] == "login refused" {
				unobserved = append(unobserved, p+" in "+n)
			}
		}
	}
	readings, unisolated := entryVerdict(runs, deny, "C", canonical, probes)
	if len(unisolated) > 0 {
		entryLogControl(t, runs["C"], unisolated)
		t.Fatalf("INVALID: the control did not reach %s; no note is written", strings.Join(unisolated, "; "))
	}
	// A deny row's cell counts as refused only on a positive refusal: a
	// reading of "not observed" (a login refused, a hang) is INVALID, never a
	// pass (pre-flight I4).
	for _, n := range deny {
		for _, p := range probes {
			if readings[n+" "+p] == "not observed" {
				unobserved = append(unobserved, p+" in "+n+" (reading)")
			}
		}
	}
	if len(unobserved) > 0 {
		t.Fatalf("INVALID: not observed: %s; no note is written", strings.Join(unobserved, "; "))
	}
	var stopped []string
	for k, v := range readings {
		if v == "reached" {
			stopped = append(stopped, k)
		}
	}
	slices.Sort(stopped)
	failedBefore := t.Failed()
	var b strings.Builder
	fmt.Fprintf(&b, "**Gate:** %s\n\nThe reference configuration and `netconf ssh` were committed: %s.\n\n",
		l68GateLine(gate, stopped), commitWord(commit))
	l68NetconfTables(&b, runs, readings, probes, names, deny)
	for _, s := range stopped {
		t.Errorf("STOP (%s): reached past the entry deny: %s; report to the controller (plan 9g R1)", gate, s)
	}
	l.l68Note(t, entry, "Whether NETCONF (`xml-mode` from the CLI, port 830, the port-22 subsystem, the exec "+
		"channel) reaches `<get-configuration/>` under a reply holding view-configuration with the entry denies "+
		"beside view-configuration's other reach denied ("+strings.Join(deny, ", ")+"), against a control with "+
		"the same bits and no deny (spec §15 L68; plan 9g Task 1, gate "+gate+").", b.String(), len(stopped) > 0,
		failedBefore)
}

// l68Note writes the note. A passing run goes through entryResult, which
// writes nothing after a failure. A STOP is a measurement, so its note is
// written, under the same leak check, but only where the run was otherwise
// VALID: failedBefore (anything failed before the STOPs were read) makes it
// INVALID, and no note is written (pre-flight I3).
func (l *lab) l68Note(t *testing.T, entry, claim, observation string, stopped, failedBefore bool) {
	t.Helper()
	if !stopped {
		l.entryResult(t, entry, claim, observation)
		return
	}
	if failedBefore {
		t.Fatalf("INVALID: %s: the run read a STOP but had already failed; no note is written", entry)
	}
	if err := leakIn(claim+"\n"+observation, poolSecrets()); err != nil {
		t.Fatalf("%s: the note is withheld: %v", entry, err)
	}
	l.result(t, entry, claim, observation)
}

// l68Tables writes the rows, every probe's cells, the verdicts against the
// control, the completion difference, the files, and each row's raw outputs.
func l68Tables(b *strings.Builder, runs map[string]l26cRun, verdicts map[string]string, surveys map[string][]string,
	files string) {
	names := []string{"P", "H", "O", "V", "Vc", "C"}
	b.WriteString("| row | reply | why | `show cli authorization` bits |\n|---|---|---|---|\n")
	for _, v := range junosL68Variants {
		fmt.Fprintf(b, "| %s | `%s` | %s | %s |\n", v.name, tableCell(v.attrs), v.why,
			strings.Join(l68AuthBits(runs[v.name].outs["show cli authorization"]), " "))
	}
	fmt.Fprintf(b, "\n| probe | %s |\n|---|%s\n", strings.Join(names, " | "), strings.Repeat("---|", len(names)))
	var keys []string
	for _, p := range slices.Concat(l68Probes, l68ExecProbes) {
		keys = append(keys, p.key())
	}
	keys = append(keys, "pager s", "scp /config/juniper.conf.gz")
	for _, k := range keys {
		cells := make([]string, len(names))
		for i, n := range names {
			cells[i] = cellOr(runs[n], k)
		}
		fmt.Fprintf(b, "| %s | %s |\n", tableCell(k), strings.Join(cells, " | "))
	}
	b.WriteString("\n### Verdict against the control\n\n| probe | P | H | O |\n|---|---|---|---|\n")
	for _, p := range l68Gated() {
		if !p.entry && p.evidence != hostEvidence {
			fmt.Fprintf(b, "| %s | %s | %s | %s |\n", tableCell(p.key()), verdicts["P "+p.key()],
				verdicts["H "+p.key()], verdicts["O "+p.key()])
		}
	}
	fmt.Fprintf(b, "\n### Completion: what view-configuration offers over `view` (C against Vc)\n\n%s\n",
		strings.Join(beyond(surveys["C"], surveys["Vc"]), ", "))
	fmt.Fprintf(b, "\n### Files under /var/tmp after the rows (`| save`, pager `s`)\n\n```\n%s\n```\n", files)
	for _, n := range names {
		fmt.Fprintf(b, "\n### %s\n", n)
		ks := make([]string, 0, len(runs[n].outs))
		for k := range runs[n].outs {
			ks = append(ks, k)
		}
		slices.Sort(ks)
		for _, k := range ks {
			fmt.Fprintf(b, "\n`%s`:\n\n```\n%s\n```\n", k, firstLines(runs[n].outs[k], 20))
		}
	}
}

// l68NetconfTables writes the NETCONF rows' cells, the deny rows' verdicts
// and the raw outputs.
func l68NetconfTables(b *strings.Builder, runs map[string]l26cRun, readings map[string]string, probes, names,
	deny []string) {
	fmt.Fprintf(b, "| probe | %s |\n|---|%s\n", strings.Join(names, " | "), strings.Repeat("---|", len(names)))
	for _, p := range probes {
		cells := make([]string, len(names))
		for i, n := range names {
			cells[i] = cellOr(runs[n], p)
		}
		fmt.Fprintf(b, "| %s | %s |\n", tableCell(p), strings.Join(cells, " | "))
	}
	fmt.Fprintf(b, "\n### Verdict against the control\n\n| probe | %s |\n|---|%s\n", strings.Join(deny, " | "),
		strings.Repeat("---|", len(deny)))
	for _, p := range probes {
		cells := make([]string, len(deny))
		for i, n := range deny {
			cells[i] = jsdOrDash(readings[n+" "+p])
		}
		fmt.Fprintf(b, "| %s | %s |\n", tableCell(p), strings.Join(cells, " | "))
	}
	for _, n := range names {
		fmt.Fprintf(b, "\n### %s\n", n)
		ks := make([]string, 0, len(runs[n].outs))
		for k := range runs[n].outs {
			ks = append(ks, k)
		}
		slices.Sort(ks)
		for _, k := range ks {
			fmt.Fprintf(b, "\n`%s`:\n\n```\n%s\n```\n", k, firstLines(runs[n].outs[k], 20))
		}
	}
}
