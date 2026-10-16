//go:build lab

package lab

import (
	"errors"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/rhwendt/port49/internal/engine"
	adapter "github.com/rhwendt/port49/internal/platform"
	"github.com/rhwendt/port49/internal/projection"
)

// l68Shipped renders a juniper_junos composition at level on set version, as
// the policy layer hands the projection one (internal/projection's `shipped`
// helper).
func l68Shipped(version, level string, rules ...engine.Rule) (projection.Result, error) {
	set, _ := adapter.Set(version)
	d := set["juniper_junos"]
	return projection.Project(projection.Input{
		Platform:  "juniper_junos",
		Dialect:   d,
		Level:     level,
		Bits:      d.CeilingBits[level],
		Rules:     rules,
		Normalize: engine.Normalize{PipeToken: "|", StripCR: true, SessionOnly: true},
		Facts:     projection.JunosFacts,
		Keywords:  adapter.KeywordsFor(version, "juniper_junos"),
	})
}

func l68Rule(verdict, rule string) engine.Rule {
	return engine.Rule{Verdict: verdict, Rule: rule, Role: "r"}
}

// Rows P and O are byte for byte what set 1.2.0 renders for a readonly, and
// for an operator also granted `clear **`, granted `show **` less `show
// security **` and `monitor **`, and within RFC 8907.
func TestL68ProjectedIsSet120sRender(t *testing.T) {
	for _, c := range []struct {
		level string
		bits  string
		extra []engine.Rule
	}{
		{"readonly", "user-permissions=view view-configuration", nil},
		{"operator", "user-permissions=clear view view-configuration", []engine.Rule{l68Rule(engine.Permit, "clear **")}},
	} {
		rules := append([]engine.Rule{l68Rule(engine.Permit, "show **"), l68Rule(engine.Deny, "show security **"),
			l68Rule(engine.Deny, "monitor **")}, c.extra...)
		res, err := l68Shipped("1.2.0", c.level, rules...)
		if err != nil || res.Shape != projection.ShapeCapability || !slices.Equal(res.Attributes, []string{c.bits, l68Projected}) {
			t.Fatalf("%s: %s %q %+v %v", c.level, res.Shape, res.Attributes, res.Refusal, err)
		}
	}
	if len(l68Projected) != 173 || len(l68Projected) > engine.MaxAttribute {
		t.Errorf("deny-commands is %d bytes", len(l68Projected))
	}
}

// Row H fits RFC 8907, denies an example of every rule of set 1.2.0's
// view-configuration reach that is not a carve-out, the grant's deny and the
// entry denies, and leaves the configuration and the carve-outs open.
func TestL68HandFitsAndCoversTheReach(t *testing.T) {
	if len(l68Hand) > engine.MaxAttribute {
		t.Fatalf("H's deny-commands is %d bytes", len(l68Hand))
	}
	re := regexp.MustCompile(strings.TrimPrefix(l68Hand, "deny-commands="))
	set, _ := adapter.Set("1.2.0")
	d := set["juniper_junos"]
	for _, r := range d.Bits["view-configuration"] {
		if slices.Contains(d.CarveOuts["view-configuration"], r) {
			continue
		}
		if ex := strings.TrimSuffix(r, " **") + " x"; !re.MatchString(ex) {
			t.Errorf("H leaves %q open", ex)
		}
	}
	for _, s := range []string{"show security zones", "show security zones | no-more", "junoscript", "op url x",
		"monitor list", "  monitor   list"} {
		if !re.MatchString(s) {
			t.Errorf("H leaves %q open", s)
		}
	}
	for _, s := range []string{"show configuration system host-name", "show log messages", "show firewall",
		"show policer", "show version", "request system reboot", "load merge x"} {
		if re.MatchString(s) {
			t.Errorf("H denies %q", s)
		}
	}
}

// A cell reads where the CLI refused: on the probe's prefix (refused), after
// it or not at all (past), by a platform's refusal of the whole command
// (platform refused), or by its evidence (ran).
func TestL68Cell(t *testing.T) {
	// The window's first echo carries no prompt; the caret's column counts it
	// (caretAt, TestCaretAt).
	const prompt = "p49user@vjunos1> "
	pl := len(prompt)
	caret := func(off int) string { return strings.Repeat(" ", pl+off) + "^" }
	mpls := l68Probe{cmd: "request mpls p49-none", prefix: 2}
	for _, c := range []struct {
		p    l68Probe
		out  string
		want string
	}{
		{mpls, "request mpls p49-none\n" + caret(8) + "\nsyntax error.\n" + prompt, "refused"},
		{mpls, "request mpls p49-none\n" + caret(0) + "\nsyntax error.\n" + prompt, "refused"},
		{mpls, "request mpls p49-none\n" + caret(13) + "\nsyntax error, expecting <command>.\n" + prompt, "past"},
		{l68Probe{cmd: "req mpls p49-none", prefix: 2}, "req mpls p49-none\n" + caret(4) + "\nsyntax error.\n" + prompt,
			"refused"},
		{mpls, "request mpls p49-none\nerror: permission denied\n" + prompt, "refused"},
		{l68Probe{cmd: "save dhcp-security-snoop | count", prefix: 2},
			"save dhcp-security-snoop | count\nerror: command is not valid on the vsrx\n" + prompt, "platform refused"},
		{l68Probe{cmd: "monitor list", prefix: 1}, "monitor list\n" + prompt, "past"},
		{l68Probe{cmd: "junoscript", prefix: 1}, "junoscript\nerror: unknown command: junoscript\n" + prompt, "refused"},
		{l68Probe{cmd: "show configuration system host-name", evidence: hostEvidence},
			"show configuration system host-name\n" + hostEvidence + ";\n" + prompt, "ran"},
		{l68Probe{cmd: "show configuration system host-name", evidence: hostEvidence},
			"show configuration system host-name\n" + prompt, "not observed"},
		{l68Probe{cmd: "configure", prefix: 1, evidence: l68ConfigMode, entry: true},
			"configure\nEntering configuration mode\n\n[edit]\np49user@vjunos1# ", "ran"},
		{l68Probe{cmd: "configure", prefix: 1, evidence: l68ConfigMode, entry: true},
			"configure\n" + caret(0) + "\nunknown command.\n" + prompt, "refused"},
	} {
		if got := l68Cell(c.p, c.out, pl); got != c.want {
			t.Errorf("%q on %q: %s, want %s", c.p.cmd, c.out, got, c.want)
		}
	}
}

// An exec-channel command's cell: its evidence, a refusal word, or an exit
// that said neither.
func TestL68ExecCell(t *testing.T) {
	show := l68Probe{cmd: "show configuration system host-name", evidence: hostEvidence}
	mon := l68Probe{cmd: "monitor list", prefix: 1}
	for _, c := range []struct {
		p    l68Probe
		out  string
		err  error
		want string
	}{
		{show, hostEvidence + ";\n", nil, "ran"},
		{show, "", nil, "not observed"},
		{mon, "error: syntax error: monitor\n", errors.New("Process exited with status 1"), "refused"},
		{mon, "", nil, "past"},
		{mon, "", errors.New("no exit within 45s"), "not observed"},
	} {
		if got := l68ExecCell(c.p, c.out, c.err); got != c.want {
			t.Errorf("%q on %q %v: %s, want %s", c.p.cmd, c.out, c.err, got, c.want)
		}
	}
}

// `show cli authorization` lists the session's bits under "Permissions:".
func TestL68AuthBits(t *testing.T) {
	out := "Current user: 'remote' login: 'p49user' class 'p49-remote'\nPermissions:\n" +
		"    view        -- Can view current values and statistics\n" +
		"    view-configuration-- Can view all configuration (not including secrets)\n" +
		"Individual command authorization:\n    Allow regular expression: none\n"
	if got := l68AuthBits(out); !slices.Equal(got, []string{"view", "view-configuration"}) {
		t.Errorf("%v", got)
	}
	if got := l68AuthBits("Permissions:\nIndividual command authorization:\n"); len(got) != 0 {
		t.Errorf("no bits: %v", got)
	}
}

func TestL68Verdict(t *testing.T) {
	for _, c := range []struct{ row, control, want string }{
		{"refused", "past", "deny"}, {"refused", "ran", "deny"}, {"past", "past", "reached"},
		{"ran", "ran", "reached"}, {"refused", "refused", "runs nowhere"}, {"not observed", "past", "not observed"},
		{"platform refused", "platform refused", "runs nowhere"}, {"platform refused", "past", "reached"},
		{"refused", "platform refused", "deny"},
	} {
		if got := l68Verdict(c.row, c.control); got != c.want {
			t.Errorf("%s against %s: %s, want %s", c.row, c.control, got, c.want)
		}
	}
}

// The gate: a deny row (P, H) that takes what it denies is a STOP, and O's is
// a G1-operator STOP; P, H or O not running the configuration, or V running
// it, likewise; any row entering configuration mode, likewise; the control
// not taking a canonical probe is INVALID; completion beyond the declared
// reach is a STOP.
func TestL68Gate(t *testing.T) {
	good := func() map[string]l26cRun {
		runs := map[string]l26cRun{}
		for _, n := range []string{"P", "H", "O", "V", "Vc", "C"} {
			runs[n] = newL26cRun()
		}
		for _, p := range l68Gated() {
			k := p.key()
			switch {
			case p.entry:
				for _, n := range []string{"P", "H", "O", "V", "C"} {
					runs[n].cells[k] = "refused"
				}
				continue
			case p.evidence == hostEvidence:
				runs["V"].cells[k] = "refused"
				runs["C"].cells[k] = "ran"
				for _, n := range l68DenyRows {
					runs[n].cells[k] = "ran"
				}
				continue
			case p.evidence != "":
				runs["C"].cells[k] = "ran"
			default:
				runs["C"].cells[k] = "past"
			}
			for _, n := range l68DenyRows {
				runs[n].cells[k] = "refused"
			}
		}
		return runs
	}
	reach := []string{"show configuration **", "show log **", "monitor **", "request mpls **"}
	vc := []string{"show", "show configuration", "show log", "monitor", "monitor list", "request mpls"}
	v := []string{"show", "show configuration"}
	if inv, stop, op, _ := l68Gate(good(), vc, v, reach); len(inv)+len(stop)+len(op) != 0 {
		t.Fatalf("a clean run: invalid %v stop %v operator %v", inv, stop, op)
	}
	runs := good()
	runs["P"].cells["monitor p49-none"] = "past"
	if _, stop, op, _ := l68Gate(runs, vc, v, reach); len(stop) != 1 || len(op) != 0 ||
		!strings.Contains(stop[0], "monitor p49-none") {
		t.Errorf("P took monitor: %v %v", stop, op)
	}
	runs = good()
	runs["O"].cells["exec: monitor list"] = "past"
	if _, stop, op, _ := l68Gate(runs, vc, v, reach); len(stop) != 0 || len(op) != 1 {
		t.Errorf("O took monitor over exec: %v %v", stop, op)
	}
	runs = good()
	runs["H"].cells["show configuration system host-name"] = "refused"
	if _, stop, _, _ := l68Gate(runs, vc, v, reach); len(stop) != 1 {
		t.Errorf("H refused the configuration: %v", stop)
	}
	runs = good()
	runs["V"].cells["show configuration system host-name"] = "ran"
	if _, stop, _, _ := l68Gate(runs, vc, v, reach); len(stop) != 1 {
		t.Errorf("V ran the configuration: %v", stop)
	}
	runs = good()
	runs["C"].cells["configure"] = "ran"
	if _, stop, _, _ := l68Gate(runs, vc, v, reach); len(stop) != 1 || !strings.Contains(stop[0], "configuration mode") {
		t.Errorf("C entered configuration mode: %v", stop)
	}
	runs = good()
	runs["C"].cells["request mpls p49-none"] = "refused"
	if inv, _, _, _ := l68Gate(runs, vc, v, reach); len(inv) != 1 {
		t.Errorf("the control refused a canonical probe: %v", inv)
	}
	if _, stop, _, _ := l68Gate(good(), append(slices.Clone(vc), "request zzz"), v, reach); len(stop) != 1 ||
		!strings.Contains(stop[0], "request zzz") {
		t.Errorf("completion beyond the reach: %v", stop)
	}
}
