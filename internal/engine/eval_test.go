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

// An abbreviation is compared the way a word is, by case folding, so a
// spelling that folds to a prefix of a deny's word is denied too.
func TestAFoldedAbbreviationCannotSlipPastADeny(t *testing.T) {
	typed := program(t, false, "admin:permit **", "ro:deny show **")
	expect(t, typed, "ſh run", false, decision.NoPermitDominatesDeny)
}

// Spec §3 rule 4 for a class or regex term: on a platform that may send what
// was typed, `int ma1` must not slip past `deny interface @management`. A
// deny's pattern that names a literal stem also matches every abbreviation of
// the stem followed by what the pattern allows after it, so `Ma1` is denied as
// `Management1` is; a permit's pattern still matches only as written.
func TestAnAbbreviatedNameCannotSlipPastADenysPattern(t *testing.T) {
	lines := []string{"admin:permit **", "no_mgmt:deny interface @management", "no_lo:deny interface /^Loopback[0-9]+$/"}
	typed := program(t, false, lines...)
	for _, line := range []string{"int ma1", "interface Ma1", "interface management1", "interface M1", "interface lo0", "int Loop0"} {
		expect(t, typed, line, false, decision.NoPermitDominatesDeny)
	}
	// Past the stem the pattern binds as written: `Ma` alone names no
	// interface @management holds, and `Mx1` abbreviates nothing.
	for _, line := range []string{"interface Ma", "interface Mx1", "interface Ethernet1"} {
		expect(t, typed, line, true, decision.PermitDominates)
	}
	ro := program(t, false, "net:permit interface @management", "net:permit interface /^Loopback[0-9]+$/")
	expect(t, ro, "interface Ma1", false, decision.NoRuleMatched)
	expect(t, ro, "interface Lo0", false, decision.NoRuleMatched)
	resolved := program(t, true, lines...)
	expect(t, resolved, "interface Ma1", true, decision.PermitDominates)
}

// A deny's pattern whose abbreviations cannot be read from its syntax —
// unanchored, or not starting with its literal name — matches any argument in
// its position on a platform that may send what was typed: an over-denial
// spec §3 rule 4 accepts, rather than an abbreviation slipping past it or a
// device refused altogether. Its other terms still bind, WidenedToAny names
// it, and where the platform sends resolved words, or on a permit, it is
// matched as written.
func TestADenyPatternWithUnreadableAbbreviationsMatchesAnything(t *testing.T) {
	for _, rule := range []string{"interface /Management/", "interface /^[a-z]+[0-9]+$/", "interface /^Ma.?nagement1$/",
		"interface /^Gig[a-z]*[0-9]+$/"} {
		typed := program(t, false, "admin:permit **", "d:deny "+rule)
		expect(t, typed, "interface Port-channel7", false, decision.NoPermitDominatesDeny)
		expect(t, typed, "vlan Port-channel7", true, decision.PermitDominates)
		if got := WidenedToAny(rule, nil, typed.Blob.Normalize); len(got) != 1 || !strings.Contains(got[0], "abbreviat") {
			t.Errorf("%s: %q, want the term named with why", rule, got)
		}
		resolved := program(t, true, "admin:permit **", "d:deny "+rule)
		expect(t, resolved, "interface Port-channel7", true, decision.PermitDominates)
		if got := WidenedToAny(rule, nil, resolved.Blob.Normalize); len(got) != 0 {
			t.Errorf("%s, resolved words: %q", rule, got)
		}
		permit := program(t, false, "p:permit "+rule)
		expect(t, permit, "interface Port-channel7", false, decision.NoRuleMatched)
	}
	// A name with an optional part, an alternation, a pattern past which
	// anything may follow, and one that starts with no letter all read.
	for _, rule := range []string{"interface /^Gig(abit)?Ethernet[0-9/]+$/", "interface /^(management|mgmt)[0-9]*$/",
		"copy * /^tftp:/", "show /^run.*/", "vlan /^[0-9]+$/", "interface @physical"} {
		if got := WidenedToAny(rule, testBlob(false).Classes, testBlob(false).Normalize); len(got) != 0 {
			t.Errorf("%s: %q", rule, got)
		}
	}
	gig := program(t, false, "admin:permit **", "d:deny interface /^Gig(abit)?Ethernet[0-9/]+$/")
	for _, line := range []string{"int Gi1/0/1", "interface GigE1", "interface g0"} {
		expect(t, gig, line, false, decision.NoPermitDominatesDeny)
	}
	expect(t, gig, "interface Port-channel7", true, decision.PermitDominates)
}

// L21 on IOS-XE: `int Gi1` arrives as two arguments, `GigabitEthernet` and
// `1` (tests/lab/results/L21-cisco_iosxe.md), so a deny written with the name
// joined would never match what the device sends. Where the platform splits
// names, a deny's word, class or regex naming an interface with its index also
// matches the name and the index as two arguments, and the record names the
// deny as written. A permit matches only as written, and the vector is never
// re-joined (spec §3 rule 5).
func TestADenyNamingAnInterfaceMatchesItSplit(t *testing.T) {
	lines := []string{"admin:permit **", "no_gi1:deny interface GigabitEthernet1 **", "no_mgmt:deny interface @management",
		"no_lo:deny interface /^Loopback[0-9]+$/"}
	b := testBlob(true, lines...)
	b.Normalize.SplitsInterfaceNames = true
	xe := compileBlob(t, b)
	o := expect(t, xe, "interface GigabitEthernet 1", false, decision.NoPermitDominatesDeny)
	if o.Deny == nil || o.Deny.Rule != "interface GigabitEthernet1 **" || o.Deny.Role != "no_gi1" || !reflect.DeepEqual(o.Deny.Specificity, []int{3, 3, 3}) {
		t.Errorf("the split name is denied by the rule as written: %+v", o.Deny)
	}
	for _, line := range []string{"interface GigabitEthernet1", "interface gigabitethernet 1 shutdown",
		"interface Management 1", "interface loopback 0", "interface Loopback 10"} {
		expect(t, xe, line, false, decision.NoPermitDominatesDeny)
	}
	// Only an index splits off: a second word, another number, or a name
	// with nothing after it is not the name the deny wrote.
	for _, line := range []string{"interface GigabitEthernet 2", "interface GigabitEthernet x1", "interface Loopback 0/1",
		"interface Loopback x",
		"interface Loopback", "interface Management"} {
		expect(t, xe, line, true, decision.PermitDominates)
	}
	pb := testBlob(true, "net:permit interface GigabitEthernet1", "net:permit interface @management")
	pb.Normalize.SplitsInterfaceNames = true
	expect(t, compileBlob(t, pb), "interface GigabitEthernet 1", false, decision.NoRuleMatched)
	expect(t, compileBlob(t, pb), "interface Management 1", false, decision.NoRuleMatched)
	expect(t, program(t, true, lines...), "interface GigabitEthernet 1", true, decision.PermitDominates)
}

// A deny that matches a command both as written and split is recorded once.
func TestADenyMatchingTwoWaysIsNamedOnce(t *testing.T) {
	b := testBlob(true, "admin:permit **", "no_gi:deny interface /^Gig.*/ **")
	b.Normalize.SplitsInterfaceNames = true
	o := expect(t, compileBlob(t, b), "interface GigabitEthernet 1", false, decision.NoPermitDominatesDeny)
	if len(o.Denies) != 1 {
		t.Errorf("denies %+v", o.Denies)
	}
}

// The split is read at match time, so it needs nothing from a pattern's
// syntax: any deny term matches a name and an index the device sent apart
// when it matches them joined, and nothing is refused for it (spec §3 rule 5).
func TestAnyDenyTermMatchesTheSplitName(t *testing.T) {
	b := testBlob(true, "admin:permit **", "d:deny interface /^Gig[a-z]*[0-9]+$/", "e:deny ip /ethernet2/ **",
		"f:deny shutdown Port-channel10")
	b.Normalize.SplitsInterfaceNames = true
	xe := compileBlob(t, b)
	for _, line := range []string{"interface Gigabit 1", "interface GigabitEthernet1", "ip xEthernet 2 x", "ip Ethernet 22",
		"shutdown Port-channel 10", "shutdown Port-channel1 0", "shutdown port-channel10"} {
		expect(t, xe, line, false, decision.NoPermitDominatesDeny)
	}
	for _, line := range []string{"interface Gigabit x", "interface Gigabit 1 2", "shutdown Port-channel 1"} {
		expect(t, xe, line, true, decision.PermitDominates)
	}
}

// A deny's `*` is "any one argument", and authors write it where the
// interface goes; on IOS-XE that argument arrives as a name and an index
// (tests/lab/results/L21-cisco_iosxe.md), so the `*` also takes a letters
// name followed by an index-shaped argument, or the deny stops binding and
// the daemon permits what explain denies (spec §3 rule 5).
func TestADenyAnyTermMatchesTheSplitName(t *testing.T) {
	b := testBlob(true, "admin:permit **", "d:deny default interface *", "c:deny show interfaces * counters")
	b.Normalize.SplitsInterfaceNames = true
	xe := compileBlob(t, b)
	for _, line := range []string{"default interface GigabitEthernet 1", "default interface Loopback0",
		"show interfaces GigabitEthernet 1 counters", "show interfaces Port-channel 10 counters",
		"show interfaces Gi1 counters"} {
		expect(t, xe, line, false, decision.NoPermitDominatesDeny)
	}
	// Only a name and an index join: two words, or a number and an index,
	// are two arguments the `*` does not take.
	for _, line := range []string{"default interface GigabitEthernet x", "default interface 1 1",
		"show interfaces GigabitEthernet 1 2 counters"} {
		expect(t, xe, line, true, decision.PermitDominates)
	}
	// A permit's `*` is never split: it matches only as written.
	pb := testBlob(true, "net:permit default interface *")
	pb.Normalize.SplitsInterfaceNames = true
	expect(t, compileBlob(t, pb), "default interface GigabitEthernet 1", false, decision.NoRuleMatched)
}

// A platform measured sending no per-command authorization (Junos; spec §13
// decision 21) has no command to widen for, so no deny is widened or refused
// for it: a command that did arrive is matched as written.
func TestASessionOnlyPlatformWidensNothing(t *testing.T) {
	b := testBlob(false, "admin:permit **", "nd:deny reload **", "d:deny interface /Management/")
	expect(t, compileBlob(t, b), "interface x", false, decision.NoPermitDominatesDeny)
	b.Normalize.SessionOnly = true
	p := compileBlob(t, b)
	expect(t, p, "rel", true, decision.PermitDominates)
	expect(t, p, "reload", false, decision.NoPermitDominatesDeny)
	expect(t, p, "interface xManagementx", false, decision.NoPermitDominatesDeny)
	expect(t, p, "interface x", true, decision.PermitDominates)
	if got := WidenedToAny("interface /Management/", nil, b.Normalize); len(got) != 0 {
		t.Errorf("%q", got)
	}
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
