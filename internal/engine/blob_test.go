package engine

import (
	"errors"
	"strings"
	"testing"
)

// eos is a small compiled blob in the shape the broker writes.
func eos() Blob {
	return Blob{Bundle: "sha256:policy", Platform: "arista_eos",
		Normalize: Normalize{PipeToken: "|", StripCR: true},
		Privilege: "admin", Attributes: []string{"priv-lvl=15", "home-directory*/home/{username}"},
		Rules: []Rule{
			{Verdict: Permit, Rule: "show **", Role: "read_only"},
			{Verdict: Deny, Rule: "interface @management", Role: "interface_tech"},
		},
		Pipe:    []string{"include **"},
		Classes: map[string][]string{"management": {`^Management[0-9]+$`}, "unused": {`^x$`}},
	}
}

// A blob is named by its content: one decision, one hash (spec §5.1.1). The
// canonical form is what makes that true — rule order, spacing and repeats,
// pattern order, and classes no rule names do not change the name.
func TestOneDecisionIsOneHash(t *testing.T) {
	body, h1, err := Encode(eos())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h1, "sha256:") || HashOf(body) != h1 {
		t.Fatalf("hash %q", h1)
	}
	shuffled := eos()
	shuffled.Rules = []Rule{
		{Verdict: Deny, Rule: "interface   @management", Role: "interface_tech"},
		{Verdict: Permit, Rule: "show **", Role: "read_only"},
		{Verdict: Permit, Rule: " show ** ", Role: "read_only"},
	}
	shuffled.Classes = map[string][]string{"management": {`^Management[0-9]+$`, `^Management[0-9]+$`}}
	if _, h2, err := Encode(shuffled); err != nil || h2 != h1 {
		t.Fatalf("the same decision, reordered, got %s %v; want %s", h2, err, h1)
	}
	other := eos()
	other.Platform = "cisco_nxos"
	if _, h3, _ := Encode(other); h3 == h1 {
		t.Fatal("two platforms must not share a blob")
	}
	reordered := eos()
	reordered.Attributes = []string{"home-directory*/home/{username}", "priv-lvl=15"}
	if _, h4, _ := Encode(reordered); h4 == h1 {
		t.Fatal("attributes go on the wire in order; Encode must not reorder them")
	}
	in := eos()
	Encode(in)
	if in.Rules[0].Rule != "show **" || len(in.Classes) != 2 {
		t.Fatal("Encode must not mutate the caller's blob")
	}
}

func TestDecodeRoundTrips(t *testing.T) {
	body, hash, _ := Encode(eos())
	b, err := Decode(hash, body)
	if err != nil {
		t.Fatal(err)
	}
	if b.Version != Version || b.Platform != "arista_eos" || len(b.Rules) != 2 || len(b.Classes) != 1 ||
		b.Classes["management"][0] != `^Management[0-9]+$` || b.Attributes[1] != "home-directory*/home/{username}" {
		t.Fatalf("round trip: %+v", b)
	}
}

// A blob the daemon cannot fully decide with is refused, never half-read
// (spec §5.1.2). The hash proves the bytes are the ones named, not that this
// build understands them.
func TestDecodeRefusesWhatItCannotDecideWith(t *testing.T) {
	body, hash, _ := Encode(eos())
	tampered := []byte(strings.Replace(string(body), `show **`, `show *`, 1))
	if _, err := Decode(hash, tampered); !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("a tampered body must be refused as a hash mismatch: %v", err)
	}
	const head = `{"version":2,"bundle":"b","platform":"arista_eos","normalize":{"pipe_token":"|","pipe_authorized":false,"strip_cr":true,"expands_abbreviations":false},"privilege":"","attributes":[],`
	for name, tt := range map[string]struct{ body, want string }{
		"plan 3's slice blob": {`{"platform":"arista_eos","privilege":15,"attributes":[],"permit":["**"],"deny":[]}`, "plan 3's"},
		"a newer version":     {strings.Replace(head, `"version":2`, `"version":3`, 1) + `"rules":[],"pipe":[],"classes":{}}`, "format version 3"},
		"an unknown field":    {head + `"rules":[],"pipe":[],"classes":{},"extra":1}`, `unknown field "extra"`},
		"trailing bytes":      {head + `"rules":[],"pipe":[],"classes":{}} {}`, "bytes after the blob"},
		"no platform":         {strings.Replace(head, `"arista_eos"`, `""`, 1) + `"rules":[],"pipe":[],"classes":{}}`, "names no platform"},
		"no pipe token":       {strings.Replace(head, `"pipe_token":"|"`, `"pipe_token":""`, 1) + `"rules":[],"pipe":[],"classes":{}}`, "no pipe token"},
		"a class with no pattern": {head + `"rules":[{"verdict":"deny","rule":"interface @management","role":"r"}],` +
			`"pipe":[],"classes":{}}`, "carries no pattern"},
		"a regex RE2 refuses": {head + `"rules":[{"verdict":"deny","rule":"interface /(?!x)/","role":"r"}],"pipe":[],"classes":{}}`, "regex"},
		"a verdict that is neither": {head + `"rules":[{"verdict":"allow","rule":"show **","role":"r"}],` +
			`"pipe":[],"classes":{}}`, "neither permit nor deny"},
		"a rule with no role":          {head + `"rules":[{"verdict":"permit","rule":"show **","role":""}],"pipe":[],"classes":{}}`, "names no role"},
		"a non-trailing **":            {head + `"rules":[{"verdict":"permit","rule":"show ** detail","role":"r"}],"pipe":[],"classes":{}}`, "trailing-only"},
		"an attribute with no sep":     {strings.Replace(head, `"attributes":[]`, `"attributes":["priv-lvl"]`, 1) + `"rules":[],"pipe":[],"classes":{}}`, "separator"},
		"an unknown substitution":      {strings.Replace(head, `"attributes":[]`, `"attributes":["home*{home}"]`, 1) + `"rules":[],"pipe":[],"classes":{}}`, "not a substitution"},
		"a pipe rule that won't parse": {head + `"rules":[],"pipe":["** include"],"classes":{}}`, "pipe rule"},
	} {
		if b, err := Decode(HashOf([]byte(tt.body)), []byte(tt.body)); err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: decoded %+v, %v; want an error mentioning %q", name, b, err, tt.want)
		}
	}
}

// Encode refuses what Decode would refuse: a daemon must never be handed a
// blob it cannot read.
func TestEncodeRefusesWhatDecodeRefuses(t *testing.T) {
	for name, tt := range map[string]struct {
		mutate func(*Blob)
		want   string
	}{
		"no platform":          {func(b *Blob) { b.Platform = "" }, "names no platform"},
		"an undefined class":   {func(b *Blob) { b.Classes = nil }, "carries no pattern"},
		"a bad attribute":      {func(b *Blob) { b.Attributes = []string{"=15"} }, "empty name"},
		"a rule with no role":  {func(b *Blob) { b.Rules[0].Role = "" }, "names no role"},
		"no pipe token":        {func(b *Blob) { b.Normalize.PipeToken = "" }, "no pipe token"},
		"an unparseable rule":  {func(b *Blob) { b.Rules[0].Rule = "show int*" }, "whole term"},
		"an unknown verdict":   {func(b *Blob) { b.Rules[0].Verdict = "allow" }, "neither permit nor deny"},
		"an empty regex":       {func(b *Blob) { b.Rules[0].Rule = "show //" }, "empty regex"},
		"a class not snake":    {func(b *Blob) { b.Rules[0].Rule = "interface @Mgmt" }, "not a class name"},
		"a wildcard in a word": {func(b *Blob) { b.Pipe = []string{"inc*"} }, "whole term"},
	} {
		b := eos()
		tt.mutate(&b)
		if _, _, err := Encode(b); err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: Encode = %v, want an error mentioning %q", name, err, tt.want)
		}
	}
}

// Spec §4's grammar: five term kinds, ranked 3, 2, 2, 1, 0.
func TestParseRule(t *testing.T) {
	terms, err := ParseRule("interface @physical /^Ethernet1$/ * **")
	if err != nil {
		t.Fatal(err)
	}
	want := []struct {
		kind Kind
		text string
		rank int
	}{{Word, "interface", 3}, {Class, "physical", 2}, {Regex, "^Ethernet1$", 2}, {Any, "", 1}, {Rest, "", 0}}
	for i, w := range want {
		if terms[i].Kind != w.kind || terms[i].Text != w.text || terms[i].Kind.Rank() != w.rank {
			t.Errorf("term %d: %+v rank %d, want %+v", i, terms[i], terms[i].Kind.Rank(), w)
		}
	}
	for rule, want := range map[string]string{
		"":               "empty",
		"show ** detail": "trailing-only",
		"show int*":      "whole term",
		"interface @":    "class name",
		"show //":        "empty regex",
		"show /(?=x)/":   "regex",
	} {
		if _, err := ParseRule(rule); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("ParseRule(%q) = %v, want an error mentioning %q", rule, err, want)
		}
	}
	if CanonicalRule("  show   version ") != "show version" {
		t.Error("CanonicalRule respaces")
	}
}

// Spec §6: exactly one separator's worth of structure, a name, 255 bytes, and
// the four substitutions and nothing else.
func TestCheckAttribute(t *testing.T) {
	for _, ok := range []string{"priv-lvl=15", "shell:roles*network-admin", `cisco-av-pair*shell:roles="x"`,
		"home-directory*/home/{username}", "F5-LTM-User-Partition*{device}"} {
		if err := CheckAttribute(ok); err != nil {
			t.Errorf("CheckAttribute(%q): %v", ok, err)
		}
	}
	for a, want := range map[string]string{
		"priv-lvl":                          "separator",
		"=15":                               "empty name",
		"priv lvl=15":                       "whitespace",
		"x=" + strings.Repeat("a", 254):     "255",
		"home-directory*/home/{user}":       "not a substitution",
		"home-directory*/home/{username}{}": "not a substitution",
	} {
		if err := CheckAttribute(a); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("CheckAttribute(%q) = %v, want an error mentioning %q", a, err, want)
		}
	}
	if AttributeName("shell:roles*x=y") != "shell:roles" || !Mandatory("priv-lvl=15") || Mandatory("priv-lvl*15") {
		t.Error("the separator is the first `=` or `*`")
	}
}

// Substitution happens per session, from the context and the device, and the
// result is refused rather than truncated when it will not fit on the wire.
func TestSessionAttributesSubstitute(t *testing.T) {
	b := eos()
	b.Attributes = []string{"home-directory*/home/{username}", "note*{principal} on {device} at {privilege}"}
	got, err := b.SessionAttributes(Values{Username: "alice", Principal: "user:alice@example.com", Device: "leaf-01"})
	if err != nil {
		t.Fatal(err)
	}
	if got[0] != "home-directory*/home/alice" || got[1] != "note*user:alice@example.com on leaf-01 at admin" {
		t.Fatalf("substituted: %q", got)
	}
	if b.Attributes[0] != "home-directory*/home/{username}" {
		t.Fatal("SessionAttributes must not rewrite the blob")
	}
	if _, err := b.SessionAttributes(Values{Username: strings.Repeat("a", 250)}); !errors.Is(err, ErrAttributeTooLong) {
		t.Fatalf("an over-long substitution: %v", err)
	}
}
