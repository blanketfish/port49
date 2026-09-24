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

func mustEncode(t *testing.T, b Blob) ([]byte, string) {
	t.Helper()
	body, hash, err := Encode(b)
	if err != nil {
		t.Fatal(err)
	}
	return body, hash
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
	if _, h3 := mustEncode(t, other); h3 == h1 {
		t.Fatal("two platforms must not share a blob")
	}
	reordered := eos()
	reordered.Attributes = []string{"home-directory*/home/{username}", "priv-lvl=15"}
	if _, h4 := mustEncode(t, reordered); h4 == h1 {
		t.Fatal("attributes go on the wire in order; Encode must not reorder them")
	}
	in := eos()
	mustEncode(t, in)
	if in.Rules[0].Rule != "show **" || len(in.Classes) != 2 {
		t.Fatal("Encode must not mutate the caller's blob")
	}
}

func TestDecodeRoundTrips(t *testing.T) {
	body, hash := mustEncode(t, eos())
	b, err := Decode(hash, body)
	if err != nil {
		t.Fatal(err)
	}
	if b.Version != Version || b.Platform != "arista_eos" || len(b.Rules) != 2 || len(b.Classes) != 1 ||
		b.Classes["management"][0] != `^Management[0-9]+$` || b.Attributes[1] != "home-directory*/home/{username}" {
		t.Fatalf("round trip: %+v", b)
	}
	if again, _ := mustEncode(t, b); string(again) != string(body) {
		t.Fatalf("Encode(Decode(body)) is not body:\n%s\n%s", again, body)
	}
}

// encoding/json reads keys case-insensitively and lets a repeated key's last
// value win. A body whose bytes show a rule the daemon would not evaluate is
// refused: the canonical form is the only spelling a blob has.
func TestDecodeRefusesANonCanonicalBody(t *testing.T) {
	body, _ := mustEncode(t, eos())
	for name, b := range map[string]string{
		"a duplicate rules key": strings.Replace(string(body), `"rules":[`,
			`"rules":[{"verdict":"deny","rule":"show **","role":"r"}],"rules":[`, 1),
		"a case-variant key":       strings.Replace(string(body), `"version"`, `"VERSION"`, 1),
		"insignificant whitespace": strings.Replace(string(body), `{`, `{ `, 1),
	} {
		if b == string(body) {
			t.Fatalf("%s: the mutation did not apply", name)
		}
		if _, err := Decode(HashOf([]byte(b)), []byte(b)); err == nil || !strings.Contains(err.Error(), "canonical") {
			t.Errorf("%s: Decode = %v, want a canonical-form refusal", name, err)
		}
	}
}

// A blob the daemon cannot fully decide with is refused, never half-read
// (spec §5.1.2). The hash proves the bytes are the ones named, not that this
// build understands them.
func TestDecodeRefusesWhatItCannotDecideWith(t *testing.T) {
	body, hash := mustEncode(t, eos())
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

// A dialect flag added after version 2 is written only when set, so a v2 blob
// written without it still decodes, reads it as false, and is still the one
// canonical spelling of its decision; the flag set is a different blob.
func TestALaterDialectFlagIsOmittedWhenFalse(t *testing.T) {
	const v2 = `{"version":2,"bundle":"b","platform":"cisco_iosxe","normalize":{"pipe_token":"|","pipe_authorized":false,` +
		`"strip_cr":true,"expands_abbreviations":true},"privilege":"","attributes":[],"rules":[],"pipe":[],"classes":{}}`
	b, err := Decode(HashOf([]byte(v2)), []byte(v2))
	if err != nil || b.Normalize.SplitsInterfaceNames {
		t.Fatalf("a v2 blob without the key: %+v, %v", b.Normalize, err)
	}
	body, hash, err := Encode(b)
	if err != nil || string(body) != v2 || hash != HashOf([]byte(v2)) {
		t.Fatalf("re-encoded as %s, %v", body, err)
	}
	b.Normalize.SplitsInterfaceNames = true
	body, split, err := Encode(b)
	if err != nil || split == hash || !strings.Contains(string(body), `"splits_interface_names":true`) {
		t.Fatalf("set: %s %v", body, err)
	}
	if _, err := Decode(split, body); err != nil {
		t.Fatal(err)
	}
}

// The adapter's accepted_attributes ride in the blob so the daemon refuses a
// reply the device would refuse, under whatever adapter the policy merged. A
// v2 blob written without the key decodes as no restriction and keeps its
// hash; set, the list is sorted and deduplicated, so it has one spelling.
func TestAcceptedAttributesAreCanonicalAndOmittedWhenEmpty(t *testing.T) {
	const v2 = `{"version":2,"bundle":"b","platform":"cisco_iosxe","normalize":{"pipe_token":"|","pipe_authorized":false,` +
		`"strip_cr":true,"expands_abbreviations":true},"privilege":"","attributes":["priv-lvl=1"],"rules":[],"pipe":[],"classes":{}}`
	b, err := Decode(HashOf([]byte(v2)), []byte(v2))
	if err != nil || b.AcceptedAttributes != nil || !b.Accepts("idletime*30") {
		t.Fatalf("a v2 blob without the key: %+v, %v", b.AcceptedAttributes, err)
	}
	b.AcceptedAttributes = []string{}
	if body, _, err := Encode(b); err != nil || string(body) != v2 {
		t.Fatalf("an empty list is no list: %s %v", body, err)
	}
	b.AcceptedAttributes = []string{"priv-lvl", "idletime", "priv-lvl"}
	body, hash, err := Encode(b)
	if err != nil || hash == HashOf([]byte(v2)) ||
		!strings.Contains(string(body), `"attributes":["priv-lvl=1"],"accepted_attributes":["idletime","priv-lvl"],`) {
		t.Fatalf("set: %s %v", body, err)
	}
	got, err := Decode(hash, body)
	if err != nil || !got.Accepts("priv-lvl*15") || !got.Accepts("idletime=5") || got.Accepts("roles=x") {
		t.Fatalf("round trip: %+v %v", got.AcceptedAttributes, err)
	}
	unsorted := strings.Replace(string(body), `["idletime","priv-lvl"]`, `["priv-lvl","idletime"]`, 1)
	if _, err := Decode(HashOf([]byte(unsorted)), []byte(unsorted)); err == nil || !strings.Contains(err.Error(), "canonical") {
		t.Fatalf("an unsorted list: %v", err)
	}
	for _, bad := range []string{"", "a=b", "a b", "a*", "a\xff"} {
		b.AcceptedAttributes = []string{bad}
		if _, _, err := Encode(b); err == nil {
			t.Errorf("%q: encoded", bad)
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
		"no bundle":            {func(b *Blob) { b.Bundle = "" }, "names no bundle"},
		"invalid UTF-8":        {func(b *Blob) { b.Attributes = []string{"a*\xff"} }, "invalid UTF-8"},
		"invalid UTF-8 role":   {func(b *Blob) { b.Rules[0].Role = "r\xff" }, "invalid UTF-8"},
		"a duplicate name":     {func(b *Blob) { b.Attributes = []string{"priv-lvl=1", "priv-lvl*15"} }, "appears twice"},
		"a name placeholder":   {func(b *Blob) { b.Attributes = []string{"{username}*x"} }, "only in the value"},
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
		"{username}*x":                      "only in the value",
		"shell:{device}=x":                  "only in the value",
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
	// A substituted value cannot start another attribute or smuggle a
	// separator: "priv-lvl=15 " as a username must not become a mandatory
	// priv-lvl anywhere in the reply.
	for _, u := range []string{"priv-lvl=15 ", "a*b", "a\nb", "a\x00b", "a\xffb"} {
		if got, err := b.SessionAttributes(Values{Username: u}); !errors.Is(err, ErrSubstitution) {
			t.Errorf("username %q: %q, %v; want ErrSubstitution", u, got, err)
		}
	}
	// A value the attribute does not use is not checked.
	plain := eos()
	plain.Attributes = []string{"priv-lvl=15"}
	if _, err := plain.SessionAttributes(Values{Username: "a=b"}); err != nil {
		t.Errorf("an unused value refused: %v", err)
	}
}
