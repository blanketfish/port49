package blob

import (
	"errors"
	"strings"
	"testing"
)

func eos() Blob {
	return Blob{Platform: "arista_eos", Privilege: 15, Attributes: []string{"priv-lvl=15"},
		Permit: []string{"**"}, Deny: []string{"reload **", "show hostname"}}
}

// A blob is named by its content: the same decision encodes to the same bytes
// and the same hash, which is what lets a sweep collapse to one blob per
// platform (spec §5.1.1).
func TestEncodeIsContentAddressed(t *testing.T) {
	b1, h1, err := Encode(eos())
	if err != nil {
		t.Fatal(err)
	}
	b2, h2, _ := Encode(eos())
	if h1 != h2 || string(b1) != string(b2) || !strings.HasPrefix(h1, "sha256:") || h1 != HashOf(b1) {
		t.Fatalf("encode is not stable: %s %s", h1, h2)
	}
	other := eos()
	other.Platform = "cisco_nxos"
	if _, h3, _ := Encode(other); h3 == h1 {
		t.Fatal("two platforms must not share a blob")
	}
}

func TestDecodeRoundTripsAndRefusesATamperedBody(t *testing.T) {
	body, hash, _ := Encode(eos())
	got, err := Decode(hash, body)
	if err != nil || got.Platform != "arista_eos" || got.Privilege != 15 || len(got.Deny) != 2 {
		t.Fatalf("round trip: %+v %v", got, err)
	}
	tampered := []byte(strings.Replace(string(body), `"reload **"`, `"reboot **"`, 1))
	if _, err := Decode(hash, tampered); !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("a body that does not hash to its name must be refused: %v", err)
	}
	unknown := []byte(`{"platform":"arista_eos","extra":1}`)
	if _, err := Decode(HashOf(unknown), unknown); err == nil {
		t.Fatal("a blob with a field this daemon does not know must be refused, not half-read")
	}
}

// Spec §4: rules match the whole vector, words case-insensitively, `*` one
// argument, `**` zero or more and only at the end.
func TestMatches(t *testing.T) {
	for _, tt := range []struct {
		rule   string
		vector []string
		want   bool
	}{
		{"show **", []string{"show"}, true},
		{"show **", []string{"show", "version"}, true},
		{"show version", []string{"SHOW", "Version"}, true},
		{"show version", []string{"show", "version", "detail"}, false},
		{"show bgp summary", []string{"show", "bgp"}, false},
		{"clear counters *", []string{"clear", "counters", "Ethernet1"}, true},
		{"clear counters *", []string{"clear", "counters"}, false},
		{"**", nil, true},
		{"reload **", []string{"show", "reload"}, false},
	} {
		if got := Matches(tt.rule, tt.vector); got != tt.want {
			t.Errorf("Matches(%q, %q) = %v, want %v", tt.rule, tt.vector, got, tt.want)
		}
	}
}

// Everything outside the subset is refused by name rather than matched as a
// word: `@physical` read literally would silently never match (spec §4).
func TestCheckRuleRefusesWhatThePolicyEngineOwns(t *testing.T) {
	for _, ok := range []string{"show **", "clear counters *", "**", "show  version"} {
		if err := CheckRule(ok); err != nil {
			t.Errorf("CheckRule(%q): %v", ok, err)
		}
	}
	for rule, want := range map[string]string{
		"":                           "empty",
		"show ** detail":             "trailing-only",
		"interface @physical":        "plan 4",
		"interface /^Ethernet[0-9]/": "plan 4",
		"show int*":                  "whole term",
	} {
		if err := CheckRule(rule); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("CheckRule(%q) = %v, want an error mentioning %q", rule, err, want)
		}
	}
}

// Deny-overrides: a matching deny refuses whatever permit also matches.
func TestCommandVerdicts(t *testing.T) {
	b := eos()
	for _, tt := range []struct {
		vector []string
		want   Verdict
	}{
		{[]string{"show", "version"}, Permitted},
		{[]string{"show", "hostname"}, Denied},
		{[]string{"reload", "now"}, Denied},
	} {
		if got := b.Command(tt.vector); got != tt.want {
			t.Errorf("Command(%q) = %v, want %v", tt.vector, got, tt.want)
		}
	}
	if got := (Blob{Permit: []string{"show **"}}).Command([]string{"configure"}); got != NoRuleMatched {
		t.Errorf("an unmatched command is NoRuleMatched, got %v", got)
	}
}

// A correctly named body is not therefore understood: a rule outside the
// subset, or a blob naming no platform, is refused rather than read. Read, a
// misplaced `**` permits too much and an unknown class drops a deny.
func TestDecodeRefusesWhatItCannotMatch(t *testing.T) {
	for name, body := range map[string]string{
		"non-trailing **":         `{"platform":"arista_eos","privilege":15,"attributes":[],"permit":["show ** detail"],"deny":[]}`,
		"unknown class in a deny": `{"platform":"arista_eos","privilege":15,"attributes":[],"permit":["**"],"deny":["reload @now"]}`,
		"empty rule":              `{"platform":"arista_eos","privilege":15,"attributes":[],"permit":[""],"deny":[]}`,
		"null body":               `null`,
		"no platform":             `{"privilege":15,"attributes":[],"permit":["**"],"deny":[]}`,
		"trailing bytes":          `{"platform":"arista_eos","privilege":15,"attributes":[],"permit":[],"deny":[]} {}`,
	} {
		if b, err := Decode(HashOf([]byte(body)), []byte(body)); err == nil {
			t.Errorf("%s: decoded %+v, want an error", name, b)
		}
	}
}

// Matches stands on its own: a caller that skipped CheckRule still cannot
// make a rule outside the subset match more than it says.
func TestMatchesRefusesWhatCheckRuleRefuses(t *testing.T) {
	for _, tt := range []struct {
		rule   string
		vector []string
	}{
		{"show ** detail", []string{"show", "running-config"}},
		{"", nil},
		{"   ", nil},
	} {
		if Matches(tt.rule, tt.vector) {
			t.Errorf("Matches(%q, %q) = true, want false", tt.rule, tt.vector)
		}
	}
}

// One decision, one name: nil and empty, spacing, order and duplicates of
// the rules do not change the hash. Attribute order is the wire's, and kept.
func TestEncodeCanonicalizes(t *testing.T) {
	_, want, err := Encode(Blob{Platform: "arista_eos", Attributes: []string{},
		Permit: []string{"show version"}, Deny: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string]Blob{
		"nil slices": {Platform: "arista_eos", Permit: []string{"show version"}},
		"spacing":    {Platform: "arista_eos", Permit: []string{"  show   version "}},
		"duplicates": {Platform: "arista_eos", Permit: []string{"show version", "show  version"}},
	} {
		if _, got, err := Encode(b); err != nil || got != want {
			t.Errorf("%s: %s %v, want %s", name, got, err, want)
		}
	}
	_, h1, _ := Encode(Blob{Platform: "p", Permit: []string{"a", "b"}, Deny: []string{"c", "d"}})
	_, h2, _ := Encode(Blob{Platform: "p", Permit: []string{"b", "a"}, Deny: []string{"d", "c"}})
	if h1 != h2 {
		t.Error("rule order must not change the hash: deny-overrides is order-independent")
	}
	_, a1, _ := Encode(Blob{Platform: "p", Attributes: []string{"x=1", "y=2"}})
	_, a2, _ := Encode(Blob{Platform: "p", Attributes: []string{"y=2", "x=1"}})
	if a1 == a2 {
		t.Error("attributes go on the wire in order; Encode must not reorder them")
	}
	in := Blob{Platform: "p", Permit: []string{"b", "a"}}
	Encode(in)
	if in.Permit[0] != "b" {
		t.Error("Encode must not mutate the caller's slices")
	}
}

// Encode refuses what Decode would refuse: a daemon must never be handed a
// blob it cannot read.
func TestEncodeRefusesWhatDecodeRefuses(t *testing.T) {
	for name, b := range map[string]Blob{
		"no platform": {Permit: []string{"**"}},
		"bad rule":    {Platform: "p", Deny: []string{"reload @now"}},
	} {
		if _, _, err := Encode(b); err == nil {
			t.Errorf("%s: encoded, want an error", name)
		}
	}
}
