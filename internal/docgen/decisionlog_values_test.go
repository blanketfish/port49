package docgen

import (
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
)

func TestEveryEventTheCodeNamesHasATableRow(t *testing.T) {
	desc, err := LoadDecisionLogDescriptions(repoRoot)
	if err != nil {
		t.Fatal(err)
	}
	page, err := DecisionLogPage(readSpec(t), desc)
	if err != nil {
		t.Fatal(err)
	}
	events, err := EventNames(repoRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) < 20 {
		t.Fatalf("EventNames found only %v: the parse is broken", events)
	}
	for _, e := range events {
		if !strings.Contains(page, "| `"+e+"` |") {
			t.Errorf("the events tables have no row for the event %q", e)
		}
	}
}

func TestAReasonCodeListedTwiceInTheSpecIsRefused(t *testing.T) {
	spec := []byte("#### Reason codes\n\n| reason | Meaning |\n|---|---|\n| `grants_matched` | one |\n| `grants_matched` | two |\n")
	_, err := ReasonPage(spec)
	if err == nil || !strings.Contains(err.Error(), "grants_matched appears twice") {
		t.Fatalf("err = %v, want a duplicate row named", err)
	}
}

func TestAnOpenLabIDRendersWithItsStatusAndALink(t *testing.T) {
	reg := map[string]LabRow{"L4": {ID: "L4", Open: true}, "L9": {ID: "L9"}}
	got, err := RenderLabIDs("a `L4` claim, see L9 and (L4).", reg, "lab-register.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"[L4 (open)](lab-register.md#l4)", "[L9 (closed)](lab-register.md#l9)"} {
		if !strings.Contains(got, want) {
			t.Errorf("RenderLabIDs = %q, want it to hold %q", got, want)
		}
	}
	if strings.Contains(got, "`L4`") {
		t.Errorf("a code-span ID stays in its span: %q", got)
	}
	if _, err := RenderLabIDs("see L99", reg, "lab-register.md"); err == nil {
		t.Error("an ID that is not in the register is an error")
	}
}

func TestTheGeneratedPagesRenderTheirLabIDsWithStatus(t *testing.T) {
	desc, err := LoadDecisionLogDescriptions(repoRoot)
	if err != nil {
		t.Fatal(err)
	}
	spec := readSpec(t)
	log, err := DecisionLogPage(spec, desc)
	if err != nil {
		t.Fatal(err)
	}
	reasons, err := ReasonPage(spec)
	if err != nil {
		t.Fatal(err)
	}
	bare := regexp.MustCompile("(^|[^\\[A-Za-z0-9_/])L[0-9]+[a-z]?\\b")
	for name, page := range map[string]string{"decision log": log, "reason codes": reasons} {
		if m := bare.FindString(page); m != "" {
			t.Errorf("%s page has a lab ID without its status: %q", name, m)
		}
	}
}

// The value lists the descriptions give must be the lists the code holds. A backticked word in the
// description is a value unless it is listed in others.
func TestDescribedValueListsAreTheCodesValues(t *testing.T) {
	desc, err := LoadDecisionLogDescriptions(repoRoot)
	if err != nil {
		t.Fatal(err)
	}
	attribution, err := AttributionValues(repoRoot)
	if err != nil {
		t.Fatal(err)
	}
	diagnosis, err := DiagnosisValues(repoRoot)
	if err != nil {
		t.Fatal(err)
	}
	kinds, err := SecurityChangeKinds(repoRoot)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		key    string
		code   []string
		others []string
	}{
		{"attribution", attribution, []string{"account"}},
		{"unvalidated.diagnosis", diagnosis, []string{"key_ref"}},
		{"change.kind", kinds, []string{"transport", "platform"}},
	}
	word := regexp.MustCompile("`([a-z][a-z0-9_]*)`")
	for _, c := range cases {
		if len(c.code) < 3 {
			t.Errorf("%s: the parse found only %v", c.key, c.code)
		}
		have := map[string]bool{}
		for _, m := range word.FindAllStringSubmatch(desc[c.key], -1) {
			have[m[1]] = true
		}
		for _, v := range c.code {
			if !have[v] {
				t.Errorf("%s: the description does not name the code's value %q", c.key, v)
			}
			delete(have, v)
		}
		for _, o := range c.others {
			delete(have, o)
		}
		var extra []string
		for v := range have {
			extra = append(extra, v)
		}
		sort.Strings(extra)
		if len(extra) > 0 {
			t.Errorf("%s: the description names %v, which the code does not", c.key, extra)
		}
	}
	if !slices.Contains(attribution, "foreign") {
		t.Errorf("attribution values %v lack foreign", attribution)
	}
}
