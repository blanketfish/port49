package engine

import (
	"testing"
)

// A shadow is exactly a dominance that can happen (spec §5.4, §12): the
// motivating CVE case is one, a broad permit is none, and a deny the permit
// never meets is none.
func TestShadowsAreTheDominancesThatCanHappen(t *testing.T) {
	for _, tt := range []struct {
		name          string
		permit, deny  string
		want          bool
		wantPossible  bool
		expandsAbbrev bool
	}{
		{"the backup account's exception", "show chassis hardware", "show chassis **", true, false, true},
		{"a broader permit", "show **", "show chassis **", false, false, true},
		{"the tftp deny", "copy **", "* * /^tftp:/", false, false, true},
		{"equal tuples", "show version", "show version", false, false, true},
		{"never the same command", "show version", "reload **", false, false, true},
		{"a word the regex takes", "copy running-config tftp://x", "* * /^tftp:/", true, false, true},
		{"a word the regex refuses", "copy running-config scp://x", "* * /^tftp:/", false, false, true},
		{"a class against a regex", "copy running-config @backup_targets", "* * /^scp:/", true, true, true},
		{"a deny of everything", "show version", "**", true, false, true},
		// A case-sensitive permit matches a subset of what the same pattern
		// matches folded, so whether it meets the deny is still only possible.
		{"a case-sensitive permit", "copy running-config /(?-i)^TFTP:/", "* * /^tftp:/", true, true, true},
		{"a case-sensitive permit, same text", "copy running-config /(?-i)^tftp:/", "* * /(?-i)^tftp:/", true, false, true},
		// Where the platform may send what was typed, the deny's word also
		// takes its own abbreviations, and a permit written as one meets it.
		{"an abbreviation, sent as typed", "rel now", "reload **", true, false, false},
		{"an abbreviation, sent resolved", "rel now", "reload **", false, false, true},
		// The permit's word matches every case-fold of itself, and each is an
		// abbreviation the deny takes.
		{"a folded abbreviation", "ſh version", "show **", true, false, false},
		// A deny's class takes the abbreviations of its names the same way
		// (spec §3 rule 4), so a permit naming one is a shadow.
		{"an abbreviated name, sent as typed", "interface Ma1", "interface @management", true, false, false},
		{"an abbreviated name, sent resolved", "interface Ma1", "interface @management", false, false, true},
	} {
		p := program(t, tt.expandsAbbrev, "p:permit "+tt.permit, "d:deny "+tt.deny)
		got := p.Shadows()
		if (len(got) == 1) != tt.want {
			t.Errorf("%s: shadows %+v, want %v", tt.name, got, tt.want)
			continue
		}
		if tt.want && (got[0].Possible != tt.wantPossible || got[0].Deny.Rule != CanonicalRule(tt.deny) ||
			got[0].Permit.Role != "p") {
			t.Errorf("%s: %+v", tt.name, got[0])
		}
	}
}

// Shadows are listed in one order whatever the rules' order, so a report
// built on them is stable across a shuffled policy.
func TestShadowsAreOrdered(t *testing.T) {
	a := program(t, true, "x:permit show chassis hardware", "y:permit show chassis cluster status",
		"c:deny show chassis **", "b:deny show * hardware")
	b := program(t, true, "b:deny show * hardware", "c:deny show chassis **",
		"y:permit show chassis cluster status", "x:permit show chassis hardware")
	sa, sb := a.Shadows(), b.Shadows()
	if len(sa) != 3 || len(sb) != 3 {
		t.Fatalf("%+v / %+v", sa, sb)
	}
	for i := range sa {
		if sa[i] != sb[i] {
			t.Fatalf("order differs at %d: %+v / %+v", i, sa[i], sb[i])
		}
	}
	if sa[0].Deny.Role != "b" || sa[1].Permit.Role != "x" || sa[2].Permit.Role != "y" {
		t.Fatalf("%+v", sa)
	}
}
