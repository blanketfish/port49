package engine

import (
	"fmt"
	"testing"
	"time"
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

// A permit naming the split interface a deny names joined overrides it where
// the platform splits names, and is a shadow there only.
func TestASplitNameIsAShadowWhereThePlatformSplits(t *testing.T) {
	b := testBlob(true, "p:permit interface GigabitEthernet 1 shutdown", "d:deny interface GigabitEthernet1 **")
	if got := compileBlob(t, b).Shadows(); len(got) != 0 {
		t.Fatalf("joined: %+v", got)
	}
	b.Normalize.SplitsInterfaceNames = true
	if got := compileBlob(t, b).Shadows(); len(got) != 1 || got[0].Deny.Rule != "interface GigabitEthernet1 **" || got[0].Possible {
		t.Fatalf("split: %+v", got)
	}
	// A deny the permit overrides both as written and split is one shadow.
	b.Rules[1].Rule = "interface /^Gig.*/ **"
	if got := compileBlob(t, b).Shadows(); len(got) != 1 || got[0].Possible {
		t.Fatalf("both ways: %+v", got)
	}
}

// wideBlob is a policy's worth of rules on a platform that abbreviates and
// splits interface names, the dialect that asks overlap the most: 84 permits,
// most of them patterns and some unanchored, against 24 denies, most of them
// long interface words at the same positions, so nearly every pair reads a
// pattern against a padded word and its abbreviations and splits.
func wideBlob() Blob {
	permitForms := []string{
		"show interfaces /^Ethernet%d(\\/[0-9]+)?$/ **",
		"show interfaces @physical counters",
		"show log /^messages[0-9]*$/ %d",
		"ping /^10\\.%d\\.[0-9.]+$/ count /^[0-9]+$/",
		"show /^(ver|VER)(sion)?$/ %d",
		"clear counters /^Ethernet%d/",
		"show running-config /^interface-%d$/ **",
		"show ip route /^10\\.%d\\./ **",
		"show interfaces * status %d",
		"show lldp neighbors /^Eth[0-9]+$/ %d",
		"show interfaces /[0-9]$/ counters %d",
		"show /\\s*run/ %d **",
		"show interfaces /Port-Channel\\s*[0-9]+/ %d",
		"show interfaces /^(Gi|Te|Hu)[a-z]*[0-9/]+$/ %d **",
	}
	denyRules := []string{
		"show interfaces Management1", "show interfaces Management1 **", "show running-config",
		"show running-config interface-0 **", "reload **", "configure terminal", "show interfaces Ethernet1 **",
		"show log messages 3", "ping 10.0.0.1 count 5", "show ip route 10.1.1.1", "show version 4",
		"clear counters Ethernet1", "show interfaces Gi1 status 2", "show lldp neighbors Ethernet12 7",
		"copy running-config startup-config", "show interfaces Port-Channel1 counters",
		"show ip route 10.2.0.0 longer-prefixes", "clear counters Management1", "show log messages 9",
		"show interfaces Ethernet3/1 transceiver", "show interfaces GigabitEthernet1/0/1 counters",
		"show interfaces TenGigabitEthernet1/1/1 1", "show running-config interface Port-Channel10",
		"show interfaces HundredGigE1/0/49 2 status",
	}
	var lines []string
	for i := 0; i < 84; i++ {
		f := permitForms[i%len(permitForms)]
		if n := i / len(permitForms); countVerbs(f) > 0 {
			f = fmt.Sprintf(f, n)
		}
		lines = append(lines, "a:permit "+f)
	}
	for _, d := range denyRules {
		lines = append(lines, "b:deny "+d)
	}
	b := testBlob(false, lines...)
	b.Normalize.SplitsInterfaceNames = true
	return b
}

func countVerbs(f string) int {
	n := 0
	for i := 0; i+1 < len(f); i++ {
		if f[i] == '%' && f[i+1] == 'd' {
			n++
		}
	}
	return n
}

// BenchmarkShadows times Shadows on a freshly compiled program each time,
// as `port49 policy test` runs it once per blob: a term's reader keeps what
// it has read, so a program asked twice would time only the second, warm
// run. Compile is timed apart so its share can be told.
func BenchmarkShadows(b *testing.B) {
	blob := wideBlob()
	for _, tt := range []struct {
		name string
		n    Normalize
	}{
		{"session_only", Normalize{PipeToken: "|", StripCR: true, SessionOnly: true}},
		{"abbreviating", Normalize{PipeToken: "|", StripCR: true}},
		{"abbreviating_split", blob.Normalize},
	} {
		blob := blob
		blob.Normalize = tt.n
		b.Run(tt.name+"/compile", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if _, err := Compile(blob); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run(tt.name+"/compile_and_shadows", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				p, err := Compile(blob)
				if err != nil {
					b.Fatal(err)
				}
				p.Shadows()
			}
		})
	}
}

// The shadowed-deny report runs once per device, subject and instant in
// `port49 policy test`, so a blob's report has to come back in milliseconds:
// the widest dialect's, on a policy's worth of rules, within 10ms. Each run
// is on a freshly compiled program, so nothing a reader kept is reused, and
// the best of five is timed so a busy machine does not fail it.
func TestShadowsComeBackFast(t *testing.T) {
	if raceBuild {
		t.Skip("the race detector slows the engine several times over; the bound is for a plain build")
	}
	best := time.Hour
	for i := 0; i < 5; i++ {
		p, err := Compile(wideBlob())
		if err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		p.Shadows()
		best = min(best, time.Since(start))
	}
	if best > 10*time.Millisecond {
		t.Errorf("Shadows() took %v on the abbreviating, splitting blob; the bound is 10ms", best)
	}
	t.Logf("Shadows() on the abbreviating, splitting blob: %v", best)
}
