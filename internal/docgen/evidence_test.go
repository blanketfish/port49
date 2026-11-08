package docgen

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const resultsDir = "../../tests/lab/results"

var leadsWithLabID = regexp.MustCompile(`^L[0-9]+[a-z]?-.*\.md$`)

func TestEveryResultsNoteBelongsToOnePage(t *testing.T) {
	entries, err := os.ReadDir(resultsDir)
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, e := range entries {
		name := e.Name()
		if !leadsWithLabID.MatchString(name) {
			continue // load-*, slice-*, session-*, QUAL-* and the yaml files are outside the test
		}
		seen++
		if _, ok := MultiPage[name]; ok {
			continue
		}
		if _, _, err := NoteOwner(name); err != nil {
			t.Error(err)
		}
	}
	if seen < 200 {
		t.Errorf("read %d L-notes, want the whole results directory", seen)
	}
}

func TestADeviceMatchBeatsNonDevice(t *testing.T) {
	for _, name := range []string{"L33-e2e-netbox-arista_eos.md", "L33-e2e-nautobot-arista_eos.md"} {
		page, non, err := NoteOwner(name)
		if err != nil || page != "arista-eos" || non != "" {
			t.Errorf("%s: got (%q, %q, %v), want the page arista-eos", name, page, non, err)
		}
	}
	page, non, err := NoteOwner("L33-e2e-netbox.md")
	if err != nil || page != "" || non != "netbox" {
		t.Errorf("L33-e2e-netbox.md: got (%q, %q, %v), want the nonDevice entry netbox", page, non, err)
	}
	if _, _, err := NoteOwner("L99-arista_eos-cisco_nxos.md"); err == nil || !strings.Contains(err.Error(), "more than one") {
		t.Errorf("a note matching two device pages: got %v, want an error", err)
	}
	if _, _, err := NoteOwner("L99-unheard_of.md"); err == nil {
		t.Error("a note that fits nothing must fail")
	}
	// A prefix entry takes any segment that starts with it.
	if _, non, err := NoteOwner("L67-windows_ad-x.md"); err != nil || non != "windows*" {
		t.Errorf("windows_ad: got (%q, %v), want windows*", non, err)
	}
}

func TestEveryDevicePageSuffixBelongsToOnePage(t *testing.T) {
	seen := map[string]string{}
	for _, p := range DevicePages {
		for _, s := range p.Suffixes {
			if other, dup := seen[s]; dup {
				t.Errorf("suffix %s is on %s and %s", s, other, p.Slug)
			}
			seen[s] = p.Slug
		}
	}
}

func writeNote(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestEvidenceParsesEveryHeaderStyle(t *testing.T) {
	dir := t.TempDir()
	// A bullet header, as L4-arista_eos.md has it.
	writeNote(t, dir, "L4-arista_eos.md", "# L4 — arista_eos\n\n"+
		"- **Date measured:** 2026-09-20\n"+
		"- **Platform:** arista_eos (containerlab node `leaf1`, 172.100.100.11)\n"+
		"- **Image version:** vEOS-lab 4.31.2F (image tagged 4.32.2F) (`vrnetlab/arista_veos:4.32.2F`)\n"+
		"- **Transport:** SSH\n\n## Claim\n\nDate: 2001-01-01\n")
	// A bullet header with a date that carries a trailer, and no image line.
	writeNote(t, dir, "L76-nokia_srlinux.md", "# L76 — nokia_srlinux\n\n"+
		"- **Date measured:** 2026-11-07, on beehive\n"+
		"- **Platform:** nokia_srlinux (containerlab node `srl1`)\n\n## Claim\n")
	// The L88 single line.
	writeNote(t, dir, "L88-cisco_xrd.md", "# L88: the reference\n\n"+
		"Platform: cisco_xrd. Image: XRd control plane 26.1.1. Transport: tcp. Measured 2026-11-04 by TestL88.\n\n- a line\n")
	// Plain lines, and an HTTP Date: below the header that must not be read.
	writeNote(t, dir, "L90-cisco_xrd-plain.md", "# L90\n\nDate: 2026-10-01\nPlatform: cisco_xrd\nImage: XRd 26.1.1\n\n## Body\n\nDate: Wed, 23 Sep 2026 06:51:30 GMT\n")
	// Nothing parseable.
	writeNote(t, dir, "L91-cisco_xrd-bare.md", "# L91\n\nno header here\n")

	ev, err := EvidenceFor(dir, DevicePage{Slug: "x", Suffixes: []string{"cisco_xrd", "nokia_srlinux", "arista_eos"}})
	if err != nil {
		t.Fatal(err)
	}
	want := []Evidence{
		{"L4", "L4-arista_eos.md", "arista_eos", "vEOS-lab 4.31.2F (image tagged 4.32.2F)", "2026-09-20"},
		{"L76", "L76-nokia_srlinux.md", "nokia_srlinux", "—", "2026-11-07"},
		{"L88", "L88-cisco_xrd.md", "cisco_xrd", "XRd control plane 26.1.1", "2026-11-04"},
		{"L90", "L90-cisco_xrd-plain.md", "cisco_xrd", "XRd 26.1.1", "2026-10-01"},
		{"L91", "L91-cisco_xrd-bare.md", "—", "—", "—"},
	}
	if len(ev) != len(want) {
		t.Fatalf("got %d rows %+v, want %d", len(ev), ev, len(want))
	}
	for i := range want {
		if ev[i] != want[i] {
			t.Errorf("row %d: got %+v, want %+v", i, ev[i], want[i])
		}
	}
}

func TestEvidenceListsAMultiPageNoteOnBothPages(t *testing.T) {
	dir := t.TempDir()
	name := "L31-breakglass-cisco-singleconnection.md"
	writeNote(t, dir, name, "# L31\n\n- **Date observed:** 2026-09-30 (the runs)\n- **Platforms:**\n  - cisco_iosxe\n")
	writeNote(t, dir, "L2-cisco_nxos.md", "# L2\n\n- **Date measured:** 2026-09-20\n")
	for _, slug := range MultiPage[name] {
		var page DevicePage
		for _, p := range DevicePages {
			if p.Slug == slug {
				page = p
			}
		}
		ev, err := EvidenceFor(dir, page)
		if err != nil {
			t.Fatal(err)
		}
		found := 0
		for _, e := range ev {
			if e.File == name {
				found++
				if e.Date != "2026-09-30" || e.Platform != "—" {
					t.Errorf("%s: got %+v", slug, e)
				}
			}
		}
		if found != 1 {
			t.Errorf("%s lists %s %d times, want once", slug, name, found)
		}
	}
}

// A note that measured two images lists them under "Platforms:". Each page shows its own platform row.
func TestEvidenceReadsThePlatformsListForEachPage(t *testing.T) {
	dir := t.TempDir()
	name := "L31-breakglass-cisco-singleconnection.md"
	writeNote(t, dir, name, "# L31\n\n- **Date observed:** 2026-09-30 (the runs)\n- **Platforms:**\n"+
		"  - cisco_iosxe (containerlab node `xe1`, 192.0.2.41): Catalyst 8000V 17.13.01a\n"+
		"    (`vrnetlab/cisco_c8000v:17.13.01a`)\n"+
		"  - cisco_nxos (containerlab node `nx1`, 192.0.2.31): Nexus 9300v 10.4(2)F\n"+
		"    (`vrnetlab/cisco_n9kv:9300v64-10.4.2.F`)\n"+
		"  - For comparison, unaffected: vEOS-lab 4.31.2F\n"+
		"- **Runs analysed:** plan 6b\n\n## Claim\n")
	want := map[string][2]string{
		"cisco-ios-xe": {"cisco_iosxe", "Catalyst 8000V 17.13.01a"},
		"cisco-nx-os":  {"cisco_nxos", "Nexus 9300v 10.4(2)F"},
	}
	for slug, w := range want {
		var page DevicePage
		for _, p := range DevicePages {
			if p.Slug == slug {
				page = p
			}
		}
		ev, err := EvidenceFor(dir, page)
		if err != nil {
			t.Fatal(err)
		}
		if len(ev) != 1 || ev[0].Platform != w[0] || ev[0].Image != w[1] {
			t.Errorf("%s: got %+v, want platform %q image %q", slug, ev, w[0], w[1])
		}
	}
}

func TestEvidenceTableRendersTheRegisterStatus(t *testing.T) {
	reg := map[string]LabRow{"L4": {ID: "L4", Open: true}, "L5": {ID: "L5"}}
	ev := []Evidence{
		{"L4", "L4-arista_eos.md", "arista_eos", "vEOS 4.31.2F", "2026-09-20"},
		{"L5", "L5-arista_eos.md", "arista_eos", "vEOS | 4.31.2F", "2026-09-21"},
	}
	got, err := EvidenceTable(ev, reg)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"| Entry | Platform | Image | Date | Note |",
		"[L4 (open)](" + specLabURL + ")",
		"[L5 (closed)](" + specLabURL + ")",
		"[L4-arista_eos.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L4-arista_eos.md)",
		`vEOS \| 4.31.2F`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("table lacks %q:\n%s", want, got)
		}
	}
	empty, err := EvidenceTable(nil, reg)
	if err != nil || strings.Contains(empty, "| L") {
		t.Errorf("an empty table names an entry or fails: %v\n%s", err, empty)
	}
}

// A note whose ID the register does not hold fails the build; it is not shown bare.
func TestEvidenceTableFailsOnAnUnknownLabID(t *testing.T) {
	reg := map[string]LabRow{"L4": {ID: "L4"}}
	ev := []Evidence{{"L999", "L999-arista_eos.md", "arista_eos", "vEOS", "2026-09-20"}}
	if got, err := EvidenceTable(ev, reg); err == nil {
		t.Errorf("an unknown lab ID was accepted:\n%s", got)
	}
}

func TestLLMsTxtFollowsTheNav(t *testing.T) {
	yml, err := os.ReadFile("../../mkdocs.yml")
	if err != nil {
		t.Fatal(err)
	}
	got, err := LLMsTxt(yml, "../../docs/site")
	if err != nil {
		t.Fatal(err)
	}
	const base = "https://blanketfish.github.io/port49/"
	lines := strings.Split(got, "\n")
	if lines[0] != "# port49" || !strings.HasPrefix(lines[2], "> ") {
		t.Fatalf("the head is %q", lines[:3])
	}
	var links []string
	for _, l := range lines {
		if strings.HasPrefix(l, "- [") {
			links = append(links, l)
		}
	}
	if len(links) < 2 || !strings.Contains(links[0], "("+base+"agents/setup-runbook/)") ||
		!strings.Contains(links[1], "("+base+"agents/quick-start/)") {
		t.Fatalf("Start here must list the runbook, then the quick start; got %q", links[:2])
	}
	if lines[4] != "## Start here" {
		t.Errorf("the first section is %q", lines[4])
	}
	// every nav page appears once after Start here
	_, secs, err := parseNav(yml)
	if err != nil {
		t.Fatal(err)
	}
	var nav []string
	for _, s := range secs {
		for _, p := range s.Pages {
			nav = append(nav, p.Path)
		}
	}
	if len(nav) < 30 {
		t.Fatalf("parsed %d nav pages", len(nav))
	}
	count := map[string]int{}
	for _, l := range links[2:] {
		count[l[strings.Index(l, "](")+2:strings.Index(l, "):")]]++
	}
	for _, p := range nav {
		u := pageURL(base, p)
		if count[u] != 1 {
			t.Errorf("%s (%s) appears %d times, want once", p, u, count[u])
		}
		delete(count, u)
	}
	for u := range count {
		t.Errorf("%s is listed but not in the nav", u)
	}
	if !strings.Contains(got, "- [Home]("+base+"): ") {
		t.Error("index.md must link to site_url itself")
	}
	var sections []string
	for _, l := range lines {
		if strings.HasPrefix(l, "## ") {
			sections = append(sections, l)
		}
	}
	wantSecs := []string{"## Start here", "## Home", "## Concepts", "## Operate", "## Administer", "## AI agents", "## Reference", "## Contributing"}
	if strings.Join(sections, "|") != strings.Join(wantSecs, "|") {
		t.Errorf("sections %q, want %q", sections, wantSecs)
	}
}

func TestPageURL(t *testing.T) {
	const base = "https://x/p/"
	for in, want := range map[string]string{
		"index.md": base, "a/b.md": base + "a/b/", "a/index.md": base + "a/", "a/b/index.md": base + "a/b/",
	} {
		if got := pageURL(base, in); got != want {
			t.Errorf("pageURL(%q) = %q, want %q", in, got, want)
		}
	}
}
