package docgen

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// DevicePage is one page of docs/site/admin/devices and the results-note suffixes that belong to it.
type DevicePage struct {
	Slug, Title string
	Suffixes    []string
}

// DevicePages lists the device pages. A results note belongs to a page when one of the page's suffixes
// is a contiguous run of segments in the note's name (MatchNote). The generic adapter has no notes.
var DevicePages = []DevicePage{
	{"arista-eos", "Arista EOS", []string{"arista_eos", "arista_ceos"}},
	// IOL-XE 17.18.02 is IOS XE (L71-cisco_iol-xe.md).
	{"cisco-ios-xe", "Cisco IOS XE", []string{"cisco_iosxe", "cisco_iol"}},
	{"cisco-nx-os", "Cisco NX-OS", []string{"cisco_nxos"}},
	{"cisco-ios-xr", "Cisco IOS XR", []string{"cisco_xrd"}},
	{"juniper-junos", "Juniper Junos", []string{"juniper_vjunos-router", "juniper_vjunos", "juniper_vsrx", "juniper_srx"}},
	{"nokia-sr-linux", "Nokia SR Linux", []string{"nokia_srlinux"}},
	{"other-platforms", "Other platforms", nil},
}

// MultiPage names the notes that measured more than one device image, so more than one page lists them.
var MultiPage = map[string][]string{
	"L31-breakglass-cisco-singleconnection.md": {"cisco-ios-xe", "cisco-nx-os"},
}

// nonDevice lists the notes that are about no device page: the harness, the directories and identity
// providers, and the machines the lab runs on. An entry that ends in "*" matches any segment that starts
// with the rest of it.
var nonDevice = []string{"kind", "regions", "netbox", "nautobot", "openldap", "samba", "samba_ad", "windows*",
	"keycloak", "ser8", "systemd-docker", "reference", "step_ca", "beehive*"}

// matchEntry reports whether the entry's segments occur as a run in rest. A trailing "*" in the entry's
// last segment makes it a prefix.
func matchEntry(rest []string, entry string) bool {
	if prefix, ok := strings.CutSuffix(entry, "*"); ok {
		for _, s := range rest {
			if strings.HasPrefix(s, prefix) {
				return true
			}
		}
		return false
	}
	return hasRun(rest, strings.Split(entry, "-"))
}

// ownersOf returns every device page that name belongs to, and the nonDevice entry that matches it.
func ownersOf(name string) (pages []string, non string) {
	_, rest := NoteParts(name)
	for _, p := range DevicePages {
		if _, ok := MatchNote(name, p.Suffixes); ok {
			pages = append(pages, p.Slug)
		}
	}
	for _, e := range nonDevice {
		if matchEntry(rest, e) {
			non = e
			break
		}
	}
	return pages, non
}

// NoteOwner returns the one device page whose suffixes match the results note name, else the nonDevice
// entry that does. A device match beats a nonDevice match (L33-e2e-netbox-arista_eos.md ran on vEOS),
// a name that matches two device pages is an error, and so is one that matches nothing. A note in
// MultiPage is not for this function: its callers look it up first.
func NoteOwner(name string) (page string, nonDev string, err error) {
	pages, non := ownersOf(name)
	switch {
	case len(pages) > 1:
		return "", "", fmt.Errorf("%s matches more than one device page: %s", name, strings.Join(pages, ", "))
	case len(pages) == 1:
		return pages[0], "", nil
	case non != "":
		return "", non, nil
	}
	return "", "", fmt.Errorf("%s belongs to no device page and no nonDevice entry: add its platform to DevicePages", name)
}

// Evidence is one results note as the evidence table shows it.
type Evidence struct{ ID, File, Platform, Image, Date string }

const none = "—"

var (
	isoDate     = regexp.MustCompile(`[0-9]{4}-[0-9]{2}-[0-9]{2}`)
	bulletDate  = regexp.MustCompile(`^- \*\*Date (?:measured|reported|observed):\*\*\s*(.*)$`)
	bulletPlat  = regexp.MustCompile(`^- \*\*Platform:\*\*\s*(.*)$`)
	bulletImage = regexp.MustCompile(`^- \*\*Image version:\*\*\s*(.*)$`)
	plainDate   = regexp.MustCompile(`^Date:\s*([0-9]{4}-[0-9]{2}-[0-9]{2})\s*$`)
	plainPlat   = regexp.MustCompile(`^Platform:\s*(.*)$`)
	plainImage  = regexp.MustCompile(`^Image:\s*(.*)$`)
	// A note that measured several images lists them under "Platforms:", one nested "- <platform> (...): <image>" each.
	bulletPlatforms = regexp.MustCompile(`^- \*\*Platforms:\*\*\s*$`)
	nestedPlatform  = regexp.MustCompile(`^\s+- ([A-Za-z0-9_.-]+)[^:]*:\s*(.*)$`)
	oneLiner        = regexp.MustCompile(`^Platform:\s*(.+?)\.\s+Image:\s*(.+?)\.\s+Transport:\s*.+?\.\s+Measured\s+(\S+?)[.,;]?\s+by\s`)
)

// headerLimit bounds how far into a note the header can reach.
const headerLimit = 40

// readEvidence parses the header of one results note: the lines before its first "## " heading. It keeps
// the three fields and prints nothing else. A "Platforms:" list gives the row of the one entry whose name is
// in suffixes, the page's own platform.
func readEvidence(dir, name string, suffixes []string) (Evidence, error) {
	f, err := os.Open(filepath.Join(dir, name))
	if err != nil {
		return Evidence{}, err
	}
	defer f.Close()
	ids, _ := NoteParts(name)
	ev := Evidence{ID: strings.Join(ids, ", "), File: name, Platform: none, Image: none, Date: none}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	inPlatforms := false
	for n := 0; n < headerLimit && sc.Scan(); n++ {
		line := sc.Text()
		if strings.HasPrefix(line, "## ") {
			break
		}
		if bulletPlatforms.MatchString(line) {
			inPlatforms = true
			continue
		}
		if inPlatforms {
			if strings.HasPrefix(line, "- ") {
				inPlatforms = false
			} else if m := nestedPlatform.FindStringSubmatch(line); m != nil {
				for _, s := range suffixes {
					if m[1] == s {
						ev.Platform, ev.Image = m[1], cleanImage(m[2])
					}
				}
				continue
			} else {
				continue
			}
		}
		if m := oneLiner.FindStringSubmatch(line); m != nil {
			ev.Platform, ev.Image, ev.Date = cleanPlatform(m[1]), cleanImage(m[2]), m[3]
			continue
		}
		for _, r := range []struct {
			re  *regexp.Regexp
			set func(string)
		}{
			{bulletDate, func(v string) { ev.Date = isoOr(v) }},
			{plainDate, func(v string) { ev.Date = isoOr(v) }},
			{bulletPlat, func(v string) { ev.Platform = cleanPlatform(v) }},
			{plainPlat, func(v string) { ev.Platform = cleanPlatform(v) }},
			{bulletImage, func(v string) { ev.Image = cleanImage(v) }},
			{plainImage, func(v string) { ev.Image = cleanImage(v) }},
		} {
			if m := r.re.FindStringSubmatch(line); m != nil {
				r.set(m[1])
			}
		}
	}
	if err := sc.Err(); err != nil {
		return Evidence{}, fmt.Errorf("%s: %w", name, err)
	}
	return ev, nil
}

func isoOr(v string) string {
	if d := isoDate.FindString(v); d != "" {
		return d
	}
	return none
}

// cleanPlatform keeps the platform name and drops the parenthetical that names the lab node.
func cleanPlatform(v string) string {
	v, _, _ = strings.Cut(v, " (")
	return orNone(strings.TrimSpace(v))
}

// cleanImage drops the parenthetical that names the container image.
func cleanImage(v string) string {
	if i := strings.Index(v, " (`"); i >= 0 {
		v = v[:i]
	}
	return orNone(strings.TrimSpace(v))
}

func orNone(v string) string {
	if v == "" {
		return none
	}
	return v
}

// EvidenceFor lists the results notes of page p, in lab-ID order: the notes whose names match p's
// suffixes by segments, and the MultiPage notes that name p. A note that matches two pages is an error.
func EvidenceFor(resultsDir string, p DevicePage) ([]Evidence, error) {
	entries, err := os.ReadDir(resultsDir)
	if err != nil {
		return nil, err
	}
	var out []Evidence
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".md") {
			continue
		}
		if ids, _ := NoteParts(name); len(ids) == 0 {
			continue
		}
		mine := false
		if slugs, multi := MultiPage[name]; multi {
			for _, s := range slugs {
				mine = mine || s == p.Slug
			}
		} else {
			pages, _ := ownersOf(name)
			if len(pages) > 1 {
				return nil, fmt.Errorf("%s matches more than one device page: %s", name, strings.Join(pages, ", "))
			}
			// p may be a fixture page, so match it directly rather than through DevicePages.
			_, mine = MatchNote(name, p.Suffixes)
		}
		if !mine {
			continue
		}
		ev, err := readEvidence(resultsDir, name, p.Suffixes)
		if err != nil {
			return nil, err
		}
		out = append(out, ev)
	}
	sort.SliceStable(out, func(i, j int) bool {
		ni, si := idKey(out[i].ID)
		nj, sj := idKey(out[j].ID)
		if ni != nj {
			return ni < nj
		}
		if si != sj {
			return si < sj
		}
		return out[i].File < out[j].File
	})
	return out, nil
}

// idKey splits "L26c, L27" at its first ID into 26 and "c".
func idKey(id string) (int, string) {
	first, _, _ := strings.Cut(id, ",")
	first = strings.TrimPrefix(strings.TrimSpace(first), "L")
	i := 0
	for i < len(first) && first[i] >= '0' && first[i] <= '9' {
		i++
	}
	n, _ := strconv.Atoi(first[:i])
	return n, first[i:]
}

// resultsURL is where a results note lives on GitHub.
const resultsURL = "https://github.com/blanketfish/port49/blob/main/tests/lab/results/"

// EvidenceTable is the table a device page includes under "Lab evidence": one row per note, with the
// register entry and whether it is open or closed, the platform, image and date the note records, and a
// link to the note. An ID the register does not hold is an error, so the build fails on it. A page with
// no notes gets a sentence in place of the table.
func EvidenceTable(ev []Evidence, reg map[string]LabRow) (string, error) {
	if len(ev) == 0 {
		return Header + "\n\nNo lab results note covers this page.\n", nil
	}
	var b strings.Builder
	b.WriteString(Header + "\n\n| Entry | Platform | Image | Date | Note |\n|---|---|---|---|---|\n")
	for _, e := range ev {
		entry, err := RenderLabIDs(e.ID, reg, RegisterLinkFrom("admin/devices/x.md"))
		if err != nil {
			return "", fmt.Errorf("%s: %w", e.File, err)
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s | [%s](%s%s) |\n", entry, cell(e.Platform), cell(e.Image), cell(e.Date),
			e.File, resultsURL, e.File)
	}
	return b.String(), nil
}
