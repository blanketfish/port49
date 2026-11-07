package ci

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"golang.org/x/net/html"
	"gopkg.in/yaml.v3"

	"github.com/blanketfish/port49/internal/docgen"
)

// The documentation follows the lab register (CLAUDE.md): a claim cited to an open spec §15 row is
// unmeasured, so a page writes it as unmeasured or cites the measured note for the platform it is about.

const (
	specPath    = "../../docs/design/2026-08-23-policy-engine-spec.md"
	resultsDir  = "../lab/results"
	resultsURL  = "https://github.com/blanketfish/port49/blob/main/tests/lab/results/"
	labFixtures = "testdata/docslab"
)

var (
	labRef       = regexp.MustCompile(`\bL[0-9]+[a-z]?\b`)
	warnOpen     = regexp.MustCompile(`^!!! warning "Unmeasured`)
	pendingOpen  = regexp.MustCompile(`^!!! note "Regression rerun pending"`)
	admonition   = regexp.MustCompile(`^!!! \w+`)
	issueRef     = regexp.MustCompile(`#[0-9]+\b`)
	resultsNote  = regexp.MustCompile(`tests/lab/results/(L[^\s)\]"<>]*?\.md)`)
	markdownLink = regexp.MustCompile(`\]\(` + regexp.QuoteMeta(resultsURL) + `(L[^)\s]*?\.md)\)`)
)

// labFinding names a rule and a line, never the text, as the docs lint does.
type labFinding struct {
	File string
	Line int
	Code string
}

func (f labFinding) String() string { return fmt.Sprintf("%s:%d: %s", f.File, f.Line, f.Code) }

func hasCode(found []labFinding, code string) bool {
	for _, f := range found {
		if f.Code == code {
			return true
		}
	}
	return false
}

func loadRegister(t *testing.T, path string) map[string]docgen.LabRow {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	reg, err := docgen.LabRegister(b)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return reg
}

// splitPage returns a page's platforms: front matter and the markdown after the front matter, with the
// number of lines the front matter took so a finding names the page's own line.
func splitPage(text string) (platforms []string, body string, skipped int, err error) {
	rest, ok := strings.CutPrefix(text, "---\n")
	if !ok {
		return nil, text, 0, nil
	}
	block, after, ok := strings.Cut(rest, "\n---\n")
	if !ok {
		return nil, text, 0, fmt.Errorf("front matter is not closed with ---")
	}
	var fm struct {
		Platforms []string `yaml:"platforms"`
	}
	if err := yaml.Unmarshal([]byte(block), &fm); err != nil {
		return nil, "", 0, err
	}
	return fm.Platforms, after, strings.Count(block, "\n") + 3, nil
}

// walkMarkdown lists the pages a check reads: every .md under root except _snippets (the built-site pass
// covers them through the page that includes them) and a generated page.
func walkMarkdown(t *testing.T, root string) []string {
	t.Helper()
	var pages []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && d.Name() == docsSnippets {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(p, ".md") {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if !bytes.Contains(b, []byte(docgen.Header)) {
			pages = append(pages, p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(pages)
	return pages
}

// citesNote reports whether names holds a results note that leads with id and belongs, by the segment
// rule, to one of the page's platforms. The universe is every suffix any page claims, so that
// juniper_vjunos never takes a juniper_vjunos-router note.
func citesNote(names []string, id string, platforms, universe []string, results string) bool {
	for _, name := range names {
		ids, _ := docgen.NoteParts(name)
		leads := false
		for _, i := range ids {
			leads = leads || i == id
		}
		if !leads {
			continue
		}
		if _, err := os.Stat(filepath.Join(results, name)); err != nil {
			continue
		}
		if suffix, ok := docgen.MatchNote(name, universe); ok && contains(platforms, suffix) {
			return true
		}
		// A note that measured two images is carried by each page that lists it.
		for _, slug := range docgen.MultiPage[name] {
			for _, p := range docgen.DevicePages {
				if p.Slug != slug {
					continue
				}
				for _, s := range p.Suffixes {
					if contains(platforms, s) {
						return true
					}
				}
			}
		}
	}
	return false
}

func noteNames(re *regexp.Regexp, text string) []string {
	var names []string
	for _, m := range re.FindAllStringSubmatch(text, -1) {
		names = append(names, m[1])
	}
	return names
}

// checkOpenEntries is TestOpenLabEntriesAreWrittenAsUnmeasured on one page.
func checkOpenEntries(file string, text string, reg map[string]docgen.LabRow, universe []string, results string) []labFinding {
	platforms, body, skipped, err := splitPage(text)
	if err != nil {
		return []labFinding{{file, 1, "front_matter"}}
	}
	var out []labFinding
	inWarn := false
	for i, line := range strings.Split(body, "\n") {
		switch {
		case warnOpen.MatchString(line):
			inWarn = true
		case inWarn && line != "" && !strings.HasPrefix(line, "    ") && !strings.HasPrefix(line, "\t"):
			inWarn = false
		}
		for _, id := range labRef.FindAllString(line, -1) {
			row, ok := reg[id]
			switch {
			case !ok:
				out = append(out, labFinding{file, skipped + i + 1, "unknown_lab_id"})
			case row.Open && !inWarn && !citesNote(noteNames(markdownLink, line), id, platforms, universe, results):
				out = append(out, labFinding{file, skipped + i + 1, "open_entry_asserted"})
			case !row.Open && inWarn:
				out = append(out, labFinding{file, skipped + i + 1, "closed_entry_unmeasured"})
			}
		}
	}
	return out
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// siteUniverse is every suffix the device pages own (docgen.DevicePages). A page's own platforms: must
// equal its suffixes (TestEveryDevicePageDeclaresItsPlatforms), so this is the suffixes any page claims.
func siteUniverse(t *testing.T) []string {
	t.Helper()
	var u []string
	for _, p := range docgen.DevicePages {
		u = append(u, p.Suffixes...)
	}
	sort.Strings(u)
	return u
}

// TestEveryDevicePageDeclaresItsPlatforms fails when a device page's platforms: front matter differs from
// the suffixes docgen.DevicePages gives it. Without it the device checks pass on a page that declares none.
func TestEveryDevicePageDeclaresItsPlatforms(t *testing.T) {
	for _, p := range docgen.DevicePages {
		page := "admin/devices/" + p.Slug + ".md"
		fm := frontMatter(t, page)
		if fm == nil {
			continue
		}
		var got []string
		if raw, ok := fm["platforms"].([]any); ok {
			for _, v := range raw {
				s, _ := v.(string)
				got = append(got, s)
			}
		} else if fm["platforms"] != nil {
			t.Errorf("%s: platforms: is not a list", page)
		}
		want := append([]string(nil), p.Suffixes...)
		sort.Strings(want)
		sort.Strings(got)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%s: platforms: is %v, want the suffixes %v", page, got, want)
		}
		if b := readFile(t, filepath.Join(docsRoot, filepath.FromSlash(page))); !strings.Contains(b,
			`--8<-- "docs/site/_snippets/evidence/`+p.Slug+`.md"`) {
			t.Errorf("%s does not include its evidence table", page)
		}
	}
}

// A note two pages share counts as evidence on both of them.
func TestAMultiPageNoteCountsOnEachOfItsPages(t *testing.T) {
	const name = "L31-breakglass-cisco-singleconnection.md"
	universe := siteUniverse(t)
	for _, platforms := range [][]string{{"cisco_iosxe", "cisco_iol"}, {"cisco_nxos"}} {
		if !citesNote([]string{name}, "L31", platforms, universe, resultsDir) {
			t.Errorf("%s does not carry %v", name, platforms)
		}
	}
	if citesNote([]string{name}, "L31", []string{"arista_eos", "arista_ceos"}, universe, resultsDir) {
		t.Errorf("%s carries an Arista page", name)
	}
	page := "---\nplatforms:\n  - cisco_nxos\n---\n\n# x\n\nThe single-connection break-glass login fails after a reset " +
		"([L31](" + resultsURL + name + ")).\n"
	if got := checkDeviceClaims("p.md", page, universe, resultsDir); len(got) != 0 {
		t.Errorf("a claim citing the shared note failed: %v", got)
	}
}

var fixtureUniverse = []string{"juniper_vjunos", "juniper_vjunos-router", "juniper_vsrx", "arista_eos"}

func TestOpenLabEntriesAreWrittenAsUnmeasured(t *testing.T) {
	reg := loadRegister(t, specPath)
	universe := siteUniverse(t)
	for _, p := range walkMarkdown(t, docsRoot) {
		for _, f := range checkOpenEntries(p, readFile(t, p), reg, universe, resultsDir) {
			t.Error(f)
		}
	}
}

func TestOpenLabCheckPassesItsPassFixtures(t *testing.T) {
	reg := loadRegister(t, filepath.Join(labFixtures, "register.md"))
	results := filepath.Join(labFixtures, "results")
	pages := walkMarkdown(t, filepath.Join(labFixtures, "pass"))
	if len(pages) < 4 {
		t.Fatalf("only %d pass fixtures", len(pages))
	}
	for _, p := range pages {
		for _, f := range checkOpenEntries(p, readFile(t, p), reg, fixtureUniverse, results) {
			t.Error(f)
		}
	}
	// The skipped files do assert an open entry: they pass only because the walk leaves them out.
	for _, p := range []string{"pass/_snippets/snippet.md", "pass/generated.md"} {
		text := readFile(t, filepath.Join(labFixtures, p))
		if got := checkOpenEntries(p, text, reg, fixtureUniverse, results); !hasCode(got, "open_entry_asserted") {
			t.Errorf("%s is meant to assert an open entry and it does not: %v", p, got)
		}
	}
	for _, p := range pages {
		if strings.Contains(p, "snippet") || strings.HasSuffix(p, "generated.md") {
			t.Errorf("the walk kept %s", p)
		}
	}
}

func TestOpenLabCheckFailsItsFailFixtures(t *testing.T) {
	reg := loadRegister(t, filepath.Join(labFixtures, "register.md"))
	results := filepath.Join(labFixtures, "results")
	files, err := filepath.Glob(filepath.Join(labFixtures, "fail", "*.md"))
	if err != nil || len(files) < 7 {
		t.Fatalf("fail fixtures: %d %v", len(files), err)
	}
	for _, p := range files {
		want, _, _ := strings.Cut(filepath.Base(p), "--")
		got := checkOpenEntries(p, readFile(t, p), reg, fixtureUniverse, results)
		if len(got) == 0 || !hasCode(got, want) {
			t.Errorf("%s: got %v, want %s", p, got, want)
		}
		for _, f := range got {
			if f.Code != want {
				t.Errorf("%s: also %s", p, f)
			}
		}
	}
}

func TestACorrectCitationToAPrefixedNotePasses(t *testing.T) {
	reg := loadRegister(t, filepath.Join(labFixtures, "register.md"))
	if !reg["L4"].Open {
		t.Fatal("the fixture register must hold L4 open")
	}
	p := filepath.Join(labFixtures, "pass", "prefixed-note.md")
	text := readFile(t, p)
	if !strings.Contains(text, "platforms: [juniper_vjunos-router]") || !strings.Contains(text, "An ERROR is final") ||
		!strings.Contains(text, "L4-error-juniper_vjunos-router.md") {
		t.Fatal("the fixture is not the Junos page the test is about")
	}
	if got := checkOpenEntries(p, text, reg, fixtureUniverse, filepath.Join(labFixtures, "results")); len(got) != 0 {
		t.Errorf("a correct citation failed: %v", got)
	}
}

// --- device claims carry evidence ---

type claim struct {
	Line int
	Text string
}

var (
	heading    = regexp.MustCompile(`^#{1,6} `)
	listItem   = regexp.MustCompile(`^\s*([-*+]|[0-9]+[.)])\s+`)
	tableSep   = regexp.MustCompile(`^\|?\s*:?-{3,}`)
	evidenceH2 = map[string]bool{"What the lab measured": true, "Traps": true}
)

// claimsOf returns the blocks of a device page that must cite evidence: each paragraph and list item in
// the lead, "What the lab measured" and "Traps", less the blocks under an Unmeasured warning. The
// findings it returns are the "Regression rerun pending" notes that break the rules.
func claimsOf(body string, skipped int) (claims []claim, bad []labFinding) {
	const file = "page"
	lines := strings.Split(body, "\n")
	inScope := true // the lead
	fence := false
	var cur *claim
	var pending *claim // the body of a Regression rerun pending note
	pendingCount := 0
	skipIndent := false // under an Unmeasured warning
	flush := func() {
		if cur != nil {
			claims = append(claims, *cur)
			cur = nil
		}
	}
	endPending := func() {
		if pending == nil {
			return
		}
		switch {
		case pendingCount > 1:
			bad = append(bad, labFinding{file, pending.Line, "second_rerun_note"})
		case labRef.MatchString(pending.Text):
			claims = append(claims, *pending) // checked like any other block
		case !issueRef.MatchString(pending.Text):
			bad = append(bad, labFinding{file, pending.Line, "rerun_note_without_issue"})
		}
		pending = nil
	}
	for i, raw := range lines {
		n := skipped + i + 1
		if strings.HasPrefix(strings.TrimSpace(raw), "```") {
			flush()
			fence = !fence
			continue
		}
		if fence {
			continue
		}
		indented := strings.HasPrefix(raw, "    ") || strings.HasPrefix(raw, "\t")
		if pending != nil && raw != "" && !indented {
			endPending()
		}
		if skipIndent && raw != "" && !indented {
			skipIndent = false
		}
		switch {
		case strings.HasPrefix(raw, "## "):
			flush()
			inScope = evidenceH2[strings.TrimSpace(strings.TrimPrefix(raw, "## "))]
			continue
		case heading.MatchString(raw):
			flush()
			continue
		case pendingOpen.MatchString(raw):
			// counted across the whole page, in the checked sections or not
			flush()
			pendingCount++
			if inScope {
				pending = &claim{Line: n}
			} else if pendingCount > 1 {
				bad = append(bad, labFinding{file, n, "second_rerun_note"})
			}
			continue
		case !inScope:
			continue
		case warnOpen.MatchString(raw):
			flush()
			skipIndent = true
			continue
		case admonition.MatchString(raw):
			flush()
			continue
		case skipIndent:
			continue
		}
		text := strings.TrimSpace(raw)
		if pending != nil {
			pending.Text += " " + text
			continue
		}
		switch {
		case text == "":
			flush()
		case strings.HasPrefix(text, "|"):
			flush()
			next := ""
			if i+1 < len(lines) {
				next = strings.TrimSpace(lines[i+1])
			}
			// the header row, the separator under it, and then one claim per row
			if !tableSep.MatchString(text) && !tableSep.MatchString(next) {
				claims = append(claims, claim{n, text})
			}
		case listItem.MatchString(raw):
			flush()
			cur = &claim{n, text}
		default:
			if cur == nil {
				cur = &claim{n, text}
			} else {
				cur.Text += " " + text
			}
		}
	}
	flush()
	endPending()
	return claims, bad
}

// checkDeviceClaims is TestEveryDeviceClaimCitesItsEvidence on one page. A page without platforms: holds
// no device claims.
func checkDeviceClaims(file, text string, universe []string, results string) []labFinding {
	platforms, body, skipped, err := splitPage(text)
	if err != nil {
		return []labFinding{{file, 1, "front_matter"}}
	}
	if len(platforms) == 0 {
		return nil
	}
	claims, out := claimsOf(body, skipped)
	for i := range out {
		out[i].File = file
	}
	for _, c := range claims {
		if !citesAny(noteNames(markdownLink, c.Text), platforms, universe, results) {
			out = append(out, labFinding{file, c.Line, "claim_without_evidence"})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Line < out[j].Line })
	return out
}

// citesAny is citesNote for any lab ID the note leads with.
func citesAny(names []string, platforms, universe []string, results string) bool {
	for _, name := range names {
		ids, _ := docgen.NoteParts(name)
		for _, id := range ids {
			if citesNote([]string{name}, id, platforms, universe, results) {
				return true
			}
		}
	}
	return false
}

func TestEveryDeviceClaimCitesItsEvidence(t *testing.T) {
	universe := siteUniverse(t)
	for _, page := range sitePages(t) {
		p := filepath.Join(docsRoot, filepath.FromSlash(page))
		for _, f := range checkDeviceClaims(p, readFile(t, p), universe, resultsDir) {
			t.Error(f)
		}
	}
}

func TestDeviceClaimFixtures(t *testing.T) {
	results := filepath.Join(labFixtures, "results")
	for _, dir := range []string{"pass", "fail"} {
		files, err := filepath.Glob(filepath.Join(labFixtures, "claims", dir, "*.md"))
		if err != nil || len(files) == 0 {
			t.Fatalf("claims/%s fixtures: %d %v", dir, len(files), err)
		}
		for _, p := range files {
			got := checkDeviceClaims(p, readFile(t, p), fixtureUniverse, results)
			if dir == "pass" {
				for _, f := range got {
					t.Error(f)
				}
				continue
			}
			want, _, _ := strings.Cut(filepath.Base(p), "--")
			if !hasCode(got, want) {
				t.Errorf("%s: got %v, want %s", p, got, want)
			}
		}
	}
}

// --- the built site ---

type builtBlock struct {
	Text       string
	Unmeasured bool
}

var inlineTags = map[string]bool{"a": true, "code": true, "em": true, "strong": true, "span": true, "b": true,
	"i": true, "kbd": true, "abbr": true, "sub": true, "sup": true, "mark": true, "small": true, "u": true}

func attr(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if a.Key == key {
			return a.Val
		}
	}
	return ""
}

func hasClass(n *html.Node, class string) bool {
	return contains(strings.Fields(attr(n, "class")), class)
}

func textOf(n *html.Node) string {
	var b strings.Builder
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.TextNode {
			b.WriteString(n.Data)
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(n)
	return strings.Join(strings.Fields(b.String()), " ")
}

// builtBlocks cuts a page's article into text blocks. A link's href follows its text, so a sentence that
// links a results note names it. A block inside a warning admonition titled "Unmeasured" says so.
func builtBlocks(doc []byte) ([]builtBlock, error) {
	root, err := html.Parse(bytes.NewReader(doc))
	if err != nil {
		return nil, err
	}
	var article *html.Node
	var find func(*html.Node)
	find = func(n *html.Node) {
		if article == nil && n.Type == html.ElementNode && n.Data == "article" {
			article = n
		}
		for c := n.FirstChild; c != nil && article == nil; c = c.NextSibling {
			find(c)
		}
	}
	find(root)
	if article == nil {
		article = root
	}
	var blocks []builtBlock
	var cur strings.Builder
	flush := func(unmeasured bool) {
		if s := strings.Join(strings.Fields(cur.String()), " "); s != "" {
			blocks = append(blocks, builtBlock{s, unmeasured})
		}
		cur.Reset()
	}
	var walk func(n *html.Node, unmeasured bool)
	walk = func(n *html.Node, unmeasured bool) {
		switch n.Type {
		case html.TextNode:
			cur.WriteString(n.Data)
			return
		case html.ElementNode:
			if n.Data == "script" || n.Data == "style" || n.Data == "nav" {
				return
			}
		}
		if n.Type != html.ElementNode {
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				walk(c, unmeasured)
			}
			return
		}
		if n.Data == "td" || n.Data == "th" {
			// the row is the block, so an ID cell and the note cell beside it are one sentence
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				walk(c, unmeasured)
			}
			cur.WriteString(" | ")
			return
		}
		if inlineTags[n.Data] {
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				walk(c, unmeasured)
			}
			if n.Data == "a" {
				if href := attr(n, "href"); href != "" {
					cur.WriteString(" [" + href + "] ")
				}
			}
			return
		}
		flush(unmeasured)
		inner := unmeasured
		if n.Data == "div" && hasClass(n, "admonition") && hasClass(n, "warning") {
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				if c.Type == html.ElementNode && hasClass(c, "admonition-title") {
					inner = inner || strings.HasPrefix(textOf(c), "Unmeasured")
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c, inner)
		}
		flush(inner)
	}
	walk(article, false)
	return blocks, nil
}

var (
	sentenceEnd = regexp.MustCompile(`[.!?](?:\s+|$)`)
	notMeasured = regexp.MustCompile(`(?i)\b(?:unmeasured|not measured)\b`)
)

// sentenceAround returns the sentence of text holding [start,end).
func sentenceAround(text string, start, end int) (sentence string, from int) {
	from, to := 0, len(text)
	for _, m := range sentenceEnd.FindAllStringIndex(text, -1) {
		if m[1] <= start {
			from = m[1]
		} else if m[1] >= end {
			to = m[1]
			break
		}
	}
	return text[from:to], from
}

// readmeWording is the READMEs' own way of saying a row is open, matched tightly: "open" counts only
// beside the ID, and "unmeasured" or "not measured" only in the same clause (no . ; : between them,
// within 80 characters).
func readmeWording(sentence, id string, start, end int) bool {
	if regexp.MustCompile(`\b` + id + `(?: is open|, open|; open)\b`).MatchString(sentence) {
		return true
	}
	for _, m := range notMeasured.FindAllStringIndex(sentence, -1) {
		var gap string
		if m[0] >= end {
			gap = sentence[end:m[0]]
		} else if m[1] <= start {
			gap = sentence[m[1]:start]
		} else {
			continue
		}
		if len(gap) <= 80 && !strings.ContainsAny(gap, ".;:") {
			return true
		}
	}
	return false
}

// checkBuiltHTML is the built-site pass on one page.
func checkBuiltHTML(file string, doc []byte, platforms []string, reg map[string]docgen.LabRow, universe []string, results string) ([]labFinding, error) {
	blocks, err := builtBlocks(doc)
	if err != nil {
		return nil, err
	}
	var out []labFinding
	for _, b := range blocks {
		for _, m := range labRef.FindAllStringIndex(b.Text, -1) {
			id := b.Text[m[0]:m[1]]
			row, ok := reg[id]
			switch {
			case !ok:
				out = append(out, labFinding{file, 0, "unknown_lab_id"})
			case !row.Open && b.Unmeasured:
				out = append(out, labFinding{file, 0, "closed_entry_unmeasured"})
			case row.Open && !b.Unmeasured:
				sentence, from := sentenceAround(b.Text, m[0], m[1])
				if citesNote(noteNames(resultsNote, sentence), id, platforms, universe, results) ||
					readmeWording(sentence, id, m[0]-from, m[1]-from) {
					continue
				}
				out = append(out, labFinding{file, 0, "open_entry_asserted"})
			}
		}
	}
	return out, nil
}

// sourceOf maps site/<path>/index.html back to docs/site/<path>.md (or <path>/index.md).
func sourceOf(siteRoot, htmlPath, docs string) (string, bool) {
	rel, err := filepath.Rel(siteRoot, htmlPath)
	if err != nil {
		return "", false
	}
	dir := filepath.Dir(rel)
	if filepath.Base(rel) != "index.html" {
		return "", false
	}
	cands := []string{filepath.Join(docs, dir+".md"), filepath.Join(docs, dir, "index.md")}
	if dir == "." {
		cands = []string{filepath.Join(docs, "index.md")}
	}
	for _, c := range cands {
		if _, err := os.Stat(c); err == nil {
			return c, true
		}
	}
	return "", false
}

// checkBuiltSite walks a built site. A page whose source is generated is skipped.
func checkBuiltSite(t *testing.T, siteRoot, docs string, reg map[string]docgen.LabRow, universe []string, results string) (findings []labFinding, pages int) {
	t.Helper()
	err := filepath.WalkDir(siteRoot, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(p, ".html") {
			return nil
		}
		var platforms []string
		if src, ok := sourceOf(siteRoot, p, docs); ok {
			text := readFile(t, src)
			if strings.Contains(text, docgen.Header) {
				return nil
			}
			platforms, _, _, err = splitPage(text)
			if err != nil {
				return fmt.Errorf("%s: %w", src, err)
			}
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		got, err := checkBuiltHTML(p, b, platforms, reg, universe, results)
		if err != nil {
			return err
		}
		findings = append(findings, got...)
		pages++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return findings, pages
}

func TestTheBuiltSiteCitesOpenEntriesAsUnmeasured(t *testing.T) {
	dir := builtSiteDir(t)
	reg := loadRegister(t, specPath)
	findings, pages := checkBuiltSite(t, dir, docsRoot, reg, siteUniverse(t), resultsDir)
	if pages == 0 {
		t.Fatalf("no *.html under %s", dir)
	}
	for _, f := range findings {
		t.Error(f)
	}
}

func TestBuiltSiteWordingFixtures(t *testing.T) {
	reg := loadRegister(t, filepath.Join(labFixtures, "register.md"))
	results := filepath.Join(labFixtures, "results")
	for _, dir := range []string{"pass", "fail"} {
		files, err := filepath.Glob(filepath.Join(labFixtures, "built", dir, "*.html"))
		if err != nil || len(files) == 0 {
			t.Fatalf("built/%s fixtures: %d %v", dir, len(files), err)
		}
		for _, p := range files {
			got, err := checkBuiltHTML(p, []byte(readFile(t, p)), []string{"juniper_vsrx"}, reg, fixtureUniverse, results)
			if err != nil {
				t.Fatal(err)
			}
			if dir == "pass" && len(got) != 0 {
				t.Errorf("%s: %v", p, got)
			}
			if dir == "fail" {
				want, _, _ := strings.Cut(filepath.Base(p), "--")
				if !hasCode(got, want) {
					t.Errorf("%s: got %v, want %s", p, got, want)
				}
			}
		}
	}
}

func TestBuiltSiteMapsAPageToItsSource(t *testing.T) {
	reg := loadRegister(t, filepath.Join(labFixtures, "register.md"))
	root := filepath.Join(labFixtures, "mapped")
	got, pages := checkBuiltSite(t, filepath.Join(root, "site"), filepath.Join(root, "docs"), reg, fixtureUniverse,
		filepath.Join(labFixtures, "results"))
	if pages != 2 {
		t.Errorf("read %d pages, want 2 (a device page and an ordinary one; the generated page is skipped)", pages)
	}
	if len(got) != 1 || got[0].Code != "open_entry_asserted" || !strings.Contains(got[0].File, "ordinary") {
		t.Errorf("want exactly the ordinary page to fail, got %v", got)
	}
}
