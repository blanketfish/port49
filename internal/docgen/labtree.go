package docgen

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// siteRoot is the docs_dir of mkdocs.yml, from the repository root.
const siteRoot = "docs/site"

// generatedIncludes are the included files another generator writes, which links its own lab IDs.
var generatedIncludes = map[string]bool{"docs/qualified-platforms.md": true}

// Region is a run of lines of a file, 1-based and inclusive, that a site page pastes in.
type Region struct {
	File     string // repository-relative, slash-separated
	From, To int
}

var (
	includeLine = regexp.MustCompile(`^\s*--8<--\s+"([^"]+)"\s*$`)
	includeRef  = regexp.MustCompile(`^(.*?)(?:((?::[0-9]*){1,2})|(:[a-z][-_0-9a-z]*))?$`)
	sectionMark = regexp.MustCompile(`(?i)-{1,}8<-{1,}\s+\[\s*(start|end)\s*:\s*([a-z][-_0-9a-z]*)\s*\]`)
)

// sitePages lists every .md under root/docs/site, as paths relative to it.
func sitePages(root string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(filepath.Join(root, siteRoot), func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(p, ".md") {
			rel, err := filepath.Rel(filepath.Join(root, siteRoot), p)
			if err != nil {
				return err
			}
			out = append(out, filepath.ToSlash(rel))
		}
		return nil
	})
	sort.Strings(out)
	return out, err
}

func readLines(root, file string) ([]string, error) {
	b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(file)))
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(b), "\n")
	if lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines, nil
}

// IncludedRegions lists the regions of other files that the pages under docs/site paste in with
// pymdownx.snippets, merged per file. A page in docs/site/_snippets is a fragment of the site itself, so
// an include of one is not listed.
func IncludedRegions(root string) ([]Region, error) {
	pages, err := sitePages(root)
	if err != nil {
		return nil, err
	}
	byFile := map[string][]Region{}
	for _, page := range pages {
		lines, err := readLines(root, path.Join(siteRoot, page))
		if err != nil {
			return nil, err
		}
		for n, line := range lines {
			m := includeLine.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			ref := includeRef.FindStringSubmatch(m[1])
			file := strings.TrimSpace(ref[1])
			if strings.HasPrefix(file, siteRoot+"/") {
				continue
			}
			target, err := readLines(root, file)
			if err != nil {
				return nil, fmt.Errorf("%s:%d: %w", page, n+1, err)
			}
			regs, err := regionsOf(file, target, ref[2], ref[3])
			if err != nil {
				return nil, fmt.Errorf("%s:%d: %w", page, n+1, err)
			}
			byFile[file] = append(byFile[file], regs...)
		}
	}
	var out []Region
	for _, regs := range byFile {
		sort.Slice(regs, func(i, j int) bool { return regs[i].From < regs[j].From })
		cur := regs[0]
		for _, r := range regs[1:] {
			if r.From <= cur.To+1 {
				cur.To = max(cur.To, r.To)
				continue
			}
			out = append(out, cur)
			cur = r
		}
		out = append(out, cur)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].File != out[j].File {
			return out[i].File < out[j].File
		}
		return out[i].From < out[j].From
	})
	return out, nil
}

// regionsOf is the lines of file that an include with the given ":from:to" or ":section" suffix pastes.
func regionsOf(file string, lines []string, span, section string) ([]Region, error) {
	switch {
	case section != "":
		name := strings.TrimPrefix(section, ":")
		var out []Region
		from := 0
		for i, l := range lines {
			m := sectionMark.FindStringSubmatch(l)
			switch {
			case m == nil || !strings.EqualFold(m[2], name):
			case strings.EqualFold(m[1], "start") && from == 0:
				from = i + 2
			case strings.EqualFold(m[1], "end") && from != 0:
				if i >= from {
					out = append(out, Region{file, from, i})
				}
				from = 0
			}
		}
		if len(out) == 0 {
			return nil, fmt.Errorf("%s has no section %q", file, name)
		}
		return out, nil
	case span != "":
		var out []Region
		for _, part := range strings.Split(strings.TrimPrefix(span, ":"), ",") {
			ends := strings.Split(part, ":")
			from, to := 1, len(lines)
			if ends[0] != "" {
				if _, err := fmt.Sscanf(ends[0], "%d", &from); err != nil || from < 1 {
					return nil, fmt.Errorf("%s: include line %q is not supported", file, part)
				}
			}
			if len(ends) > 1 && ends[1] != "" {
				if _, err := fmt.Sscanf(ends[1], "%d", &to); err != nil {
					return nil, fmt.Errorf("%s: include line %q is not supported", file, part)
				}
			}
			to = min(to, len(lines))
			if from <= to {
				out = append(out, Region{file, from, to})
			}
		}
		return out, nil
	}
	return []Region{{file, 1, len(lines)}}, nil
}

// LinkLabIDsInTree is the rewriter: it links every bare lab ID on the hand-written pages under
// docs/site, by a relative link to the register page, and in the regions of other files those pages
// include, by the register's site URL (the file is read on GitHub too). It leaves generated pages and
// generated included files to their generators. Nothing is written when an ID is not in reg. It returns
// the repository-relative paths it changed.
func LinkLabIDsInTree(root string, reg map[string]LabRow) ([]string, error) {
	pages, err := sitePages(root)
	if err != nil {
		return nil, err
	}
	writes := map[string]string{}
	for _, page := range pages {
		file := path.Join(siteRoot, page)
		b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(file)))
		if err != nil {
			return nil, err
		}
		if strings.Contains(string(b), Header) {
			continue
		}
		out, err := LinkLabIDs(string(b), reg, RegisterLinkFrom(page))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", file, err)
		}
		if out != string(b) {
			writes[file] = out
		}
	}
	regions, err := IncludedRegions(root)
	if err != nil {
		return nil, err
	}
	for _, r := range regions {
		if generatedIncludes[r.File] {
			continue
		}
		lines, err := readLines(root, r.File)
		if err != nil {
			return nil, err
		}
		region := strings.Join(lines[r.From-1:r.To], "\n")
		out, err := LinkLabIDs(region, reg, LabRegisterSiteURL)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", r.File, err)
		}
		if out == region {
			continue
		}
		// regions of one file are applied last to first so earlier line numbers stay true
		if _, ok := writes[r.File]; !ok {
			writes[r.File] = strings.Join(lines, "\n") + "\n"
		}
		cur := strings.Split(strings.TrimSuffix(writes[r.File], "\n"), "\n")
		shift := len(cur) - len(lines)
		repl := strings.Split(out, "\n")
		cur = append(append(append([]string{}, cur[:r.From-1+shift]...), repl...), cur[r.To+shift:]...)
		writes[r.File] = strings.Join(cur, "\n") + "\n"
	}
	var changed []string
	for file, text := range writes {
		if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(file)), []byte(text), 0o644); err != nil {
			return nil, err
		}
		changed = append(changed, file)
	}
	sort.Strings(changed)
	return changed, nil
}

// LabIDFinding is one thing CheckLabIDs reports: the file, the line and the rule, never the text.
type LabIDFinding struct {
	File string
	Line int
	Rule string
}

func (f LabIDFinding) String() string { return fmt.Sprintf("%s:%d:%s", f.File, f.Line, f.Rule) }

var registerLink = regexp.MustCompile(`\]\(([^)\s]*lab-register[^)\s]*)\)`)

// CheckLabIDs is the lint behind the rewriter. It reports a lab ID outside a link and a code span on any page
// under docs/site (generated pages and fragments included), and in the regions of the files those pages
// include. In an included file a link to the register must be the absolute site URL, because a relative one
// is wrong on GitHub or on the site.
func CheckLabIDs(root string) ([]LabIDFinding, error) {
	pages, err := sitePages(root)
	if err != nil {
		return nil, err
	}
	var out []LabIDFinding
	for _, page := range pages {
		file := path.Join(siteRoot, page)
		b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(file)))
		if err != nil {
			return nil, err
		}
		out = append(out, bareFindings(file, string(b), 1)...)
	}
	regions, err := IncludedRegions(root)
	if err != nil {
		return nil, err
	}
	for _, r := range regions {
		lines, err := readLines(root, r.File)
		if err != nil {
			return nil, err
		}
		region := strings.Join(lines[r.From-1:r.To], "\n")
		out = append(out, bareFindings(r.File, region, r.From)...)
		for i, line := range lines[r.From-1 : r.To] {
			for _, m := range registerLink.FindAllStringSubmatch(line, -1) {
				if !strings.HasPrefix(m[1], LabRegisterSiteURL) {
					out = append(out, LabIDFinding{r.File, r.From + i, "relative_register_link_in_included_file"})
				}
			}
		}
	}
	return out, nil
}

func bareFindings(file, text string, firstLine int) []LabIDFinding {
	var out []LabIDFinding
	for _, s := range BareLabIDs(text) {
		out = append(out, LabIDFinding{file, firstLine + strings.Count(text[:s.Start], "\n"), "bare_lab_id"})
	}
	return out
}
