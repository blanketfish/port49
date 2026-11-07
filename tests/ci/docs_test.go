package ci

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// The documentation site (plan 13): docs/site is mkdocs.yml's docs_dir. docs/site/_snippets holds
// fragments that pymdownx.snippets pastes into pages; a fragment has no front matter, because the
// paste would put it in the middle of the page.
const (
	docsRoot     = "../../docs/site"
	docsSnippets = "_snippets"
)

// builtSiteDir is the built site the tests under PORT49_DOCS_SITE read. The variable is relative to the
// repository root (docs.yml sets PORT49_DOCS_SITE=site), but go test runs in tests/ci. It skips when the
// variable is unset.
func builtSiteDir(t *testing.T) string {
	t.Helper()
	dir := os.Getenv("PORT49_DOCS_SITE")
	if dir == "" {
		t.Skip("PORT49_DOCS_SITE is not set; make docs-build and the docs workflow set it")
	}
	if !filepath.IsAbs(dir) {
		dir = filepath.Join(repoRoot, dir)
	}
	return dir
}

// sitePages returns every .md under docs/site, slash-separated and relative to it, less the snippets.
func sitePages(t *testing.T) []string {
	t.Helper()
	var pages []string
	err := filepath.WalkDir(docsRoot, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(docsRoot, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() && rel == docsSnippets {
			return filepath.SkipDir
		}
		if !d.IsDir() && strings.HasSuffix(rel, ".md") {
			pages = append(pages, rel)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", docsRoot, err)
	}
	sort.Strings(pages)
	return pages
}

// frontMatter parses the YAML block a page opens with.
func frontMatter(t *testing.T, page string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(docsRoot, filepath.FromSlash(page)))
	if err != nil {
		t.Fatal(err)
	}
	rest, ok := strings.CutPrefix(string(b), "---\n")
	if !ok {
		t.Errorf("%s does not start with front matter", page)
		return nil
	}
	block, _, ok := strings.Cut(rest, "\n---\n")
	if !ok {
		t.Errorf("%s: front matter is not closed with ---", page)
		return nil
	}
	fm := map[string]any{}
	if err := yaml.Unmarshal([]byte(block), &fm); err != nil {
		t.Errorf("%s: front matter: %v", page, err)
		return nil
	}
	return fm
}

// llms.txt lists each page with its description, so the description is one sentence, short enough
// for a search result.
func TestEveryPageHasATitleAndADescription(t *testing.T) {
	pages := sitePages(t)
	if len(pages) == 0 {
		t.Fatalf("no pages under %s", docsRoot)
	}
	for _, page := range pages {
		fm := frontMatter(t, page)
		if fm == nil {
			continue
		}
		title, _ := fm["title"].(string)
		if strings.TrimSpace(title) == "" {
			t.Errorf("%s has no title", page)
		}
		desc, _ := fm["description"].(string)
		desc = strings.TrimSpace(desc)
		switch {
		case desc == "":
			t.Errorf("%s has no description", page)
		case len([]rune(desc)) > 160:
			t.Errorf("%s: description is %d characters, at most 160", page, len([]rune(desc)))
		case strings.ContainsAny(desc, "\n") || !strings.HasSuffix(desc, ".") ||
			strings.Contains(desc, ". ") || strings.Contains(desc, "? ") || strings.Contains(desc, "! "):
			t.Errorf("%s: description is not one sentence ending in a full stop: %q", page, desc)
		}
	}
}

// A run-together name in the first line (`docs-servequal`) would silently drop two targets from .PHONY.
func TestTheMakefileDeclaresTheDocsTargetsPhony(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	first, _, _ := strings.Cut(string(b), "\n")
	names, ok := strings.CutPrefix(first, ".PHONY:")
	if !ok {
		t.Fatalf("Makefile's first line is not .PHONY: %.60s", first)
	}
	phony := map[string]bool{}
	for _, n := range strings.Fields(names) {
		phony[n] = true
	}
	for _, want := range []string{"docs-build", "docs-serve", "qual", "requirements-release"} {
		if !phony[want] {
			t.Errorf("Makefile's .PHONY line does not name %s", want)
		}
	}
}

// navPaths walks the nav: a string is a page, a one-key map is a title over a page or a list of nav items.
func navPaths(t *testing.T, n any, out *[]string) {
	t.Helper()
	switch v := n.(type) {
	case string:
		*out = append(*out, v)
	case []any:
		for _, e := range v {
			navPaths(t, e, out)
		}
	case map[string]any:
		for _, e := range v {
			navPaths(t, e, out)
		}
	default:
		t.Errorf("mkdocs.yml: nav holds a %T", n)
	}
}

func TestTheNavAndThePagesAgree(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "mkdocs.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Nav []any `yaml:"nav"`
	}
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		t.Fatalf("mkdocs.yml: %v", err)
	}
	var navd []string
	navPaths(t, cfg.Nav, &navd)
	inNav := map[string]bool{}
	for _, p := range navd {
		if inNav[p] {
			t.Errorf("mkdocs.yml: nav lists %s twice", p)
		}
		inNav[p] = true
	}
	onDisk := map[string]bool{}
	for _, p := range sitePages(t) {
		onDisk[p] = true
		if !inNav[p] {
			t.Errorf("docs/site/%s is a page the nav does not list", p)
		}
	}
	for p := range inNav {
		if !onDisk[p] {
			t.Errorf("mkdocs.yml: nav lists %s, which is not a file under docs/site", p)
		}
	}
}
