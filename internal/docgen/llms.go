package docgen

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// navPage is one page of the nav: its path under docs/ and the label the nav gives it, if any.
type navPage struct{ Label, Path string }

// navSection is one top-level nav entry with every page under it, subsections flattened, in nav order.
type navSection struct {
	Title string
	Pages []navPage
}

// parseNav reads site_url and the nav of mkdocs.yml.
func parseNav(mkdocsYAML []byte) (siteURL string, sections []navSection, err error) {
	var cfg struct {
		SiteURL string `yaml:"site_url"`
		Nav     []any  `yaml:"nav"`
	}
	if err := yaml.Unmarshal(mkdocsYAML, &cfg); err != nil {
		return "", nil, fmt.Errorf("mkdocs.yml: %w", err)
	}
	if cfg.SiteURL == "" || len(cfg.Nav) == 0 {
		return "", nil, fmt.Errorf("mkdocs.yml: site_url and nav are both required")
	}
	for _, item := range cfg.Nav {
		m, ok := item.(map[string]any)
		if !ok || len(m) != 1 {
			return "", nil, fmt.Errorf("mkdocs.yml: a top-level nav entry must be one \"Title: ...\" pair, got %v", item)
		}
		for title, v := range m {
			pages, err := flattenNav(title, v)
			if err != nil {
				return "", nil, err
			}
			sections = append(sections, navSection{Title: title, Pages: pages})
		}
	}
	return cfg.SiteURL, sections, nil
}

func flattenNav(label string, v any) ([]navPage, error) {
	switch n := v.(type) {
	case string:
		return []navPage{{label, n}}, nil
	case []any:
		var out []navPage
		for _, e := range n {
			if s, ok := e.(string); ok {
				out = append(out, navPage{"", s})
				continue
			}
			m, ok := e.(map[string]any)
			if !ok || len(m) != 1 {
				return nil, fmt.Errorf("mkdocs.yml: nav entry %v is not a page or a one-key mapping", e)
			}
			for l, sub := range m {
				pages, err := flattenNav(l, sub)
				if err != nil {
					return nil, err
				}
				out = append(out, pages...)
			}
		}
		return out, nil
	}
	return nil, fmt.Errorf("mkdocs.yml: nav holds a %T", v)
}

// pageURL is the URL of a docs page: site_url plus its directory URL. index.md is site_url itself,
// a/b.md is a/b/ and a/index.md is a/.
func pageURL(siteURL, path string) string {
	siteURL = strings.TrimSuffix(siteURL, "/") + "/"
	path = strings.TrimSuffix(path, ".md")
	if path == "index" {
		return siteURL
	}
	path = strings.TrimSuffix(path, "/index")
	return siteURL + path + "/"
}

// pageMeta reads the title and description of docs/<path>.
func pageMeta(docs, path string) (title, description string, err error) {
	b, err := os.ReadFile(filepath.Join(docs, filepath.FromSlash(path)))
	if err != nil {
		return "", "", err
	}
	rest, ok := strings.CutPrefix(string(b), "---\n")
	if !ok {
		return "", "", fmt.Errorf("%s has no front matter", path)
	}
	block, _, ok := strings.Cut(rest, "\n---\n")
	if !ok {
		return "", "", fmt.Errorf("%s: front matter is not closed", path)
	}
	var fm struct {
		Title       string `yaml:"title"`
		Description string `yaml:"description"`
	}
	if err := yaml.Unmarshal([]byte(block), &fm); err != nil {
		return "", "", fmt.Errorf("%s: %w", path, err)
	}
	return fm.Title, oneLine(fm.Description), nil
}

// startHere is the first section of llms.txt, in this order.
var startHere = []string{"agents/setup-runbook.md", "agents/quick-start.md"}

// LLMsTxt is docs/site/llms.txt in the llmstxt.org shape: the site's name, a summary from index.md's
// description, a "Start here" section for an agent, then one section per nav section, in nav order.
// docs is the docs directory (docs/site). A start-here page is listed again in its own nav section.
func LLMsTxt(mkdocsYAML []byte, docs string) (string, error) {
	siteURL, sections, err := parseNav(mkdocsYAML)
	if err != nil {
		return "", err
	}
	_, summary, err := pageMeta(docs, "index.md")
	if err != nil {
		return "", err
	}
	if summary == "" {
		return "", fmt.Errorf("index.md has no description for the llms.txt summary")
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# port49\n\n> %s\n", summary)
	line := func(label, path string) error {
		title, desc, err := pageMeta(docs, path)
		if err != nil {
			return err
		}
		if label == "" {
			label = title
		}
		if desc == "" {
			return fmt.Errorf("%s has no description", path)
		}
		fmt.Fprintf(&b, "- [%s](%s): %s\n", label, pageURL(siteURL, path), desc)
		return nil
	}
	b.WriteString("\n## Start here\n\n")
	for _, p := range startHere {
		if err := line("", p); err != nil {
			return "", err
		}
	}
	for _, s := range sections {
		fmt.Fprintf(&b, "\n## %s\n\n", s.Title)
		for _, p := range s.Pages {
			if err := line(p.Label, p.Path); err != nil {
				return "", err
			}
		}
	}
	return b.String(), nil
}
