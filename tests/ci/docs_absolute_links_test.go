package ci

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// absoluteSiteLink matches a link to the published site: the path under latest/ and an optional anchor.
var absoluteSiteLink = regexp.MustCompile(`https://blanketfish\.github\.io/port49/latest/([A-Za-z0-9_./-]*)(?:#([A-Za-z0-9_.:-]+))?`)

// TestAbsoluteSiteLinksResolveAgainstTheBuiltSite checks every link to blanketfish.github.io/port49/latest/
// in the site pages and the deploy READMEs against the built site. mkdocs strict mode does not see them
// (validation.absolute_links is warn, and a README is not a page), so a renamed heading breaks them silently.
func TestAbsoluteSiteLinksResolveAgainstTheBuiltSite(t *testing.T) {
	site := builtSiteDir(t)
	var files []string
	for _, root := range []string{docsRoot, filepath.Join(repoRoot, "deploy"), filepath.Join(repoRoot, "README.md")} {
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() && strings.HasSuffix(p, ".md") {
				files = append(files, p)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walking %s: %v", root, err)
		}
	}
	pages := map[string]string{}
	read := func(rel string) (string, bool) {
		if body, ok := pages[rel]; ok {
			return body, body != ""
		}
		for _, name := range []string{filepath.Join(rel, "index.html"), rel + ".html"} {
			if b, err := os.ReadFile(filepath.Join(site, name)); err == nil {
				pages[rel] = string(b)
				return pages[rel], true
			}
		}
		pages[rel] = ""
		return "", false
	}
	checked := 0
	for _, f := range files {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range absoluteSiteLink.FindAllStringSubmatch(string(src), -1) {
			checked++
			body, ok := read(strings.Trim(m[1], "/"))
			if !ok {
				t.Errorf("%s links to %s, which the built site does not have", f, m[0])
				continue
			}
			if m[2] != "" && !strings.Contains(body, `id="`+m[2]+`"`) {
				t.Errorf("%s links to %s, and that page has no anchor %q", f, m[0], m[2])
			}
		}
	}
	if checked == 0 {
		t.Fatal("found no absolute site links to check; the pattern is wrong")
	}
}
