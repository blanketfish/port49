package ci

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// The site is versioned by mike (/port49/dev/, /port49/<X.Y>/, /port49/latest/): the dropdown is
// Material's, fed by mike's versions.json, and every deep link names a version so it cannot rot.

func init() {
	mustSay["operate/versions.md"] = append(mustSay["operate/versions.md"],
		"## Which version of these docs you are reading", "`/latest/`", "`/dev/`", "version selector",
	)
}

// release.yml's goreleaser and publish jobs also hold contents: write, so RELEASING.md must scope the claim.
func TestReleasingScopesTheDeployJobsWrite(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(repoRoot, "RELEASING.md"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if strings.Contains(s, "is the only\n   workflow job with `contents: write`") || !strings.Contains(s, "Outside `release.yml`, the `deploy`") {
		t.Error("RELEASING.md must say the deploy job is the only job with contents: write outside release.yml")
	}
	if !strings.Contains(s, "Only final\n   tags that are on `main` count") {
		t.Error("RELEASING.md does not say only final tags on main count")
	}
}

func TestTheSiteIsVersionedByMike(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(repoRoot, "mkdocs.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		SiteURL string `yaml:"site_url"`
		Plugins []any  `yaml:"plugins"`
		Extra   struct {
			Version struct {
				Provider string `yaml:"provider"`
				Alias    bool   `yaml:"alias"`
			} `yaml:"version"`
		} `yaml:"extra"`
	}
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Extra.Version.Provider != "mike" || !cfg.Extra.Version.Alias {
		t.Errorf("extra.version is %+v, want provider mike and alias true (the dropdown shows latest)", cfg.Extra.Version)
	}
	// mike appends the version to site_url, so site_url is the bare root; the mike plugin's
	// canonical_version makes every version's canonical link name latest, so search engines index one copy
	if want := "https://blanketfish.github.io/port49/"; cfg.SiteURL != want {
		t.Errorf("site_url is %q, want %q (mike appends the version)", cfg.SiteURL, want)
	}
	var search, mike bool
	for _, p := range cfg.Plugins {
		switch v := p.(type) {
		case string:
			search = search || v == "search"
		case map[string]any:
			if opts, ok := v["mike"].(map[string]any); ok {
				mike = true
				if opts["canonical_version"] != "latest" {
					t.Errorf("the mike plugin's canonical_version is %v, want latest", opts["canonical_version"])
				}
				// Material draws its own selector; mike's would add a second one
				if opts["version_selector"] != false {
					t.Errorf("the mike plugin's version_selector is %v, want false (Material's dropdown is the selector)", opts["version_selector"])
				}
			}
		}
	}
	if !mike {
		t.Error("mkdocs.yml has no mike plugin")
	}
	if !search {
		t.Error("listing plugins dropped the default search plugin")
	}
}

// deepLink is a link into the published site: the host, the /port49/ path, and a page. The bare
// site root (followed by anything but a letter) is not one.
var deepLink = regexp.MustCompile(`blanketfish\.github\.io/port49/([a-z][a-z0-9_-]*)`)

func TestEveryDeepLinkToTheSiteNamesAVersion(t *testing.T) {
	out, err := exec.Command("git", "-C", repoRoot, "ls-files", "-z").Output()
	if err != nil {
		t.Skipf("no git: %v", err)
	}
	checked := 0
	for _, rel := range strings.Split(strings.TrimRight(string(out), "\x00"), "\x00") {
		base := filepath.Base(rel)
		switch {
		case strings.HasPrefix(rel, "docs/superpowers/"), // plans and the roadmap are history, not shipped links
			strings.HasPrefix(rel, "tests/lab/logs/"), strings.HasPrefix(rel, "tests/lab/captures/"),
			base == "realm.json", strings.HasSuffix(base, ".env"), strings.HasSuffix(base, "-key.pem"), strings.HasSuffix(base, ".keytab"):
			continue
		}
		b, err := os.ReadFile(filepath.Join(repoRoot, rel))
		if err != nil {
			continue // a deleted or unreadable path is not this test's business
		}
		for _, m := range deepLink.FindAllSubmatch(b, -1) {
			checked++
			if v := string(m[1]); v != "latest" && v != "dev" {
				t.Errorf("%s links the site at /port49/%s...: a deep link is /port49/latest/%s", rel, v, v)
				break
			}
		}
	}
	if checked < 100 {
		t.Errorf("checked only %d deep links: the scan is not looking where the links are", checked)
	}
}
