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

func TestTheSiteIsVersionedByMike(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(repoRoot, "mkdocs.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		SiteURL string `yaml:"site_url"`
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
	// the absolute URLs mkdocs and docgen build (canonical links, the sitemap, llms.txt) name latest
	// whichever version is being built, so they never point at a copy that is about to be replaced
	if want := "https://blanketfish.github.io/port49/latest/"; cfg.SiteURL != want {
		t.Errorf("site_url is %q, want %q", cfg.SiteURL, want)
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
