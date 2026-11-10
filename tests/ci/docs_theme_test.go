package ci

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// The site has a light and a dark scheme. The first follows the reader's system setting, each carries a
// toggle icon, and nothing the theme loads comes from outside the site's origin.
func TestTheThemeHasALightAndADarkSchemeWithAToggle(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "mkdocs.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Theme struct {
			Font    any `yaml:"font"`
			Palette []struct {
				Media  string `yaml:"media"`
				Scheme string `yaml:"scheme"`
				Toggle struct {
					Icon string `yaml:"icon"`
					Name string `yaml:"name"`
				} `yaml:"toggle"`
			} `yaml:"palette"`
		} `yaml:"theme"`
	}
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		t.Fatalf("mkdocs.yml: %v", err)
	}
	if cfg.Theme.Font != false {
		t.Error("theme.font must stay false: the site loads no font from outside its origin")
	}
	pal := cfg.Theme.Palette
	if len(pal) != 2 {
		t.Fatalf("theme.palette has %d entries, want a default and a slate scheme", len(pal))
	}
	for i, want := range []struct{ scheme, media string }{
		{"default", "(prefers-color-scheme: light)"},
		{"slate", "(prefers-color-scheme: dark)"},
	} {
		if pal[i].Scheme != want.scheme {
			t.Errorf("palette[%d].scheme = %q, want %q", i, pal[i].Scheme, want.scheme)
		}
		if pal[i].Media != want.media {
			t.Errorf("palette[%d].media = %q, want %q", i, pal[i].Media, want.media)
		}
		if pal[i].Toggle.Icon == "" || pal[i].Toggle.Name == "" {
			t.Errorf("palette[%d] has no toggle icon and name", i)
		}
		if strings.Contains(pal[i].Toggle.Icon, "://") {
			t.Errorf("palette[%d] toggle icon is a URL", i)
		}
	}
}

// The version banner takes its colors from the theme (Material's own announce bar), so it reads in both
// schemes. A color written into the override or a stylesheet would not follow the scheme.
func TestTheBannerOverrideHardCodesNoColor(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "docs", "overrides", "main.html"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, bad := range []string{"style=", "<style", "rgb(", "rgba(", "hsl("} {
		if strings.Contains(s, bad) {
			t.Errorf("docs/overrides/main.html holds %q: use the theme's variables, not a color", bad)
		}
	}
	// a hex color, not a Jinja comment or a fragment link; a var(--md-...) reference is the theme's own
	if hex := regexp.MustCompile(`#[0-9a-fA-F]{3,8}\b`).FindString(s); hex != "" {
		t.Errorf("docs/overrides/main.html holds the color %q: use the theme's variables", hex)
	}
	b, err = os.ReadFile(filepath.Join("..", "..", "mkdocs.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		ExtraCSS []string `yaml:"extra_css"`
	}
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		t.Fatal(err)
	}
	// the one stylesheet sets the page width; a color in it would need its own dark rules
	if len(cfg.ExtraCSS) != 1 || cfg.ExtraCSS[0] != "stylesheets/extra.css" {
		t.Fatalf("mkdocs.yml extra_css is %v, want only stylesheets/extra.css", cfg.ExtraCSS)
	}
	css, err := os.ReadFile(filepath.Join(docsRoot, "stylesheets", "extra.css"))
	if err != nil {
		t.Fatal(err)
	}
	c := string(css)
	for _, bad := range []string{"color", "background", "border", "shadow", "fill", "rgb(", "hsl(", "@import", "url("} {
		if strings.Contains(c, bad) {
			t.Errorf("stylesheets/extra.css holds %q: it sets the page width only", bad)
		}
	}
	if hex := regexp.MustCompile(`#[0-9a-fA-F]{3,8}\b`).FindString(c); hex != "" {
		t.Errorf("stylesheets/extra.css holds the color %q", hex)
	}
	if !strings.Contains(c, ".md-grid") || !strings.Contains(c, "max-width") {
		t.Error("stylesheets/extra.css does not widen .md-grid")
	}
}
