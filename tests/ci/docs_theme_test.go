package ci

import (
	"os"
	"path/filepath"
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
	for _, bad := range []string{"style=", "<style", "#", "rgb(", "color:"} {
		if strings.Contains(s, bad) {
			t.Errorf("docs/overrides/main.html holds %q: use the theme's variables, not a color", bad)
		}
	}
	cfg, err := os.ReadFile(filepath.Join("..", "..", "mkdocs.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(cfg), "extra_css") {
		t.Error("mkdocs.yml adds a stylesheet: it would need its own dark rules")
	}
}
