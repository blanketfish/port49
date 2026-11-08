package ci

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Task 24: the top-level README and the site's home page. The README is an overview of why anyone would
// use port49, not a feature list; the home page carries the same points, shorter.
const siteURL = "https://blanketfish.github.io/port49/"

func init() {
	mustSay["index.md"] = append(mustSay["index.md"],
		"## Why port49", "systemd", "Helm", "Apache-2.0", siteURL, "qualified-platforms", "contributing/",
	)
}

func TestTheReadmeSaysWhatItMust(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(repoRoot, "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"## Why port49", "systemd", "Helm", "Apache-2.0", siteURL, "qualified-platforms", "docs/site/contributing/"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("README.md does not say %q", want)
		}
	}
}

var topBullet = regexp.MustCompile(`^[-*] `)

// topBullets counts the top-level bullets of text outside fenced blocks.
func topBullets(text string) int {
	n, in := 0, false
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "```") {
			in = !in
			continue
		}
		if !in && topBullet.MatchString(line) {
			n++
		}
	}
	return n
}

func TestTheBulletCounterCountsTopLevelOnly(t *testing.T) {
	if got := topBullets("- a\n  - b\n* c\n```\n- d\n```\ntext\n"); got != 2 {
		t.Errorf("counted %d, want 2", got)
	}
}

func TestTheReadmeIsNotAFeatureList(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(repoRoot, "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	_, rest, ok := strings.Cut(text, "## Why port49\n")
	if !ok {
		t.Fatal("README.md has no `## Why port49` heading")
	}
	why, after, _ := strings.Cut(rest, "\n## ")
	before, _, _ := strings.Cut(text, "## Why port49\n")
	if n := topBullets(why); n < 3 || n > 5 {
		t.Errorf("`## Why port49` holds %d top-level bullets, want 3 to 5", n)
	}
	if n := topBullets(before + after); n > 7 {
		t.Errorf("the rest of the README holds %d top-level bullets, want at most 7", n)
	}
	for _, banned := range []string{"Kubernetes-native", "Nothing is implemented"} {
		if strings.Contains(text, banned) {
			t.Errorf("README.md says %q", banned)
		}
	}
}
