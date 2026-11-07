package ci

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// mustSay maps a page (relative to docs/site) to literal strings it has to contain. The content tasks
// add their rows from their own files, so a fact a page owes its reader cannot be edited out unseen.
var mustSay = map[string][]string{}

func TestEveryPageSaysWhatItMust(t *testing.T) {
	pages := make([]string, 0, len(mustSay))
	for p := range mustSay {
		pages = append(pages, p)
	}
	sort.Strings(pages)
	for _, page := range pages {
		b, err := os.ReadFile(filepath.Join(docsRoot, filepath.FromSlash(page)))
		if err != nil {
			t.Errorf("%s: %v", page, err)
			continue
		}
		for _, want := range mustSay[page] {
			if !strings.Contains(string(b), want) {
				t.Errorf("%s does not say %q", page, want)
			}
		}
	}
}
