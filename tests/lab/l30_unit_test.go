//go:build lab

package lab

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestL30FixturesAreWhatTheNotesSay reads every L30 fixture directory: each
// file parses and carries no credential, the product's note names the
// directory as a capture pointer, and rest-pages.json followed `next` to a
// null and saw every device it counted exactly once — the claim L30 exists
// to make — or the note says it did not.
func TestL30FixturesAreWhatTheNotesSay(t *testing.T) {
	dirs, _ := filepath.Glob(filepath.Join("sot", "l30", "*"))
	if len(dirs) == 0 {
		t.Skip("no L30 fixtures recorded yet")
	}
	for _, dir := range dirs {
		product := strings.SplitN(filepath.Base(dir), "-", 2)[0]
		note, err := os.ReadFile(filepath.Join("results", "L30-"+product+".md"))
		if err != nil {
			t.Fatalf("%s has fixtures and no note: %v", dir, err)
		}
		if !strings.Contains(string(note), "tests/lab/sot/l30/"+filepath.Base(dir)+"/") {
			t.Errorf("L30-%s.md does not name %s as a capture pointer", product, dir)
		}
		files, _ := filepath.Glob(filepath.Join(dir, "*.json"))
		for _, path := range files {
			raw, err := os.ReadFile(path)
			if err != nil || !json.Valid(raw) {
				t.Fatalf("%s: unreadable or not JSON: %v", path, err)
			}
			if strings.Contains(string(raw), `"Authorization"`) || l27Credential.Match(raw) {
				t.Fatalf("%s carries a credential", path)
			}
		}
		raw, err := os.ReadFile(filepath.Join(dir, "rest-pages.json"))
		if err != nil {
			t.Fatalf("%s: %v", dir, err)
		}
		var pages struct {
			Count    int      `json:"count"`
			Names    []string `json:"names"`
			EndedAt  string   `json:"ended_at"`
			Repeated []string `json:"repeated"`
		}
		if err := json.Unmarshal(raw, &pages); err != nil {
			t.Fatal(err)
		}
		complete := pages.EndedAt == "null_next" && len(pages.Names) == pages.Count && len(pages.Repeated) == 0
		if !complete && !strings.Contains(string(note), filepath.Base(dir)+": the list did not page to the end once") {
			t.Errorf("%s: %d of %d names, ended at %q, repeated %v, and the note does not say so",
				dir, len(pages.Names), pages.Count, pages.EndedAt, pages.Repeated)
		}
	}
}
