//go:build lab

package lab

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestL27FixturesAreWhatTheNotesSay reads every recorded fixture directory:
// each file parses, no fixture carries the lab API token's header, and the
// version each status.json reports is named in its product's note, so a note
// cannot claim a version the run did not record.
func TestL27FixturesAreWhatTheNotesSay(t *testing.T) {
	dirs, _ := filepath.Glob(filepath.Join("sot", "fixtures", "*"))
	if len(dirs) == 0 {
		t.Skip("no L27 fixtures recorded yet")
	}
	for _, dir := range dirs {
		product := strings.SplitN(filepath.Base(dir), "-", 2)[0]
		note, err := os.ReadFile(filepath.Join("results", "L27-"+product+".md"))
		if err != nil {
			t.Fatalf("%s has fixtures and no note: %v", dir, err)
		}
		for _, name := range []string{"status.json", "api-root.json", "seed.json", "rest-device.json",
			"rest-page.json", "graphql.json", "webhooks.json"} {
			raw, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil {
				t.Fatalf("%s: %v", dir, err)
			}
			if !json.Valid(raw) {
				t.Fatalf("%s/%s is not JSON", dir, name)
			}
			if strings.Contains(string(raw), `"Authorization"`) {
				t.Fatalf("%s/%s carries an Authorization header", dir, name)
			}
		}
		var status struct {
			Body map[string]any `json:"body"`
		}
		raw, _ := os.ReadFile(filepath.Join(dir, "status.json"))
		if err := json.Unmarshal(raw, &status); err != nil {
			t.Fatal(err)
		}
		version, _ := status.Body[product+"-version"].(string)
		if version == "" || !strings.Contains(string(note), version) {
			t.Errorf("%s reports %s-version %q, which L27-%s.md does not name", dir, product, version, product)
		}
	}
}
