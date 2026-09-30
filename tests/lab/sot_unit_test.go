//go:build lab

package lab

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// l27Credential is what a NetBox v2 or a v1 token looks like on the wire.
var l27Credential = regexp.MustCompile(`nbt_[A-Za-z0-9]|Token [0-9a-f]{40}`)

// TestL27FixturesAreWhatTheNotesSay reads every recorded fixture directory:
// each file parses, no fixture carries the lab API token's header or a
// token's wire form, the note names the directory as a capture pointer, and
// the version each status.json reports is named in its product's note, so a
// note cannot claim a version or a directory the run did not record.
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
		if !strings.Contains(string(note), "tests/lab/sot/fixtures/"+filepath.Base(dir)+"/") {
			t.Errorf("L27-%s.md does not name %s as a capture pointer", product, dir)
		}
		for _, name := range []string{"status.json", "api-root.json", "seed.json", "rest-device.json",
			"rest-page.json", "graphql.json", "webhooks.json"} {
			if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
				t.Fatalf("%s: %v", dir, err)
			}
		}
		// Every file, the per-stack extras (auth-v1.json, rest-device-depth1.json) included.
		files, _ := filepath.Glob(filepath.Join(dir, "*.json"))
		for _, path := range files {
			name := filepath.Base(path)
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("%s: %v", dir, err)
			}
			if !json.Valid(raw) {
				t.Fatalf("%s/%s is not JSON", dir, name)
			}
			if strings.Contains(string(raw), `"Authorization"`) {
				t.Fatalf("%s/%s carries an Authorization header", dir, name)
			}
			if l27Credential.Match(raw) {
				t.Fatalf("%s/%s carries a token", dir, name)
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
