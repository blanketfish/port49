//go:build lab

package lab

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// l30Stack is what the L30 notes claim per stack for the proxied page and the
// unpaged GraphQL list: the proxy's host (run.sh puts it on the stack's port
// plus 1000) and the status value as graphql_list_0 returned it.
var l30Stack = map[string]struct{ proxyHost, status string }{
	"netbox-3.7":   {"127.0.0.1:19037", `"ACTIVE"`},
	"netbox-4":     {"127.0.0.1:19080", `"active"`},
	"nautobot-1.6": {"127.0.0.1:19016", `{"name":"Active"}`},
	"nautobot-2":   {"127.0.0.1:19020", `{"name":"Active"}`},
	"nautobot-3":   {"127.0.0.1:19030", `{"name":"Active"}`},
}

// TestL30FixturesAreWhatTheNotesSay reads every L30 fixture directory: each
// file parses and carries no credential, the product's note names the
// directory as a capture pointer, the list held more devices than its limit
// and was read over more than one page, and rest-pages.json followed `next`
// to a null and saw every device it counted exactly once — the claim L30
// exists to make — or the note says it did not. The proxied page's `next` is
// https on the proxy's host, and the unpaged GraphQL list returned every
// device with the status spelling the note gives: a run whose bulk seed
// failed fails here.
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
			Limit    int              `json:"limit"`
			Pages    []map[string]any `json:"pages"`
			Count    int              `json:"count"`
			Names    []string         `json:"names"`
			EndedAt  string           `json:"ended_at"`
			Repeated []string         `json:"repeated"`
		}
		if err := json.Unmarshal(raw, &pages); err != nil {
			t.Fatal(err)
		}
		if pages.Limit <= 0 || pages.Count <= pages.Limit || len(pages.Pages) < 2 {
			t.Errorf("%s: count %d, limit %d, %d pages: the list did not page", dir, pages.Count, pages.Limit, len(pages.Pages))
		}
		want, ok := l30Stack[filepath.Base(dir)]
		if !ok {
			t.Fatalf("%s: no expectation for this stack in l30Stack", dir)
		}
		raw, err = os.ReadFile(filepath.Join(dir, "rest-page-proxied.json"))
		if err != nil {
			t.Fatalf("%s: %v", dir, err)
		}
		var proxied struct {
			Status int `json:"status"`
			Body   struct {
				Next string `json:"next"`
			} `json:"body"`
		}
		if err := json.Unmarshal(raw, &proxied); err != nil {
			t.Fatal(err)
		}
		next, err := url.Parse(proxied.Body.Next)
		if proxied.Status != 200 || err != nil || next.Scheme != "https" || next.Host != want.proxyHost {
			t.Errorf("%s: proxied page status %d, next %q; want 200 and https://%s/…", dir, proxied.Status,
				proxied.Body.Next, want.proxyHost)
		}
		raw, err = os.ReadFile(filepath.Join(dir, "graphql-list.json"))
		if err != nil {
			t.Fatalf("%s: %v", dir, err)
		}
		var lists []struct {
			Step   string `json:"step"`
			Status int    `json:"status"`
			Names  int    `json:"names"`
			First  struct {
				Status json.RawMessage `json:"status"`
			} `json:"first"`
		}
		if err := json.Unmarshal(raw, &lists); err != nil {
			t.Fatal(err)
		}
		if len(lists) == 0 || lists[0].Step != "graphql_list_0" {
			t.Fatalf("%s: graphql-list.json has no graphql_list_0 first", dir)
		}
		unpaged := lists[0]
		var status any
		_ = json.Unmarshal(unpaged.First.Status, &status)
		got, _ := json.Marshal(status)
		if unpaged.Status != 200 || unpaged.Names != pages.Count || string(got) != want.status {
			t.Errorf("%s: graphql_list_0 status %d, %d names (the list counted %d), device status %s; want 200, every name, %s",
				dir, unpaged.Status, unpaged.Names, pages.Count, got, want.status)
		}
		complete := pages.EndedAt == "null_next" && len(pages.Names) == pages.Count && len(pages.Repeated) == 0
		if !complete && !strings.Contains(string(note), filepath.Base(dir)+": the list did not page to the end once") {
			t.Errorf("%s: %d of %d names, ended at %q, repeated %v, and the note does not say so",
				dir, len(pages.Names), pages.Count, pages.EndedAt, pages.Repeated)
		}
	}
}
