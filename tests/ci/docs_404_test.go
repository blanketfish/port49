package ci

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The site's root 404.html (deployed to gh-pages by docs.yml) sends a link written before the site was
// versioned, /port49/<page>, to /port49/latest/<page>, and leaves a real 404 inside a version alone.

const docs404 = ".github/docs-404.html"

// script404 is the page's one inline script.
func script404(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot, docs404))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?s)<script>(.*?)</script>`).FindSubmatch(b)
	if m == nil {
		t.Fatalf("%s has no inline script", docs404)
	}
	if strings.Contains(string(b), "src=") || strings.Contains(string(b), "http://") || strings.Contains(string(b), "https://") {
		t.Errorf("%s loads or names another origin", docs404)
	}
	return string(m[1])
}

// run404 runs the script under node with a fake location and a versions.json of versions (nil: the
// fetch fails) and returns where it sent the browser, or "" if it stayed.
func run404(t *testing.T, node, script, path, search, hash string, versions any) string {
	t.Helper()
	vj, _ := json.Marshal(versions)
	fetch := `function () { return Promise.reject(new Error("offline")); }`
	if versions != nil {
		fetch = `function () { return Promise.resolve({ json: function () { return Promise.resolve(` + string(vj) + `); } }); }`
	}
	harness := `var out = "";
var location = { pathname: ` + jsString(path) + `, search: ` + jsString(search) + `, hash: ` + jsString(hash) + `, replace: function (u) { out = u; } };
var fetch = ` + fetch + `;
` + script + `
setTimeout(function () { console.log(out); }, 20);`
	f := filepath.Join(t.TempDir(), "h.js")
	if err := os.WriteFile(f, []byte(harness), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(node, f).CombinedOutput()
	if err != nil {
		t.Fatalf("node: %v\n%s", err, out)
	}
	return strings.TrimSpace(string(out))
}

func jsString(s string) string { b, _ := json.Marshal(s); return string(b) }

func TestTheRoot404SendsOldLinksToLatest(t *testing.T) {
	script := script404(t)
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("no node to run the script with")
	}
	versions := []map[string]any{
		{"version": "dev", "aliases": []string{}},
		{"version": "0.2", "aliases": []string{"latest"}},
		{"version": "0.1", "aliases": []string{}},
	}
	for _, c := range []struct {
		name, path, search, hash string
		versions                 any
		want                     string
	}{
		{"an old deep link", "/port49/admin/policy/", "", "", versions, "/port49/latest/admin/policy/"},
		{"keeps the query and the hash", "/port49/reference/alerts/", "?q=a", "#port49_target_down", versions, "/port49/latest/reference/alerts/?q=a#port49_target_down"},
		{"the old root llms.txt", "/port49/llms.txt", "", "", versions, "/port49/latest/llms.txt"},
		{"a real 404 in dev", "/port49/dev/nope/", "", "", versions, ""},
		{"a real 404 in latest", "/port49/latest/nope/", "", "", versions, ""},
		{"a real 404 in a release", "/port49/0.1/nope/", "", "", versions, ""},
		{"a version the site does not have", "/port49/0.9/admin/", "", "", versions, "/port49/latest/0.9/admin/"},
		{"a path outside the site", "/other/x/", "", "", versions, ""},
		{"versions.json unreachable, an old link", "/port49/admin/policy/", "", "", nil, "/port49/latest/admin/policy/"},
		{"versions.json unreachable, a version-shaped path", "/port49/0.3/nope/", "", "", nil, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := run404(t, node, script, c.path, c.search, c.hash, c.versions); got != c.want {
				t.Errorf("%s%s%s went to %q, want %q", c.path, c.search, c.hash, got, c.want)
			}
		})
	}
}
