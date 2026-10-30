package shapes

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const maintainerAddress = "port49 maintainers <port49@blanketfish.com>"

// Every maintainer or author field in the tree names the one project address. A field that does not
// exist (Chart.yaml maintainers, pyproject authors) is not required; one that does exist must match.
func TestEveryMaintainerFieldNamesTheProjectAddress(t *testing.T) {
	read := func(rel string) []byte {
		b, err := os.ReadFile(filepath.Join("..", "..", filepath.FromSlash(rel)))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	// walk finds every key named maintainer(s) or author(s) in a YAML document and hands its value over.
	var walk func(n any, f func(key string, v any))
	walk = func(n any, f func(string, any)) {
		switch x := n.(type) {
		case map[string]any:
			for k, v := range x {
				switch k {
				case "maintainer", "maintainers", "author", "authors":
					f(k, v)
				}
				walk(v, f)
			}
		case []any:
			for _, v := range x {
				walk(v, f)
			}
		}
	}
	found := map[string]int{}
	for _, rel := range []string{".goreleaser.yaml", "clients/ansible/ansible_collections/port49/client/galaxy.yml", "deploy/helm/port49/Chart.yaml"} {
		var doc any
		if err := yaml.Unmarshal(read(rel), &doc); err != nil {
			t.Fatalf("%s: %v", rel, err)
		}
		walk(doc, func(k string, v any) {
			found[rel]++
			var vals []string
			switch x := v.(type) {
			case string:
				vals = []string{x}
			case []any:
				for _, e := range x {
					if s, ok := e.(string); ok {
						vals = append(vals, s)
					} else if m, ok := e.(map[string]any); ok { // a Chart.yaml maintainer: name and email
						vals = append(vals, "port49 maintainers <"+toString(m["email"])+">")
						if toString(m["name"]) != "port49 maintainers" {
							vals[len(vals)-1] += " (name " + toString(m["name"]) + ")"
						}
					}
				}
			}
			if len(vals) == 0 {
				t.Errorf("%s: %s is not a string or a list of them", rel, k)
			}
			for _, s := range vals {
				if s != maintainerAddress {
					t.Errorf("%s: %s is %q, want %q", rel, k, s, maintainerAddress)
				}
			}
		})
	}
	if found[".goreleaser.yaml"] != 2 {
		t.Errorf(".goreleaser.yaml has %d maintainer fields, want one per package (2)", found[".goreleaser.yaml"])
	}
	if found["clients/ansible/ansible_collections/port49/client/galaxy.yml"] != 1 {
		t.Error("galaxy.yml has no authors field")
	}
	// pyproject.toml: if it names authors or maintainers, they name the address too.
	for _, l := range strings.Split(string(read("clients/python/pyproject.toml")), "\n") {
		if k := strings.TrimSpace(l); strings.HasPrefix(k, "authors") || strings.HasPrefix(k, "maintainers") {
			if !strings.Contains(k, "port49@blanketfish.com") {
				t.Errorf("pyproject.toml: %q does not name the project address", k)
			}
		}
	}
	// No placeholder address is left anywhere in the packaging.
	for _, rel := range []string{".goreleaser.yaml", "clients/python/pyproject.toml", "deploy/helm/port49/Chart.yaml", "clients/ansible/ansible_collections/port49/client/galaxy.yml"} {
		if strings.Contains(string(read(rel)), "example.com") || strings.Contains(string(read(rel)), "placeholder: Ryan") {
			t.Errorf("%s still carries the placeholder maintainer address", rel)
		}
	}
}

func toString(v any) string {
	s, _ := v.(string)
	return s
}
