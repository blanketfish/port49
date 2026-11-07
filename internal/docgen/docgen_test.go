package docgen

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

const repoRoot = "../.."

type fixtureDur time.Duration

func (*fixtureDur) UnmarshalYAML(*yaml.Node) error { return nil }

type fixtureInner struct {
	C string `yaml:"c"`
}

type fixtureMapped struct {
	D int `yaml:"d"`
}

type fixtureItem struct {
	E bool `yaml:"e"`
}

type fixtureRoot struct {
	A      string                   `yaml:"a"`
	Hidden string                   `yaml:"-"`
	B      *fixtureInner            `yaml:"b"`
	M      map[string]fixtureMapped `yaml:"m"`
	L      []fixtureItem            `yaml:"l"`
	U      fixtureDur               `yaml:"u"`
}

func TestKeysWalksTheYAMLTags(t *testing.T) {
	got := Keys(reflect.TypeOf(fixtureRoot{}))
	want := []Key{{"a", "string"}, {"b.c", "string"}, {"m.<name>.d", "integer"}, {"l.[].e", "boolean"}, {"u", "duration"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Keys = %v, want %v", got, want)
	}
}

type fixtureNames struct {
	Plain     string        `yaml:"plain"`
	SecretRef string        `yaml:"secret_ref"`
	PwRef     string        `yaml:"password_secret_ref"`
	Wait      time.Duration `yaml:"wait"`
	Words     []string      `yaml:"words"`
	Labels    map[string]string
	Refused   time.Duration `yaml:"receipt_ttl"`
	Embedded  fixtureInner  `yaml:",inline"`
	Percent   *int          `yaml:"percent"`
}

func TestKeysTypesAndNames(t *testing.T) {
	got := Keys(reflect.TypeOf(fixtureNames{}))
	want := []Key{{"plain", "string"}, {"secret_ref", "secret reference"}, {"password_secret_ref", "secret reference"},
		{"wait", "duration"}, {"words", "list of string"}, {"labels", "map of string"}, {"c", "string"}, {"percent", "integer"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Keys = %v, want %v", got, want)
	}
}

func TestEveryKeyHasADescriptionAndEveryDescriptionAKey(t *testing.T) {
	for _, s := range Schemas() {
		desc, err := LoadDescriptions(repoRoot, s)
		if err != nil {
			t.Fatalf("%s: %v", s.File, err)
		}
		if _, err := ConfigPage(s, desc); err != nil {
			t.Errorf("%s: %v", s.File, err)
		}
	}
}

func TestConfigPageNamesWhatIsMissingAndWhatIsExtra(t *testing.T) {
	s := Schema{File: "fixture.yaml", Title: "Fixture", Page: "reference/config/fixture.md", Root: reflect.TypeOf(fixtureRoot{})}
	desc := map[string]string{"a": "the a", "b.c": "the c", "m.<name>.d": "the d", "l.[].e": "DRAFT: the e", "gone": "no key"}
	_, err := ConfigPage(s, desc)
	if err == nil {
		t.Fatal("ConfigPage accepted a page with a missing key, a stale description and a draft")
	}
	for _, want := range []string{"no description for u", "no key for description gone", "l.[].e is still a DRAFT"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not say %q", err, want)
		}
	}
}

func TestTheCommittedPagesAreTheGenerated(t *testing.T) {
	pages, err := Pages(repoRoot)
	if err != nil {
		t.Fatal(err)
	}
	for path, want := range pages {
		got, err := os.ReadFile(filepath.Join(repoRoot, filepath.FromSlash(path)))
		if err != nil {
			t.Errorf("%s is missing: run make docs (%v)", path, err)
			continue
		}
		if string(got) != want {
			t.Errorf("%s is stale: run make docs", path)
		}
	}
}

// The deploy trees ship a file for each schema; each must decode under its own loader, so the schema
// the pages are written from is the one that reads what operators are handed.
func TestSchemasDecodeTheShippedExamples(t *testing.T) {
	dirs := []string{"deploy/compose/config", "deploy/systemd/config", "deploy/examples/stores/single-site",
		"deploy/examples/stores/multi-region"}
	checked := 0
	for _, s := range Schemas() {
		for _, dir := range dirs {
			raw, err := os.ReadFile(filepath.Join(repoRoot, filepath.FromSlash(dir), s.File))
			if os.IsNotExist(err) {
				continue
			}
			if err != nil {
				t.Fatal(err)
			}
			checked++
			if err := s.Decode(raw); err != nil {
				t.Errorf("%s/%s does not decode: %v", dir, s.File, err)
			}
		}
	}
	// Files whose name is not their schema's.
	for _, f := range []struct{ schema, path string }{
		{"policy.yaml", "deploy/device-aaa/policy-platforms.yaml"},
		{"config.yaml", "packaging/client/config.yaml"},
	} {
		for _, s := range Schemas() {
			if s.File != f.schema {
				continue
			}
			raw, err := os.ReadFile(filepath.Join(repoRoot, filepath.FromSlash(f.path)))
			if err != nil {
				t.Fatal(err)
			}
			checked++
			if err := s.Decode(raw); err != nil {
				t.Errorf("%s does not decode as %s: %v", f.path, f.schema, err)
			}
		}
	}
	if checked < 12 {
		t.Errorf("decoded only %d shipped files; the deploy trees moved", checked)
	}
}

// The loader spells two refusals `keys:` and `policy:`; the reference table names keys, not error text.
func TestTheBrokerRefusalTableNamesKeysWithoutColons(t *testing.T) {
	for _, line := range strings.Split(BrokerSection(), "\n") {
		if strings.HasPrefix(line, "| `") && strings.Contains(strings.SplitN(line, "|", 3)[1], ":`") {
			t.Errorf("a refused key is written with a colon: %s", line)
		}
	}
}

func TestNoGeneratedPageIsUnlisted(t *testing.T) {
	pages, err := Pages(repoRoot)
	if err != nil {
		t.Fatal(err)
	}
	site := filepath.Join(repoRoot, "docs", "site")
	err = filepath.WalkDir(site, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".md") {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if !strings.Contains(string(b), Header) {
			return nil
		}
		rel, err := filepath.Rel(repoRoot, p)
		if err != nil {
			return err
		}
		if _, ok := pages[filepath.ToSlash(rel)]; !ok {
			t.Errorf("%s carries the generated header but Pages does not list it", rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
