package inventory

import (
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// descriptionsFile is the file the generated port49-inventory reference is written from
// (internal/docgen). docgen imports this package, so the test reads the YAML as data.
const descriptionsFile = "../docgen/descriptions/port49-inventory.yaml"

// A key whose description names the values it takes must name the values Load takes: each accepted
// value is loaded for real, a value that is none is refused, and every backticked word in the
// description is an accepted value or a listed non-value.
func TestEnumeratedValuesAreLoadersValues(t *testing.T) {
	t.Setenv("PORT49_TEST_NETBOX_TOKEN", testToken)
	source := func(typ, api string) string {
		s := "  - name: s1\n    type: " + typ + "\n"
		if typ == "file" {
			return s + "    path: /etc/i/s1.yaml\n"
		}
		s += "    url: https://netbox.example.com\n    ca_file: /etc/i/netbox-ca.pem\n" +
			"    token_secret_ref: env:PORT49_TEST_NETBOX_TOKEN\n"
		if api != "" {
			s += "    api: " + api + "\n"
		}
		return s
	}
	base := strings.Split(minimalConfig, "sync:")[0] + "sync:\n"
	loads := func(body string) bool {
		_, err := loadString(t, body)
		return err == nil
	}
	cases := []struct {
		key    string
		accept []string
		others []string
		loads  func(v string) bool
	}{
		{"sync.[].type", []string{"file", "netbox", "nautobot"}, nil,
			func(v string) bool { return loads(base + source(v, "")) }},
		{"sync.[].api", []string{"auto", "graphql", "rest"}, []string{"netbox", "nautobot"},
			func(v string) bool { return loads(base + source("netbox", v)) }},
	}
	raw, err := os.ReadFile(descriptionsFile)
	if err != nil {
		t.Fatal(err)
	}
	desc := map[string]string{}
	if err := yaml.Unmarshal(raw, &desc); err != nil {
		t.Fatal(err)
	}
	backticked := regexp.MustCompile("`([a-z][a-z0-9_-]*)`")
	for _, c := range cases {
		d, ok := desc[c.key]
		if !ok {
			t.Errorf("%s: no description", c.key)
			continue
		}
		for _, v := range c.accept {
			if !c.loads(v) {
				t.Errorf("%s: Load refuses %q, which the test lists as accepted", c.key, v)
			}
		}
		if c.loads("zz_not_a_value") {
			t.Errorf("%s: Load takes a value that is none, so the probe proves nothing", c.key)
		}
		var named []string
		for _, m := range backticked.FindAllStringSubmatch(d, -1) {
			named = append(named, m[1])
		}
		for _, v := range c.accept {
			if !slices.Contains(named, v) {
				t.Errorf("%s: the description does not name `%s`", c.key, v)
			}
		}
		var stray []string
		for _, w := range named {
			if !slices.Contains(c.accept, w) && !slices.Contains(c.others, w) {
				stray = append(stray, w)
			}
		}
		sort.Strings(stray)
		if len(stray) > 0 {
			t.Errorf("%s: the description names %s, which Load does not take (accepted: %s)", c.key,
				strings.Join(stray, ", "), strings.Join(c.accept, ", "))
		}
	}
}
