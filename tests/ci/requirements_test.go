package ci

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// packaging/requirements-release.txt is what the release workflow installs with --require-hashes: every
// requirement is an exact pin carrying at least one sha256, and it pins what the .in file asks for.
func TestTheReleaseRequirementsAreExactAndHashed(t *testing.T) {
	read := func(name string) string {
		b, err := os.ReadFile(filepath.Join("..", "..", "packaging", name))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	txt := read("requirements-release.txt")
	pins := map[string]string{}
	var cur string
	hashes := map[string]int{}
	req := regexp.MustCompile(`^([A-Za-z0-9_.-]+)==([A-Za-z0-9_.+!-]+) \\$`)
	hash := regexp.MustCompile(`^\s+--hash=sha256:[0-9a-f]{64}( \\)?$`)
	for _, l := range strings.Split(txt, "\n") {
		switch {
		case l == "" || strings.HasPrefix(strings.TrimSpace(l), "#"):
		case req.MatchString(l):
			m := req.FindStringSubmatch(l)
			cur = strings.ToLower(strings.ReplaceAll(m[1], "_", "-"))
			pins[cur] = m[2]
		case hash.MatchString(l):
			hashes[cur]++
		default:
			t.Errorf("requirements-release.txt has a line that is not an exact pin or a sha256: %q", l)
		}
	}
	for name, v := range pins {
		if hashes[name] == 0 {
			t.Errorf("%s==%s has no hash", name, v)
		}
	}
	for _, l := range strings.Split(read("requirements-release.in"), "\n") {
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		name, v, ok := strings.Cut(l, "==")
		if !ok {
			t.Errorf("requirements-release.in line %q is not an exact pin", l)
			continue
		}
		if pins[strings.ToLower(name)] != v {
			t.Errorf("%s is %q in the .in file and %q in the .txt: regenerate with make requirements-release", name, v, pins[strings.ToLower(name)])
		}
	}
	for _, need := range []string{"build", "setuptools", "ansible-core"} {
		if pins[need] == "" {
			t.Errorf("%s is not pinned", need)
		}
	}
}
