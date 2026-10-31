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
	exactAndHashed(t, "requirements-release", []string{"build", "setuptools", "ansible-core"})
}

// The Python test job installs from packaging/requirements-ci.txt the same way, and the workflow says
// --require-hashes (a pip install of bare pins would take whatever the index serves).
func TestThePythonJobInstallsWithHashes(t *testing.T) {
	exactAndHashed(t, "requirements-ci", []string{"ansible-core", "paramiko", "ansible-pylibssh"})
	b, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "python.yml"))
	if err != nil {
		t.Fatal(err)
	}
	for i, l := range strings.Split(string(b), "\n") {
		if strings.Contains(l, "pip install") && !strings.Contains(l, "--require-hashes") {
			t.Errorf("python.yml:%d installs without --require-hashes: %s", i+1, strings.TrimSpace(l))
		}
	}
}

func exactAndHashed(t *testing.T, base string, need []string) {
	t.Helper()
	read := func(name string) string {
		b, err := os.ReadFile(filepath.Join("..", "..", "packaging", name))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	txt := read(base + ".txt")
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
			t.Errorf(base+".txt has a line that is not an exact pin or a sha256: %q", l)
		}
	}
	for name, v := range pins {
		if hashes[name] == 0 {
			t.Errorf("%s==%s has no hash", name, v)
		}
	}
	for _, l := range strings.Split(read(base+".in"), "\n") {
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		name, v, ok := strings.Cut(l, "==")
		if !ok {
			t.Errorf(base+".in line %q is not an exact pin", l)
			continue
		}
		if pins[strings.ToLower(name)] != v {
			t.Errorf("%s is %q in the .in file and %q in the .txt: regenerate with make requirements-release", name, v, pins[strings.ToLower(name)])
		}
	}
	for _, need := range need {
		if pins[need] == "" {
			t.Errorf("%s is not pinned", need)
		}
	}
}
