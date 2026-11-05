package ci

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The release's builds (pre-beta Task 20): what a pull request must build so a tag never meets a
// build failure first, and the license every artifact carries.

func readRepo(t *testing.T, rel ...string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(append([]string{"..", ".."}, rel...)...))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// A PEP 639 license expression and a License:: classifier cannot sit together: setuptools refuses
// the project, and the release's wheel build with it.
func TestThePythonProjectHasNoLicenseClassifierBesideItsExpression(t *testing.T) {
	raw := readRepo(t, "clients", "python", "pyproject.toml")
	if regexp.MustCompile(`(?m)^license\s*=\s*"`).MatchString(raw) && strings.Contains(raw, "License ::") {
		t.Error("pyproject.toml has license = \"...\" and a License :: classifier")
	}
}

func TestAPullRequestBuildsWhatTheReleaseBuilds(t *testing.T) {
	f, _ := load(t, "../../.github/workflows/python.yml")
	want := []string{
		"pip install --require-hashes -r packaging/requirements-release.txt",
		"python -m build --no-isolation clients/python",
		"ansible-galaxy collection build",
	}
	for id, j := range f.Jobs {
		var runs []string
		for _, s := range j.Steps {
			runs = append(runs, s.Run)
		}
		all := strings.Join(runs, "\n")
		ok := true
		for _, w := range want {
			ok = ok && strings.Contains(all, w)
		}
		if ok {
			return
		}
		_ = id
	}
	t.Errorf("no python.yml job runs all of %q", want)
}

func TestTheGoToolchainMatchesTheDockerfile(t *testing.T) {
	m := regexp.MustCompile(`(?m)^toolchain go(\S+)$`).FindStringSubmatch(readRepo(t, "go.mod"))
	if m == nil {
		t.Fatal("go.mod has no toolchain line")
	}
	d := regexp.MustCompile(`# golang:\S+ \((\d+\.\d+\.\d+),`).FindStringSubmatch(readRepo(t, "Dockerfile"))
	if d == nil {
		t.Fatal("Dockerfile has no golang patch comment")
	}
	if m[1] != d[1] {
		t.Errorf("go.mod toolchain go%s, Dockerfile comment %s", m[1], d[1])
	}
}

// A restored build cache is an input a tag's release did not review.
func TestReleaseSetupGoNeverRestoresACache(t *testing.T) {
	f, _ := release(t)
	n := 0
	for id, j := range f.Jobs {
		for _, s := range j.Steps {
			if !strings.HasPrefix(s.Uses, "actions/setup-go@") {
				continue
			}
			n++
			if v, ok := s.With["cache"].(bool); !ok || v {
				t.Errorf("release.yml job %s: setup-go lacks cache: false", id)
			}
		}
	}
	if n == 0 {
		t.Fatal("release.yml has no setup-go")
	}
}

func TestEveryArtifactCarriesTheLicense(t *testing.T) {
	lic := readRepo(t, "LICENSE")
	for _, p := range [][]string{
		{"clients", "python", "LICENSE"},
		{"clients", "ansible", "ansible_collections", "port49", "client", "LICENSE"},
	} {
		if readRepo(t, p...) != lic {
			t.Errorf("%s is not a copy of LICENSE", filepath.Join(p...))
		}
	}
	if !strings.Contains(readRepo(t, "packaging", "copyright"), "Apache-2.0") {
		t.Error("packaging/copyright does not name Apache-2.0")
	}
	if !regexp.MustCompile(`(?m)^license-files\s*=\s*\[[^\]]*"LICENSE"`).MatchString(readRepo(t, "clients", "python", "pyproject.toml")) {
		t.Error("pyproject.toml license-files does not list LICENSE")
	}
	g := readRepo(t, ".goreleaser.yaml")
	if !regexp.MustCompile(`src: packaging/copyright\n\s+dst: /usr/share/doc/port49-server/copyright\n`).MatchString(g) {
		t.Error(".goreleaser.yaml: port49-server does not ship /usr/share/doc/port49-server/copyright")
	}
	if !strings.Contains(readRepo(t, "Dockerfile"), "COPY LICENSE /LICENSE") {
		t.Error("Dockerfile does not COPY LICENSE /LICENSE")
	}
}
