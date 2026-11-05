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
	rel := releasePython(t)
	for _, j := range f.Jobs {
		var runs []string
		for _, s := range j.Steps {
			runs = append(runs, s.Run)
		}
		all := strings.Join(runs, "\n")
		ok := true
		for _, w := range want {
			ok = ok && strings.Contains(all, w)
		}
		if !ok {
			continue
		}
		for _, s := range j.Steps {
			if strings.HasPrefix(s.Uses, "actions/setup-python@") {
				if pv, _ := s.With["python-version"].(string); pv != rel {
					t.Errorf("the PR build uses Python %q, the release %q", pv, rel)
				}
			}
		}
		return
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
	if !strings.Contains(readRepo(t, "clients", "python", "pyproject.toml"), `"setuptools>=77"`) {
		t.Error("pyproject.toml's build-system needs setuptools>=77 (PEP 639)")
	}
	if !regexp.MustCompile(`(?m)^license-files\s*=\s*\[[^\]]*"LICENSE"`).MatchString(readRepo(t, "clients", "python", "pyproject.toml")) {
		t.Error("pyproject.toml license-files does not list LICENSE")
	}
	g := readRepo(t, ".goreleaser.yaml")
	for _, pkg := range []string{"port49-server", "port49"} {
		if !regexp.MustCompile(`src: packaging/copyright\n\s+dst: /usr/share/doc/` + pkg + `/copyright\n`).MatchString(g) {
			t.Errorf(".goreleaser.yaml: %s does not ship /usr/share/doc/%s/copyright", pkg, pkg)
		}
	}
	if !strings.Contains(readRepo(t, "Dockerfile"), "COPY LICENSE /LICENSE") {
		t.Error("Dockerfile does not COPY LICENSE /LICENSE")
	}
}

// Nothing goes public until every artifact has built: the image and the chart wait for the wheel
// and the collection, so a failed Python build never leaves them behind.
func TestNoPublicPushPrecedesTheArtifactBuilds(t *testing.T) {
	f, _ := release(t)
	for _, id := range []string{"image", "chart"} {
		have := map[string]bool{}
		switch n := f.Jobs[id].Needs.(type) {
		case []any:
			for _, x := range n {
				have[x.(string)] = true
			}
		case string:
			have[n] = true
		}
		for _, w := range []string{"build-python", "build-galaxy"} {
			if !have[w] {
				t.Errorf("release.yml job %s does not need %s", id, w)
			}
		}
	}
}
