package ci

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
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

// Every binary the release builds reports the tag it was built from (plan 13 task 9).
func TestTheReleaseSetsTheVersion(t *testing.T) {
	var cfg struct {
		Builds []struct {
			ID      string   `yaml:"id"`
			Ldflags []string `yaml:"ldflags"`
		} `yaml:"builds"`
	}
	if err := yaml.Unmarshal([]byte(readRepo(t, ".goreleaser.yaml")), &cfg); err != nil {
		t.Fatal(err)
	}
	if len(cfg.Builds) < 5 {
		t.Fatalf("found %d builds, want at least 5: the scan is broken", len(cfg.Builds))
	}
	const flag = "-X github.com/blanketfish/port49/internal/version.Version={{.Version}}"
	for _, b := range cfg.Builds {
		if !strings.Contains(strings.Join(b.Ldflags, " "), flag) {
			t.Errorf("build %s: ldflags %q lack %s", b.ID, b.Ldflags, flag)
		}
	}
}

// The released image is built by the Dockerfile, not goreleaser, so its four binaries are stamped
// by a build argument the release passes to the image build, with the same -X path and the same
// v-less string goreleaser's {{.Version}} gives.
func TestTheImageBuildStampsTheVersion(t *testing.T) {
	const path = "-X github.com/blanketfish/port49/internal/version.Version="
	df := readRepo(t, "Dockerfile")
	if !regexp.MustCompile(`(?m)^ARG VERSION=dev$`).MatchString(df) {
		t.Error("Dockerfile does not declare ARG VERSION=dev")
	}
	var goBuilds int
	for _, line := range strings.Split(strings.ReplaceAll(df, "\\\n", " "), "\n") {
		if !strings.Contains(line, "go build") {
			continue
		}
		goBuilds++
		if !strings.Contains(line, path+"${VERSION}") || !strings.Contains(line, "-s -w") || !strings.Contains(line, "-trimpath") {
			t.Errorf("Dockerfile go build does not stamp %s${VERSION} beside -s -w and -trimpath: %s", path, line)
		}
	}
	if goBuilds == 0 {
		t.Error("found no go build in the Dockerfile: the scan is broken")
	}

	f, _ := load(t, "../../.github/workflows/release.yml")
	found := false
	for _, s := range f.Jobs["image"].Steps {
		if strings.HasPrefix(s.Uses, "docker/build-push-action@") {
			found = true
			args, _ := s.With["build-args"].(string)
			if !strings.Contains(args, "VERSION=${{ steps.tags.outputs.version }}") {
				t.Errorf("release.yml's image build passes build-args %q, want VERSION from the tags step", args)
			}
		}
	}
	if !found {
		t.Error("release.yml's image job has no docker/build-push-action step")
	}
	if !strings.Contains(readRepo(t, "Makefile"), "--build-arg VERSION=$(VERSION)") {
		t.Error("the Makefile's image target does not pass --build-arg VERSION=$(VERSION)")
	}
}

// One version string everywhere: the Makefile strips the tag's leading v as goreleaser does, falls
// back to dev outside a git checkout, and stamps the same path the release does.
func TestTheMakefileVersionMatchesTheReleaseString(t *testing.T) {
	mk := readRepo(t, "Makefile")
	if !strings.Contains(mk, "VERSION ?= $(patsubst v%,%,$(shell git describe --tags --always --dirty 2>/dev/null || echo dev))") {
		t.Error("Makefile VERSION does not strip a leading v and fall back to dev")
	}
	if !strings.Contains(mk, `-ldflags "-X github.com/blanketfish/port49/internal/version.Version=$(VERSION)"`) {
		t.Error("Makefile VERSION_LDFLAGS does not stamp internal/version.Version")
	}
	seen := 0
	defer func() {
		if seen != 2 {
			t.Errorf("found %d install build lines in the Makefile, want 2: the scan is broken", seen)
		}
	}()
	for _, line := range strings.Split(mk, "\n") {
		// the two targets that write the binaries an operator installs
		if strings.Contains(line, "go build") && (strings.Contains(line, "-o bin/$$c ./cmd/") || strings.Contains(line, "-o bin/port49-client")) {
			seen++
			if !strings.Contains(line, "$(VERSION_LDFLAGS)") {
				t.Errorf("Makefile build line lacks $(VERSION_LDFLAGS): %s", line)
			}
		}
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
		for _, n := range jobNeeds(t, id, f.Jobs[id]) {
			have[n] = true
		}
		for _, w := range []string{"build-python", "build-galaxy"} {
			if !have[w] {
				t.Errorf("release.yml job %s does not need %s", id, w)
			}
		}
	}
}
