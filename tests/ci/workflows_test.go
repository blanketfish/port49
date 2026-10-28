package ci

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// The release workflow's own rules (plan 12b, Task 12), on top of the rules every workflow keeps
// (workflow_test.go): what runs it, who holds a token, what the publishing jobs may do, and
// that the release binary is the pinned one. Nothing here runs a workflow.

type step struct {
	Name string            `yaml:"name"`
	Uses string            `yaml:"uses"`
	Run  string            `yaml:"run"`
	With map[string]any    `yaml:"with"`
	Env  map[string]string `yaml:"env"`
}

type job struct {
	Needs       any            `yaml:"needs"`
	Environment any            `yaml:"environment"`
	Permissions map[string]any `yaml:"permissions"`
	Steps       []step         `yaml:"steps"`
}

type flow struct {
	On          yaml.Node      `yaml:"on"`
	Permissions map[string]any `yaml:"permissions"`
	Jobs        map[string]job `yaml:"jobs"`
}

func load(t *testing.T, path string) (flow, string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var f flow
	if err := yaml.Unmarshal(raw, &f); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return f, string(raw)
}

func release(t *testing.T) (flow, string) { return load(t, "../../.github/workflows/release.yml") }

func allWorkflows(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, g := range []string{"*.yml", "*.yaml"} {
		files, _ := filepath.Glob("../../.github/workflows/" + g)
		for _, f := range files {
			b, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			out[filepath.Base(f)] = string(b)
		}
	}
	if len(out) < 8 {
		t.Fatalf("found %d workflows, want the seven and release.yml", len(out))
	}
	return out
}

func TestReleaseRunsOnTagsOnly(t *testing.T) {
	f, _ := release(t)
	if f.On.Kind != yaml.MappingNode || len(f.On.Content) != 2 || f.On.Content[0].Value != "push" {
		t.Fatalf("release.yml's on is not exactly push: %v", triggers(f.On))
	}
	var push struct {
		Tags     []string `yaml:"tags"`
		Branches []string `yaml:"branches"`
	}
	if err := f.On.Content[1].Decode(&push); err != nil {
		t.Fatal(err)
	}
	if len(push.Tags) != 1 || push.Tags[0] != "v*" || len(push.Branches) != 0 {
		t.Errorf("push is tags %v branches %v, want exactly tags: ['v*']", push.Tags, push.Branches)
	}
}

func TestOnlyThreeJobsHoldIDToken(t *testing.T) {
	for name, text := range allWorkflows(t) {
		f, _ := load(t, "../../.github/workflows/"+name)
		if !readOnly(f.Permissions) {
			t.Errorf("%s: top-level permissions are %v, want exactly contents: read", name, f.Permissions)
		}
		if strings.Contains(text, "write-all") {
			t.Errorf("%s: write-all", name)
		}
		for _, tr := range triggers(f.On) {
			if tr == "pull_request_target" {
				t.Errorf("%s: pull_request_target", name)
			}
		}
		for id, j := range f.Jobs {
			holds := j.Permissions["id-token"] != nil
			may := name == "release.yml" && (id == "pypi" || id == "goreleaser" || id == "image")
			if holds && !may {
				t.Errorf("%s: job %s holds id-token", name, id)
			}
			if may && j.Permissions["id-token"] != "write" {
				t.Errorf("release.yml: job %s does not hold id-token: write", id)
			}
		}
	}
	f, _ := release(t)
	for id, want := range map[string]string{"pypi": "pypi", "galaxy": "galaxy"} {
		if f.Jobs[id].Environment != want {
			t.Errorf("job %s has environment %v, want %s", id, f.Jobs[id].Environment, want)
		}
	}
	for id, j := range f.Jobs {
		if id != "pypi" && id != "galaxy" && j.Environment != nil {
			t.Errorf("job %s names an environment (%v)", id, j.Environment)
		}
	}
	// GALAXY_API_KEY is read once, in the galaxy job's publish step's env, and nowhere else
	for name, text := range allWorkflows(t) {
		n := strings.Count(text, "secrets.GALAXY_API_KEY")
		if want := map[bool]int{true: 1, false: 0}[name == "release.yml"]; n != want {
			t.Errorf("%s names secrets.GALAXY_API_KEY %d times, want %d", name, n, want)
		}
	}
	for id, j := range f.Jobs {
		for _, s := range j.Steps {
			for _, v := range s.Env {
				if strings.Contains(v, "GALAXY_API_KEY") && !(id == "galaxy" && strings.Contains(s.Run, "ansible-galaxy collection publish")) {
					t.Errorf("job %s: %s outside galaxy's publish step", id, v)
				}
			}
		}
	}
}

func hasUses(j job, prefix string) bool {
	for _, s := range j.Steps {
		if strings.HasPrefix(s.Uses, prefix) {
			return true
		}
	}
	return false
}

func TestPublishJobsBuildNothing(t *testing.T) {
	f, _ := release(t)
	for _, id := range []string{"pypi", "galaxy"} {
		if hasUses(f.Jobs[id], "actions/checkout@") {
			t.Errorf("%s has a checkout", id)
		}
	}
	py := f.Jobs["pypi"]
	if len(py.Steps) != 2 || !strings.HasPrefix(py.Steps[0].Uses, "actions/download-artifact@") ||
		!strings.HasPrefix(py.Steps[1].Uses, "pypa/gh-action-pypi-publish@") {
		t.Errorf("pypi's steps are not exactly a download-artifact and the publish action: %+v", py.Steps)
	} else if py.Steps[1].With["skip-existing"] != true || py.Steps[1].With["packages-dir"] != "dist" {
		t.Errorf("pypi's publish options are %v, want packages-dir dist and skip-existing", py.Steps[1].With)
	}
	gx := f.Jobs["galaxy"]
	var runs []step
	for _, s := range gx.Steps {
		if s.Run != "" {
			runs = append(runs, s)
		}
	}
	if len(gx.Steps) != 2 || !strings.HasPrefix(gx.Steps[0].Uses, "actions/download-artifact@") || len(runs) != 1 {
		t.Fatalf("galaxy is not a download-artifact and one run step: %+v", gx.Steps)
	}
	lines := strings.Split(strings.TrimSpace(runs[0].Run), "\n")
	if len(lines) != 2 || lines[0] != "pip install --require-hashes -r requirements-release.txt" ||
		lines[1] != `ansible-galaxy collection publish port49-client-*.tar.gz --token "$GALAXY_API_KEY" 2>&1 | tee publish.log || grep -q "already exists" publish.log` {
		t.Errorf("galaxy's commands are %q", lines)
	}
	if runs[0].Env["GALAXY_API_KEY"] != "${{ secrets.GALAXY_API_KEY }}" {
		t.Errorf("galaxy's publish env is %v", runs[0].Env)
	}
	for _, id := range []string{"build-python", "build-galaxy"} {
		j := f.Jobs[id]
		if j.Permissions["id-token"] != nil || j.Environment != nil {
			t.Errorf("%s holds a token or an environment", id)
		}
		installs := 0
		for _, s := range j.Steps {
			for _, ln := range strings.Split(s.Run, "\n") {
				if strings.Contains(ln, "pip install") {
					installs++
					if ln != "pip install --require-hashes -r packaging/requirements-release.txt" {
						t.Errorf("%s installs with %q", id, ln)
					}
				}
			}
		}
		if installs != 1 {
			t.Errorf("%s has %d pip installs, want the one hash-pinned", id, installs)
		}
	}
	// the galaxy build hands its requirements file on with the tarball
	found := false
	for _, s := range f.Jobs["build-galaxy"].Steps {
		found = found || strings.Contains(s.Run, "cp packaging/requirements-release.txt galaxy-dist/")
	}
	if !found {
		t.Error("build-galaxy does not put requirements-release.txt in its artifact")
	}
}

func TestCheckoutsKeepNoCredentials(t *testing.T) {
	f, _ := release(t)
	for id, j := range f.Jobs {
		for _, s := range j.Steps {
			if !strings.HasPrefix(s.Uses, "actions/checkout@") {
				continue
			}
			keeps := s.With["persist-credentials"] != false
			if keeps != (id == "goreleaser") {
				t.Errorf("job %s: checkout persist-credentials is %v: only goreleaser's keeps them", id, s.With["persist-credentials"])
			}
		}
	}
}

func TestGoReleaserIsThePinnedBinary(t *testing.T) {
	for name, text := range allWorkflows(t) {
		if strings.Contains(text, "goreleaser/goreleaser-action") {
			t.Errorf("%s uses goreleaser-action", name)
		}
	}
	f, _ := release(t)
	var runs []string
	for _, s := range f.Jobs["goreleaser"].Steps {
		if s.Run != "" {
			runs = append(runs, strings.TrimSpace(s.Run))
		}
	}
	if len(runs) != 1 || runs[0] != "make release-packages" {
		t.Fatalf("the goreleaser job's commands are %q, want exactly make release-packages", runs)
	}
	mk, _ := os.ReadFile("../../Makefile")
	if !regexp.MustCompile(`(?m)^release-packages: bin/goreleaser-\$\(GORELEASER_VERSION\)\n\tbin/goreleaser-\$\(GORELEASER_VERSION\) release --clean$`).Match(mk) {
		t.Error("make release-packages is not the pinned binary's release --clean")
	}
	if !regexp.MustCompile(`(?m)^bin/goreleaser-\$\(GORELEASER_VERSION\):\n(.*\n)*?\techo "\$\(GORELEASER_SHA256_LINUX_X64\)  bin/goreleaser.tar.gz" \| sha256sum -c -\n\ttar `).Match(mk) {
		t.Error("the binary is extracted before its sha256 is checked, or not checked")
	}
}

func TestEveryActionIsPinnedBySHA(t *testing.T) {
	sha := regexp.MustCompile(`@[0-9a-f]{40}( |$)`)
	for name, text := range allWorkflows(t) {
		for i, ln := range strings.Split(text, "\n") {
			tl := strings.TrimSpace(ln)
			if strings.HasPrefix(tl, "#") {
				continue
			}
			if _, after, ok := strings.Cut(tl, "uses:"); ok && !sha.MatchString(after) {
				t.Errorf("%s:%d: %s", name, i+1, tl)
			}
		}
	}
}

func TestNoWorkflowTracesShell(t *testing.T) {
	for name, text := range allWorkflows(t) {
		for _, bad := range []string{"set -x", "ACTIONS_STEP_DEBUG", "ACTIONS_RUNNER_DEBUG"} {
			for _, ln := range strings.Split(text, "\n") {
				if !strings.HasPrefix(strings.TrimSpace(ln), "#") && strings.Contains(ln, bad) {
					t.Errorf("%s names %s", name, bad)
				}
			}
		}
	}
}

// The image's tags: :latest only when the tag has no hyphen, and the digest that is attested is
// the one the build pushed.
func TestTheImageJobTagsAndAttests(t *testing.T) {
	f, _ := release(t)
	j := f.Jobs["image"]
	var tags, build, attest *step
	for i, s := range j.Steps {
		switch {
		case strings.Contains(s.Run, "port49:latest"):
			tags = &j.Steps[i]
		case strings.HasPrefix(s.Uses, "docker/build-push-action@"):
			build = &j.Steps[i]
		case strings.HasPrefix(s.Uses, "actions/attest-build-provenance@"):
			attest = &j.Steps[i]
		}
	}
	if tags == nil || build == nil || attest == nil {
		t.Fatal("the image job lacks its tags step, build or attestation")
	}
	if !strings.Contains(tags.Run, `case "$version" in *-*) ;; *) echo "ghcr.io/rhwendt/port49:latest" ;; esac`) {
		t.Error("the :latest tag is not withheld from a pre-release")
	}
	if build.With["target"] != "port49" || build.With["platforms"] != "linux/amd64,linux/arm64" || build.With["push"] != true {
		t.Errorf("the build's options are %v", build.With)
	}
	if attest.With["subject-digest"] != "${{ steps.build.outputs.digest }}" || attest.With["push-to-registry"] != true {
		t.Errorf("the attestation's options are %v", attest.With)
	}
	// the jobs that publish wait for every check and build, and PyPI and Galaxy publish last
	for _, id := range []string{"pypi", "galaxy"} {
		need, _ := f.Jobs[id].Needs.([]any)
		got := map[string]bool{}
		for _, n := range need {
			got[n.(string)] = true
		}
		for _, w := range []string{"goreleaser", "image", "chart"} {
			if !got[w] {
				t.Errorf("%s does not wait for %s", id, w)
			}
		}
	}
}
