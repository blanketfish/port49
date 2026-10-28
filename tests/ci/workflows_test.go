package ci

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
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
	Env         map[string]string `yaml:"env"`
	Needs       any               `yaml:"needs"`
	Environment any               `yaml:"environment"`
	Permissions map[string]any    `yaml:"permissions"`
	Steps       []step            `yaml:"steps"`
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
	for id, want := range map[string]string{"pypi": "pypi", "galaxy": "galaxy", "goreleaser": "release", "image": "release", "chart": "release"} {
		if f.Jobs[id].Environment != want {
			t.Errorf("job %s has environment %v, want %s", id, f.Jobs[id].Environment, want)
		}
	}
	for id, j := range f.Jobs {
		if _, named := map[string]bool{"pypi": true, "galaxy": true, "goreleaser": true, "image": true, "chart": true}[id]; !named && j.Environment != nil {
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

func envNames(m map[string]string) []string {
	var n []string
	for k := range m {
		n = append(n, k)
	}
	return n
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
	if len(gx.Steps) != 4 || !strings.HasPrefix(gx.Steps[0].Uses, "actions/download-artifact@") ||
		!strings.HasPrefix(gx.Steps[1].Uses, "actions/setup-python@") || gx.Steps[2].Run == "" || gx.Steps[3].Run == "" {
		t.Fatalf("galaxy is not a download-artifact, a setup-python, a pip step and the publish step: %+v", gx.Steps)
	}
	if len(gx.Env) != 0 {
		t.Errorf("galaxy has job-level env %v (names only): the token env belongs on the publish step", envNames(gx.Env))
	}
	if gx.Steps[2].Run != "pip install --require-hashes -r requirements-release.txt" || len(gx.Steps[2].Env) != 0 {
		t.Errorf("galaxy's pip step is %q with env %v", gx.Steps[2].Run, envNames(gx.Steps[2].Env))
	}
	pub := gx.Steps[3]
	// the token reaches ansible-galaxy through its server config in the environment, never argv
	for _, bad := range []string{"--token", "--api-key", "GALAXY_API_KEY", "pip"} {
		if strings.Contains(pub.Run, bad) {
			t.Errorf("galaxy's publish text names %s", bad)
		}
	}
	if !strings.HasPrefix(pub.Run, "set +e\nansible-galaxy collection publish port49-client-*.tar.gz > publish.log 2>&1\n") {
		t.Errorf("galaxy's publish text is %q", pub.Run)
	}
	if pub.Env["ANSIBLE_GALAXY_SERVER_LIST"] != "public" ||
		pub.Env["ANSIBLE_GALAXY_SERVER_PUBLIC_URL"] != "https://galaxy.ansible.com/" ||
		pub.Env["ANSIBLE_GALAXY_SERVER_PUBLIC_TOKEN"] != "${{ secrets.GALAXY_API_KEY }}" || len(pub.Env) != 3 {
		t.Errorf("galaxy's publish env is %v (names only)", envNames(pub.Env))
	}
	// no step but the publish holds the token, and no step that holds it runs pip
	for id, j := range f.Jobs {
		for i, s := range j.Steps {
			if _, held := s.Env["ANSIBLE_GALAXY_SERVER_PUBLIC_TOKEN"]; held && !(id == "galaxy" && i == 3) {
				t.Errorf("job %s step %d holds the Galaxy token", id, i)
			}
		}
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
			if s.With["persist-credentials"] != false {
				t.Errorf("job %s: checkout persist-credentials is %v, want false (GoReleaser takes GITHUB_TOKEN from env)", id, s.With["persist-credentials"])
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
	// a draft release, then the attestation over the real artifacts, then the publish
	var order []string
	for _, s := range f.Jobs["goreleaser"].Steps {
		switch {
		case strings.TrimSpace(s.Run) == "make release-packages":
			order = append(order, "release")
			if s.Env["GITHUB_TOKEN"] != "${{ secrets.GITHUB_TOKEN }}" {
				t.Error("make release-packages does not take GITHUB_TOKEN from env")
			}
		case strings.HasPrefix(s.Uses, "actions/attest-build-provenance@"):
			order = append(order, "attest")
		case strings.TrimSpace(s.Run) == `gh release edit "$GITHUB_REF_NAME" --draft=false`:
			order = append(order, "publish")
			if s.Env["GH_TOKEN"] != "${{ secrets.GITHUB_TOKEN }}" || s.Env["GH_REPO"] != "${{ github.repository }}" {
				t.Error("the publish step lacks GH_TOKEN or GH_REPO in env")
			}
		case s.Run != "":
			t.Errorf("the goreleaser job runs %q", s.Run)
		}
	}
	if strings.Join(order, ",") != "release,attest,publish" {
		t.Errorf("the goreleaser job's order is %v, want release, attest, publish", order)
	}
	gr, _ := os.ReadFile("../../.goreleaser.yaml")
	if !regexp.MustCompile(`(?m)^release:\n  draft: true$`).Match(gr) {
		t.Error(".goreleaser.yaml does not create a draft release")
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
	// image and chart push after goreleaser's draft and attestation succeeded
	for _, id := range []string{"image", "chart"} {
		got := false
		if need, ok := f.Jobs[id].Needs.([]any); ok {
			for _, n := range need {
				got = got || n == "goreleaser"
			}
		}
		if !got {
			t.Errorf("%s does not need goreleaser", id)
		}
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

// Every publishing job waits for check, and check refuses a tag that is not on main and a tag
// that disagrees with the version files: a release from an unreviewed commit never publishes.
func TestEveryPublishingJobWaitsForTheCheck(t *testing.T) {
	f, _ := release(t)
	for id, j := range f.Jobs {
		if id == "check" {
			continue
		}
		var needs []string
		switch n := j.Needs.(type) {
		case string:
			needs = []string{n}
		case []any:
			for _, x := range n {
				needs = append(needs, x.(string))
			}
		}
		found := false
		for _, n := range needs {
			found = found || n == "check"
		}
		if !found {
			t.Errorf("job %s does not need check (needs %v)", id, needs)
		}
	}
	var runs []string
	for _, s := range f.Jobs["check"].Steps {
		if s.Run != "" {
			runs = append(runs, strings.TrimSpace(s.Run))
		}
		if strings.HasPrefix(s.Uses, "actions/checkout@") && s.With["fetch-depth"] != 0 {
			t.Errorf("check's checkout has fetch-depth %v, want 0 (the ancestor test needs main)", s.With["fetch-depth"])
		}
	}
	for _, want := range []string{
		`go run ./tests/ci/cmd/versioncheck -tag "$GITHUB_REF_NAME"`,
		`git merge-base --is-ancestor "$GITHUB_SHA" origin/main || { echo "tag is not on main"; exit 1; }`,
	} {
		found := false
		for _, r := range runs {
			found = found || r == want
		}
		if !found {
			t.Errorf("check does not run %q", want)
		}
	}
}

// The publish step's exit status, run for real with a stub ansible-galaxy: success, a refusal
// that is not "already exists", the anchored refusal, and the phrase on a line that is not
// Galaxy's error. Only the first and the third pass.
func TestTheGalaxyPublishStepPassesOnlyOnSuccessOrAnExistingVersion(t *testing.T) {
	f, _ := release(t)
	run := f.Jobs["galaxy"].Steps[3].Run
	const existing = "[ERROR]: GalaxyError: Error when publishing collection to public (https://galaxy.ansible.com/) (HTTP Code: 400, Message: Collection version already exists Code: conflict)\n"
	for _, c := range []struct {
		name, out string
		rc        int
		pass      bool
	}{
		{"success", "published\n", 0, true},
		{"unrelated failure", "[ERROR]: GalaxyError: Error when publishing collection to public (https://galaxy.ansible.com/) (HTTP Code: 401, Message: Invalid token Code: unauthorized)\n", 1, false},
		{"existing version", existing, 1, true},
		{"phrase off the error line", "note: the thing already exists\n", 1, false},
		{"phrase after an unanchored prefix", "x " + existing, 1, false},
		{"a 400 that says exists but not already", "[ERROR]: GalaxyError: Error when publishing collection to public (https://galaxy.ansible.com/) (HTTP Code: 400, Message: Namespace exists but you do not own it Code: forbidden)\n", 1, false},
		{"another server's refusal", "[ERROR]: GalaxyError: Error when publishing collection to other (https://example.invalid/) (HTTP Code: 400, Message: Collection version already exists Code: conflict)\n", 1, false},
		{"no output at all", "", 1, false},
	} {
		dir := t.TempDir()
		stub := "#!/bin/sh\nprintf '%s' \"$STUB_OUT\"\nexit $STUB_RC\n"
		if err := os.WriteFile(filepath.Join(dir, "ansible-galaxy"), []byte(stub), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "port49-client-1.0.0.tar.gz"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("bash", "-eo", "pipefail", "-c", run)
		cmd.Dir = dir
		cmd.Env = []string{"PATH=" + dir + ":/usr/bin:/bin", "STUB_OUT=" + c.out, "STUB_RC=" + strconv.Itoa(c.rc)}
		err := cmd.Run()
		if (err == nil) != c.pass {
			t.Errorf("%s: step passed=%v, want %v", c.name, err == nil, c.pass)
		}
	}
}
