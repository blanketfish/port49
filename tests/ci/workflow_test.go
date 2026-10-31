package ci

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Every workflow is held to the CI rules (plan 12b): only the triggers a fork cannot widen,
// every action pinned by a full commit SHA with its version in a comment, no persisted
// checkout credentials, a job-level permissions block of exactly contents: read, a timeout,
// and no untrusted event data or secret in a run line. workflowProblems reads the YAML, so a
// hyphenated job name or a flow-style block cannot slip past a regexp.

var (
	pinned     = regexp.MustCompile(`^[\w.-]+/[\w./-]+@[0-9a-f]{40}$`)
	versionTag = regexp.MustCompile(`@[0-9a-f]{40} # v\d+(\.\d+)*\s*$`)
)

// allowedTriggers are the events a workflow may run on. pull_request_target and workflow_run
// run with a write token and secrets on a fork's code.
var allowedTriggers = map[string]bool{"push": true, "pull_request": true, "workflow_dispatch": true}

type workflow struct {
	On          yaml.Node `yaml:"on"`
	Permissions any       `yaml:"permissions"`
	Jobs        map[string]struct {
		Permissions    any `yaml:"permissions"`
		TimeoutMinutes int `yaml:"timeout-minutes"`
		Strategy       struct {
			Matrix struct {
				Shard []string `yaml:"shard"`
			} `yaml:"matrix"`
		} `yaml:"strategy"`
		Steps []struct {
			Uses string            `yaml:"uses"`
			Run  string            `yaml:"run"`
			With map[string]any    `yaml:"with"`
			Env  map[string]string `yaml:"env"`
		} `yaml:"steps"`
	} `yaml:"jobs"`
}

// releaseJobPerms is what each job of release.yml may hold, and nothing else: a job that
// publishes holds its one write, and the two that build with no token hold only a read. These
// are the only exceptions to the contents: read rule, and no other workflow has any.
var releaseJobPerms = map[string]map[string]string{
	"check":        {"contents": "read"},
	"goreleaser":   {"contents": "write", "attestations": "write", "id-token": "write"},
	"image":        {"contents": "read", "packages": "write", "attestations": "write", "id-token": "write"},
	"chart":        {"contents": "read", "packages": "write"},
	"build-python": {"contents": "read"},
	"pypi":         {"id-token": "write"},
	"build-galaxy": {"contents": "read"},
	"galaxy":       {},
	"publish":      {"contents": "write"},
}

// jobPermsOK is whether p is what job id of workflow name may hold.
func jobPermsOK(name, id string, p any) bool {
	if name != "release.yml" {
		return readOnly(p)
	}
	want, ok := releaseJobPerms[id]
	m, isMap := p.(map[string]any)
	if !ok || !isMap || len(m) != len(want) {
		return false
	}
	for k, v := range want {
		if m[k] != v {
			return false
		}
	}
	return true
}

// readOnly is a permissions value of exactly contents: read; write-all, read-all and a missing
// block are none of that.
func readOnly(p any) bool {
	m, ok := p.(map[string]any)
	return ok && len(m) == 1 && m["contents"] == "read"
}

func triggers(n yaml.Node) []string {
	var out []string
	switch n.Kind {
	case yaml.ScalarNode:
		out = append(out, n.Value)
	case yaml.SequenceNode:
		for _, c := range n.Content {
			out = append(out, c.Value)
		}
	case yaml.MappingNode:
		for i := 0; i < len(n.Content); i += 2 {
			out = append(out, n.Content[i].Value)
		}
	}
	sort.Strings(out)
	return out
}

// workflowProblems is every rule the workflow named name breaks.
func workflowProblems(name string, raw []byte) []string {
	var w workflow
	if err := yaml.Unmarshal(raw, &w); err != nil {
		return []string{name + ": not YAML: " + err.Error()}
	}
	var p []string
	add := func(format string, a ...any) { p = append(p, name+": "+fmt.Sprintf(format, a...)) }
	for _, t := range triggers(w.On) {
		if !allowedTriggers[t] {
			add("trigger %q is not one of push, pull_request, workflow_dispatch", t)
		}
	}
	if !readOnly(w.Permissions) {
		add("the workflow's permissions are %v, want exactly contents: read", w.Permissions)
	}
	if len(w.Jobs) == 0 {
		add("no jobs")
	}
	for id, j := range w.Jobs {
		if !jobPermsOK(name, id, j.Permissions) {
			add("job %s: permissions are %v, want exactly contents: read set on the job (release.yml: its table)", id, j.Permissions)
		}
		if j.TimeoutMinutes == 0 {
			add("job %s: no timeout-minutes", id)
		}
		for _, s := range j.Steps {
			if s.Uses != "" && !pinned.MatchString(s.Uses) {
				add("job %s: %q is not pinned by a full commit SHA", id, s.Uses)
			}
			if strings.HasPrefix(s.Uses, "actions/checkout@") && fmt.Sprint(s.With["persist-credentials"]) != "false" {
				add("job %s: a checkout without persist-credentials: false", id)
			}
			for _, bad := range []string{"github.event", "github.head_ref", "github.ref_name", "secrets."} {
				if strings.Contains(s.Run, bad) {
					add("job %s: a run line uses %s", id, bad)
				}
			}
			if strings.Contains(s.Run, "set -x") {
				add("job %s: a run line sets -x", id)
			}
		}
	}
	// the version a pin names is a comment, which the YAML parser drops
	for i, ln := range strings.Split(string(raw), "\n") {
		if t := strings.TrimSpace(ln); strings.Contains(t, "uses:") && !strings.HasPrefix(t, "#") && !versionTag.MatchString(t) {
			add("line %d: a pin without its version in a comment: %s", i+1, t)
		}
	}
	return p
}

func TestEveryWorkflowFollowsTheCIRules(t *testing.T) {
	files, err := filepath.Glob("../../.github/workflows/*.yml")
	if err == nil {
		var more []string
		more, err = filepath.Glob("../../.github/workflows/*.yaml")
		files = append(files, more...)
	}
	if err != nil || len(files) < 7 {
		t.Fatalf("found %d workflows (%v), want at least the seven shipped", len(files), err)
	}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range workflowProblems(filepath.Base(f), raw) {
			t.Error(p)
		}
	}
}

func TestTheTestWorkflowShape(t *testing.T) {
	raw, err := os.ReadFile("../../.github/workflows/test.yml")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, want := range []string{"testshard -pkg ./internal/port49d -check -n 3", "make test-shard SHARD=${{ matrix.shard }}",
		`shard: ["1/3", "2/3", "3/3"]`, "make test-root", "make test-rest"} {
		if !strings.Contains(text, want) {
			t.Errorf("test.yml lacks %q", want)
		}
	}
	var w workflow
	if err := yaml.Unmarshal(raw, &w); err != nil {
		t.Fatal(err)
	}
	// the race jobs run the same cut as the plain ones, and the shards job checks that cut
	plain, race := w.Jobs["port49d"].Strategy.Matrix.Shard, w.Jobs["race-port49d"].Strategy.Matrix.Shard
	if len(plain) == 0 || strings.Join(plain, ",") != strings.Join(race, ",") {
		t.Errorf("the port49d shards %v and the race shards %v differ", plain, race)
	}
	if want := fmt.Sprintf("-check -n %d", len(plain)); !strings.Contains(text, want) {
		t.Errorf("test.yml has %d shards and does not run testshard %s", len(plain), want)
	}
	for _, want := range []string{"make race-shard SHARD=${{ matrix.shard }}", "make race-rest", "busybox"} {
		if !strings.Contains(text, want) {
			t.Errorf("test.yml lacks %q", want)
		}
	}
	// the packages are built and checked on every pull request, rpm installed first, in that order
	const packagesTests = "go test -tags packages ./tests/packages/ -count=1 -v"
	var order []string
	for _, st := range w.Jobs["packages"].Steps {
		switch st.Run {
		case "sudo apt-get install -y rpm", "make packages", packagesTests:
			order = append(order, st.Run)
		}
	}
	if strings.Join(order, " | ") != "sudo apt-get install -y rpm | make packages | "+packagesTests {
		t.Errorf("test.yml's packages job runs %v, want rpm installed, then make packages, then %q", order, packagesTests)
	}
	// the release requirements are resolved on the Python the release workflow uses, on every pull request
	rr := w.Jobs["release-requirements"]
	const hashInstall = "pip install --dry-run --require-hashes -r packaging/requirements-release.txt"
	var py, ran bool
	for _, st := range rr.Steps {
		if strings.HasPrefix(st.Uses, "actions/setup-python@") && st.With["python-version"] == releasePython(t) {
			py = true
		}
		if st.Run == hashInstall {
			ran = true
		}
	}
	if !py || !ran {
		t.Errorf("test.yml's release-requirements job must set up Python %s (the release workflow's) and run %q (python %v, run %v)", releasePython(t), hashInstall, py, ran)
	}
	for id, j := range w.Jobs {
		// go test's -timeout is 30m: a job that is cancelled first leaves no goroutine dump
		if j.TimeoutMinutes < 40 {
			t.Errorf("job %s: timeout-minutes %d, want at least 40, above go test's 30m", id, j.TimeoutMinutes)
		}
	}
}

const goodWorkflow = `name: x
on:
  push: {branches: [main]}
  pull_request:
permissions: {contents: read}
jobs:
  my-job:
    runs-on: ubuntu-24.04
    timeout-minutes: 40
    permissions: {contents: read}
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with: {persist-credentials: false}
      - run: make test
`

func TestTheWorkflowRulesCatchEachMistake(t *testing.T) {
	if p := workflowProblems("good.yml", []byte(goodWorkflow)); len(p) != 0 {
		t.Fatalf("the good fixture: %v", p)
	}
	for _, c := range []struct{ name, old, new, want string }{
		{"a hyphenated job with no permissions", "    permissions: {contents: read}\n    steps", "    steps", "job my-job: permissions"},
		{"a job with write", "    permissions: {contents: read}\n    steps", "    permissions: {contents: write}\n    steps", "job my-job: permissions"},
		{"a job with an extra permission", "    permissions: {contents: read}\n    steps", "    permissions: {contents: read, id-token: write}\n    steps", "job my-job: permissions"},
		{"pull_request_target", "  pull_request:\n", "  pull_request_target:\n", "pull_request_target"},
		{"workflow_run", "  pull_request:\n", "  workflow_run: {workflows: [x]}\n", "workflow_run"},
		{"a tag pin", "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2", "actions/checkout@v4", "not pinned"},
		{"a pin with no version comment", " # v4.2.2", "", "without its version"},
		{"persisted credentials", "{persist-credentials: false}", "{fetch-depth: 0}", "persist-credentials"},
		{"event data in a run line", "make test", "echo ${{ github.event.pull_request.title }}", "github.event"},
		{"a head ref in a run line", "make test", "echo ${{ github.head_ref }}", "github.head_ref"},
		{"a secret in a run line", "make test", "echo ${{ secrets.TOKEN }}", "secrets."},
		{"set -x", "make test", "set -x; make test", "-x"},
		{"no timeout", "    timeout-minutes: 40\n", "", "timeout-minutes"},
		{"workflow-level write", "permissions: {contents: read}\njobs", "permissions: write-all\njobs", "workflow's permissions"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if !strings.Contains(goodWorkflow, c.old) {
				t.Fatalf("fixture lacks %q", c.old)
			}
			p := workflowProblems("bad.yml", []byte(strings.Replace(goodWorkflow, c.old, c.new, 1)))
			if !strings.Contains(strings.Join(p, "\n"), c.want) {
				t.Errorf("want a problem containing %q, got %v", c.want, p)
			}
		})
	}
}

// releasePython is the python-version the release workflow's build jobs use; they all use one.
func releasePython(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile("../../.github/workflows/release.yml")
	if err != nil {
		t.Fatal(err)
	}
	var w workflow
	if err := yaml.Unmarshal(raw, &w); err != nil {
		t.Fatal(err)
	}
	var v string
	for id, j := range w.Jobs {
		for _, st := range j.Steps {
			if !strings.HasPrefix(st.Uses, "actions/setup-python@") {
				continue
			}
			pv, _ := st.With["python-version"].(string)
			if v != "" && pv != v {
				t.Fatalf("release.yml job %s uses python %q, another uses %q", id, pv, v)
			}
			v = pv
		}
	}
	if v == "" {
		t.Fatal("release.yml sets up no Python")
	}
	return v
}
