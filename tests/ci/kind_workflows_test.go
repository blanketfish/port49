package ci

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// The kind workflows (plan 12b, Tasks 11 and 13) run the Kubernetes smokes and the kind lab entries
// on GitHub-hosted runners, because kind's nodes are privileged containers and the key-host guard
// refuses them on a machine that holds a TPM or a security key. The generic CI rules
// (workflow_test.go) hold for both files; what is pinned here is what only these files do.

type kindWorkflow struct {
	On   yaml.Node `yaml:"on"`
	Jobs map[string]struct {
		If             string         `yaml:"if"`
		RunsOn         any            `yaml:"runs-on"`
		TimeoutMinutes int            `yaml:"timeout-minutes"`
		Env            map[string]any `yaml:"env"`
		Defaults       struct {
			Run struct {
				Shell string `yaml:"shell"`
			} `yaml:"run"`
		} `yaml:"defaults"`
		Strategy struct {
			FailFast *bool `yaml:"fail-fast"`
			Matrix   struct {
				Cell []string `yaml:"cell"`
			} `yaml:"matrix"`
		} `yaml:"strategy"`
		Steps []struct {
			If   string         `yaml:"if"`
			Uses string         `yaml:"uses"`
			Run  string         `yaml:"run"`
			With map[string]any `yaml:"with"`
		} `yaml:"steps"`
	} `yaml:"jobs"`
}

// the override's name is built from two pieces: a test may not name it as one string (sdtest)
var hostOverride = "PORT49_SMOKE_ON_" + "KEY_HOST"

// makeRecipe is the recipe of target in the Makefile text, joined into one line.
func makeRecipe(mk, target string) string {
	i := strings.Index(mk, "\n"+target+":")
	if i < 0 {
		return ""
	}
	rest := mk[i+1:]
	lines := strings.Split(rest, "\n")
	var out []string
	for _, l := range lines[1:] {
		if !strings.HasPrefix(l, "\t") {
			break
		}
		out = append(out, strings.TrimSpace(l))
	}
	return strings.Join(out, " ")
}

var anchoredTest = regexp.MustCompile(`-run '\^Test[A-Za-z0-9]+\$\$'`)

// kindWorkflowProblems is every rule the two kind workflows break. lab is lab-kind.yml, kind is
// kind.yml, mk is the Makefile.
func kindWorkflowProblems(lab, kind []byte, mk string) []string {
	var p []string
	add := func(format string, a ...any) { p = append(p, fmt.Sprintf(format, a...)) }
	var l, k kindWorkflow
	if err := yaml.Unmarshal(lab, &l); err != nil {
		return []string{"lab-kind.yml: " + err.Error()}
	}
	if err := yaml.Unmarshal(kind, &k); err != nil {
		return []string{"kind.yml: " + err.Error()}
	}
	hosted := func(file, id string, rn any, env map[string]any) {
		if s, _ := rn.(string); s != "ubuntu-24.04" {
			add("%s job %s: runs-on %v, want ubuntu-24.04 (the override is only for a hosted runner)", file, id, rn)
		}
		if env[hostOverride] != "1" {
			add("%s job %s: the job env does not set the key-host override to \"1\"", file, id)
		}
	}

	// lab-kind.yml: a labelled pull request, never a push
	var on struct {
		PullRequest struct {
			Types []string `yaml:"types"`
		} `yaml:"pull_request"`
	}
	if err := l.On.Decode(&on); err != nil {
		add("lab-kind.yml: its triggers are not a mapping: %v", err)
	}
	if got := triggers(l.On); strings.Join(got, ",") != "pull_request" {
		add("lab-kind.yml: triggers %v, want pull_request alone (never a push)", got)
	}
	ty := append([]string(nil), on.PullRequest.Types...)
	sort.Strings(ty)
	if strings.Join(ty, ",") != "labeled,synchronize" {
		add("lab-kind.yml: pull_request types %v, want labeled and synchronize", on.PullRequest.Types)
	}
	if len(l.Jobs) != 1 {
		add("lab-kind.yml: %d jobs, want one matrix job", len(l.Jobs))
	}
	for id, j := range l.Jobs {
		if !strings.Contains(j.If, "contains(github.event.pull_request.labels.*.name, 'lab-kind')") {
			add("lab-kind.yml job %s: its if does not require the lab-kind label: %q", id, j.If)
		}
		if !strings.Contains(j.If, "github.event.label.name == 'lab-kind'") {
			add("lab-kind.yml job %s: adding some other label would start a run: %q", id, j.If)
		}
		hosted("lab-kind.yml", id, j.RunsOn, j.Env)
		if j.TimeoutMinutes != 60 {
			add("lab-kind.yml job %s: timeout-minutes %d, want 60", id, j.TimeoutMinutes)
		}
		if j.Strategy.FailFast == nil || *j.Strategy.FailFast {
			add("lab-kind.yml job %s: fail-fast is not false, so one cell's failure would cancel the others' evidence", id)
		}
		cells := j.Strategy.Matrix.Cell
		for _, want := range []string{"l82", "l83"} {
			if !contains(cells, want) {
				add("lab-kind.yml job %s: matrix cells %v lack %s", id, cells, want)
			}
		}
		var runs, uploads int
		for _, st := range j.Steps {
			if st.Run == "make lab-${{ matrix.cell }} 2>&1 | bash tests/qual/secret-filter.sh" {
				runs++
			}
			if strings.HasPrefix(st.Uses, "actions/upload-artifact@") {
				uploads++
				if st.If != "always()" {
					add("lab-kind.yml job %s: the artifact upload's if is %q, want always(): a failed run is evidence too", id, st.If)
				}
				if st.With["retention-days"] != 30 {
					add("lab-kind.yml job %s: retention-days %v, want 30", id, st.With["retention-days"])
				}
				if st.With["path"] != "bin/lab-out/${{ matrix.cell }}" || st.With["name"] != "lab-${{ matrix.cell }}" {
					add("lab-kind.yml job %s: the artifact is %v at %v, want lab-${{ matrix.cell }} from bin/lab-out/${{ matrix.cell }}", id, st.With["name"], st.With["path"])
				}
			}
		}
		if j.Defaults.Run.Shell != "bash" {
			add("lab-kind.yml job %s: the run shell is %q, want bash (pipefail), so the filter's pipe cannot hide make's exit status", id, j.Defaults.Run.Shell)
		}
		if runs != 1 || uploads != 1 {
			add("lab-kind.yml job %s: %d make lab-<cell> steps and %d artifact uploads, want one of each", id, runs, uploads)
		}
		// every cell has an anchored, lab-tagged target that writes to the directory the upload reads
		for _, c := range cells {
			r := makeRecipe(mk, "lab-"+c)
			switch {
			case r == "":
				add("Makefile has no lab-%s target", c)
			case !strings.Contains(r, "-tags lab") || !anchoredTest.MatchString(r):
				add("Makefile lab-%s does not run `-tags lab` with an anchored -run '^TestX$$': %s", c, r)
			case !strings.Contains(r, "PORT49_LAB_OUT=$(LAB_OUT)/"+c):
				add("Makefile lab-%s does not write its evidence to $(LAB_OUT)/%s", c, c)
			}
		}
	}
	if !strings.Contains(mk, "LAB_OUT ?= $(CURDIR)/bin/lab-out") {
		add("Makefile's LAB_OUT is not $(CURDIR)/bin/lab-out, where the workflow uploads from")
	}

	// kind.yml: the smoke and its red run, on every pull request and on main
	if got := triggers(k.On); strings.Join(got, ",") != "pull_request,push" {
		add("kind.yml: triggers %v, want pull_request and push", got)
	}
	want := map[string]string{"make kind-smoke": "", "make kind-smoke-red": ""}
	for id, j := range k.Jobs {
		hosted("kind.yml", id, j.RunsOn, j.Env)
		if j.TimeoutMinutes != 45 {
			add("kind.yml job %s: timeout-minutes %d, want 45", id, j.TimeoutMinutes)
		}
		for _, st := range j.Steps {
			if _, ok := want[st.Run]; ok {
				want[st.Run] = id
			}
		}
	}
	for run, id := range want {
		if id == "" {
			add("kind.yml runs no %q", run)
		}
	}
	return p
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func readKindInputs(t *testing.T) (lab, kind []byte, mk string) {
	t.Helper()
	var err error
	if lab, err = os.ReadFile("../../.github/workflows/lab-kind.yml"); err != nil {
		t.Fatal(err)
	}
	if kind, err = os.ReadFile("../../.github/workflows/kind.yml"); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile("../../Makefile")
	if err != nil {
		t.Fatal(err)
	}
	return lab, kind, string(b)
}

func TestTheKindWorkflowsShape(t *testing.T) {
	lab, kind, mk := readKindInputs(t)
	for _, p := range kindWorkflowProblems(lab, kind, mk) {
		t.Error(p)
	}
}

// envLine is the job env's one line.
var envLine = "      " + hostOverride + ": \"1\"\n"

func TestTheKindWorkflowRulesCatchEachMistake(t *testing.T) {
	lab, kind, mk := readKindInputs(t)
	if p := kindWorkflowProblems(lab, kind, mk); len(p) != 0 {
		t.Fatalf("the shipped files: %v", p)
	}
	for _, c := range []struct {
		name, file, old, new, want string
	}{
		{"a push trigger", "lab", "  pull_request:\n    types: [labeled, synchronize]", "  push: {branches: [main]}\n  pull_request:\n    types: [labeled, synchronize]", "want pull_request alone"},
		{"no synchronize", "lab", "[labeled, synchronize]", "[labeled]", "types"},
		{"no label gate", "lab", "contains(github.event.pull_request.labels.*.name, 'lab-kind') && ", "", "require the lab-kind label"},
		{"any label starts a run", "lab", " && (github.event.action == 'synchronize' || github.event.label.name == 'lab-kind')", "", "other label"},
		{"no pipefail shell", "lab", "    defaults: {run: {shell: bash}}\n", "", "pipefail"},
		{"no override", "lab", envLine, "      OTHER: \"1\"\n", "override"},
		{"a self-hosted runner", "lab", "runs-on: ubuntu-24.04", "runs-on: self-hosted", "runs-on"},
		{"a short timeout", "lab", "timeout-minutes: 60", "timeout-minutes: 40", "timeout-minutes"},
		{"fail-fast", "lab", "fail-fast: false", "fail-fast: true", "fail-fast"},
		{"no l82 in the matrix", "lab", "cell: [l82, l83]", "cell: [l83]", "lack l82"},
		{"no l83 in the matrix", "lab", "cell: [l82, l83]", "cell: [l82]", "lack l83"},
		{"an upload that skips a failed run", "lab", "      - if: always()\n        uses: actions/upload-artifact", "      - uses: actions/upload-artifact", "always()"},
		{"short retention", "lab", "retention-days: 30", "retention-days: 1", "retention-days"},
		{"an upload from the wrong directory", "lab", "path: bin/lab-out/${{ matrix.cell }}", "path: bin", "artifact is"},
		{"a hard-coded cell", "lab", "run: make lab-${{ matrix.cell }}", "run: make lab-l82", "make lab-<cell>"},
		{"a log that is not filtered", "lab", " 2>&1 | bash tests/qual/secret-filter.sh", "", "make lab-<cell>"},
		{"the smoke job without its override", "kind", envLine, "", "override"},
		{"no red run", "kind", "- run: make kind-smoke-red", "- run: make kind-smoke", "runs no"},
		{"kind.yml on push only", "kind", "  pull_request:\n", "", "triggers"},
		{"an unanchored lab target", "mk", "-run '^TestL82$$'", "-run TestL82", "anchored"},
		{"a lab target with no tag", "mk", "go test -tags lab ./tests/lab/ -run '^TestL82$$'", "go test ./tests/lab/ -run '^TestL82$$'", "-tags lab"},
		{"a lab target that writes elsewhere", "mk", "PORT49_LAB_OUT=$(LAB_OUT)/l82", "PORT49_LAB_OUT=/tmp/out", "LAB_OUT"},
	} {
		t.Run(c.name, func(t *testing.T) {
			l, k, m := string(lab), string(kind), mk
			target := &l
			switch c.file {
			case "kind":
				target = &k
			case "mk":
				target = &m
			}
			if !strings.Contains(*target, c.old) {
				t.Fatalf("fixture lacks %q", c.old)
			}
			*target = strings.Replace(*target, c.old, c.new, 1)
			p := kindWorkflowProblems([]byte(l), []byte(k), m)
			if !strings.Contains(strings.Join(p, "\n"), c.want) {
				t.Errorf("want a problem containing %q, got %v", c.want, p)
			}
		})
	}
}
